"""
A NetBox source for octoDNS.

Automatically creating A/AAAA records and their corresponding PTR records
based on a NetBox API.
"""

import logging
import re
import typing
from ipaddress import ip_interface

from typing import Annotated, Literal

import pynetbox
import requests
from octodns.record import Record, Rr
from octodns.source.base import BaseSource
from octodns.zone import SubzoneRecordException, Zone
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationInfo,
    field_validator,
)

import octodns_netbox.reversename

# Type alias for URL validation
Url = Annotated[
    str,
    BeforeValidator(lambda value: str(TypeAdapter(AnyHttpUrl).validate_python(value))),
]


class NetboxSourceConfig(BaseModel):
    """Configuration model for the NetboxSource."""

    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)

    multivalue_ptr: bool = False
    SUPPORTS_MULTIVALUE_PTR_: bool = Field(
        default_factory=lambda: False,
        alias="SUPPORTS_MULTIVALUE_PTR",
        description="Whether multiple PTR records are supported.",
    )
    SUPPORTS_DYNAMIC_: bool = Field(
        False,
        alias="SUPPORTS_DYNAMIC",
        description="Whether dynamic records are supported.",
    )
    SUPPORTS_GEO: bool = False
    SUPPORTS: typing.Set[str] = set(("A", "AAAA", "PTR"))

    id: str
    url: Url
    token: str
    field_name: str = "description"
    populate_tags: typing.List[str] = []
    populate_vrf_id: Annotated[
        typing.Union[int, Literal["null"], None], Field(validate_default=True)
    ] = None
    populate_vrf_name: Annotated[typing.Optional[str], Field(validate_default=True)] = (
        None
    )
    populate_subdomains: bool = True
    ttl: int = 60
    ssl_verify: bool = True
    log: logging.Logger

    @field_validator("url")
    def remove_trailing_api(cls, v: str) -> str:
        """
        Removes any trailing '/api' or '/api/' from the URL.

        Args:
            v (str): The URL to be validated.

        Returns:
            str: A sanitized URL without trailing '/api'.
        """
        if re.search(r"/api/?$", v):
            v = re.sub(r"/api/?$", "", v)
        return v

    @field_validator("populate_vrf_name")
    def validate_vrf_name(
        cls, v: typing.Optional[str], info: ValidationInfo
    ) -> typing.Optional[str]:
        """
        Ensures that populate_vrf_name and populate_vrf_id
        are not set simultaneously.

        Args:
            v (Optional[str]): The VRF name to validate.
            info (ValidationInfo): Contains context about the overall model.

        Returns:
            Optional[str]: The validated VRF name.

        Raises:
            ValueError: If both populate_vrf_id and populate_vrf_name are set.
        """
        data = info.data
        if v is not None and data.get("populate_vrf_id") is not None:
            raise ValueError("Do not set both populate_vrf_id and populate_vrf_name.")
        return v


class NetboxSource(BaseSource, NetboxSourceConfig):
    """
    NetboxSource class for octoDNS.

    This source fetches IP address data from NetBox based on certain filters
    (VRF, tags, etc.) and automatically creates A/AAAA and corresponding PTR
    records in octoDNS.
    """

    def __init__(self, id: str, **kwargs: typing.Any):
        """
        Initializes the NetboxSource by combining BaseSource and NetboxSourceConfig.

        Args:
            id (str): The unique identifier for this source.
            **kwargs (dict): Additional keyword arguments to configure the source.
        """
        # Set the mandatory 'id' and a dedicated logger
        kwargs["id"] = id
        kwargs["log"] = logging.getLogger(f"{self.__class__.__name__}[{id}]")

        # Initialize the configuration model (NetboxSourceConfig)
        NetboxSourceConfig.__init__(self, **kwargs)

        # Initialize the octoDNS BaseSource
        BaseSource.__init__(self, id)

        self.log.debug(
            f"Initializing NetboxSource: id={id}, url={self.url}, "
            f"ttl={self.ttl}, ssl_verify={self.ssl_verify}"
        )

        # Initialize NetBox client
        self._nb_client = pynetbox.api(url=self.url, token=self.token)
        session = requests.Session()
        session.verify = self.ssl_verify
        self._nb_client.http_session = session

        # Initialize VRF settings (if specified)
        self._init_vrf()

    def _init_vrf(self) -> None:
        """
        Retrieves the VRF ID from NetBox if 'populate_vrf_name' is set,
        or handles the special "Global"/ID=0 case.
        """
        if self._is_global_vrf():
            self.populate_vrf_id = "null"
            return

        if self.populate_vrf_name is not None:
            self._set_vrf_id_from_name()

    def _is_global_vrf(self) -> bool:
        """
        Determines if the user explicitly wants the 'Global' VRF or has ID=0.
        Interprets this as "null" in NetBox.

        Returns:
            bool: True if the VRF should be treated as global/null, False otherwise.
        """
        return self.populate_vrf_name == "Global" or self.populate_vrf_id == 0

    def _set_vrf_id_from_name(self) -> None:
        """
        Retrieves the VRF from NetBox by name and sets the 'populate_vrf_id'.
        Raises a ValueError if the VRF cannot be found.

        Raises:
            ValueError: If VRF name is invalid or not found in NetBox.
        """
        try:
            vrf_obj = self._nb_client.ipam.vrfs.get(name=self.populate_vrf_name)
            if vrf_obj is None:
                raise ValueError(
                    f"VRF '{self.populate_vrf_name}' not found. "
                    "Use a valid name or VRF ID."
                )
            self.populate_vrf_id = vrf_obj.id
        except (ValueError, AttributeError) as exc:
            raise ValueError(
                f"Failed to retrieve VRF information by name '{self.populate_vrf_name}'. "
                "Use a valid populate_vrf_id instead."
            ) from exc

    def populate(self, zone: Zone, target: bool = False, lenient: bool = False) -> None:
        """
        Populates the given zone with records from NetBox.

        Args:
            zone (Zone): The octoDNS zone object to populate.
            target (bool, optional): Unused in this implementation. Defaults to False.
            lenient (bool, optional): If True, allows more permissive record handling.
                                      Defaults to False.
        """
        self.log.debug(
            f"populate called for zone={zone.name}, target={target}, lenient={lenient}"
        )
        before = len(zone.records)

        # Decide whether this is a reverse zone (PTR) or forward zone (A/AAAA)
        if zone.name.endswith(".in-addr.arpa."):
            # IPv4 reverse zone
            records = self._populate_ptr_records(zone, family=4)
        elif zone.name.endswith(".ip6.arpa."):
            # IPv6 reverse zone
            records = self._populate_ptr_records(zone, family=6)
        else:
            # Forward zone (A/AAAA)
            records = self._populate_forward_records(zone)

        self._add_records_to_zone(zone, records, lenient)
        self.log.info(
            "Populated %s new records in zone %s", len(zone.records) - before, zone.name
        )

    def _populate_ptr_records(
        self, zone: Zone, family: Literal[4, 6]
    ) -> typing.List[Rr]:
        """
        Populates PTR records for a reverse zone (in-addr.arpa or ip6.arpa).

        Args:
            zone (Zone): The reverse zone to populate.
            family (Literal[4, 6]): IP family (4 for IPv4, 6 for IPv6).

        Returns:
            List[Rr]: A list of Rr objects for PTR records.
        """
        network = octodns_netbox.reversename.to_network(zone)
        filter_kwargs = self._build_ptr_filter_kwargs(network, family)

        ipam_records = self._nb_client.ipam.ip_addresses.filter(**filter_kwargs)
        return self._build_ptr_records(zone, ipam_records)

    def _build_ptr_filter_kwargs(
        self, network: typing.Any, family: Literal[4, 6]
    ) -> dict[str, typing.Any]:
        """
        Builds the filter kwargs for NetBox queries when populating PTR records.

        Args:
            network (Any): The IP network derived from the reverse zone.
            family (Literal[4, 6]): The IP family (4 or 6).

        Returns:
            dict[str, Any]: A dictionary of filter criteria for NetBox.
        """
        filter_kwargs = {
            f"{self.field_name}__empty": "false",
            "parent": network.compressed,
            "family": family,
            "vrf_id": self.populate_vrf_id,
            "tag": self.populate_tags,
        }

        # https://github.com/netbox-community/pynetbox/pull/545
        # From pynetbox v7.4.0, None will be mapped to null.
        # When vrf_id is null, it does not mean that it is not filtered by vrf_id,
        # but it would be an intention that VRF is not set.
        if filter_kwargs["vrf_id"] is None:
            del filter_kwargs["vrf_id"]

        return filter_kwargs

    def _build_ptr_records(
        self,
        zone: Zone,
        ipam_records: typing.Iterable[typing.Any],
    ) -> typing.List[Rr]:
        """
        Builds PTR Rr objects from NetBox IPAM records.

        Args:
            zone (Zone): The reverse zone being populated.
            ipam_records (Iterable[Any]): IPAM records returned by NetBox filter query.

        Returns:
            List[Rr]: A list of PTR record objects to be added to the zone.
        """
        records: typing.List[Rr] = []
        for ipam_record in ipam_records:
            ip_address = ip_interface(ipam_record.address).ip
            ptr_name = zone.hostname_from_fqdn(
                octodns_netbox.reversename.from_address(zone, ip_address)
            )
            # Potentially multiple FQDNs in the designated field
            fqdns = self._parse_fqdns_list(
                ipam_record[self.field_name],
                len_limit=None if self.multivalue_ptr else 1,
            )
            for fqdn in fqdns:
                rr = Rr(ptr_name, "PTR", self.ttl, fqdn)
                self.log.debug(f"Adding PTR record {rr} to zone {zone.name}")
                records.append(rr)
        return records

    def _populate_forward_records(self, zone: Zone) -> typing.List[Rr]:
        """
        Populates A/AAAA records for a forward zone.

        Args:
            zone (Zone): The forward zone to populate.

        Returns:
            List[Rr]: A list of Rr objects for A/AAAA records.
        """
        filter_kwargs = self._build_forward_filter_kwargs(zone)
        ipam_records = self._nb_client.ipam.ip_addresses.filter(**filter_kwargs)

        return self._build_forward_records(zone, ipam_records)

    def _build_forward_filter_kwargs(self, zone: Zone) -> dict[str, typing.Any]:
        """
        Builds the filter kwargs for NetBox queries when populating forward A/AAAA records.

        Args:
            zone (Zone): The forward zone for which to build query filters.

        Returns:
            dict[str, Any]: A dictionary of filter criteria for NetBox queries.
        """
        zone_name_no_dot = zone.name.rstrip(".")
        filter_kwargs = {
            f"{self.field_name}__ic": zone_name_no_dot,
            "vrf_id": self.populate_vrf_id,
            "tag": self.populate_tags,
        }
        if filter_kwargs["vrf_id"] is None:
            del filter_kwargs["vrf_id"]
        return filter_kwargs

    def _build_forward_records(
        self, zone: Zone, ipam_records: typing.Iterable[typing.Any]
    ) -> typing.List[Rr]:
        """
        Creates A/AAAA Rr objects from NetBox IP address records for the given zone.

        Args:
            zone (Zone): The forward zone being populated.
            ipam_records (Iterable[Any]): IPAM records returned by NetBox filter query.

        Returns:
            List[Rr]: A list of forward record objects to be added to the zone.
        """
        records: typing.List[Rr] = []
        for ipam_record in ipam_records:
            # Delegate the per-record processing to a helper method
            new_records = self._build_records_for_ipam_record(zone, ipam_record)
            records.extend(new_records)

        return records

    def _build_records_for_ipam_record(
        self, zone: Zone, ipam_record: typing.Any
    ) -> typing.List[Rr]:
        """
        Converts a single NetBox IPAM record into one or more octoDNS record objects.

        Args:
            zone (Zone): The forward zone being populated.
            ipam_record (Any): A single IPAM record from NetBox.

        Returns:
            List[Rr]: A list of forward (A/AAAA) record objects corresponding
                    to the provided IPAM record.
        """
        records: typing.List[Rr] = []

        # Derive IP address and record type
        ip_address = ip_interface(ipam_record.address).ip
        record_type: Literal["A", "AAAA"] = "A" if ip_address.version == 4 else "AAAA"

        # Parse out any FQDNs listed in the desired NetBox field
        fqdns = self._parse_fqdns_list(ipam_record[self.field_name])

        # For each FQDN, determine if it belongs to this zone and create records
        for fqdn in fqdns:
            if not self._fqdn_in_zone(fqdn, zone):
                self.log.debug(f"Skip: FQDN={fqdn} on zone {zone.name}")
                continue

            name = zone.hostname_from_fqdn(fqdn)
            rr = Rr(name, record_type, self.ttl, ip_address.compressed)
            self.log.debug(f"Created {record_type} record {rr} for zone {zone.name}")
            records.append(rr)

        return records

    def _fqdn_in_zone(self, fqdn: str, zone: Zone) -> bool:
        """
        Checks whether a given FQDN belongs in the specified zone.

        1. If FQDN matches the zone's apex (fqdn == zone.name), it's valid.
        2. If FQDN ends with ".<zone.name>", it's valid. However, if
           self.populate_subdomains is False, we exclude deeper subdomains.
        3. Otherwise, it's invalid.

        Args:
            fqdn (str): The fully qualified domain name to check.
            zone (Zone): The zone against which to match.

        Returns:
            bool: True if the FQDN should be included in this zone, False otherwise.
        """
        if fqdn == zone.name:
            return True

        if fqdn.endswith(f".{zone.name}"):
            leftover = fqdn[: -len(zone.name)].rstrip(".")
            # If not populating subdomains, exclude multi-level subdomains
            if self.populate_subdomains or "." not in leftover:
                return True

        return False

    def _add_records_to_zone(
        self, zone: Zone, rrs: typing.List[Rr], lenient: bool
    ) -> None:
        """
        Adds Rr objects to the given zone, respecting lenient mode
        and subzone exceptions.

        Args:
            zone (Zone): The zone to which records will be added.
            rrs (List[Rr]): A list of Rr objects.
            lenient (bool): If True, subzone exceptions will not raise an error.
        """
        for record in Record.from_rrs(zone, rrs, lenient=lenient):
            try:
                zone.add_record(record, lenient=lenient)
            except SubzoneRecordException:
                self.log.warning(f"Skipping subzone record: {record}")

    def _parse_fqdns_list(
        self, field_value: str, len_limit: typing.Optional[int] = None
    ) -> typing.List[str]:
        """
        Parses a string containing one or more comma-separated FQDNs into a list.
        Ensures each FQDN ends with a trailing period.

        Args:
            field_value (str): The raw field containing comma-separated FQDNs.
            len_limit (Optional[int]): If set, limits how many FQDNs to parse.

        Returns:
            List[str]: A list of sanitized FQDNs, each ending with a period.
        """
        fqdns = [
            fqdn.strip() if fqdn.strip().endswith(".") else f"{fqdn.strip()}."
            for fqdn in field_value.split(",")
            if fqdn.strip()
        ]
        return fqdns[:len_limit] if len_limit else fqdns
