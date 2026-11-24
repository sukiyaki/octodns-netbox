"""
A NetBox source for octoDNS.

Automatically creating A/AAAA records and their corresponding PTR records
based on a NetBox API.
"""

import logging
import re
import typing
from collections import defaultdict
from ipaddress import ip_interface
from typing import Annotated, Literal, NamedTuple

import pynetbox
import requests
from octodns.record import Record
from octodns.source.base import BaseSource
from octodns.zone import SubzoneRecordException, Zone
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    TypeAdapter,
    ValidationInfo,
    field_validator,
)

import octodns_netbox.reversename

try:
    from octodns.record import Rrset
except ImportError:  # pragma: no-cover-with-rrset
    # octoDNS before 1.22 has no Rrset. Its Rr holds one value.
    from octodns.record import Rr

    def _octodns_records(
        zone: Zone, rdatas: dict[tuple[str, str], list[str]], ttl: int, lenient: bool
    ) -> list[typing.Any]:
        rrs = [
            Rr(owner, _type, ttl, rdata)
            for (owner, _type), values in rdatas.items()
            for rdata in values
        ]
        return Record.from_rrs(zone, rrs, lenient=lenient)

else:  # pragma: no-cover-without-rrset

    def _octodns_records(
        zone: Zone, rdatas: dict[tuple[str, str], list[str]], ttl: int, lenient: bool
    ) -> list[typing.Any]:
        rrsets = [
            Rrset(owner, _type, ttl, values)
            for (owner, _type), values in rdatas.items()
        ]
        return Record.from_rrsets(zone, rrsets, lenient=lenient)


# Type alias for URL validation
Url = Annotated[
    str,
    BeforeValidator(lambda value: str(TypeAdapter(AnyHttpUrl).validate_python(value))),
]

# The IP addresses a source reads: those in every VRF (None), those without
# a VRF, which NetBox calls the Global VRF ("global"), or those in the VRF
# with this ID.
VrfFilter = int | Literal["global"] | None


class ResourceRecord(NamedTuple):
    """One value of a record. The source groups them by owner and type."""

    owner: str  # relative to the zone
    type: str
    rdata: str


class NetboxSourceConfig(BaseModel):
    """The settings of a NetboxSource in the octoDNS config.

    Unknown keys are dropped. NetboxSource logs a warning for each one.
    """

    model_config = ConfigDict(frozen=True, extra="ignore")

    url: Url
    token: str
    field_name: str = "description"
    populate_tags: list[str] = []
    # "null" is the Global VRF, like 0.
    populate_vrf_id: int | Literal["null"] | None = None
    populate_vrf_name: str | None = None
    populate_subdomains: bool = True
    multivalue_ptr: bool = False
    ttl: int = 60
    ssl_verify: bool = True

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
    @classmethod
    def validate_one_vrf(cls, value: str | None, info: ValidationInfo) -> str | None:
        """
        Ensures that populate_vrf_name and populate_vrf_id
        are not set simultaneously.

        Raises:
            ValueError: If both populate_vrf_id and populate_vrf_name are set.
        """
        if value is not None and info.data.get("populate_vrf_id") is not None:
            raise ValueError("Do not set both populate_vrf_id and populate_vrf_name.")
        return value


class NetboxSource(BaseSource):
    """
    NetboxSource class for octoDNS.

    This source fetches IP address data from NetBox based on certain filters
    (VRF, tags, etc.) and automatically creates A/AAAA and corresponding PTR
    records in octoDNS.
    """

    SUPPORTS_GEO = False
    SUPPORTS = frozenset({"A", "AAAA", "PTR"})

    def __init__(self, id: str, **settings: typing.Any):
        """
        Validates the settings and connects the NetBox client.

        Args:
            id (str): The unique identifier for this source.
            **settings: The source's keys from the octoDNS config,
                validated by NetboxSourceConfig.
        """
        self.log = logging.getLogger(f"{self.__class__.__name__}[{id}]")
        self.config = NetboxSourceConfig(**settings)
        super().__init__(id)
        for key in settings:
            if key not in NetboxSourceConfig.model_fields:
                self.log.warning("Unknown setting %s has no effect.", key)

        self.log.debug(
            f"Initializing NetboxSource: id={id}, url={self.config.url}, "
            f"ttl={self.config.ttl}, ssl_verify={self.config.ssl_verify}"
        )

        # Initialize NetBox client
        self._nb_client = pynetbox.api(url=self.config.url, token=self.config.token)
        session = requests.Session()
        session.verify = self.config.ssl_verify
        self._nb_client.http_session = session

        self._vrf = self._resolve_vrf()

    def _resolve_vrf(self) -> VrfFilter:
        """
        Resolves populate_vrf_id or populate_vrf_name to the VRF to read.
        ID 0, ID "null", and the name "Global" mean the Global VRF. A VRF name
        is looked up in NetBox.

        Returns:
            VrfFilter: The VRF the source reads IP addresses from.

        Raises:
            ValueError: If VRF name is invalid or not found in NetBox.
        """
        name, vrf_id = self.config.populate_vrf_name, self.config.populate_vrf_id
        if name == "Global" or vrf_id == 0 or vrf_id == "null":
            return "global"
        if name is None:
            return vrf_id
        try:
            vrf_obj = self._nb_client.ipam.vrfs.get(name=name)
            if vrf_obj is None:
                raise ValueError(f"VRF '{name}' not found. Use a valid name or VRF ID.")
            return vrf_obj.id
        except (ValueError, AttributeError) as exc:
            raise ValueError(
                f"Failed to retrieve VRF information by name '{name}'. "
                "Use a valid populate_vrf_id instead."
            ) from exc

    def _ip_addresses(
        self, filters: dict[str, typing.Any]
    ) -> typing.Iterable[typing.Any]:
        """
        Queries NetBox for the IP addresses that match `filters`, the VRF,
        and the tags.

        Args:
            filters (dict[str, Any]): The zone's filters for NetBox.

        Returns:
            Iterable[Any]: The IPAM records NetBox returns.
        """
        vrf: dict[str, int | str] = {}
        if self._vrf == "global":
            # NetBox reads vrf_id=null as "no VRF".
            vrf = {"vrf_id": "null"}
        elif self._vrf is not None:
            vrf = {"vrf_id": self._vrf}
        return self._nb_client.ipam.ip_addresses.filter(
            **filters, **vrf, tag=self.config.populate_tags
        )

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
    ) -> list[ResourceRecord]:
        """
        Populates PTR records for a reverse zone (in-addr.arpa or ip6.arpa).

        Args:
            zone (Zone): The reverse zone to populate.
            family (Literal[4, 6]): IP family (4 for IPv4, 6 for IPv6).

        Returns:
            list[ResourceRecord]: The PTR records.
        """
        network = octodns_netbox.reversename.to_network(zone)
        ipam_records = self._ip_addresses(
            {
                f"{self.config.field_name}__empty": "false",
                "parent": network.compressed,
                "family": family,
            }
        )
        return self._build_ptr_records(zone, ipam_records)

    def _build_ptr_records(
        self,
        zone: Zone,
        ipam_records: typing.Iterable[typing.Any],
    ) -> list[ResourceRecord]:
        """
        Builds PTR records from NetBox IPAM records.

        Args:
            zone (Zone): The reverse zone being populated.
            ipam_records (Iterable[Any]): IPAM records returned by NetBox filter query.

        Returns:
            list[ResourceRecord]: The PTR records to add to the zone.
        """
        records: list[ResourceRecord] = []
        for ipam_record in ipam_records:
            ip_address = ip_interface(ipam_record.address).ip
            ptr_name = zone.hostname_from_fqdn(
                octodns_netbox.reversename.from_address(zone, ip_address)
            )
            # Potentially multiple FQDNs in the designated field
            fqdns = self._parse_fqdns_list(
                ipam_record[self.config.field_name],
                len_limit=None if self.config.multivalue_ptr else 1,
            )
            for fqdn in fqdns:
                rr = ResourceRecord(ptr_name, "PTR", fqdn)
                self.log.debug(f"Adding PTR record {rr} to zone {zone.name}")
                records.append(rr)
        return records

    def _populate_forward_records(self, zone: Zone) -> list[ResourceRecord]:
        """
        Populates A/AAAA records for a forward zone.

        Args:
            zone (Zone): The forward zone to populate.

        Returns:
            list[ResourceRecord]: The A and AAAA records.
        """
        zone_name_no_dot = zone.name.rstrip(".")
        ipam_records = self._ip_addresses(
            {f"{self.config.field_name}__ic": zone_name_no_dot}
        )
        return self._build_forward_records(zone, ipam_records)

    def _build_forward_records(
        self, zone: Zone, ipam_records: typing.Iterable[typing.Any]
    ) -> list[ResourceRecord]:
        """
        Creates A/AAAA records from NetBox IP address records for the given zone.

        Args:
            zone (Zone): The forward zone being populated.
            ipam_records (Iterable[Any]): IPAM records returned by NetBox filter query.

        Returns:
            list[ResourceRecord]: The forward records to add to the zone.
        """
        records: list[ResourceRecord] = []
        for ipam_record in ipam_records:
            # Delegate the per-record processing to a helper method
            new_records = self._build_records_for_ipam_record(zone, ipam_record)
            records.extend(new_records)

        return records

    def _build_records_for_ipam_record(
        self, zone: Zone, ipam_record: typing.Any
    ) -> list[ResourceRecord]:
        """
        Converts a single NetBox IPAM record into one or more octoDNS record objects.

        Args:
            zone (Zone): The forward zone being populated.
            ipam_record (Any): A single IPAM record from NetBox.

        Returns:
            list[ResourceRecord]: The A or AAAA records for the IPAM record.
        """
        records: list[ResourceRecord] = []

        # Derive IP address and record type
        ip_address = ip_interface(ipam_record.address).ip
        record_type: Literal["A", "AAAA"] = "A" if ip_address.version == 4 else "AAAA"

        # Parse out any FQDNs listed in the desired NetBox field
        fqdns = self._parse_fqdns_list(ipam_record[self.config.field_name])

        # For each FQDN, determine if it belongs to this zone and create records
        for fqdn in fqdns:
            if not self._fqdn_in_zone(fqdn, zone):
                self.log.debug(f"Skip: FQDN={fqdn} on zone {zone.name}")
                continue

            name = zone.hostname_from_fqdn(fqdn)
            rr = ResourceRecord(name, record_type, ip_address.compressed)
            self.log.debug(f"Created {record_type} record {rr} for zone {zone.name}")
            records.append(rr)

        return records

    def _fqdn_in_zone(self, fqdn: str, zone: Zone) -> bool:
        """
        Checks whether a given FQDN belongs in the specified zone.

        1. If FQDN matches the zone's apex (fqdn == zone.name), it's valid.
        2. If FQDN ends with ".<zone.name>", it's valid. However, if
           populate_subdomains is False, we exclude deeper subdomains.
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
            if self.config.populate_subdomains or "." not in leftover:
                return True

        return False

    def _add_records_to_zone(
        self, zone: Zone, rrs: list[ResourceRecord], lenient: bool
    ) -> None:
        """
        Groups the records by owner and type and adds them to the given
        zone, respecting lenient mode and subzone exceptions.

        Args:
            zone (Zone): The zone to which records will be added.
            rrs (list[ResourceRecord]): The records, in the order NetBox
                returned their addresses.
            lenient (bool): If True, subzone exceptions will not raise an error.
        """
        rdatas: dict[tuple[str, str], list[str]] = defaultdict(list)
        for rr in rrs:
            rdatas[(rr.owner, rr.type)].append(rr.rdata)
        for record in _octodns_records(zone, rdatas, self.config.ttl, lenient):
            try:
                zone.add_record(record, lenient=lenient)
            except SubzoneRecordException:
                self.log.warning(f"Skipping subzone record: {record}")

    def _parse_fqdns_list(
        self, field_value: str, len_limit: int | None = None
    ) -> list[str]:
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
