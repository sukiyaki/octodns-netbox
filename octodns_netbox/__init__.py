"""
A NetBox source for octoDNS.

Automatically creating A/AAAA records and their corresponding PTR records
based on a NetBox API.
"""

import logging
import re
from collections import defaultdict
from collections.abc import Iterable
from ipaddress import ip_interface
from typing import Any, Literal, NamedTuple

import pynetbox
import requests
from octodns.record import Record
from octodns.source.base import BaseSource
from octodns.zone import SubzoneRecordException, Zone
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    TypeAdapter,
    ValidationInfo,
    field_validator,
)

from octodns_netbox import reversename

try:
    from octodns.record import Rrset
except ImportError:  # pragma: no-cover-with-rrset
    # octoDNS before 1.22 has no Rrset. Its Rr holds one value.
    from octodns.record import Rr

    def _octodns_records(
        zone: Zone, rdatas: dict[tuple[str, str], list[str]], ttl: int, lenient: bool
    ) -> list[Any]:
        rrs = [
            Rr(owner, _type, ttl, rdata)
            for (owner, _type), values in rdatas.items()
            for rdata in values
        ]
        return Record.from_rrs(zone, rrs, lenient=lenient)

else:  # pragma: no-cover-without-rrset

    def _octodns_records(
        zone: Zone, rdatas: dict[tuple[str, str], list[str]], ttl: int, lenient: bool
    ) -> list[Any]:
        rrsets = [
            Rrset(owner, _type, ttl, values)
            for (owner, _type), values in rdatas.items()
        ]
        return Record.from_rrsets(zone, rrsets, lenient=lenient)


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

    url: str
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

    @field_validator("url", mode="before")
    @classmethod
    def http_url_without_api(cls, value: Any) -> str:
        """pynetbox adds /api to the URL, so a trailing /api or /api/ is dropped."""
        url = str(TypeAdapter(AnyHttpUrl).validate_python(value))
        return re.sub(r"/api/?$", "", url)

    @field_validator("populate_vrf_name")
    @classmethod
    def validate_one_vrf(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is not None and info.data.get("populate_vrf_id") is not None:
            raise ValueError("Do not set both populate_vrf_id and populate_vrf_name.")
        return value


class NetboxSource(BaseSource):
    """Creates A, AAAA, and PTR records from the IP addresses in NetBox."""

    SUPPORTS_GEO = False
    SUPPORTS = frozenset({"A", "AAAA", "PTR"})

    def __init__(self, id: str, **settings: Any):
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

        self._nb_client = pynetbox.api(url=self.config.url, token=self.config.token)
        session = requests.Session()
        session.verify = self.config.ssl_verify
        self._nb_client.http_session = session

        self._vrf = self._resolve_vrf()

    def _resolve_vrf(self) -> VrfFilter:
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

    def _ip_addresses(self, filters: dict[str, Any]) -> Iterable[Any]:
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
        self.log.debug(
            f"populate called for zone={zone.name}, target={target}, lenient={lenient}"
        )
        before = len(zone.records)
        if reversename.is_reverse(zone):
            rrs = self._ptr_records(zone)
        else:
            rrs = self._forward_records(zone)

        rdatas: dict[tuple[str, str], list[str]] = defaultdict(list)
        for rr in rrs:
            rdatas[(rr.owner, rr.type)].append(rr.rdata)
        for record in _octodns_records(zone, rdatas, self.config.ttl, lenient):
            try:
                zone.add_record(record, lenient=lenient)
            except SubzoneRecordException:
                self.log.warning(f"Skipping subzone record: {record}")
        self.log.info(
            "Populated %s new records in zone %s", len(zone.records) - before, zone.name
        )

    def _ptr_records(self, zone: Zone) -> list[ResourceRecord]:
        field_name = self.config.field_name
        network = reversename.to_network(zone)
        ipam_records = self._ip_addresses(
            {
                f"{field_name}__empty": "false",
                "parent": network.compressed,
                "family": network.version,
            }
        )
        records: list[ResourceRecord] = []
        for ipam_record in ipam_records:
            ip_address = ip_interface(ipam_record.address).ip
            ptr_name = zone.hostname_from_fqdn(
                reversename.from_address(zone, ip_address)
            )
            fqdns = _fqdns(ipam_record[field_name])
            if not self.config.multivalue_ptr:
                fqdns = fqdns[:1]
            for fqdn in fqdns:
                rr = ResourceRecord(ptr_name, "PTR", fqdn)
                self.log.debug(f"Adding PTR record {rr} to zone {zone.name}")
                records.append(rr)
        return records

    def _forward_records(self, zone: Zone) -> list[ResourceRecord]:
        field_name = self.config.field_name
        ipam_records = self._ip_addresses({f"{field_name}__ic": zone.name.rstrip(".")})
        records: list[ResourceRecord] = []
        for ipam_record in ipam_records:
            ip_address = ip_interface(ipam_record.address).ip
            record_type = "A" if ip_address.version == 4 else "AAAA"
            for fqdn in _fqdns(ipam_record[field_name]):
                if not self._fqdn_in_zone(fqdn, zone):
                    self.log.debug(f"Skip: FQDN={fqdn} on zone {zone.name}")
                    continue
                name = zone.hostname_from_fqdn(fqdn)
                rr = ResourceRecord(name, record_type, ip_address.compressed)
                self.log.debug(
                    f"Created {record_type} record {rr} for zone {zone.name}"
                )
                records.append(rr)
        return records

    def _fqdn_in_zone(self, fqdn: str, zone: Zone) -> bool:
        if fqdn == zone.name:
            return True
        if fqdn.endswith(f".{zone.name}"):
            leftover = fqdn[: -len(zone.name)].rstrip(".")
            return self.config.populate_subdomains or "." not in leftover
        return False


def _fqdns(field_value: str) -> list[str]:
    names = (name.strip() for name in field_value.split(","))
    return [name if name.endswith(".") else f"{name}." for name in names if name]
