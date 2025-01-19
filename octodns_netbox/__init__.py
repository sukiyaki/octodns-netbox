"""
A NetBox source for octoDNS.

Automatically creating A/AAAA records and their corresponding PTR records
based on a NetBox API.
"""

import logging
import re
import sys
import typing
from ipaddress import ip_interface

if sys.version_info >= (3, 9):
    from typing import Annotated, Literal
elif sys.version_info >= (3, 8):
    from typing import Literal

    from typing_extensions import Annotated
else:
    from typing_extensions import Annotated, Literal

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

Url = Annotated[
    str,
    BeforeValidator(lambda value: str(TypeAdapter(AnyHttpUrl).validate_python(value))),
]


class NetboxSourceConfig(BaseModel):
    model_config = ConfigDict(extra="allow", arbitrary_types_allowed=True)

    multivalue_ptr: bool = False
    SUPPORTS_MULTIVALUE_PTR_: bool = Field(
        multivalue_ptr, alias="SUPPORTS_MULTIVALUE_PTR"
    )
    SUPPORTS_DYNAMIC_: bool = Field(False, alias="SUPPORTS_DYNAMIC")
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
    def check_url(cls, v) -> str:
        if re.search("/api/?$", v):
            v = re.sub("/api/?$", "", v)
        return v

    @field_validator("populate_vrf_name")
    def check_vrf_name(
        cls, v: typing.Optional[str], info: ValidationInfo
    ) -> typing.Optional[str]:
        if "populate_vrf_id" in info.data and (
            v is not None and info.data["populate_vrf_id"] is not None
        ):
            raise ValueError("Do not set both populate_vrf_id and populate_vrf")
        return v


class NetboxSource(BaseSource, NetboxSourceConfig):
    def __init__(self, id: str, **kwargs):
        kwargs["id"] = id
        kwargs["log"] = logging.getLogger(f"{self.__class__.__name__}[{id}]")

        NetboxSourceConfig.__init__(self, **kwargs)
        BaseSource.__init__(self, id)

        self.log.debug(
            f"__init__: id={id}, url={self.url}, ttl={self.ttl}, ssl_verify={self.ssl_verify}"
        )

        self._nb_client = pynetbox.api(url=self.url, token=self.token)

        session = requests.Session()
        session.verify = self.ssl_verify
        self._nb_client.http_session = session

        self._populate_vrf()

    def _populate_vrf(self) -> None:
        if self.populate_vrf_name == "Global" or self.populate_vrf_id == 0:
            self.populate_vrf_id = "null"
            return

        if self.populate_vrf_name is not None:
            try:
                self.populate_vrf_id = self._nb_client.ipam.vrfs.get(
                    name=self.populate_vrf_name
                ).id
            except (ValueError, AttributeError):
                raise ValueError(
                    "Failed to retrive vrf information by name, use populate_vrf_id instead"
                )

    def populate(self, zone: Zone, target=False, lenient=False):
        self.log.debug(
            f"populate: name={zone.name}, target={target}, lenient={lenient}"
        )
        before = len(zone.records)

        if zone.name.endswith(".in-addr.arpa."):
            rrs = self._populate_PTR(zone, family=4)
        elif zone.name.endswith(".ip6.arpa."):
            rrs = self._populate_PTR(zone, family=6)
        else:
            rrs = self._populate_normal(zone)

        self._add_record(zone, rrs, lenient)

        self.log.info("populate:   found %s records", len(zone.records) - before)

    def _add_record(
        self,
        zone: Zone,
        rrs: typing.List[Rr],
        lenient: bool,
    ):
        rrs = [rr for rr in rrs if self.populate_subdomains or rr.name.count(".") == 0]

        for record in Record.from_rrs(zone, rrs, lenient=lenient):
            try:
                zone.add_record(record, lenient=lenient)
            except SubzoneRecordException:
                self.log.warning(f"Skipping subzone record: {record}")

    def _populate_PTR(self, zone: Zone, family: Literal[4, 6]) -> typing.List[Rr]:
        ret = []
        network = octodns_netbox.reversename.to_network(zone)

        kw = {
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
        if kw["vrf_id"] is None:
            del kw["vrf_id"]

        ipam_records = self._nb_client.ipam.ip_addresses.filter(**kw)

        for ipam_record in ipam_records:
            ip_address = ip_interface(ipam_record.address).ip
            name = zone.hostname_from_fqdn(
                octodns_netbox.reversename.from_address(zone, ip_address)
            )
            # take the first fqdn
            fqdns = self._get_fqdns_list(
                ipam_record[self.field_name],
                len_limit=None if self.multivalue_ptr else 1,
            )

            for fqdn in fqdns:
                rr = Rr(name, "PTR", self.ttl, fqdn)
                self.log.info(f"zone {zone.name} record added: {rr}")
                ret.append(rr)

        return ret

    def _populate_normal(self, zone: Zone) -> typing.List[Rr]:
        ret = []

        kw = {
            f"{self.field_name}__ic": f".{zone.name[:-1]}",
            "vrf_id": self.populate_vrf_id,
            "tag": self.populate_tags,
        }

        # https://github.com/netbox-community/pynetbox/pull/545
        # From pynetbox v7.4.0, None will be mapped to null.
        # When vrf_id is null, it does not mean that it is not filtered by vrf_id,
        # but it would be an intention that VRF is not set.
        if kw["vrf_id"] is None:
            del kw["vrf_id"]

        ipam_records = self._nb_client.ipam.ip_addresses.filter(**kw)

        for ipam_record in ipam_records:
            ip_address = ip_interface(ipam_record.address).ip
            _type: Literal["A", "AAAA"] = "A" if ip_address.version == 4 else "AAAA"
            fqdns = self._get_fqdns_list(ipam_record[self.field_name])

            for fqdn in fqdns:
                if not fqdn.endswith(zone.name):
                    continue

                name = zone.hostname_from_fqdn(fqdn)
                rr = Rr(name, _type, self.ttl, ip_address.compressed)
                self.log.info(f"zone {zone.name} record added: {rr}")
                ret.append(rr)

        return ret

    def _get_fqdns_list(
        self, field_value: str, len_limit: typing.Optional[int] = None
    ) -> typing.List[str]:
        ret = [
            fqdn if fqdn[-1] == "." else f"{fqdn}." for fqdn in field_value.split(",")
        ]
        return ret[:len_limit]
