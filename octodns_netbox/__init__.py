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

if sys.version_info >= (3, 8):
    from typing import Literal
else:
    from typing_extensions import Literal

import pynetbox
import requests
from octodns.record import Record
from octodns.source.base import BaseSource
from octodns.zone import DuplicateRecordException, SubzoneRecordException, Zone
from pydantic import AnyHttpUrl, BaseModel, Extra, validator


class NetboxSourceConfig(BaseModel):
    SUPPORTS_GEO: bool = False
    SUPPORTS_DYNAMIC: bool = False
    SUPPORTS: typing.Set[str] = set(("A", "AAAA", "PTR"))

    id: str
    url: AnyHttpUrl
    token: str
    field_name: str = "description"
    populate_tags: typing.List[str] = []
    populate_vrf_id: typing.Optional[int] = None
    populate_vrf_name: typing.Optional[str] = None
    populate_subdomains: bool = True
    ttl: int = 60
    ssl_verify: bool = True
    log: logging.Logger

    @validator("url")
    def check_url(cls, v):
        if re.search("/api/?$", v):
            v = re.sub("/api/?$", "", v)
        return v

    @validator("populate_vrf_name")
    def check_vrf_name(cls, v, values):
        if "populate_vrf_id" in values and (
            v is not None and values["populate_vrf_id"] is not None
        ):
            raise ValueError("Do not set both populate_vrf_id and populate_vrf")
        return v

    class Config:
        extra = Extra.allow
        underscore_attrs_are_private = True
        arbitrary_types_allowed = True


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

        if (
            self.populate_vrf_id is not None
            and self._nb_client.ipam.vrfs.get(self.populate_vrf_id) is None
        ):
            raise ValueError(
                "Failed to retrive vrf information by id, check populate_vrf_id"
            )

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
            self._populate_PTR(zone, family=4, lenient=lenient)
        elif zone.name.endswith(".ip6.arpa."):
            self._populate_PTR(zone, family=6, lenient=lenient)
        else:
            self._populate_normal(zone, lenient)

        self.log.info("populate:   found %s records", len(zone.records) - before)

    def _add_record(
        self,
        zone: Zone,
        name: str,
        _type: Literal["A", "AAAA", "PTR"],
        value: str,
        lenient: bool,
    ):
        if _type == "PTR" and value[-1] != ".":
            value = f"{value}."

        self.log.info(
            f"{_type} record added: zone={zone.name}, name={name}, value={value}"
        )
        record = Record.new(
            zone,
            name,
            {"ttl": self.ttl, "type": _type, "value": f"{value}"},
            source=self,
            lenient=lenient,
        )
        try:
            zone.add_record(record, lenient=lenient)
        except DuplicateRecordException:
            self.log.warning(f"Skipping duplicated record: {record}")
        except SubzoneRecordException:
            self.log.warning(f"Skipping subzone record: {record}")

    def _populate_PTR(self, zone, family, lenient):
        zone_length = len(zone.name.split(".")[:-3])

        if family == 4:
            if zone_length > 3:
                # parent = networkaddr/mask
                parent = ".".join(zone.name.split(".")[:-3][::-1])
            else:
                # parent = networkaddr
                parent = ".".join(zone.name.split(".")[:-3][::-1])
                for _ in range(4 - zone_length):
                    parent += ".0"
                parent += "/{}".format(8 * zone_length)
        elif family == 6:
            zone_reverse_str = "".join(zone.name.split(".")[:-3][::-1])
            if len(zone_reverse_str) % 4 != 0:
                for _ in range(4 - (len(zone_reverse_str) % 4)):
                    zone_reverse_str += "0"
            parent = ":".join(
                [
                    zone_reverse_str[i : i + 4]
                    for i in range(0, len(zone_reverse_str), 4)
                ]
            )
            parent += "::/{}".format(zone_length * 4)

        ipam_records = self._nb_client.ipam.ip_addresses.filter(
            parent=parent,
            family=family,
            vrf_id=self.populate_vrf_id,
            tag=self.populate_tags,
        )

        for ipam_record in ipam_records:
            ip_address = ip_interface(ipam_record.address).ip
            fqdn_base = ipam_record[self.field_name]
            fqdn = None

            if family == 4:
                if zone_length > 3:
                    _name = "{}.{}".format(
                        ip_address.compressed.split(".")[-1], zone.name
                    )
                    name = zone.hostname_from_fqdn(_name)
                else:
                    name = zone.hostname_from_fqdn(ip_address.reverse_pointer)
            elif family == 6:
                name = zone.hostname_from_fqdn(ip_address.reverse_pointer)

            # take the first fqdn
            fqdn = fqdn_base.split(",")[0]

            if fqdn:
                self._add_record(zone, name, "PTR", fqdn, lenient)

    def _populate_normal(self, zone, lenient):
        kw = {f"{self.field_name}__ic": zone.name[:-1]}
        ipam_records = self._nb_client.ipam.ip_addresses.filter(
            vrf_id=self.populate_vrf_id, tag=self.populate_tags, **kw
        )

        for ipam_record in ipam_records:
            ip_address = ip_interface(ipam_record.address).ip
            _type = "A" if ip_address.version == 4 else "AAAA"
            fqdn_base = ipam_record[self.field_name]

            for fqdn in fqdn_base.split(","):
                if fqdn[-1] != ".":
                    fqdn = f"{fqdn}."

                if not fqdn.endswith(zone.name):
                    continue

                if not self.populate_subdomains and (
                    fqdn.count(".") != zone.name.count(".") + 1
                ):
                    # Skip subdomain records.
                    self.log.debug(
                        f"{_type} record skipped: populate_subdomains=False, FQDN={fqdn}"
                    )
                    continue

                name = zone.hostname_from_fqdn(fqdn)
                self._add_record(zone, name, _type, ip_address.compressed, lenient)
