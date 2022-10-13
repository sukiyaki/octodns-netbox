"""
A NetBox source for octoDNS.

Automatically creating A/AAAA records and their corresponding PTR records
based on a NetBox API.
"""

import logging
import re
from collections import defaultdict
from ipaddress import ip_interface

import pynetbox
import requests
from octodns.record import Record
from octodns.source.base import BaseSource
from octodns.zone import DuplicateRecordException, SubzoneRecordException


class NetboxSource(BaseSource):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS = set(("A", "AAAA", "PTR"))

    def __init__(
        self,
        id,
        url,
        token,
        name_field="description",
        populate_tags=[],
        populate_vrf_id=None,
        populate_vrf_name=None,
        populate_subdomains=True,
        ttl=60,
        ssl_verify=True,
    ):
        self.log = logging.getLogger(f"{self.__class__.__name__}[{id}]")
        self.log.debug(
            f"__init__: id={id}, url={url}, ttl={ttl}, ssl_verify={ssl_verify}"
        )
        super().__init__(id)

        if re.search("/api/?$", url):
            self.log.warning(
                "Please remove `/api` at the end of the URL (still working for backwards compatibility)"
            )
            url = re.sub("/api/?$", "", url)
        self._nb_client = pynetbox.api(url=url, token=token)

        session = requests.Session()
        session.verify = ssl_verify
        self._nb_client.http_session = session

        if not isinstance(name_field, str):
            raise TypeError("Invalid type for name_field: must be a string")
        self._name_field = name_field

        if not isinstance(ttl, (str, int)):
            raise TypeError("Invalid type for ttl: must be a string or int")
        try:
            self._ttl = int(ttl)
        except ValueError:
            raise ValueError("Invalid value: ttl")

        if not isinstance(populate_tags, list):
            raise TypeError("Invalid type for populate_tags: must be a list")
        self._populate_tags = populate_tags

        if not isinstance(populate_vrf_id, (str, int, type(None))):
            raise TypeError("Invalid type for populate_vrf_id: must be a string or int")
        try:
            if populate_vrf_id is None:
                self._populate_vrf_id = None
            else:
                self._populate_vrf_id = int(populate_vrf_id)
        except ValueError:
            raise ValueError("Invalid value: populate_vrf_id")
        if (
            self._populate_vrf_id is not None
            and self._nb_client.ipam.vrfs.get(self._populate_vrf_id) is None
        ):
            raise ValueError(
                "Failed to retrive vrf information by id, check populate_vrf_id"
            )

        if populate_vrf_name is not None and self._populate_vrf_id is not None:
            raise ValueError("Do not set both populate_vrf_id and populate_vrf")
        if not isinstance(populate_vrf_name, (str, type(None))):
            raise TypeError("Invalid type for populate_vrf_name: must be a string")
        if populate_vrf_name is not None:
            try:
                self._populate_vrf_id = self._nb_client.ipam.vrfs.get(
                    name=populate_vrf_name
                ).id
            except (ValueError, AttributeError):
                raise ValueError(
                    "Failed to retrive vrf information by name, use populate_vrf_id instead"
                )

        if type(populate_subdomains) != bool:
            raise TypeError("Invalid type for populate_subdomains: must be a bool")
        self._populate_subdomains = populate_subdomains

    def populate(self, zone, target=False, lenient=False):
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
            vrf_id=self._populate_vrf_id,
            tag=self._populate_tags,
        )

        for ipam_record in ipam_records:
            ip_address = ip_interface(ipam_record.address).ip
            fqdn_base = ipam_record[self._name_field]
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
                if fqdn[-1] != ".":
                    fqdn = f"{fqdn}."

                self.log.info(
                    f"PTR record added: zone={zone.name}, name={name}, value={fqdn}"
                )
                record = Record.new(
                    zone,
                    name,
                    {"ttl": self._ttl, "type": "PTR", "value": f"{fqdn}"},
                    source=self,
                    lenient=lenient,
                )
                try:
                    zone.add_record(record, lenient=lenient)
                except DuplicateRecordException:
                    self.log.warning(f"Skipping duplicated record: {record}")

    def _populate_normal(self, zone, lenient):
        data = defaultdict(lambda: defaultdict(list))

        kw = {f"{self._name_field}__ic": zone.name[:-1]}
        ipam_records = self._nb_client.ipam.ip_addresses.filter(
            vrf_id=self._populate_vrf_id, tag=self._populate_tags, **kw
        )

        for ipam_record in ipam_records:
            ip_address = ip_interface(ipam_record.address).ip
            _type = "A" if ip_address.version == 4 else "AAAA"
            fqdn_base = ipam_record[self._name_field]

            for fqdn in fqdn_base.split(","):
                if fqdn[-1] != ".":
                    fqdn = f"{fqdn}."

                if not fqdn.endswith(zone.name):
                    continue
                if not self._populate_subdomains and (
                    fqdn.count(".") != zone.name.count(".") + 1
                ):
                    # Skip subdomain records.
                    self.log.debug(
                        f"{_type} record skipped: populate_subdomains=False, FQDN={fqdn}"
                    )
                    continue
                name = zone.hostname_from_fqdn(fqdn)
                data[name][_type].append(ip_address.compressed)

        for name, types in data.items():
            for _type, d in types.items():
                self.log.info(
                    f"{_type} record added: zone={zone.name}, name={name}, values={d}"
                )
                record = Record.new(
                    zone,
                    name,
                    {"ttl": self._ttl, "type": _type, "values": d},
                    source=self,
                    lenient=lenient,
                )
                try:
                    zone.add_record(record, lenient=lenient)
                except SubzoneRecordException:
                    self.log.warning(f"Skipping subzone record: {record}")
