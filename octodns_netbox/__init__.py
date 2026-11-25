"""
A NetBox source for octoDNS.

Automatically creating A/AAAA records and their corresponding PTR records
based on a NetBox API.
"""

import logging
import re
from collections import defaultdict
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv6Address, ip_interface
from typing import Any, Literal, NamedTuple, Self, cast

import pynetbox
import requests
from octodns.idna import IdnaError, idna_encode
from octodns.record import Record
from octodns.record.exception import ValidationError as InvalidRecord
from octodns.source.base import BaseSource
from octodns.zone import SubzoneRecordException, Zone
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    ModelWrapValidatorHandler,
    NonNegativeInt,
    TypeAdapter,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_core import InitErrorDetails

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
        return cast(list[Any], Record.from_rrs(zone, rrs, lenient=lenient))

else:  # pragma: no-cover-without-rrset

    def _octodns_records(
        zone: Zone, rdatas: dict[tuple[str, str], list[str]], ttl: int, lenient: bool
    ) -> list[Any]:
        rrsets = [
            Rrset(owner, _type, ttl, values)
            for (owner, _type), values in rdatas.items()
        ]
        return cast(list[Any], Record.from_rrsets(zone, rrsets, lenient=lenient))


# The IP addresses a source reads: those in every VRF (None), those without
# a VRF, which NetBox calls the Global VRF ("global"), or those in the VRF
# with this ID.
VrfFilter = int | Literal["global"] | None


class _Session(requests.Session):
    """A session that takes only proxies and a CA bundle from the environment.

    requests also reads ~/.netrc, or the file in NETRC, for a request without
    auth, and again on a redirect. It then sends a login from that file as a
    Basic auth header in place of the token that pynetbox sets, and NetBox
    answers 403.

    For a request without a verify argument, which is every request that
    pynetbox sends, requests takes the CA bundle in REQUESTS_CA_BUNDLE or
    CURL_CA_BUNDLE over Session.verify. ssl_verify: false would then still
    verify the certificate against that bundle.
    """

    def __init__(self) -> None:
        super().__init__()
        # requests reads netrc only for a request without auth. This auth
        # leaves the request as pynetbox made it.
        self.auth = lambda request: request

    def rebuild_auth(self, prepared_request: Any, response: Any) -> None:
        """Drop the token on a redirect to another host, as requests does.

        requests then reads netrc for the new URL, and this method does not.
        """
        if self.should_strip_auth(response.request.url, prepared_request.url):
            prepared_request.headers.pop("Authorization", None)

    def merge_environment_settings(
        self, url: Any, proxies: Any, stream: Any, verify: Any, cert: Any
    ) -> dict[str, Any]:
        if verify is None:
            verify = self.verify
        return super().merge_environment_settings(url, proxies, stream, verify, cert)


class ResourceRecord(NamedTuple):
    """One value of a record. The source groups them by owner and type."""

    owner: str  # FQDN. octoDNS makes it relative to the zone.
    type: str
    rdata: str


class NetboxSourceConfig(BaseModel):
    """The settings of a NetboxSource in the octoDNS config.

    Unknown keys are dropped. NetboxSource logs a warning for each one.
    A ValidationError names each key that failed, and holds no value.
    """

    # Keeps the input out of str() and repr() of a ValidationError.
    model_config = ConfigDict(frozen=True, extra="ignore", hide_input_in_errors=True)

    url: str
    token: str
    field_name: str = "description"
    populate_tags: list[str] = []
    # "null" is the Global VRF, like 0.
    populate_vrf_id: int | Literal["null"] | None = None
    populate_vrf_name: str | None = None
    populate_subdomains: bool = True
    multivalue_ptr: bool = False
    ttl: NonNegativeInt = 60
    ssl_verify: bool = True

    @field_validator("url", mode="before")
    @classmethod
    def http_url_without_api(cls, value: Any) -> str:
        """pynetbox adds /api to the URL, so a trailing /api or /api/ is dropped.

        requests sends a user name or password in the URL as a Basic auth
        header in place of the token, so such a URL cannot work.
        """
        url = TypeAdapter(AnyHttpUrl).validate_python(value)
        if url.username or url.password:
            raise ValueError("Remove the user name and password from the URL.")
        return re.sub(r"/api/?$", "", str(url))

    @field_validator("token", mode="before")
    @classmethod
    def token_as_written(cls, value: Any) -> Any:
        """An int is a token of digits that octoDNS read from env/.

        octoDNS drops the zeros at the start of the digits. A v1 token has 40
        characters, so 40 digits give the token back.
        """
        if type(value) is int:
            return f"{value:040d}"
        return value

    @field_validator("token")
    @classmethod
    def token_without_whitespace(cls, value: str) -> str:
        """Remove the whitespace around the token.

        A Kubernetes Secret often ends in a line break, and a .env file with
        CRLF line ends leaves a carriage return. requests and http.client
        refuse such a header, with an error that holds the whole token.
        A NetBox token is ASCII. http.client sends a header in Latin-1, and its
        UnicodeEncodeError for a character outside Latin-1 holds the whole
        header too.
        """
        token = value.strip()
        if " " in token or not token.isprintable() or not token.isascii():
            raise ValueError(
                "The token holds whitespace, or a character that is not printable "
                "or not ASCII."
            )
        return token

    @field_validator("populate_vrf_id", "ttl", mode="before")
    @classmethod
    def number_not_bool(cls, value: Any) -> Any:
        """pydantic takes a bool as an int, so true would be 1."""
        if isinstance(value, bool):
            raise ValueError("Write a number, not true or false.")
        return value

    @field_validator("populate_vrf_name")
    @classmethod
    def validate_one_vrf(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is not None and info.data.get("populate_vrf_id") is not None:
            raise ValueError("Do not set both populate_vrf_id and populate_vrf_name.")
        return value

    @field_validator("populate_vrf_name")
    @classmethod
    def vrf_name_not_blank(cls, value: str | None) -> str | None:
        """NetBox ignores a blank name filter, and returns every VRF."""
        if value is not None and not value.strip():
            raise ValueError("Write the name of a VRF.")
        return value

    @model_validator(mode="wrap")
    @classmethod
    def drop_input_from_errors(
        cls, data: Any, handler: ModelWrapValidatorHandler[Self]
    ) -> Self:
        """Replace the input of each error, which can hold the token, with None.

        hide_input_in_errors does not reach error.json() or error.errors(), and
        the input of a missing key is every setting.
        """
        try:
            return handler(data)
        except ValidationError as error:
            lines = []
            for line in error.errors():
                details = InitErrorDetails(
                    type=line["type"], loc=line["loc"], input=None
                )
                if "ctx" in line:
                    details["ctx"] = line["ctx"]
                lines.append(details)
            raise ValidationError.from_exception_data(error.title, lines) from None


# octoDNS has no type information, so BaseSource is Any to mypy.
class NetboxSource(BaseSource):  # type: ignore[misc]
    """Creates A, AAAA, and PTR records from the IP addresses in NetBox."""

    SUPPORTS_GEO = False
    SUPPORTS = frozenset({"A", "AAAA", "PTR"})

    def __init__(self, id: str, /, **settings: Any):
        self.log = logging.getLogger(f"{self.__class__.__name__}[{id}]")
        self.config = NetboxSourceConfig(**settings)
        super().__init__(id)
        for key in settings:
            if key not in NetboxSourceConfig.model_fields:
                self.log.warning("Unknown setting %s has no effect.", key)

        self.log.debug(
            "Initializing NetboxSource: id=%s, ttl=%s, ssl_verify=%s",
            id,
            self.config.ttl,
            self.config.ssl_verify,
        )

        self._nb_client = pynetbox.api(url=self.config.url, token=self.config.token)
        session = _Session()
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
            return cast(int, vrf_obj.id)
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
        return cast(
            Iterable[Any],
            self._nb_client.ipam.ip_addresses.filter(
                **filters, **vrf, tag=self.config.populate_tags
            ),
        )

    def populate(self, zone: Zone, target: bool = False, lenient: bool = False) -> None:
        self.log.debug(
            "populate called for zone=%s, target=%s, lenient=%s",
            zone.name,
            target,
            lenient,
        )
        before = len(zone.records)
        if reversename.is_reverse(zone):
            rrs = self._ptr_records(zone, lenient)
        else:
            rrs = self._forward_records(zone, lenient)

        # Two NetBox IP addresses can give a record the same value, such as one
        # address and name in two VRFs. octoDNS keeps a value it gets twice,
        # and a provider holds it once, so each sync would plan an update.
        rdatas: dict[tuple[str, str], list[str]] = defaultdict(list)
        for rr in rrs:
            values = rdatas[(rr.owner, rr.type)]
            if rr.rdata not in values:
                values.append(rr.rdata)
        for record in _octodns_records(zone, rdatas, self.config.ttl, lenient):
            try:
                zone.add_record(record, lenient=lenient)
            except SubzoneRecordException:
                self.log.warning("Skipping subzone record: %s", record)
        self.log.info(
            "Populated %s new records in zone %s", len(zone.records) - before, zone.name
        )

    def _ptr_records(self, zone: Zone, lenient: bool) -> list[ResourceRecord]:
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
        # The VRF, as (ID, name), and the first value of each NetBox IP
        # address that gave a value, by PTR name and address.
        sources: dict[
            tuple[str, IPv4Address | IPv6Address],
            list[tuple[tuple[int | None, str], str]],
        ]
        sources = defaultdict(list)
        for ipam_record in ipam_records:
            ip_address = ip_interface(ipam_record.address).ip
            ptr_name = reversename.from_address(zone, ip_address)
            names = _names(ipam_record[field_name])
            if not self.config.multivalue_ptr:
                names = names[:1]
            fqdns = []
            for fqdn in self._octodns_fqdns(names, ip_address, zone):
                rr = ResourceRecord(ptr_name, "PTR", fqdn)
                if not self._usable(rr, ip_address, zone, lenient):
                    continue
                self.log.debug("Adding PTR record %s to zone %s", rr, zone.name)
                records.append(rr)
                fqdns.append(fqdn)
            if fqdns:
                nb_vrf = ipam_record.vrf
                vrf = (nb_vrf.id, nb_vrf.name) if nb_vrf else (None, "Global")
                sources[(ptr_name, ip_address)].append((vrf, fqdns[0]))
        if not self.config.multivalue_ptr:
            for (ptr_name, ip_address), values in sources.items():
                names_by_vrf: dict[tuple[int | None, str], set[str]]
                names_by_vrf = defaultdict(set)
                for vrf, fqdn in values:
                    names_by_vrf[vrf].add(fqdn)
                # Reading one VRF gives the PTR one value only when each VRF
                # gives one name. A VRF that gives two by itself, as anycast
                # addresses can, keeps two whichever VRF the source reads.
                one_name_each = all(len(n) == 1 for n in names_by_vrf.values())
                if one_name_each and len({fqdn for _, fqdn in values}) > 1:
                    self.log.warning(
                        "PTR %s gets a value from each of %d NetBox IP addresses "
                        "for %s, in VRFs %s. Set populate_vrf_id or "
                        "populate_vrf_name to read one VRF.",
                        ptr_name,
                        len(values),
                        ip_address,
                        ", ".join(name for _, name in names_by_vrf),
                    )
        return records

    def _forward_records(self, zone: Zone, lenient: bool) -> list[ResourceRecord]:
        field_name = self.config.field_name
        ipam_records = self._ip_addresses({f"{field_name}__ic": zone.name.rstrip(".")})
        records: list[ResourceRecord] = []
        for ipam_record in ipam_records:
            ip_address = ip_interface(ipam_record.address).ip
            record_type = "A" if ip_address.version == 4 else "AAAA"
            names = _names(ipam_record[field_name])
            for fqdn in self._octodns_fqdns(names, ip_address, zone):
                if not self._fqdn_in_zone(fqdn, zone):
                    self.log.debug("Skip: FQDN=%s on zone %s", fqdn, zone.name)
                    continue
                rr = ResourceRecord(fqdn, record_type, ip_address.compressed)
                if not self._usable(rr, ip_address, zone, lenient):
                    continue
                self.log.debug(
                    "Created %s record %s for zone %s", record_type, rr, zone.name
                )
                records.append(rr)
        return records

    def _octodns_fqdns(
        self, names: list[str], ip_address: IPv4Address | IPv6Address, zone: Zone
    ) -> list[str]:
        """The names as octoDNS spells zone and record names.

        That is lower case, with each label that is not ASCII in IDNA form:
        höst.example. becomes xn--hst-sna.example. A name with a label that has
        no IDNA form, or with an empty label, is left out, with a warning.
        """
        fqdns: list[str] = []
        for name in names:
            try:
                # Lower case for the whole name first, as octoDNS does.
                # str.lower() turns a capital sigma at the end of a label into
                # a small sigma when the next label starts with a letter, and
                # into a final sigma in a label on its own. Then label by
                # label, as octoDNS 1.13 and later do. octoDNS 1.10 to 1.12
                # convert the whole name, and IDNA rejects the "_" in an ASCII
                # label such as ex_ample.
                labels = name.lower().split(".")
                fqdn = ".".join(idna_encode(label) for label in labels)
            except IdnaError as error:
                self._skip_name(name, ip_address, zone, error)
                continue
            # octoDNS would make .example.com. the zone apex, and accepts .www
            # as a record name. IDNA turns a full-width dot into ".", so the
            # check comes after it.
            if "" in fqdn.split(".")[:-1]:
                self._skip_name(name, ip_address, zone, "empty label")
                continue
            fqdns.append(fqdn)
        return fqdns

    def _usable(
        self,
        rr: ResourceRecord,
        ip_address: IPv4Address | IPv6Address,
        zone: Zone,
        lenient: bool,
    ) -> bool:
        """Whether octoDNS accepts the record of one name of the IP address.

        The source checks each name on its own, so a name that octoDNS rejects
        takes no other name or address with it. With lenient, octoDNS keeps a
        record that fails its validation, and so does the source.

        octoDNS decodes the record name for its logs, and raises IdnaError,
        also when lenient, for a name without a Unicode form, such as the
        invalid A-label xn--bad_label. octoDNS 1.10 to 1.12 decode the whole
        FQDN for the message of a validation error too, so in a zone such as
        xn--caf-dma.example. a name that fails validation, such as "bad name",
        raises IdnaError in place of the error. The source skips such a name
        in both modes.
        """
        rdatas = {(rr.owner, rr.type): [rr.rdata]}
        reason: IdnaError | str
        try:
            _octodns_records(zone, rdatas, self.config.ttl, lenient=False)
        except InvalidRecord as error:
            if lenient:
                return True
            reason = "; ".join(map(str, error.reasons))
        except IdnaError as error:
            reason = error
        else:
            return True
        name = rr.rdata if rr.type == "PTR" else rr.owner
        self._skip_name(name, ip_address, zone, reason)
        return False

    def _skip_name(
        self,
        name: str,
        ip_address: IPv4Address | IPv6Address,
        zone: Zone,
        reason: IdnaError | str,
    ) -> None:
        self.log.warning(
            "Skipping the name %r of %s in zone %s: %s",
            name,
            ip_address,
            zone.name,
            reason,
        )

    def _fqdn_in_zone(self, fqdn: str, zone: Zone) -> bool:
        if fqdn == zone.name:
            return True
        if fqdn.endswith(f".{zone.name}"):
            leftover = fqdn[: -len(zone.name)].rstrip(".")
            return self.config.populate_subdomains or "." not in leftover
        return False


def _names(field_value: str) -> list[str]:
    names = (name.strip() for name in field_value.split(","))
    return [name if name.endswith(".") else f"{name}." for name in names if name]
