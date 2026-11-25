"""Properties of NetboxSource.populate that hold for any NetBox data.

Hypothesis generates IP addresses in the shape of the responses in
tests/fixtures/, and a fake NetBox answers each query of the source with the
addresses that match its filters. The checks need no second implementation of
the source: populate gives records or a documented error, an IP address with a
name that the source can use gets its record next to any other rows, each
record passes octoDNS's validation inside its zone, a zone survives a round
trip through YamlProvider, and the order of the rows does not matter.

tests/conftest.py sets the number of examples. CONTRIBUTING.md says how to
run more of them.
"""

import copy
import json
from contextlib import contextmanager
from ipaddress import ip_interface, ip_network
from pathlib import Path
from typing import NamedTuple
from urllib.parse import parse_qs, urlsplit

import pytest
import requests_mock
from hypothesis import given
from hypothesis import strategies as st
from octodns.provider.yaml import YamlProvider
from octodns.record import Record
from octodns.zone import Zone

from octodns_netbox import NetboxSource

from .util import SimpleProvider

URL = "http://netbox.example.com"
IP_ADDRESSES = f"{URL}/api/ipam/ip-addresses/"


def _templates():
    """An IP address and its VRF, as NetBox 4.7 returned them."""
    fixture = Path(__file__).parent / "fixtures" / "vrf-name-and-tags.json"
    case = json.loads(fixture.read_text())
    (exchange,) = case["zones"]["vrf-tags.example."]["exchanges"]
    (address,) = exchange["response"]["json"]["results"]
    return address, address["vrf"]


ADDRESS, VRF = _templates()
VRFS = {1: "blue", 2: "green"}
TAGS = ("dns", "external")


class ZoneCase(NamedTuple):
    """A zone that the documentation describes."""

    name: str
    # The sub-zones that octoDNS would pass to the zone.
    sub_zones: list[str]
    # The network that most addresses of the rows come from. For a reverse
    # zone, it reaches past the zone, so some rows fall outside it.
    network: str
    # The addresses whose PTR records the zone holds itself, outside its
    # sub-zones. Any address for a forward zone.
    own: str


IPV6_ZONE = "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
ZONES = [
    ZoneCase("example.test.", [], "192.0.2.0/24", "192.0.2.0/24"),
    ZoneCase("example.test.", ["lab"], "2001:db8::/64", "2001:db8::/64"),
    ZoneCase("lab.example.test.", [], "192.0.2.0/24", "192.0.2.0/24"),
    ZoneCase("café.example.", [], "192.0.2.0/24", "192.0.2.0/24"),
    ZoneCase("2.0.192.in-addr.arpa.", [], "192.0.2.0/23", "192.0.2.0/24"),
    ZoneCase("2.0.192.in-addr.arpa.", ["0-26"], "192.0.2.0/24", "192.0.2.128/25"),
    ZoneCase("2.0.192.in-addr.arpa.", ["64/26"], "192.0.2.0/24", "192.0.2.128/25"),
    ZoneCase("0-26.2.0.192.in-addr.arpa.", [], "192.0.2.0/25", "192.0.2.0/26"),
    ZoneCase("0/26.2.0.192.in-addr.arpa.", [], "192.0.2.0/25", "192.0.2.0/26"),
    ZoneCase("0.192.in-addr.arpa.", ["2"], "192.0.0.0/22", "192.0.0.0/23"),
    ZoneCase(IPV6_ZONE, [], "2001:db8::/63", "2001:db8::/64"),
    ZoneCase(IPV6_ZONE, ["0"], "2001:db8::/67", "2001:db8:0:0:1000::/68"),
    ZoneCase(f"0.{IPV6_ZONE}", [], "2001:db8::/67", "2001:db8::/68"),
]
ZONE_IDS = [
    f"{zone.name}+{','.join(zone.sub_zones)}" if zone.sub_zones else zone.name
    for zone in ZONES
]
# Reverse zones that docs/configuration.md lists under "Errors while reading a
# zone". The source raises ValueError before it sends a request.
INVALID_ZONES = [
    "in-addr.arpa.",
    "ip6.arpa.",
    "300.1.in-addr.arpa.",
    "0/32.2.0.192.in-addr.arpa.",
    "1.300.in-addr.arpa.",
    "5.4.3.2.1.in-addr.arpa.",
    "1/26.2.0.192.in-addr.arpa.",
    "00.ip6.arpa.",
]

# Names in the forward zones, in a sub-zone, in no zone, and with the zone
# name only as a suffix. NetBox returns a name in café.example. for the query
# of the zone only in IDNA form.
BASES = [
    "example.test",
    "lab.example.test",
    "example.org",
    "a-example.test",
    "xn--caf-dma.example",
    "café.example",
]
# Text that people put in a name field, and labels that octoDNS or IDNA reject.
ODD_LABELS = [
    "reserved for new printer",
    "gateway",
    "*",
    "@",
    "",
    "a b",
    "a" * 64,
    "xn--bad_label",
    "a\u200db",
    "h\u00f6st",
    "HOST\uff0e",
    "\u0391\u03a3.\u03b1",
    "_srv",
    "-lead",
    "a.",
]
HOSTNAME = st.from_regex(r"[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?", fullmatch=True)
LABEL = st.one_of(HOSTNAME, HOSTNAME, st.text("abz09-_*@ .", min_size=1, max_size=6))


@st.composite
def names(draw):
    base = draw(st.sampled_from(BASES))
    kind = draw(st.sampled_from(["host"] * 4 + ["apex", "odd", "free text", "long"]))
    if kind == "apex":
        name = base
    elif kind == "odd":
        name = f"{draw(st.sampled_from(ODD_LABELS))}.{base}"
    elif kind == "free text":
        name = draw(st.sampled_from(ODD_LABELS))
    elif kind == "long":
        name = ".".join(["a" * 63] * 4 + [base])
    else:
        name = f"{draw(LABEL)}.{base}"
    if draw(st.booleans()):
        name = name.upper()
    return name + draw(st.sampled_from(["", "."]))


@st.composite
def addresses(draw, network):
    """An address with a mask, mostly in `network`, as NetBox stores it."""
    networks = [ip_network(network)] * 3 + [ip_network("198.51.100.0/24")]
    chosen = draw(st.sampled_from(networks))
    address = chosen[draw(st.integers(0, chosen.num_addresses - 1))]
    mask = draw(st.integers(1, address.max_prefixlen))
    return f"{address}/{mask}"


def ip_address_rows(network):
    """The IP addresses in NetBox, each with its ID."""
    row = st.fixed_dictionaries(
        {
            "address": addresses(network),
            "description": st.lists(names(), min_size=1, max_size=3).map(", ".join),
            "dns_name": st.one_of(names(), st.just("")),
            "vrf": st.sampled_from([None, None, *VRFS]),
            "tags": st.lists(st.sampled_from(TAGS), max_size=2, unique=True),
        }
    )
    return st.lists(row, max_size=8).map(
        lambda drawn: [{**row, "id": index} for index, row in enumerate(drawn, 1)]
    )


def ptr_name(zone_name, address):
    """The PTR name of `address`, as RFC 2317 has it in a classless zone."""
    first = zone_name.split(".")[0]
    if "/" in first or "-" in first:
        return f"{address.packed[-1]}.{zone_name}"
    return f"{address.reverse_pointer}."


@st.composite
def usable_rows(draw, zone, settings):
    """An IP address that the settings read, with a name that the source uses.

    It comes with the record name, type, and value that the zone gets for it.
    """
    network = ip_network(zone.own)
    address = network[draw(st.integers(0, network.num_addresses - 1))]
    label = draw(
        st.from_regex(r"[a-z][a-z0-9]{0,8}", fullmatch=True).filter(
            lambda label: label not in zone.sub_zones
        )
    )
    if zone.name.endswith(".arpa."):
        base = draw(st.sampled_from(["example.test", "xn--caf-dma.example"]))
        fqdn = f"{label}.{base}."
        record = (ptr_name(zone.name, address), "PTR", fqdn)
    else:
        # The zone name as octoDNS spells it: xn--caf-dma.example.
        fqdn = f"{label}.{Zone(zone.name, []).name}"
        record = (fqdn, "A" if address.version == 4 else "AAAA", address.compressed)
    name = draw(st.sampled_from([fqdn, fqdn.rstrip(".")]))
    if draw(st.booleans()):
        name = name.upper()
    vrf = settings.get("populate_vrf_id")
    if vrf is None:
        vrf = draw(st.sampled_from([None, *VRFS]))
    # VRF ID 0 is the Global VRF, which NetBox gives no ID.
    vrf = vrf or None
    tags = draw(st.lists(st.sampled_from(TAGS), max_size=2, unique=True))
    row = {
        "address": f"{address}/{draw(st.integers(1, address.max_prefixlen))}",
        "description": name,
        "dns_name": name,
        "vrf": vrf,
        "tags": sorted({*tags, *settings.get("populate_tags", [])}),
    }
    return row, record


SETTINGS = st.builds(
    lambda settings, filters: {**settings, **filters},
    st.fixed_dictionaries(
        {},
        optional={
            "field_name": st.sampled_from(["description", "dns_name"]),
            "populate_subdomains": st.booleans(),
            "multivalue_ptr": st.booleans(),
            "ttl": st.integers(0, 86400),
        },
    ),
    # Most examples read every IP address, so that most rows reach the zone.
    st.sampled_from(
        [{}] * 4
        + [
            {"populate_vrf_id": 0},
            {"populate_vrf_id": 1},
            {"populate_tags": ["dns"]},
            {"populate_tags": ["dns", "external"]},
        ]
    ),
)


def api_row(row):
    """The IP address `row` as NetBox returns it."""
    data = copy.deepcopy(ADDRESS)
    interface = ip_interface(row["address"])
    data.update(
        id=row["id"],
        url=f"{IP_ADDRESSES}{row['id']}/",
        display=row["address"],
        address=row["address"],
        family={"value": interface.version, "label": f"IPv{interface.version}"},
        description=row["description"],
        dns_name=row["dns_name"],
        tags=[tag for tag in ADDRESS["tags"] if tag["slug"] in row["tags"]],
        vrf=None,
    )
    if row["vrf"] is not None:
        name = VRFS[row["vrf"]]
        data["vrf"] = {
            **VRF,
            "id": row["vrf"],
            "url": f"{URL}/api/ipam/vrfs/{row['vrf']}/",
            "display": name,
            "name": name,
        }
    return data


def matches(row, query):
    """Whether NetBox returns `row` for the query string of the source."""
    address = ip_interface(row["address"]).ip
    for key, values in query.items():
        field, _, lookup = key.partition("__")
        if key == "limit":
            continue
        if key == "family":
            matched = address.version == int(values[0])
        elif key == "parent":
            matched = address in ip_network(values[0])
        elif key == "vrf_id":
            matched = str(row["vrf"] or "null") == values[0]
        elif key == "tag":
            matched = set(values) <= set(row["tags"])
        elif lookup == "ic":
            matched = values[0].lower() in row[field].lower()
        elif lookup == "empty":
            matched = (row[field] == "") == (values[0] == "true")
        else:
            raise AssertionError(f"The source sent the filter {key}.")
        if not matched:
            return False
    return True


@contextmanager
def netbox(rows):
    """Answer each query for IP addresses with the rows that match it."""

    def answer(request, context):
        query = parse_qs(urlsplit(request.url).query, keep_blank_values=True)
        results = [api_row(row) for row in rows if matches(row, query)]
        return {
            "count": len(results),
            "next": None,
            "previous": None,
            "results": results,
        }

    with requests_mock.Mocker() as mock:
        mock.get(IP_ADDRESSES, json=answer)
        yield mock


def populate(zone, rows, settings, lenient=False):
    zone = Zone(zone.name, zone.sub_zones)
    with netbox(rows):
        source = NetboxSource("netbox", url=URL, token="t", **settings)
        source.populate(zone, lenient=lenient)
    return zone


@pytest.mark.parametrize("zone", ZONES, ids=ZONE_IDS)
@given(data=st.data(), settings=SETTINGS, lenient=st.booleans())
def test_populate_gives_records_for_any_ip_addresses(zone, data, settings, lenient):
    # Each name that the source cannot use is skipped with a warning, so no
    # NetBox data stops a zone that docs/configuration.md lets you configure.
    populate(zone, data.draw(ip_address_rows(zone.network)), settings, lenient)


@pytest.mark.parametrize("zone", ZONES, ids=ZONE_IDS)
@given(data=st.data(), settings=SETTINGS, lenient=st.booleans())
def test_an_ip_address_with_a_usable_name_gets_its_record(
    zone, data, settings, lenient
):
    # The other rows can hold any name, so a name that the source skips, or
    # that octoDNS rejects, takes no other record with it.
    rows = data.draw(ip_address_rows(zone.network))
    usable = data.draw(st.lists(usable_rows(zone, settings), min_size=1, max_size=3))
    numbered = [{**row, "id": len(rows) + i} for i, (row, _) in enumerate(usable, 1)]
    drawn = data.draw(st.permutations([*rows, *numbered]))
    populated = populate(zone, drawn, settings, lenient)
    records = {
        (record.fqdn, record._type, str(value))
        for record in populated.records
        for value in record.values
    }
    assert {record for _, record in usable} <= records


@pytest.mark.parametrize("zone_name", INVALID_ZONES)
@given(rows=ip_address_rows("192.0.2.0/24"))
def test_populate_raises_the_documented_error_for_an_unreadable_zone(zone_name, rows):
    with netbox(rows) as mock, pytest.raises(ValueError):
        NetboxSource("netbox", url=URL, token="t").populate(Zone(zone_name, []))
    assert mock.request_history == []


@pytest.mark.parametrize("zone", ZONES, ids=ZONE_IDS)
@given(data=st.data(), settings=SETTINGS)
def test_each_record_passes_octodns_validation_inside_its_zone(zone, data, settings):
    populated = populate(zone, data.draw(ip_address_rows(zone.network)), settings)
    # octoDNS validates each record again, without lenient, in a zone with the
    # same sub-zones, as a target that reads the records would.
    again = Zone(zone.name, zone.sub_zones)
    for record in populated.records:
        assert record.fqdn == again.name or record.fqdn.endswith(f".{again.name}")
        record_data = {"type": record._type, **record.data}
        again.add_record(Record.new(again, record.name, record_data, lenient=False))


@pytest.mark.parametrize("zone", ZONES, ids=ZONE_IDS)
@given(data=st.data(), settings=SETTINGS)
def test_a_zone_written_by_yamlprovider_gives_no_change_on_the_next_run(
    tmp_path_factory, zone, data, settings
):
    rows = data.draw(ip_address_rows(zone.network))
    directory = tmp_path_factory.mktemp("zones")
    # YamlProvider writes zone 0/26.2.0.192.in-addr.arpa. into directory "0".
    (directory / zone.name).parent.mkdir(parents=True, exist_ok=True)
    provider = YamlProvider("yaml", str(directory), enforce_order=False)
    plan = provider.plan(populate(zone, rows, settings))
    if plan:
        provider.apply(plan)
    again = populate(zone, rows, settings)
    # octoDNS 1.10's YamlProvider reads nothing as a target and plans every
    # record as new, so the file is read back as a source.
    written = Zone(zone.name, zone.sub_zones)
    if (directory / f"{zone.name}yaml").exists():
        provider.populate(written)
    assert written.changes(again, SimpleProvider()) == []


@pytest.mark.parametrize("zone", ZONES, ids=ZONE_IDS)
@given(data=st.data(), settings=SETTINGS, lenient=st.booleans())
def test_the_order_of_the_rows_does_not_change_the_zone(zone, data, settings, lenient):
    rows = data.draw(ip_address_rows(zone.network))
    reordered = data.draw(st.permutations(rows))
    first = populate(zone, rows, settings, lenient)
    second = populate(zone, reordered, settings, lenient)
    assert first.changes(second, SimpleProvider()) == []
