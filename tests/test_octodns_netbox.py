"""Unit tests for NetboxSource.

Every NetBox response here was recorded from a real NetBox by
tests/live/run.py. tests/fixtures/<case>.json holds one case of
tests/live/cases.py, and tests/live/expected/<case>/ holds the zones the live
run must dump for it, so the replay and the live run check the same zones.
"""

import json
import logging
from contextlib import contextmanager
from pathlib import Path

import pytest
import requests_mock
from octodns.provider.yaml import YamlProvider
from octodns.zone import Zone
from pydantic import ValidationError

from octodns_netbox import NetboxSource

from .util import SimpleProvider

FIXTURES = Path(__file__).parent / "fixtures"
EXPECTED = Path(__file__).parent / "live" / "expected"


@pytest.fixture(autouse=True)
def no_other_requests():
    """Fail every request a test does not replay from a recording."""
    with requests_mock.Mocker():
        yield


def load_case(name):
    return json.loads((FIXTURES / f"{name}.json").read_text())


@contextmanager
def replaying(exchanges):
    """Answer the recorded requests, and fail unless each is sent exactly once."""
    with requests_mock.Mocker() as mock:
        matchers = [
            mock.register_uri(
                exchange["request"]["method"],
                exchange["request"]["url"],
                complete_qs=True,
                status_code=exchange["response"]["status"],
                json=exchange["response"]["json"],
            )
            for exchange in exchanges
        ]
        yield
    assert [matcher.call_count for matcher in matchers] == [1] * len(matchers)


def connect(case):
    with replaying(case["init"]):
        return NetboxSource("netbox", token="not-recorded", **case["source"])


def populate(source, case, zone_name):
    recorded = case["zones"][zone_name]
    zone = Zone(zone_name, recorded["sub_zones"])
    with replaying(recorded["exchanges"]):
        source.populate(zone)
    return zone


def expected_zone(case_name, zone_name, sub_zones):
    zone = Zone(zone_name, sub_zones)
    provider = YamlProvider("expected", str(EXPECTED / case_name), enforce_order=False)
    provider.populate(zone)
    return zone


def expected_zone_names(case_name):
    root = EXPECTED / case_name
    # Zone 0/26.2.0.192.in-addr.arpa. lives in 0/26.2.0.192.in-addr.arpa.yaml.
    return sorted(
        path.relative_to(root).as_posix()[: -len("yaml")]
        for path in root.rglob("*.yaml")
    )


def assert_populates_expected_zones(source, case, case_name):
    for zone_name, recorded in case["zones"].items():
        zone = populate(source, case, zone_name)
        expected = expected_zone(case_name, zone_name, recorded["sub_zones"])
        assert expected.changes(zone, SimpleProvider()) == [], zone_name


SETTINGS = {"url": "http://netbox.example.com/", "token": "testtoken"}


def rejected_keys(**settings):
    """The config keys NetboxSource names when it refuses `settings`."""
    with pytest.raises(ValidationError) as excinfo:
        NetboxSource("netbox", **settings)
    return {error["loc"][0] for error in excinfo.value.errors()}


def test_init_requires_url_and_token():
    assert rejected_keys() == {"url", "token"}
    assert rejected_keys(url=SETTINGS["url"]) == {"token"}


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("url", "netbox.example.com"),
        ("field_name", ["dns_name", "description"]),
        ("populate_tags", "tag"),
        ("populate_vrf_id", [10]),
        ("populate_vrf_id", "ten"),
        ("populate_vrf_name", ["TEST"]),
        ("populate_subdomains", "ok"),
        ("multivalue_ptr", "ok"),
        ("ttl", [10]),
        ("ttl", "ten"),
        ("ssl_verify", "ok"),
    ],
)
def test_init_rejects_a_value_of_the_wrong_type(key, value):
    assert rejected_keys(**{**SETTINGS, key: value}) == {key}


def test_init_rejects_both_populate_vrf_id_and_populate_vrf_name():
    with pytest.raises(ValidationError, match="Do not set both populate_vrf_id"):
        NetboxSource("netbox", **SETTINGS, populate_vrf_id=1, populate_vrf_name="mgmt")


@pytest.mark.parametrize(
    "settings",
    [{"populate_vrf_id": 1, "populate_vrf_name": "mgmt"}, {"ttl": "ten"}],
)
def test_init_error_does_not_contain_the_token(settings):
    token = "nbt_K3yOfTheTest.S3cretOfTheTest0123456789"
    with pytest.raises(ValidationError) as excinfo:
        NetboxSource("netbox", url=SETTINGS["url"], token=token, **settings)
    # str() shortens a long input to its start and end, so look for any piece.
    pieces = {token[i : i + 8] for i in range(len(token) - 7)}
    for text in (str(excinfo.value), excinfo.value.json()):
        assert [piece for piece in pieces if piece in text] == []


def test_init_logs_no_warning_for_known_settings(caplog):
    NetboxSource(
        "netbox",
        **SETTINGS,
        field_name="dns_name",
        populate_tags=["dns"],
        populate_vrf_id=1,
        populate_subdomains=False,
        multivalue_ptr=True,
        ttl=120,
        ssl_verify=False,
    )
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("populate_tag", ["prod"]),
        ("populate_vrf", "mgmt"),
        # Field names and aliases of the 0.5.0 config model.
        ("SUPPORTS_MULTIVALUE_PTR", True),
        ("SUPPORTS_DYNAMIC", True),
        ("SUPPORTS", ["A"]),
        ("SUPPORTS_GEO", True),
        ("log", "ignored"),
    ],
)
def test_unknown_key_logs_a_warning_and_changes_no_zone(caplog, key, value):
    case = load_case("description")
    with replaying(case["init"]):
        source = NetboxSource("netbox", token="t", **case["source"], **{key: value})
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings == [f"Unknown setting {key} has no effect."]
    assert_populates_expected_zones(source, case, "description")


def test_populate_vrf_id_null_reads_the_global_vrf():
    case = load_case("vrf-global-id")
    assert case["source"]["populate_vrf_id"] == 0
    with replaying(case["init"]):
        source = NetboxSource(
            "netbox", token="t", **{**case["source"], "populate_vrf_id": "null"}
        )
    assert_populates_expected_zones(source, case, "vrf-global-id")


@pytest.mark.parametrize("name", sorted(path.name for path in EXPECTED.iterdir()))
def test_populate_returns_the_zones_the_live_run_dumps(name):
    case = load_case(name)
    assert sorted(case["zones"]) == expected_zone_names(name)
    assert_populates_expected_zones(connect(case), case, name)


def test_init_fails_when_populate_vrf_name_is_not_in_netbox():
    case = load_case("vrf-name-not-found")
    assert [e["response"]["json"]["count"] for e in case["init"]] == [0]
    with (
        replaying(case["init"]),
        pytest.raises(ValueError, match="Failed to retrieve VRF information by name"),
    ):
        NetboxSource("netbox", token="not-recorded", **case["source"])


def test_populate_warns_about_records_inside_a_configured_subzone(caplog):
    case = load_case("subzones")
    assert case["zones"]["example.com."]["sub_zones"] == ["subdomain1"]
    populate(connect(case), case, "example.com.")
    assert "Skipping subzone record" in caplog.text


def test_populate_skips_fqdn_that_only_shares_the_zone_suffix():
    # https://github.com/sukiyaki/octodns-netbox/issues/78
    case = load_case("issue-78")
    (exchange,) = case["zones"]["test.example.com."]["exchanges"]
    returned = {ip["description"] for ip in exchange["response"]["json"]["results"]}
    assert returned == {"a-test.example.com", "host.test.example.com"}
    zone = populate(connect(case), case, "test.example.com.")
    assert {(record.name, record._type) for record in zone.records} == {("host", "A")}
