"""Unit tests for NetboxSource.

Every NetBox response here was recorded from a real NetBox by
tests/live/run.py. tests/fixtures/<case>.json holds one case of
tests/live/cases.py, and tests/live/expected/<case>/ holds the zones the live
run must dump for it, so the replay and the live run check the same zones.
"""

import json
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


class TestNetboxSourceFailSenarios:
    def test_init_failed_due_to_missing_url(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource("test")
        assert excinfo.value.errors()[0]["loc"] == ("url",)
        assert excinfo.value.errors()[0]["type"] == "missing"
        assert excinfo.value.errors()[1]["loc"] == ("token",)
        assert excinfo.value.errors()[1]["type"] == "missing"

    def test_init_failed_due_to_missing_token(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource("test", url="http://netbox.example.com/")
        assert excinfo.value.errors()[0]["loc"] == ("token",)
        assert excinfo.value.errors()[0]["type"] == "missing"

    def test_init_failed_due_to_invalid_field_name_type(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                field_name=["dns_name", "description"],
            )

        assert excinfo.value.errors()[0]["loc"] == ("field_name",)
        assert excinfo.value.errors()[0]["type"] == "string_type"

    def test_init_failed_due_to_invalid_ttl_type(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test", url="http://netbox.example.com/", token="testtoken", ttl=[10]
            )
        assert excinfo.value.errors()[0]["loc"] == ("ttl",)
        assert excinfo.value.errors()[0]["type"] == "int_type"

    def test_init_failed_due_to_invalid_ttl_value(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test", url="http://netbox.example.com/", token="testtoken", ttl="ten"
            )
        assert excinfo.value.errors()[0]["loc"] == ("ttl",)
        assert excinfo.value.errors()[0]["type"] == "int_parsing"

    def test_init_failed_due_to_invalid_populate_tags_type(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                populate_tags="tag",
            )
        assert excinfo.value.errors()[0]["loc"] == ("populate_tags",)
        assert excinfo.value.errors()[0]["type"] == "list_type"

    def test_init_failed_due_to_invalid_populate_vrf_id_type(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                populate_vrf_id=[10],
            )
        assert excinfo.value.errors()[0]["loc"] == ("populate_vrf_id", "int")
        assert excinfo.value.errors()[0]["type"] == "int_type"
        assert excinfo.value.errors()[1]["loc"] == (
            "populate_vrf_id",
            "literal['null']",
        )
        assert excinfo.value.errors()[1]["type"] == "literal_error"

    def test_init_failed_due_to_invalid_populate_vrf_id_value(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                populate_vrf_id="ten",
            )
        assert excinfo.value.errors()[0]["loc"] == ("populate_vrf_id", "int")
        assert excinfo.value.errors()[0]["type"] == "int_parsing"
        assert excinfo.value.errors()[1]["loc"] == (
            "populate_vrf_id",
            "literal['null']",
        )
        assert excinfo.value.errors()[1]["type"] == "literal_error"

    def test_init_failed_because_both_populate_vrf_id_populate_vrf_name_are_provided(
        self,
    ):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                populate_vrf_id=1,
                populate_vrf_name="TEST",
            )
        assert "Do not set both populate_vrf_id and populate_vrf" in str(excinfo.value)

    def test_init_failed_due_to_invalid_populate_vrf_name_type(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                populate_vrf_name=["TEST"],
            )
        assert excinfo.value.errors()[0]["loc"] == ("populate_vrf_name",)
        assert excinfo.value.errors()[0]["type"] == "string_type"

    def test_init_failed_due_to_invalid_populate_subdomains_type(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                populate_subdomains="ok",
            )
        assert excinfo.value.errors()[0]["loc"] == ("populate_subdomains",)
        assert excinfo.value.errors()[0]["type"] == "bool_parsing"


@pytest.mark.parametrize("name", sorted(path.name for path in EXPECTED.iterdir()))
def test_populate_returns_the_zones_the_live_run_dumps(name):
    case = load_case(name)
    assert sorted(case["zones"]) == expected_zone_names(name)
    source = connect(case)
    for zone_name, recorded in case["zones"].items():
        zone = populate(source, case, zone_name)
        expected = expected_zone(name, zone_name, recorded["sub_zones"])
        assert expected.changes(zone, SimpleProvider()) == [], zone_name


def test_init_fails_when_populate_vrf_name_is_not_in_netbox():
    case = load_case("vrf-name-not-found")
    assert [e["response"]["json"]["count"] for e in case["init"]] == [0]
    with replaying(case["init"]):
        with pytest.raises(
            ValueError, match="Failed to retrieve VRF information by name"
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
