"""Unit tests for NetboxSource.

Every NetBox response here was recorded from a real NetBox by
tests/live/run.py. tests/fixtures/<case>.json holds one case of
tests/live/cases.py, and tests/live/expected/<case>/ holds the zones the live
run must dump for it, so the replay and the live run check the same zones.
"""

import json
import logging
from contextlib import contextmanager
from ipaddress import ip_interface
from pathlib import Path

import pytest
import requests_mock
from octodns.manager import Manager
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
        yield mock
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


TOKEN = "nbt_K3yOfTheTest.S3cretOfTheTest0123456789"


@pytest.mark.parametrize(
    "settings",
    [
        pytest.param({"token": TOKEN}, id="missing-url"),
        pytest.param({"url": SETTINGS["url"], "tokne": TOKEN}, id="misspelled-token"),
        pytest.param(
            {
                "url": SETTINGS["url"],
                "token": TOKEN,
                "populate_vrf_id": 1,
                "populate_vrf_name": "vrf-name-value",
            },
            id="both-vrf-keys",
        ),
        pytest.param(
            {"url": SETTINGS["url"], "token": TOKEN, "ttl": "ttl-value"},
            id="wrong-type",
        ),
        pytest.param(
            {"url": "http://netbox-user:S3cretOfTheUrl@netbox.example", "token": TOKEN},
            id="url-with-password",
        ),
        pytest.param(
            {"url": SETTINGS["url"], "token": TOKEN.replace(".", "\n.")},
            id="token-with-line-break",
        ),
        pytest.param(
            {"url": SETTINGS["url"], "token": TOKEN.replace(".", "☃.")},
            id="token-not-ascii",
        ),
    ],
)
def test_init_error_contains_no_value_of_a_setting(settings):
    with pytest.raises(ValidationError) as excinfo:
        NetboxSource("netbox", **settings)
    error = excinfo.value
    # str() shortens a long input to its start and end, so look for any piece.
    pieces = {
        value[i : i + 8]
        for value in settings.values()
        if isinstance(value, str)
        for i in range(len(value) - 7)
    }
    for text in (str(error), error.json(), repr(error), repr(error.errors())):
        assert [piece for piece in pieces if piece in text] == []


BUNDLE = "/etc/ssl/netbox.pem"
PROXY = "http://proxy.example:3128"


@pytest.mark.parametrize(
    ("bundle_variable", "settings", "verify"),
    [
        (None, {}, True),
        (None, {"ssl_verify": False}, False),
        # A CA bundle in the environment replaces True, but never False.
        ("REQUESTS_CA_BUNDLE", {}, BUNDLE),
        ("REQUESTS_CA_BUNDLE", {"ssl_verify": False}, False),
        ("CURL_CA_BUNDLE", {}, BUNDLE),
        ("CURL_CA_BUNDLE", {"ssl_verify": False}, False),
    ],
)
def test_ssl_verify_sets_whether_each_request_verifies_tls(
    monkeypatch, bundle_variable, settings, verify
):
    for variable in (
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ):
        monkeypatch.delenv(variable, raising=False)
        monkeypatch.delenv(variable.upper(), raising=False)
    if bundle_variable is not None:
        monkeypatch.setenv(bundle_variable, BUNDLE)
    # A proxy from the environment applies whatever ssl_verify says.
    monkeypatch.setenv("HTTP_PROXY", PROXY)
    case = load_case("vrf-name")
    zone_name = "3.0.192.in-addr.arpa."
    exchanges = case["init"] + case["zones"][zone_name]["exchanges"]
    with replaying(exchanges) as mock:
        source = NetboxSource("netbox", token="t", **case["source"], **settings)
        source.populate(Zone(zone_name, []))
    sent = [
        (request.verify, request.proxies.get("http"))
        for request in mock.request_history
    ]
    assert sent == [(verify, PROXY)] * 2


V1_TOKEN = "0123456789abcdef0123456789abcdef01234567"


@pytest.fixture
def netrc(tmp_path, monkeypatch):
    """A netrc file, which requests reads, with a login for every host."""
    path = tmp_path / "netrc"
    path.write_text("default login netrc-user password netrc-password\n")
    monkeypatch.setenv("NETRC", str(path))


def test_each_request_sends_the_token_and_no_login_from_netrc(netrc):
    case = load_case("vrf-name")
    zone_name = "3.0.192.in-addr.arpa."
    exchanges = case["init"] + case["zones"][zone_name]["exchanges"]
    with replaying(exchanges) as mock:
        source = NetboxSource("netbox", token=V1_TOKEN, **case["source"])
        source.populate(Zone(zone_name, []))
    sent = [request.headers.get("Authorization") for request in mock.request_history]
    assert sent == [f"Token {V1_TOKEN}"] * 2


@pytest.mark.parametrize(
    ("location", "authorization"),
    [
        pytest.param("https://netbox.example.com", f"Token {V1_TOKEN}", id="same-host"),
        pytest.param("http://other.example.com", None, id="other-host"),
    ],
)
def test_a_redirect_sends_the_token_only_to_the_same_host(
    netrc, location, authorization
):
    case = load_case("vrf-name")
    (exchange,) = case["init"]
    url = exchange["request"]["url"]
    moved = url.replace(case["source"]["url"], location)
    with requests_mock.Mocker() as mock:
        mock.get(url, complete_qs=True, status_code=301, headers={"Location": moved})
        mock.get(moved, complete_qs=True, json=exchange["response"]["json"])
        NetboxSource("netbox", token=V1_TOKEN, **case["source"])
    first, redirected = mock.request_history
    assert first.headers.get("Authorization") == f"Token {V1_TOKEN}"
    assert redirected.url == moved
    assert redirected.headers.get("Authorization") == authorization


@pytest.mark.parametrize(
    "token",
    [
        # A Kubernetes Secret, and a .env file with CRLF line ends.
        f"{V1_TOKEN}\n",
        f"{V1_TOKEN}\r\n",
        f" \t{V1_TOKEN} ",
    ],
)
def test_each_request_sends_the_token_without_the_whitespace_around_it(token):
    case = load_case("vrf-name")
    zone_name = "3.0.192.in-addr.arpa."
    exchanges = case["init"] + case["zones"][zone_name]["exchanges"]
    with replaying(exchanges) as mock:
        source = NetboxSource("netbox", token=token, **case["source"])
        source.populate(Zone(zone_name, []))
    sent = [request.headers.get("Authorization") for request in mock.request_history]
    assert sent == [f"Token {V1_TOKEN}"] * 2


@pytest.mark.parametrize("token", ["1234567890" * 4, "0012345678" * 4])
def test_a_token_of_digits_from_env_is_sent_as_written(tmp_path, monkeypatch, token):
    # octoDNS turns an env/ value of digits into an int.
    monkeypatch.setenv("NETBOX_TOKEN", token)
    case = load_case("vrf-name")
    config = tmp_path / "config.yaml"
    config.write_text(
        "providers:\n"
        "  netbox:\n"
        "    class: octodns_netbox.NetboxSource\n"
        f"    url: {case['source']['url']}\n"
        "    token: env/NETBOX_TOKEN\n"
        f"    populate_vrf_name: {case['source']['populate_vrf_name']}\n"
        "zones: {}\n"
    )
    with replaying(case["init"]) as mock:
        Manager(str(config))
    (request,) = mock.request_history
    assert request.headers.get("Authorization") == f"Token {token}"


@pytest.mark.parametrize(
    "token",
    [
        f"{V1_TOKEN[:20]} {V1_TOKEN[20:]}",
        f"{V1_TOKEN[:20]}\n{V1_TOKEN[20:]}",
        f"{V1_TOKEN[:20]}\x00{V1_TOKEN[20:]}",
        f"{V1_TOKEN}\x7f",
        # Printable, but not ASCII as a NetBox token is. http.client sends é in
        # Latin-1, and cannot send ☃.
        f"{V1_TOKEN[:20]}é{V1_TOKEN[20:]}",
        f"{V1_TOKEN}☃",
    ],
)
def test_init_rejects_a_token_that_http_cannot_send(token):
    assert rejected_keys(url=SETTINGS["url"], token=token) == {"token"}


@pytest.mark.parametrize(
    "url",
    [
        "http://netbox-user:netbox-password@netbox.example.com",
        "http://netbox-user@netbox.example.com",
        "http://:netbox-password@netbox.example.com",
    ],
)
def test_init_rejects_a_url_with_a_user_name_or_password(url):
    assert rejected_keys(url=url, token=V1_TOKEN) == {"url"}


@pytest.mark.parametrize("suffix", ["/api", "/api/"])
def test_url_ending_in_api_sends_each_request_to_one_api_path(suffix):
    case = load_case("url-api-suffix")
    source = NetboxSource("netbox", token="t", url=f"http://netbox.example.com{suffix}")
    assert source.config.url == "http://netbox.example.com"
    assert_populates_expected_zones(source, case, "url-api-suffix")


def test_init_takes_the_name_of_the_source_only_positionally():
    with pytest.raises(TypeError):
        NetboxSource(id="netbox", **SETTINGS)


def test_config_of_a_source_cannot_change():
    source = NetboxSource("netbox", **SETTINGS)
    with pytest.raises(ValidationError):
        source.config.ttl = 120
    assert source.config.ttl == 60


def test_supports_keys_leave_the_supported_types_and_geo_unchanged():
    source = NetboxSource("netbox", **SETTINGS, SUPPORTS=["A"], SUPPORTS_GEO=True)
    assert sorted(source.SUPPORTS) == ["A", "AAAA", "PTR"]
    assert source.SUPPORTS_GEO is False


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


def test_id_key_logs_a_warning_like_any_unknown_key(tmp_path, caplog):
    # octoDNS passes the provider name as the first argument and every key
    # as a keyword argument.
    config = tmp_path / "config.yaml"
    config.write_text(
        "providers:\n"
        "  netbox:\n"
        "    class: octodns_netbox.NetboxSource\n"
        f"    url: {SETTINGS['url']}\n"
        "    token: t\n"
        "    id: stray-value\n"
        "zones: {}\n"
    )
    manager = Manager(str(config))
    assert manager.providers["netbox"].id == "netbox"
    assert source_warnings(caplog) == ["Unknown setting id has no effect."]


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


def source_warnings(caplog):
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno >= logging.WARNING and r.name.startswith("NetboxSource")
    ]


def test_populate_warns_about_an_address_whose_ptr_has_values_from_two_vrfs(caplog):
    case = load_case("description")
    populate(connect(case), case, "2.0.192.in-addr.arpa.")
    assert source_warnings(caplog) == [
        f"PTR {host}.2.0.192.in-addr.arpa. gets a value from each of 2 NetBox IP "
        f"addresses for 192.0.2.{host}, in VRFs Global, mgmt. Set populate_vrf_id "
        "or populate_vrf_name to read one VRF."
        for host in (1, 2, 3)
    ]


def test_populate_warns_only_about_different_values_from_different_vrfs(caplog):
    case = load_case("vrf-duplicate")
    populate(connect(case), case, "7.0.192.in-addr.arpa.")
    # 192.0.7.1 has two names in one VRF, and 192.0.7.2 one name in two VRFs.
    assert source_warnings(caplog) == [
        "PTR 3.7.0.192.in-addr.arpa. gets a value from each of 2 NetBox IP "
        "addresses for 192.0.7.3, in VRFs Global, anycast. Set populate_vrf_id "
        "or populate_vrf_name to read one VRF."
    ]


def test_populate_does_not_warn_about_vrfs_when_one_vrf_gives_two_values(caplog):
    case = load_case("vrf-anycast")
    populate(connect(case), case, "10.0.192.in-addr.arpa.")
    # Each VRF gives 192.0.10.1 two names, and the Global VRF gives 192.0.10.2
    # two names. Reading the Global VRF would still give each PTR two values.
    assert source_warnings(caplog) == []


@pytest.mark.parametrize("name", ["multivalue-ptr", "vrf-id", "vrf-global-name"])
def test_populate_does_not_warn_about_vrfs_with_multivalue_ptr_or_one_vrf(caplog, name):
    case = load_case(name)
    source = connect(case)
    for zone_name in case["zones"]:
        populate(source, case, zone_name)
    assert source_warnings(caplog) == []


@pytest.mark.parametrize(
    ("name", "vrfs_with_the_name"),
    [("vrf-name-not-found", 0), ("vrf-name-shared", 2)],
)
def test_init_fails_unless_one_vrf_has_the_populate_vrf_name(name, vrfs_with_the_name):
    case = load_case(name)
    assert [e["response"]["json"]["count"] for e in case["init"]] == [
        vrfs_with_the_name
    ]
    with (
        replaying(case["init"]),
        pytest.raises(ValueError, match="Failed to retrieve VRF information by name"),
    ):
        NetboxSource("netbox", token="not-recorded", **case["source"])


def test_populate_warns_once_for_each_record_inside_a_configured_subzone(caplog):
    case = load_case("subzones")
    assert case["zones"]["example.com."]["sub_zones"] == ["subdomain1"]
    populate(connect(case), case, "example.com.")
    # Zone example.com. leaves out the records of zone subdomain1.example.com.
    left_out = expected_zone("subzones", "subdomain1.example.com.", []).records
    assert len(left_out) == 3
    assert sorted(source_warnings(caplog)) == sorted(
        f"Skipping subzone record: {record!r}" for record in left_out
    )


def test_populate_skips_fqdn_that_only_shares_the_zone_suffix():
    # https://github.com/sukiyaki/octodns-netbox/issues/78
    case = load_case("issue-78")
    (exchange,) = case["zones"]["test.example.com."]["exchanges"]
    returned = {ip["description"] for ip in exchange["response"]["json"]["results"]}
    assert returned == {"a-test.example.com", "host.test.example.com"}
    zone = populate(connect(case), case, "test.example.com.")
    assert {(record.name, record._type) for record in zone.records} == {("host", "A")}


def test_populate_skips_a_name_without_an_idna_form_with_a_warning(caplog):
    case = load_case("idn")
    source = connect(case)
    for zone_name in case["zones"]:
        populate(source, case, zone_name)
    skipped = "Skipping the name 'a\\u200db.xn--caf-dma.example.' of 203.0.113.4"
    warnings = source_warnings(caplog)
    assert len(warnings) == 2
    assert all(warning.startswith(skipped) for warning in warnings)


# Each description of the idn-case case, and the name that 0.5.0 gave its PTR
# record on octoDNS 1.10.0, 1.12.0, 1.13.0, and 1.22.0 alike. With one
# description at a time, 0.5.0 gave the A record the same name, except where a
# comment says otherwise. With all of them, 0.5.0 stopped the forward zone,
# because Straße and STRAẞE gave two records of one name, as did ΑΣ and ας.
IDN_CASE = [
    ("ΑΣ.α.idn-case.example", "xn--mxa0b.xn--mxa.idn-case.example."),
    # 0.5.0 lower-cased ΑΣ without the zone name for the A record, and got ας,
    # xn--mxa8a. The PTR record pointed to ασ, a name without an A record.
    ("ΑΣ.idn-case.example", "xn--mxa0b.idn-case.example."),
    ("α.Σ.1.idn-case.example", "xn--mxa.xn--3xa.1.idn-case.example."),
    ("ΑΣ.1.idn-case.example", "xn--mxa8a.1.idn-case.example."),
    ("ας.idn-case.example", "xn--mxa8a.idn-case.example."),
    ("ΑΣ.café.idn-case.example", "xn--mxa0b.xn--caf-dma.idn-case.example."),
    # The A record of 0.5.0 was xn--1lqs71d.xn--mxa8a, as for ΑΣ.idn-case.example.
    ("東京.ΑΣ.idn-case.example", "xn--1lqs71d.xn--mxa0b.idn-case.example."),
    ("ΤΕΣΤ-テスト.idn-case.example", "xn----6lb6bcc9610eucara.idn-case.example."),
    ("Straße.idn-case.example", "xn--strae-oqa.idn-case.example."),
    ("STRAẞE.idn-case.example", "xn--strae-oqa.idn-case.example."),
    ("İstanbul.idn-case.example", "xn--istanbul-o0e.idn-case.example."),
    ("ıspanak.idn-case.example", "xn--spanak-o9a.idn-case.example."),
    ("DİYARBAKIR.idn-case.example", "xn--diyarbakir-o2f.idn-case.example."),
]


def test_populate_lower_cases_each_name_as_a_whole_as_0_5_0_did():
    case = load_case("idn-case")
    (exchange,) = case["zones"]["11.0.192.in-addr.arpa."]["exchanges"]
    address = {
        ip["description"]: ip_interface(ip["address"]).ip
        for ip in exchange["response"]["json"]["results"]
    }
    assert sorted(address) == sorted(name for name, _ in IDN_CASE)
    source = connect(case)
    forward = populate(source, case, "idn-case.example.")
    reverse = populate(source, case, "11.0.192.in-addr.arpa.")
    a = {(record.fqdn, value) for record in forward.records for value in record.values}
    assert a == {(fqdn, str(address[name])) for name, fqdn in IDN_CASE}
    ptr = {
        (record.fqdn, value) for record in reverse.records for value in record.values
    }
    assert ptr == {
        (f"{address[name].reverse_pointer}.", fqdn) for name, fqdn in IDN_CASE
    }


def test_populate_skips_a_record_name_octodns_cannot_decode_with_a_warning(caplog):
    case = load_case("invalid-a-label")
    source = connect(case)
    for zone_name in case["zones"]:
        populate(source, case, zone_name)
    # The PTR record of 192.0.9.2 keeps the name, so only the A record is gone.
    (warning,) = source_warnings(caplog)
    assert warning.startswith(
        "Skipping the name 'xn--bad_label.a-label.example.' of 192.0.9.2 "
        "in zone a-label.example.: "
    )


def test_populate_fails_on_an_ipv6_zone_label_that_is_not_one_hex_digit():
    # The autouse mocker fails any request, so this also shows that the source
    # stops before it asks NetBox anything.
    source = NetboxSource("netbox", url="http://netbox.example.com", token="t")
    with pytest.raises(ValueError, match="'00' must be one hex digit"):
        source.populate(Zone("00.ip6.arpa.", []))
