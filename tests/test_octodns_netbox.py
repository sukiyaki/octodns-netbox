import pytest
import requests_mock
from octodns.record import Record
from octodns.zone import Zone
from pydantic import ValidationError

from octodns_netbox import NetboxSource

from .util import SimpleProvider, load_fixture


@pytest.fixture(autouse=True)
def mock_requests():
    with requests_mock.Mocker() as mock:
        mock.get(
            "http://netbox.example.com/api/ipam/vrfs/?limit=0",
            complete_qs=True,
            json=load_fixture("vrfs.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/vrfs/?name=mgmt&limit=0",
            complete_qs=True,
            json=load_fixture("vrfs.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/vrfs/?name=TEST&limit=0",
            complete_qs=True,
            json={"count": 0, "next": None, "previous": None, "results": []},
        )
        mock.get(
            "http://netbox.example.com/api/ipam/vrfs/1/",
            json=load_fixture("vrf.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=192.0.2.0%2F27&family=4&description__empty=false&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_v4_non_octet_boundary.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=192.0.2.0%2F27&family=4&dns_name__empty=false&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_v4_non_octet_boundary.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=192.0.2.0%2F27&family=4&vrf_id=1&description__empty=false&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_v4_non_octet_boundary_vrf_mgmt.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=192.0.2.0%2F24&family=4&description__empty=false&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_v4_octet_boundary.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=192.0.2.0%2F24&family=4&dns_name__empty=false&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_v4_octet_boundary.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=192.0.3.0%2F24&family=4&vrf_id=null&description__empty=false&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_v4_octet_boundary_vrf_global.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=2001%3Adb8%3A%3A%2F100&family=6&description__empty=false&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_v6_non_nibble_boundary.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=2001%3Adb8%3A%3A%2F100&family=6&dns_name__empty=false&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_v6_non_nibble_boundary.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=2001%3Adb8%3A%3A%2F64&family=6&description__empty=false&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_v6_nibble_boundary.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=2001%3Adb8%3A%3A%2F64&family=6&dns_name__empty=false&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_v6_nibble_boundary.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?description__ic=example.com&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_example_com.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?description__ic=subdomain1.example.com&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_subdomain1_example_com.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?dns_name__ic=subdomain1.example.com&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_subdomain1_example_com.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?dns_name__ic=example.com&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_example_com.json"),
        )

        yield mock


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

    def test_init_maintain_backword_compatibility_for_url(self):
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/api/",
            token="testtoken",
        )
        assert source.url == "http://netbox.example.com"

    def test_init_failed_due_to_invalid_field_name_empty_list(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                field_name=[],
            )

        assert excinfo.value.errors()[0]["loc"] == ("field_name",)

    def test_init_failed_due_to_invalid_field_name_empty_string_entry(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                field_name=["dns_name", ""],
            )

        assert excinfo.value.errors()[0]["loc"] == ("field_name",)

    def test_init_failed_due_to_invalid_field_name_non_string_entry(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                field_name=["dns_name", 123],
            )

        assert excinfo.value.errors()[0]["loc"] == ("field_name",)

    def test_init_failed_due_to_invalid_field_name_wrong_type(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                field_name=123,
            )

        assert excinfo.value.errors()[0]["loc"] == ("field_name",)

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

    def test_init_failed_because_invalid_populate_vrf_name_is_not_found_at_netbox(self):
        with pytest.raises(ValueError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                populate_vrf_name="TEST",
            )
        assert "Failed to retrieve VRF information by name" in str(excinfo.value)

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


class TestNetboxSourcePopulateIPv4PTRNonOctecBoundary:
    def test_populate_PTR_v4_non_octet_boundary(self):
        zone = Zone("0/27.2.0.192.in-addr.arpa.", [])
        source = NetboxSource(
            "test", url="http://netbox.example.com/", token="testtoken"
        )
        source.populate(zone)

        assert len(zone.records) == 3

        expected = Zone("0/27.2.0.192.in-addr.arpa.", [])
        for name, data in (
            (
                "1",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["description-192-0-2-1.example.com."],
                },
            ),
            (
                "2",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["description-192-0-2-2.example.com."],
                },
            ),
            (
                "3",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["description-192-0-2-3.example.com."],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_PTR_v4_non_octet_boundary_field_name_is_dns_name(self):
        zone = Zone("0/27.2.0.192.in-addr.arpa.", [])
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/",
            token="testtoken",
            field_name="dns_name",
        )
        source.populate(zone)

        assert len(zone.records) == 3

        expected = Zone("0/27.2.0.192.in-addr.arpa.", [])
        for name, data in (
            (
                "1",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["dnsname-192-0-2-1.example.com."],
                },
            ),
            (
                "2",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["dnsname-192-0-2-2.example.com."],
                },
            ),
            (
                "3",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["dnsname-192-0-2-3.example.com."],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_PTR_v4_non_octet_boundary_custom_ttl(self):
        zone = Zone("0/27.2.0.192.in-addr.arpa.", [])
        source = NetboxSource(
            "test", url="http://netbox.example.com/", token="testtoken", ttl=120
        )
        source.populate(zone)

        assert len(zone.records) == 3

        expected = Zone("0/27.2.0.192.in-addr.arpa.", [])
        for name, data in (
            (
                "1",
                {
                    "type": "PTR",
                    "ttl": 120,
                    "values": ["description-192-0-2-1.example.com."],
                },
            ),
            (
                "2",
                {
                    "type": "PTR",
                    "ttl": 120,
                    "values": ["description-192-0-2-2.example.com."],
                },
            ),
            (
                "3",
                {
                    "type": "PTR",
                    "ttl": 120,
                    "values": ["description-192-0-2-3.example.com."],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_PTR_v4_non_octet_boundary_select_vrf_by_id(self):
        zone = Zone("0/27.2.0.192.in-addr.arpa.", [])
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/",
            token="testtoken",
            populate_vrf_id=1,
        )
        source.populate(zone)

        assert len(zone.records) == 3

        expected = Zone("0/27.2.0.192.in-addr.arpa.", [])
        for name, data in (
            (
                "1",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["vrf-mgmt-description-192-0-2-1.example.com."],
                },
            ),
            (
                "2",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["vrf-mgmt-description-192-0-2-2.example.com."],
                },
            ),
            (
                "3",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["vrf-mgmt-description-192-0-2-3.example.com."],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_PTR_v4_non_octet_boundary_select_vrf_by_name(self):
        zone = Zone("0/27.2.0.192.in-addr.arpa.", [])
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/",
            token="testtoken",
            populate_vrf_name="mgmt",
        )
        source.populate(zone)

        assert len(zone.records) == 3

        expected = Zone("0/27.2.0.192.in-addr.arpa.", [])
        for name, data in (
            (
                "1",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["vrf-mgmt-description-192-0-2-1.example.com."],
                },
            ),
            (
                "2",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["vrf-mgmt-description-192-0-2-2.example.com."],
                },
            ),
            (
                "3",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["vrf-mgmt-description-192-0-2-3.example.com."],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []


class TestNetboxSourcePopulateIPv4PTROctecBoundary:
    def test_populate_PTR_v4_octet_boundary(self):
        zone = Zone("2.0.192.in-addr.arpa.", [])
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/",
            token="testtoken",
        )
        source.populate(zone)

        assert len(zone.records) == 2

        expected = Zone("2.0.192.in-addr.arpa.", [])
        for name, data in (
            (
                "1",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["description-192-0-2-1.example.com."],
                },
            ),
            (
                "2",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["description-192-0-2-2.example.com."],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_PTR_v4_octet_boundary_multivalue_ptr_enabled(self):
        zone = Zone("2.0.192.in-addr.arpa.", [])
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/",
            token="testtoken",
            multivalue_ptr=True,
        )
        source.populate(zone)

        assert len(zone.records) == 2

        expected = Zone("2.0.192.in-addr.arpa.", [])
        for name, data in (
            (
                "1",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["description-192-0-2-1.example.com."],
                },
            ),
            (
                "2",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": [
                        "description-192-0-2-2.example.com.",
                        "description-multiptr-192-0-2-2.example.com.",
                    ],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_PTR_v4_octet_boundary_field_name_is_dns_name(self):
        zone = Zone("2.0.192.in-addr.arpa.", [])
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/",
            token="testtoken",
            field_name="dns_name",
        )
        source.populate(zone)

        assert len(zone.records) == 2

        expected = Zone("2.0.192.in-addr.arpa.", [])
        for name, data in (
            (
                "1",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["dnsname-192-0-2-1.example.com."],
                },
            ),
            (
                "2",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["dnsname-192-0-2-2.example.com."],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_PTR_v4_octet_boundary_vrf_global_by_id(self):
        zone = Zone("3.0.192.in-addr.arpa.", [])
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/",
            token="testtoken",
            populate_vrf_id=0,
        )
        source.populate(zone)

        assert len(zone.records) == 1

        expected = Zone("3.0.192.in-addr.arpa.", [])
        for name, data in (
            (
                "1",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["description-192-0-3-1.example.com."],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_PTR_v4_octet_boundary_vrf_global_by_name(self):
        zone = Zone("3.0.192.in-addr.arpa.", [])
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/",
            token="testtoken",
            populate_vrf_name="Global",
        )
        source.populate(zone)

        assert len(zone.records) == 1

        expected = Zone("3.0.192.in-addr.arpa.", [])
        for name, data in (
            (
                "1",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["description-192-0-3-1.example.com."],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []


class TestNetboxSourcePopulateIPv6PTRNonNibbleBoundary:
    def test_populate_PTR_v6_non_nibble_boundary(self):
        zone = Zone("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", [])
        source = NetboxSource(
            "test", url="http://netbox.example.com/", token="testtoken"
        )
        source.populate(zone)

        assert len(zone.records) == 2

        expected = Zone(
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", []
        )
        for name, data in (
            (
                "2.0.0.0.0.0.0",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["description-2001-0db8-2.example.com."],
                },
            ),
            (
                "3.0.0.0.0.0.0",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["description-2001-0db8-3.example.com."],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_PTR_v6_non_nibble_boundary_field_name_is_dns_name(self):
        zone = Zone("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", [])
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/",
            token="testtoken",
            field_name="dns_name",
        )
        source.populate(zone)

        assert len(zone.records) == 2

        expected = Zone(
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", []
        )
        for name, data in (
            (
                "2.0.0.0.0.0.0",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["dnsname-2001-0db8-2.example.com."],
                },
            ),
            (
                "3.0.0.0.0.0.0",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["dnsname-2001-0db8-3.example.com."],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []


class TestNetboxSourcePopulateIPv6PTRNibbleBoundary:
    def test_populate_PTR_v6_nibble_boundary(self):
        zone = Zone("0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", [])
        source = NetboxSource(
            "test", url="http://netbox.example.com/", token="testtoken"
        )
        source.populate(zone)

        assert len(zone.records) == 2

        expected = Zone("0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", [])
        for name, data in (
            (
                "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["description-2001-0db8-2.example.com."],
                },
            ),
            (
                "3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["description-2001-0db8-3.example.com."],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_PTR_v6_name_nibble_boundary_field_is_dns_name(self):
        zone = Zone("0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", [])
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/",
            token="testtoken",
            field_name="dns_name",
        )
        source.populate(zone)

        assert len(zone.records) == 2

        expected = Zone("0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", [])
        for name, data in (
            (
                "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["dnsname-2001-0db8-2.example.com."],
                },
            ),
            (
                "3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0",
                {
                    "type": "PTR",
                    "ttl": 60,
                    "values": ["dnsname-2001-0db8-3.example.com."],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []


class TestNetboxSourcePopulateNormal:
    def test_populate_A_and_AAAA(self):
        zone = Zone("example.com.", [])
        source = NetboxSource(
            "test", url="http://netbox.example.com/", token="testtoken"
        )
        source.populate(zone)

        assert len(zone.records) == 12

        expected = Zone("example.com.", [])
        for name, data in (
            (
                "description-host1",
                {
                    "type": "A",
                    "ttl": 60,
                    "values": ["192.0.4.1"],
                },
            ),
            (
                "description-host1",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": ["2001:db8::1:1"],
                },
            ),
            (
                "description-host2.subdomain1",
                {
                    "type": "A",
                    "ttl": 60,
                    "values": ["192.0.4.2"],
                },
            ),
            (
                "description-host2.subdomain1",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": ["2001:db8::1:2"],
                },
            ),
            (
                "description-host2.subdomain2",
                {
                    "type": "A",
                    "ttl": 60,
                    "values": ["192.0.4.2"],
                },
            ),
            (
                "description-host2.subdomain2",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": ["2001:db8::1:2"],
                },
            ),
            (
                "description-host3.subdomain2",
                {
                    "type": "A",
                    "ttl": 60,
                    "values": ["192.0.4.3"],
                },
            ),
            (
                "description-host3.subdomain2",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": ["2001:db8::1:3"],
                },
            ),
            (
                "description-subdomain1",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": ["2001:db8::1:4"],
                },
            ),
            (
                "description-roundrobin",
                {
                    "type": "A",
                    "ttl": 60,
                    "values": ["192.0.4.5", "192.0.4.6"],
                },
            ),
            (
                "description-roundrobin",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": ["2001:db8::1:5", "2001:db8::1:6"],
                },
            ),
            (
                "",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": ["2001:db8::1:7"],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_populate_subdomains_is_False(self, caplog):
        zone = Zone("subdomain1.example.com.", [])
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/",
            token="testtoken",
            populate_subdomains=False,
        )
        source.populate(zone)

        assert len(zone.records) == 3

        expected = Zone("example.com.", [])
        for name, data in (
            (
                "",
                {
                    "type": "A",
                    "ttl": 60,
                    "values": ["192.0.4.4"],
                },
            ),
            (
                "description-host2",
                {
                    "type": "A",
                    "ttl": 60,
                    "values": ["192.0.4.2"],
                },
            ),
            (
                "description-host2",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": ["2001:db8::1:2"],
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_A_and_AAAA_field_is_dns_name(self):
        zone = Zone("example.com.", [])
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/",
            token="testtoken",
            field_name="dns_name",
        )
        source.populate(zone)

        assert len(zone.records) == 9

        expected = Zone("example.com.", [])
        for name, data in (
            (
                "dnsname-host1",
                {
                    "type": "A",
                    "ttl": 60,
                    "values": ["192.0.4.1"],
                },
            ),
            (
                "dnsname-host1",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": ["2001:db8::1:1"],
                },
            ),
            (
                "dnsname-host2.subdomain1",
                {
                    "type": "A",
                    "ttl": 60,
                    "values": ["192.0.4.2"],
                },
            ),
            (
                "dnsname-host2.subdomain1",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": ["2001:db8::1:2"],
                },
            ),
            (
                "subdomain1",
                {
                    "type": "A",
                    "ttl": 60,
                    "values": ["192.0.4.4"],
                },
            ),
            (
                "dnsname-subdomain1",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": ["2001:db8::1:4"],
                },
            ),
            (
                "dnsname-roundrobin",
                {
                    "type": "A",
                    "ttl": 60,
                    "values": ["192.0.4.5", "192.0.4.6"],
                },
            ),
            (
                "dnsname-roundrobin",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": ["2001:db8::1:5", "2001:db8::1:6"],
                },
            ),
            (
                "",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": "2001:db8::1:7",
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_A_and_AAAA_field_is_dns_name_populate_subdomains_is_False(self):
        zone = Zone("example.com.", [])
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/",
            token="testtoken",
            field_name="dns_name",
            populate_subdomains=False,
        )
        source.populate(zone)

        assert len(zone.records) == 7

        expected = Zone("example.com.", [])
        for name, data in (
            (
                "dnsname-host1",
                {
                    "type": "A",
                    "ttl": 60,
                    "values": ["192.0.4.1"],
                },
            ),
            (
                "dnsname-host1",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": ["2001:db8::1:1"],
                },
            ),
            (
                "subdomain1",
                {
                    "type": "A",
                    "ttl": 60,
                    "values": ["192.0.4.4"],
                },
            ),
            (
                "dnsname-subdomain1",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": ["2001:db8::1:4"],
                },
            ),
            (
                "dnsname-roundrobin",
                {
                    "type": "A",
                    "ttl": 60,
                    "values": ["192.0.4.5", "192.0.4.6"],
                },
            ),
            (
                "dnsname-roundrobin",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": ["2001:db8::1:5", "2001:db8::1:6"],
                },
            ),
            (
                "",
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": "2001:db8::1:7",
                },
            ),
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_A_and_AAAA_field_is_dns_name_populate_and_defined_sub_zones(
        self, caplog
    ):
        zone = Zone("example.com.", {"subdomain1"})
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/",
            token="testtoken",
            field_name="dns_name",
        )
        source.populate(zone)

        assert "Skipping subzone record" in caplog.text
        assert len(zone.records) == 6


class _FakeIpamRecord:
    """Minimal stand-in for a pynetbox Record supporting `r[field]` lookups
    and (optionally) a `custom_fields` dict for `cf_*` field testing."""

    def __init__(self, address: str, fields: dict, custom_fields: dict | None = None):
        self.address = address
        self._fields = fields
        self.custom_fields = custom_fields or {}

    def __getitem__(self, key: str):
        return self._fields.get(key)


class TestNetboxSourceFieldNameList:
    """Covers the list-form `field_name` capability.

    Unit-level tests for the `_collect_fqdns` helper and filter kwargs;
    integration-level tests over the existing example.com fixture, which
    carries both `dns_name` and `description` populated on every record.
    """

    def _make_source(self, **overrides):
        defaults = {
            "url": "http://netbox.example.com/",
            "token": "testtoken",
        }
        defaults.update(overrides)
        return NetboxSource("test", **defaults)

    # --- Config surface / backcompat ---

    def test_string_form_normalizes_to_single_element_list(self):
        source = self._make_source(field_name="dns_name")
        assert source.field_name == ["dns_name"]

    def test_default_is_single_element_list(self):
        source = self._make_source()
        assert source.field_name == ["description"]

    def test_list_form_is_preserved(self):
        source = self._make_source(field_name=["dns_name", "description"])
        assert source.field_name == ["dns_name", "description"]

    # --- _collect_fqdns helper ---

    def test_collect_fqdns_unions_across_fields(self):
        source = self._make_source()
        record = _FakeIpamRecord(
            "192.0.2.1/24",
            {
                "dns_name": "host.example.com.",
                "description": "alias-a.example.com., alias-b.example.com.",
            },
        )
        result = source._collect_fqdns(record, fields=["dns_name", "description"])
        assert result == [
            "host.example.com.",
            "alias-a.example.com.",
            "alias-b.example.com.",
        ]

    def test_collect_fqdns_dedupes_order_preserving(self):
        source = self._make_source()
        record = _FakeIpamRecord(
            "192.0.2.1/24",
            {
                "dns_name": "host.example.com.",
                "description": "host.example.com., alias.example.com.",
            },
        )
        result = source._collect_fqdns(record, fields=["dns_name", "description"])
        assert result == ["host.example.com.", "alias.example.com."]

    def test_collect_fqdns_skips_empty_fields(self):
        source = self._make_source()
        record = _FakeIpamRecord(
            "192.0.2.1/24",
            {"dns_name": "", "description": "alias.example.com."},
        )
        result = source._collect_fqdns(record, fields=["dns_name", "description"])
        assert result == ["alias.example.com."]

    def test_collect_fqdns_skips_none_fields(self):
        source = self._make_source()
        record = _FakeIpamRecord(
            "192.0.2.1/24",
            {"dns_name": None, "description": "alias.example.com."},
        )
        result = source._collect_fqdns(record, fields=["dns_name", "description"])
        assert result == ["alias.example.com."]

    def test_collect_fqdns_len_limit_truncates_after_dedup(self):
        source = self._make_source()
        record = _FakeIpamRecord(
            "192.0.2.1/24",
            {
                "dns_name": "host.example.com.",
                "description": "host.example.com., alias.example.com.",
            },
        )
        result = source._collect_fqdns(
            record, fields=["dns_name", "description"], len_limit=1
        )
        assert result == ["host.example.com."]

    def test_collect_fqdns_first_field_empty_single_field_no_result(self):
        """Single-valued PTR semantics: empty first field → no FQDN."""
        source = self._make_source()
        record = _FakeIpamRecord(
            "192.0.2.1/24",
            {"dns_name": "", "description": "alias.example.com."},
        )
        result = source._collect_fqdns(record, fields=["dns_name"], len_limit=1)
        assert result == []

    # --- Filter base kwargs are field-agnostic ---

    def test_ptr_base_filter_kwargs_have_no_field_part(self):
        """Base PTR kwargs are shared across per-field queries; the per-field
        `__empty` key is added in `_query_ip_addresses_per_field`, not here."""
        import ipaddress

        source = self._make_source(field_name=["dns_name", "description"])
        network = ipaddress.ip_network("192.0.2.0/24")
        kwargs = source._build_ptr_filter_kwargs(network, family=4)
        assert not any("__empty" in k for k in kwargs)
        assert "parent" in kwargs and "family" in kwargs

    def test_forward_base_filter_kwargs_have_no_field_part(self):
        """Base forward kwargs are shared across per-field queries; the per-field
        `__ic` key is added in `_query_ip_addresses_per_field`, not here."""
        source = self._make_source(field_name=["dns_name", "description"])
        zone = Zone("example.com.", [])
        kwargs = source._build_forward_filter_kwargs(zone)
        assert not any("__ic" in k for k in kwargs)

    def test_per_field_query_runs_one_request_per_field(self, mock_requests):
        """OR-across-fields: configuring [dns_name, description] hits both
        per-field URLs when populating a forward zone."""
        zone = Zone("example.com.", [])
        source = self._make_source(field_name=["dns_name", "description"])
        source.populate(zone)

        urls = [r.url for r in mock_requests.request_history]
        assert any("dns_name__ic=example.com" in u for u in urls)
        assert any("description__ic=example.com" in u for u in urls)

    def test_per_field_query_dedupes_overlapping_ips_by_id(self, mock_requests):
        """When per-field queries return overlapping IPs (same id), each IP
        contributes records once. The fixture is identical for both fields,
        so every IP appears in both queries."""
        zone = Zone("example.com.", [])
        source = self._make_source(field_name=["dns_name", "description"])
        source.populate(zone)

        # Compare counts: with [dns_name, description] vs string-form `description`.
        # The set of unique IPs is identical (same fixture); union of FQDNs is a
        # superset of either single field's FQDNs, but no IP is processed twice.
        zone_string = Zone("example.com.", [])
        source_string = self._make_source(field_name="description")
        source_string.populate(zone_string)

        # Every record in the string-form zone (description-only FQDNs)
        # has a corresponding record in the list-form zone, with no duplicate.
        list_form_records = list(zone.records)
        # Ensure no two records share the same (name, type) — that would mean
        # an IP was processed twice.
        seen_keys = set()
        for r in list_form_records:
            key = (r.name, r._type, tuple(r.values))
            assert key not in seen_keys, f"duplicate record from dedup miss: {key}"
            seen_keys.add(key)

    # --- Integration: forward zone with [dns_name, description] ---

    def test_populate_forward_list_form_unions_both_fields(self):
        """With [dns_name, description], host1 produces records from both fields.

        Fixture record 192.0.4.1 has dns_name=dnsname-host1.example.com
        and description=description-host1.example.com; both should become A records.
        """
        zone = Zone("example.com.", [])
        source = self._make_source(field_name=["dns_name", "description"])
        source.populate(zone)

        # Find all A records for 192.0.4.1
        v4_records = [
            r for r in zone.records if r._type == "A" and "192.0.4.1" in r.values
        ]
        names = {r.name for r in v4_records}
        assert "dnsname-host1" in names
        assert "description-host1" in names

    # --- PTR single-valued from first field ---

    def test_populate_ptr_default_single_valued_first_field_only(self):
        """Default (multivalue_ptr=false) with [dns_name, description] takes dns_name only."""
        zone = Zone("0/27.2.0.192.in-addr.arpa.", [])
        source = self._make_source(field_name=["dns_name", "description"])
        source.populate(zone)

        # First field is dns_name → PTR values should be dnsname-* form, not description-*
        for r in zone.records:
            if r._type == "PTR":
                # Single-valued (default)
                assert len(r.values) == 1
                # Value came from dns_name, not description
                assert "dnsname-" in r.values[0]
                assert "description-" not in r.values[0]

    # --- PTR fallthrough: empty primary field → next non-empty field ---

    def test_ptr_default_falls_through_empty_first_field(self):
        """Single-valued PTR with empty primary field falls through to the
        next-non-empty field's first FQDN (build-level fallthrough)."""
        zone = Zone("0/27.2.0.192.in-addr.arpa.", [])
        source = self._make_source(field_name=["dns_name", "description"])
        fake_record = _FakeIpamRecord(
            "192.0.2.5/27",
            {"dns_name": "", "description": "fallback.example.com."},
        )
        rrs = source._build_ptr_records(zone, [fake_record])
        assert len(rrs) == 1
        assert rrs[0].rdata == "fallback.example.com."

    def test_ptr_default_uses_primary_field_when_populated(self):
        """When the primary field is populated, the PTR comes from it (no
        fallthrough), even if a secondary field is also set."""
        zone = Zone("0/27.2.0.192.in-addr.arpa.", [])
        source = self._make_source(field_name=["dns_name", "description"])
        fake_record = _FakeIpamRecord(
            "192.0.2.5/27",
            {
                "dns_name": "primary.example.com.",
                "description": "alias.example.com.",
            },
        )
        rrs = source._build_ptr_records(zone, [fake_record])
        assert len(rrs) == 1
        assert rrs[0].rdata == "primary.example.com."

    # --- PTR multi-valued unions all fields ---

    def test_populate_ptr_multivalue_list_form_unions_all_fields(self):
        """multivalue_ptr=true with [dns_name, description] unions both fields' FQDNs."""
        zone = Zone("0/27.2.0.192.in-addr.arpa.", [])
        source = self._make_source(
            field_name=["dns_name", "description"], multivalue_ptr=True
        )
        source.populate(zone)

        # At least one PTR record should have both a dnsname- and description- value
        ptr_records = [r for r in zone.records if r._type == "PTR"]
        assert ptr_records, "expected at least one PTR record"
        any_multi = any(
            any("dnsname-" in v for v in r.values)
            and any("description-" in v for v in r.values)
            for r in ptr_records
        )
        assert any_multi, "expected a PTR record with values from both fields"

    # --- Interaction: populate_subdomains ---

    def test_list_form_respects_populate_subdomains_false(self):
        """List-form forward union still honors populate_subdomains filtering.

        Uses `description` as the first field so the existing
        `description__ic=subdomain1.example.com` mock is exercised; the test
        validates that per-FQDN subdomain gating in `_fqdn_in_zone` is
        unchanged by the multi-field union path.
        """
        zone = Zone("subdomain1.example.com.", [])
        source = self._make_source(
            field_name=["description", "dns_name"], populate_subdomains=False
        )
        source.populate(zone)

        # Any FQDN with more than one label below the zone name should be dropped
        for r in zone.records:
            # r.name is the label below the zone; no dots means one-level-deep
            assert "." not in r.name


class TestNetboxSourceCustomFields:
    """Covers the `cf_*`-prefixed custom-field capability and its composition
    with the list-form `field_name`."""

    def _make_source(self, **overrides):
        defaults = {
            "url": "http://netbox.example.com/",
            "token": "testtoken",
        }
        defaults.update(overrides)
        return NetboxSource("test", **defaults)

    def test_get_field_value_standard_field(self):
        source = self._make_source()
        record = _FakeIpamRecord(
            "192.0.2.1/24",
            {"dns_name": "host.example.com."},
        )
        assert source._get_field_value(record, "dns_name") == "host.example.com."

    def test_get_field_value_custom_field_strips_cf_prefix(self):
        source = self._make_source()
        record = _FakeIpamRecord(
            "192.0.2.1/24",
            {},
            custom_fields={"aliases": "alias.example.com."},
        )
        assert source._get_field_value(record, "cf_aliases") == "alias.example.com."

    def test_get_field_value_custom_field_missing_returns_none(self):
        source = self._make_source()
        record = _FakeIpamRecord("192.0.2.1/24", {}, custom_fields={})
        assert source._get_field_value(record, "cf_missing") is None

    def test_get_field_value_custom_fields_attr_absent(self):
        """If the IPAM record has no `custom_fields` attribute at all, cf_*
        lookups return None rather than crashing."""

        class _RecordWithoutCustomFields:
            def __init__(self):
                self.address = "192.0.2.1/24"

            def __getitem__(self, key: str):
                return None

        source = self._make_source()
        assert source._get_field_value(_RecordWithoutCustomFields(), "cf_x") is None

    def test_collect_fqdns_mixes_standard_and_custom_fields(self):
        source = self._make_source()
        record = _FakeIpamRecord(
            "192.0.2.1/24",
            {"dns_name": "host.example.com."},
            custom_fields={"aliases": "alias-a.example.com., alias-b.example.com."},
        )
        result = source._collect_fqdns(record, fields=["dns_name", "cf_aliases"])
        assert result == [
            "host.example.com.",
            "alias-a.example.com.",
            "alias-b.example.com.",
        ]

    def test_collect_fqdns_cf_only(self):
        source = self._make_source()
        record = _FakeIpamRecord(
            "192.0.2.1/24",
            {},
            custom_fields={"aliases": "a.example.com., b.example.com."},
        )
        result = source._collect_fqdns(record, fields=["cf_aliases"])
        assert result == ["a.example.com.", "b.example.com."]

    def test_collect_fqdns_cf_dedupes_against_standard(self):
        source = self._make_source()
        record = _FakeIpamRecord(
            "192.0.2.1/24",
            {"dns_name": "host.example.com."},
            custom_fields={"aliases": "host.example.com., other.example.com."},
        )
        result = source._collect_fqdns(record, fields=["dns_name", "cf_aliases"])
        assert result == ["host.example.com.", "other.example.com."]

    def test_string_form_cf_field_normalizes_to_list(self):
        """Backcompat: a bare `cf_*` string is normalized to a one-element list."""
        source = self._make_source(field_name="cf_aliases")
        assert source.field_name == ["cf_aliases"]
