import pytest
import requests_mock
from octodns.record import Record
from octodns.zone import Zone
from pydantic.error_wrappers import ValidationError

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
            "http://netbox.example.com/api/ipam/ip-addresses/?dns_name__ic=example.com&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_example_com.json"),
        )

        yield mock


class TestNetboxSourceFailSenarios:
    def test_init_failed_due_to_missing_url(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource("test")
        assert excinfo.value.errors() == [
            {"loc": ("url",), "msg": "field required", "type": "value_error.missing"},
            {"loc": ("token",), "msg": "field required", "type": "value_error.missing"},
        ]

    def test_init_failed_due_to_missing_token(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource("test", url="http://netbox.example.com/")
        assert excinfo.value.errors() == [
            {"loc": ("token",), "msg": "field required", "type": "value_error.missing"}
        ]

    def test_init_maintain_backword_compatibility_for_url(self):
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/api/",
            token="testtoken",
        )
        assert source.url == "http://netbox.example.com"

    def test_init_failed_due_to_invalid_field_name_type(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                field_name=["dns_name", "description"],
            )
        assert excinfo.value.errors() == [
            {
                "loc": ("field_name",),
                "msg": "str type expected",
                "type": "type_error.str",
            }
        ]

    def test_init_failed_due_to_invalid_ttl_type(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test", url="http://netbox.example.com/", token="testtoken", ttl=[10]
            )
        assert excinfo.value.errors() == [
            {
                "loc": ("ttl",),
                "msg": "value is not a valid integer",
                "type": "type_error.integer",
            }
        ]

    def test_init_failed_due_to_invalid_ttl_value(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test", url="http://netbox.example.com/", token="testtoken", ttl="ten"
            )
        assert excinfo.value.errors() == [
            {
                "loc": ("ttl",),
                "msg": "value is not a valid integer",
                "type": "type_error.integer",
            }
        ]

    def test_init_failed_due_to_invalid_populate_tags_type(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                populate_tags="tag",
            )
        assert excinfo.value.errors() == [
            {
                "loc": ("populate_tags",),
                "msg": "value is not a valid list",
                "type": "type_error.list",
            }
        ]

    def test_init_failed_due_to_invalid_populate_vrf_id_type(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                populate_vrf_id=[10],
            )
        assert excinfo.value.errors() == [
            {
                "loc": ("populate_vrf_id",),
                "msg": "value is not a valid integer",
                "type": "type_error.integer",
            },
            {
                "loc": ("populate_vrf_id",),
                "msg": "unhashable type: 'list'",
                "type": "type_error",
            },
        ]

    def test_init_failed_due_to_invalid_populate_vrf_id_value(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                populate_vrf_id="ten",
            )
        assert excinfo.value.errors() == [
            {
                "loc": ("populate_vrf_id",),
                "msg": "value is not a valid integer",
                "type": "type_error.integer",
            },
            {
                "ctx": {"given": "ten", "permitted": ("null",)},
                "loc": ("populate_vrf_id",),
                "msg": "unexpected value; permitted: 'null'",
                "type": "value_error.const",
            },
        ]

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
        assert excinfo.value.errors() == [
            {
                "loc": ("populate_vrf_name",),
                "msg": "str type expected",
                "type": "type_error.str",
            }
        ]

    def test_init_failed_because_invalid_populate_vrf_name_is_not_found_at_netbox(self):
        with pytest.raises(ValueError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                populate_vrf_name="TEST",
            )
        assert "Failed to retrive vrf information by name" in str(excinfo.value)

    def test_init_failed_due_to_invalid_populate_subdomains_type(self):
        with pytest.raises(ValidationError) as excinfo:
            NetboxSource(
                "test",
                url="http://netbox.example.com/",
                token="testtoken",
                populate_subdomains="ok",
            )
        assert excinfo.value.errors() == [
            {
                "loc": ("populate_subdomains",),
                "msg": "value could not be parsed to a boolean",
                "type": "type_error.bool",
            }
        ]


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

        assert len(zone.records) == 10

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

        assert len(zone.records) == 5

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
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_A_and_AAAA_field_is_dns_name_populate_and_defined_sub_zones(
        self, caplog
    ):
        zone = Zone("example.com.", set(["subdomain1"]))
        source = NetboxSource(
            "test",
            url="http://netbox.example.com/",
            token="testtoken",
            field_name="dns_name",
        )
        source.populate(zone)

        assert "Skipping subzone record" in caplog.text
        assert len(zone.records) == 4
