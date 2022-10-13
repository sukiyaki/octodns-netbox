import pytest
import requests_mock
from octodns.record import Record, Rr, ValidationError
from octodns.zone import SubzoneRecordException, Zone

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
            "http://netbox.example.com/api/ipam/vrfs/10/",
            json={"detail": "Not found."},
            status_code=404,
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=192.0.2.0%2F27&family=4&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_v4_non_octet_boundary.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=192.0.2.0%2F27&family=4&vrf_id=1&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_v4_non_octet_boundary_vrf_mgmt.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=192.0.2.0%2F24&family=4&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_v4_octet_boundary.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=192.0.3.0%2F24&family=4&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_v4_octet_boundary_duplicated_address.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=2001%3A0db8%3A0000%3A0000%3A0000%3A0000%3A0000%3A%3A%2F100&family=6&limit=0",
            complete_qs=True,
            json=load_fixture("ip_addresses_v6_non_nibble_boundary.json"),
        )
        mock.get(
            "http://netbox.example.com/api/ipam/ip-addresses/?parent=2001%3A0db8%3A0000%3A0000%3A%3A%2F64&family=6&limit=0",
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
        with pytest.raises(TypeError) as excinfo:
            NetboxSource("test")
        assert "required positional argument" in str(excinfo.value)

    def test_init_failed_due_to_missing_token(self):
        with pytest.raises(TypeError) as excinfo:
            NetboxSource("test", "http://netbox.example.com/")
        assert "required positional argument" in str(excinfo.value)

    def test_init_warning_due_to_invalid_url(self, caplog):
        NetboxSource(
            "test",
            "http://netbox.example.com/api/",
            "testtoken",
        )
        assert "Please remove `/api`" in caplog.text

    def test_init_failed_due_to_invalid_name_field_type(self):
        with pytest.raises(TypeError) as excinfo:
            NetboxSource(
                "test",
                "http://netbox.example.com/",
                "testtoken",
                name_field=True,
            )
        assert "Invalid type for name_field: must be a string" in str(excinfo.value)

    def test_init_failed_due_to_invalid_ttl_type(self):
        with pytest.raises(TypeError) as excinfo:
            NetboxSource("test", "http://netbox.example.com/", "testtoken", ttl=[10])
        assert "Invalid type for ttl: must be a string or int" in str(excinfo.value)

    def test_init_failed_due_to_invalid_ttl_value(self):
        with pytest.raises(ValueError) as excinfo:
            NetboxSource("test", "http://netbox.example.com/", "testtoken", ttl="ten")
        assert "Invalid value: ttl" in str(excinfo.value)

    def test_init_failed_due_to_invalid_populate_tags_type(self):
        with pytest.raises(TypeError) as excinfo:
            NetboxSource(
                "test", "http://netbox.example.com/", "testtoken", populate_tags="tag"
            )
        assert "Invalid type for populate_tags: must be a list" in str(excinfo.value)

    def test_init_failed_due_to_invalid_populate_vrf_id_type(self):
        with pytest.raises(TypeError) as excinfo:
            NetboxSource(
                "test", "http://netbox.example.com/", "testtoken", populate_vrf_id=[10]
            )
        assert "Invalid type for populate_vrf_id: must be a string or int" in str(
            excinfo.value
        )

    def test_init_failed_due_to_invalid_populate_vrf_id_value(self):
        with pytest.raises(ValueError) as excinfo:
            NetboxSource(
                "test", "http://netbox.example.com/", "testtoken", populate_vrf_id="ten"
            )
        assert "Invalid value: populate_vrf_id" in str(excinfo.value)

    def test_init_failed_because_both_populate_vrf_id_populate_vrf_name_are_provided(
        self,
    ):
        with pytest.raises(ValueError) as excinfo:
            NetboxSource(
                "test",
                "http://netbox.example.com/",
                "testtoken",
                populate_vrf_id=1,
                populate_vrf_name="TEST",
            )
        assert "Do not set both populate_vrf_id and populate_vrf" in str(excinfo.value)

    def test_init_failed_due_to_invalid_populate_vrf_name_type(self):
        with pytest.raises(TypeError) as excinfo:
            NetboxSource(
                "test",
                "http://netbox.example.com/",
                "testtoken",
                populate_vrf_name=["TEST"],
            )
        assert "Invalid type for populate_vrf_name: must be a string" in str(
            excinfo.value
        )

    def test_init_failed_due_to_invalid_populate_vrf_id(self):
        with pytest.raises(ValueError) as excinfo:
            NetboxSource(
                "test", "http://netbox.example.com/", "testtoken", populate_vrf_id=10
            )
        assert "Failed to retrive vrf information by id" in str(excinfo.value)

    def test_init_failed_due_to_invalid_populate_vrf_name(self):
        with pytest.raises(ValueError) as excinfo:
            NetboxSource(
                "test",
                "http://netbox.example.com/",
                "testtoken",
                populate_vrf_name="TEST",
            )
        assert "Failed to retrive vrf information by name" in str(excinfo.value)

    def test_init_failed_due_to_invalid_populate_subdomains_type(self):
        with pytest.raises(TypeError) as excinfo:
            NetboxSource(
                "test",
                "http://netbox.example.com/",
                "testtoken",
                populate_subdomains="True",
            )
        assert "Invalid type for populate_subdomains: must be a bool" in str(
            excinfo.value
        )


class TestNetboxSourcePopulateIPv4PTRNonOctecBoundary:
    def test_populate_PTR_v4_non_octet_boundary(self):
        zone = Zone("0/27.2.0.192.in-addr.arpa.", [])
        source = NetboxSource("test", "http://netbox.example.com/", "testtoken")
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

    def test_populate_PTR_v4_non_octet_boundary_name_field_is_dns_name(self):
        zone = Zone("0/27.2.0.192.in-addr.arpa.", [])
        source = NetboxSource(
            "test", "http://netbox.example.com/", "testtoken", name_field="dns_name"
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
            "test", "http://netbox.example.com/", "testtoken", ttl=120
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
            "test", "http://netbox.example.com/", "testtoken", populate_vrf_id=1
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
            "test", "http://netbox.example.com/", "testtoken", populate_vrf_name="mgmt"
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
        source = NetboxSource("test", "http://netbox.example.com/", "testtoken")
        source.populate(zone)

        assert len(zone.records) == 3

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

    def test_populate_PTR_v4_octet_boundary_name_field_is_dns_name(self):
        zone = Zone("2.0.192.in-addr.arpa.", [])
        source = NetboxSource(
            "test", "http://netbox.example.com/", "testtoken", name_field="dns_name"
        )
        source.populate(zone)

        assert len(zone.records) == 3

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

    def test_populate_PTR_v4_octet_boundary_duplicated_addresses(self):
        # In this scenario, two identical IP addresses are returned from IPAM.
        # This can happen when VRF is not specifically specified in octodns_netbox,
        # even though they are actually managed on the Netbox using VRF.
        zone = Zone("3.0.192.in-addr.arpa.", [])
        source = NetboxSource("test", "http://netbox.example.com/", "testtoken")
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
        source = NetboxSource("test", "http://netbox.example.com/", "testtoken")
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

    def test_populate_PTR_v6_non_nibble_boundary_name_field_is_dns_name(self):
        zone = Zone("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", [])
        source = NetboxSource(
            "test", "http://netbox.example.com/", "testtoken", name_field="dns_name"
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
        source = NetboxSource("test", "http://netbox.example.com/", "testtoken")
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
            "test", "http://netbox.example.com/", "testtoken", name_field="dns_name"
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
        source = NetboxSource("test", "http://netbox.example.com/", "testtoken")
        source.populate(zone)

        assert len(zone.records) == 8

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
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_A_and_AAAA_field_is_dns_name(self):
        zone = Zone("example.com.", [])
        source = NetboxSource(
            "test", "http://netbox.example.com/", "testtoken", name_field="dns_name"
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
        ):
            record = Record.new(expected, name, data)
            expected.add_record(record)

        changes = expected.changes(zone, SimpleProvider())
        assert changes == []

    def test_populate_A_and_AAAA_field_is_dns_name_populate_subdomains_is_False(self):
        zone = Zone("example.com.", [])
        source = NetboxSource(
            "test",
            "http://netbox.example.com/",
            "testtoken",
            name_field="dns_name",
            populate_subdomains=False,
        )
        source.populate(zone)

        assert len(zone.records) == 3

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
            "test", "http://netbox.example.com/", "testtoken", name_field="dns_name"
        )
        source.populate(zone)

        assert "Skipping subzone record" in caplog.text
        assert len(zone.records) == 2
