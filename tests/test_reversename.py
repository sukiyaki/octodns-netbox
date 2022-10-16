import ipaddress

import pytest
from octodns.zone import Zone

from octodns_netbox.reversename import from_address, to_network


class TestToNetworkIPv4:
    def test_to_network_ipv4_non_octet_boundary_rfc4183(self):
        zone_rfc4183_1 = Zone("0-26.2.100.10.in-addr.arpa.", [])
        assert to_network(zone_rfc4183_1) == ipaddress.IPv4Network("10.100.2.0/26")

    def test_to_network_ipv4_non_octet_boundary_rfc2317(self):
        zone_rfc2317_1 = Zone("0/26.2.100.10.in-addr.arpa.", [])
        assert to_network(zone_rfc2317_1) == ipaddress.IPv4Network("10.100.2.0/26")

    def test_to_network_ipv4_octet_boundary(self):
        zone_1 = Zone("10.in-addr.arpa.", [])
        assert to_network(zone_1) == ipaddress.IPv4Network("10.0.0.0/8")

        zone_2 = Zone("20.10.in-addr.arpa.", [])
        assert to_network(zone_2) == ipaddress.IPv4Network("10.20.0.0/16")

        zone_3 = Zone("30.20.10.in-addr.arpa.", [])
        assert to_network(zone_3) == ipaddress.IPv4Network("10.20.30.0/24")

    def test_to_network_fails_due_to_invalid_zone(self):
        zone_invalid_1 = Zone("300.10.in-addr.arpa.", [])
        with pytest.raises(ValueError) as excinfo:
            to_network(zone_invalid_1)
        assert "Faild to parse the zone name" in str(excinfo.value)

        zone_invalid_2_1 = Zone("300-20.10.in-addr.arpa.", [])
        with pytest.raises(ValueError) as excinfo:
            to_network(zone_invalid_2_1)
        assert "Faild to parse the zone name" in str(excinfo.value)

        zone_invalid_2_2 = Zone("300/20.10.in-addr.arpa.", [])
        with pytest.raises(ValueError) as excinfo:
            to_network(zone_invalid_2_2)
        assert "Faild to parse the zone name" in str(excinfo.value)

        zone_invalid_3_1 = Zone("30-35.10.in-addr.arpa.", [])
        with pytest.raises(ValueError) as excinfo:
            to_network(zone_invalid_3_1)
        assert "Faild to parse the zone name" in str(excinfo.value)

        zone_invalid_3_2 = Zone("30/35.10.in-addr.arpa.", [])
        with pytest.raises(ValueError) as excinfo:
            to_network(zone_invalid_3_2)
        assert "Faild to parse the zone name" in str(excinfo.value)

        zone_invalid_4 = Zone("30/35.10.in-addr.arpa.example.com.", [])
        with pytest.raises(ValueError) as excinfo:
            to_network(zone_invalid_4)
        assert "Invalid reverse IPv4/IPv6 zone" in str(excinfo.value)


class TestToNetworkIPv6:
    def test_to_network_ipv6(self):
        zone_56 = Zone("4.3.2.1.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", [])
        assert to_network(zone_56) == ipaddress.IPv6Network("2001:db8:12:3400::/56")

        zone_64 = Zone("0.0.0.0.c.d.b.a.8.b.d.0.1.0.0.2.ip6.arpa.", [])
        assert to_network(zone_64) == ipaddress.IPv6Network("2001:db8:abdc::/64")


class TestFromAddressIPv4:
    def test_from_address_ipv4_non_octet_boundary(self):
        zone_rfc4183_1 = Zone("0-26.2.100.10.in-addr.arpa.", [])
        assert (
            from_address(zone_rfc4183_1, ipaddress.IPv4Address("10.100.2.1"))
            == "1.0-26.2.100.10.in-addr.arpa."
        )

        zone_rfc2317_1 = Zone("0/26.2.100.10.in-addr.arpa.", [])
        assert (
            from_address(zone_rfc2317_1, ipaddress.IPv4Address("10.100.2.1"))
            == "1.0/26.2.100.10.in-addr.arpa."
        )

    def test_from_address_ipv4_octet_boundary(self):
        zone_1 = Zone("10.in-addr.arpa.", [])
        assert (
            from_address(zone_1, ipaddress.IPv4Address("10.100.2.1"))
            == "1.2.100.10.in-addr.arpa."
        )

        zone_2 = Zone("20.10.in-addr.arpa.", [])
        assert (
            from_address(zone_2, ipaddress.IPv4Address("10.20.2.1"))
            == "1.2.20.10.in-addr.arpa."
        )

        zone_3 = Zone("30.20.10.in-addr.arpa.", [])
        assert (
            from_address(zone_3, ipaddress.IPv4Address("10.20.30.40"))
            == "40.30.20.10.in-addr.arpa."
        )

    def test_from_address_fails_due_to_invalid_zone(self):
        zone_rfc4183_1 = Zone("0-26.2.100.10.in-addr.arpa.example.com.", [])
        with pytest.raises(ValueError) as excinfo:
            from_address(zone_rfc4183_1, ipaddress.IPv4Address("10.100.2.1"))
        assert "Invalid reverse IPv4/IPv6 zone" in str(excinfo.value)


class TestFromAddressIPv6:
    def test_from_address_ipv6(self):
        zone_64 = Zone("0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", [])
        assert (
            from_address(zone_64, ipaddress.IPv6Address("2001:db8::1"))
            == "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        )
