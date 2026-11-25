import ipaddress
import re

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

    def test_to_network_ipv4_host_zone(self):
        zone = Zone("1.2.0.192.in-addr.arpa.", [])
        assert to_network(zone) == ipaddress.IPv4Network("192.0.2.1/32")

    @pytest.mark.parametrize(
        ("name", "message"),
        [
            ("1.300.in-addr.arpa.", "Octet 300 (> 255) not permitted"),
            ("5.4.3.2.1.in-addr.arpa.", "Expected 4 octets"),
            ("1/26.2.0.192.in-addr.arpa.", "has host bits set"),
        ],
    )
    def test_to_network_ipv4_fails_on_a_network_that_ipaddress_rejects(
        self, name, message
    ):
        with pytest.raises(ValueError, match=re.escape(message)):
            to_network(Zone(name, []))

    def test_to_network_fails_due_to_invalid_zone(self):
        zone_invalid_1 = Zone("300.10.in-addr.arpa.", [])
        with pytest.raises(ValueError) as excinfo:
            to_network(zone_invalid_1)
        assert "Failed to parse the leftmost IPv4 label" in str(excinfo.value)

        zone_invalid_2_1 = Zone("300-20.10.in-addr.arpa.", [])
        with pytest.raises(ValueError) as excinfo:
            to_network(zone_invalid_2_1)
        assert "Failed to parse the leftmost IPv4 label" in str(excinfo.value)

        zone_invalid_2_2 = Zone("300/20.10.in-addr.arpa.", [])
        with pytest.raises(ValueError) as excinfo:
            to_network(zone_invalid_2_2)
        assert "Failed to parse the leftmost IPv4 label" in str(excinfo.value)

        zone_invalid_3_1 = Zone("30-35.10.in-addr.arpa.", [])
        with pytest.raises(ValueError) as excinfo:
            to_network(zone_invalid_3_1)
        assert "Failed to parse the leftmost IPv4 label" in str(excinfo.value)

        zone_invalid_3_2 = Zone("30/35.10.in-addr.arpa.", [])
        with pytest.raises(ValueError) as excinfo:
            to_network(zone_invalid_3_2)
        assert "Failed to parse the leftmost IPv4 label" in str(excinfo.value)

        zone_invalid_4 = Zone("30/35.10.in-addr.arpa.example.com.", [])
        with pytest.raises(ValueError) as excinfo:
            to_network(zone_invalid_4)
        assert "Invalid reverse zone" in str(excinfo.value)


@pytest.mark.parametrize("name", ["in-addr.arpa.", "ip6.arpa."])
def test_to_network_fails_on_a_zone_with_no_address_labels(name):
    with pytest.raises(ValueError, match=re.escape(f"'{name}'. It has no address")):
        to_network(Zone(name, []))


class TestToNetworkIPv6:
    def test_to_network_ipv6(self):
        zone_56 = Zone("4.3.2.1.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", [])
        assert to_network(zone_56) == ipaddress.IPv6Network("2001:db8:12:3400::/56")

        zone_64 = Zone("0.0.0.0.c.d.b.a.8.b.d.0.1.0.0.2.ip6.arpa.", [])
        assert to_network(zone_64) == ipaddress.IPv6Network("2001:db8:abdc::/64")

    @pytest.mark.parametrize(
        ("name", "network"),
        [
            (f"{'0.' * 21}8.b.d.0.1.0.0.2.ip6.arpa.", "2001:db8::/116"),
            (f"c.b.a.{'0.' * 20}8.b.d.0.1.0.0.2.ip6.arpa.", "2001:db8::abc0/124"),
            (f"1.{'0.' * 23}8.b.d.0.1.0.0.2.ip6.arpa.", "2001:db8::1/128"),
        ],
    )
    def test_to_network_ipv6_prefix_longer_than_112(self, name, network):
        assert to_network(Zone(name, [])) == ipaddress.IPv6Network(network)

    def test_from_address_ipv6_host_zone_is_the_apex(self):
        zone = Zone(f"1.{'0.' * 23}8.b.d.0.1.0.0.2.ip6.arpa.", [])
        assert from_address(zone, ipaddress.IPv6Address("2001:db8::1")) == zone.name

    @pytest.mark.parametrize(
        "name",
        ["00.ip6.arpa.", "0.00.ip6.arpa.", "db8.1.0.0.2.ip6.arpa.", "g.ip6.arpa."],
    )
    def test_to_network_ipv6_fails_on_a_label_that_is_not_one_hex_digit(self, name):
        with pytest.raises(ValueError, match="must be one hex digit"):
            to_network(Zone(name, []))


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

    @pytest.mark.parametrize(
        ("zone_name", "network", "address", "owner"),
        [
            (
                "0/26.0.192.in-addr.arpa.",
                "192.0.0.0/26",
                "192.0.0.5",
                "5.0/26.0.192.in-addr.arpa.",
            ),
            (
                "64-26.0.192.in-addr.arpa.",
                "192.0.64.0/26",
                "192.0.64.5",
                "5.64-26.0.192.in-addr.arpa.",
            ),
            (
                "0/25.192.in-addr.arpa.",
                "192.0.0.0/25",
                "192.0.0.1",
                "1.0/25.192.in-addr.arpa.",
            ),
            ("0/26.in-addr.arpa.", "0.0.0.0/26", "0.0.0.2", "2.0/26.in-addr.arpa."),
        ],
    )
    def test_classless_zone_with_fewer_labels(self, zone_name, network, address, owner):
        zone, address = Zone(zone_name, []), ipaddress.IPv4Address(address)
        # NetBox returns only the addresses in the network of the zone.
        assert to_network(zone) == ipaddress.IPv4Network(network)
        assert address in to_network(zone)
        assert from_address(zone, address) == owner

    def test_from_address_ipv4_host_zone_is_the_apex(self):
        zone = Zone("1.2.0.192.in-addr.arpa.", [])
        assert (
            from_address(zone, ipaddress.IPv4Address("192.0.2.1"))
            == "1.2.0.192.in-addr.arpa."
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
        zone_invalid_1 = Zone("10.in-addr.arpa.example.com.", [])
        with pytest.raises(ValueError) as excinfo:
            from_address(zone_invalid_1, ipaddress.IPv4Address("10.100.2.1"))
        assert "Invalid reverse zone" in str(excinfo.value)


class TestFromAddressIPv6:
    def test_from_address_ipv6(self):
        zone_64 = Zone("0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", [])
        assert (
            from_address(zone_64, ipaddress.IPv6Address("2001:db8::1"))
            == "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        )

    def test_from_address_ipv6_fails_for_an_address_outside_the_zone(self):
        zone = Zone("8.b.d.0.1.0.0.2.ip6.arpa.", [])
        with pytest.raises(ValueError, match="not in zone"):
            from_address(zone, ipaddress.IPv6Address("2001:db9::1"))

    def test_from_address_ipv6_fails_due_to_invalid_zone(self):
        zone_invalid_1 = Zone(
            "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.example.com.", []
        )
        with pytest.raises(ValueError) as excinfo:
            from_address(zone_invalid_1, ipaddress.IPv6Address("2001:db8::1"))
        assert "Invalid reverse zone" in str(excinfo.value)
