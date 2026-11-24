import ipaddress
import re
from typing import cast

from octodns.zone import Zone

_IPV4_SUFFIX = ".in-addr.arpa."
_IPV6_SUFFIX = ".ip6.arpa."
# The first label of an IPv4 reverse zone: an octet, or an octet and a prefix
# length in a classless zone, "0/26" (RFC 2317) or "0-26" (RFC 4183).
_IPV4_FIRST_LABEL = re.compile(
    r"^(?P<octet>25[0-5]|2[0-4]\d|[01]?\d?\d)([/-](?P<prefixlen>2[5-9]|3[0-1]))?$"
)


def is_reverse(zone: Zone) -> bool:
    return cast(str, zone.name).endswith((_IPV4_SUFFIX, _IPV6_SUFFIX))


def to_network(zone: Zone) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """The network whose addresses have their PTR records in the reverse zone."""
    if zone.name.endswith(_IPV4_SUFFIX):
        return to_network_v4(zone)
    if zone.name.endswith(_IPV6_SUFFIX):
        return to_network_v6(zone)
    raise ValueError(
        f"Invalid reverse zone '{zone.name}'. "
        "Zone must end with '.in-addr.arpa.' (IPv4) or '.ip6.arpa.' (IPv6)."
    )


def to_network_v4(zone: Zone) -> ipaddress.IPv4Network:
    labels = zone.name.removesuffix(_IPV4_SUFFIX).split(".")
    match = _IPV4_FIRST_LABEL.search(labels[0])
    if not match:
        raise ValueError(
            f"Failed to parse the leftmost IPv4 label '{labels[0]}' in zone "
            f"'{zone.name}' as an octet or slash-based netmask."
        )
    prefixlen = 8 * len(labels)
    if match["prefixlen"]:
        labels[0], prefixlen = match["octet"], int(match["prefixlen"])
    octets = labels[::-1] + ["0"] * (4 - len(labels))
    return ipaddress.IPv4Network(f"{'.'.join(octets)}/{prefixlen}")


def to_network_v6(zone: Zone) -> ipaddress.IPv6Network:
    labels = zone.name.removesuffix(_IPV6_SUFFIX).split(".")
    nibbles = "".join(reversed(labels))
    hextets = [nibbles[i : i + 4].ljust(4, "0") for i in range(0, len(nibbles), 4)]
    return ipaddress.IPv6Network(f"{':'.join(hextets)}::/{4 * len(labels)}")


def from_address(
    zone: Zone, address: ipaddress.IPv4Address | ipaddress.IPv6Address
) -> str:
    """The FQDN of the address's PTR record in the reverse zone.

    That is the address's reverse pointer, "1.2.0.192.in-addr.arpa." for
    192.0.2.1, except in a classless zone, which adds the host octet to its
    name: "1.0/26.2.0.192.in-addr.arpa." in zone "0/26.2.0.192.in-addr.arpa.".
    """
    if not is_reverse(zone):
        raise ValueError(
            f"Invalid reverse zone '{zone.name}'. "
            "Zone must end with '.in-addr.arpa.' (IPv4) or '.ip6.arpa.' (IPv6)."
        )
    pointer = f"{address.reverse_pointer}."
    if pointer == zone.name or pointer.endswith(f".{zone.name}"):
        return pointer
    if zone.name.count(".") < pointer.count("."):
        # A classless zone with fewer than four labels before in-addr.arpa,
        # such as "0/26.0.192.in-addr.arpa.", holds every address at its apex.
        return cast(str, zone.name)
    host_octet = pointer.split(".")[0]
    return f"{host_octet}.{zone.name}"
