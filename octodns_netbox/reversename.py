import ipaddress
import re
from typing import Union

from octodns.zone import Zone


def to_network(zone: Zone) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:

    if zone.name.endswith(".in-addr.arpa."):
        return to_network_v4(zone)
    elif zone.name.endswith(".ip6.arpa."):
        return to_network_v6(zone)
    else:
        raise ValueError("Invalid reverse IPv4/IPv6 zone")


def to_network_v4(zone: Zone) -> ipaddress.IPv4Network:
    """Construct an IPv4 network definition from a reverse IPv4 zone.

    Delegations for IPv4 blocks less than /24 (e.g., /30) is the problem.
    We support two notations proposed in RFC 2317 and RFC 4183.
    There can be other notations essentially, and they need to be addressed.
    """

    labels = zone.name.split(".")[:-3]
    netmask: int = 8 * len(labels)
    offset = 4 - len(labels)

    pattern = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([/-](2[5-9]|3[0-1]))?$"
    last_label_parsed = re.search(pattern, labels[0])
    if not last_label_parsed:
        raise ValueError("Faild to parse the zone name")

    if last_label_parsed.group(2):
        # non-octet boundary delegation detected
        # remove netmask and save it to the result
        last_octect = last_label_parsed.group(1)
        labels[0] = last_octect
        netmask = int(last_label_parsed.group(2)[1:])

    labels = ["0"] * offset + labels
    prefix_str = ".".join(reversed(labels))
    prefix_str += f"/{netmask}"

    return ipaddress.IPv4Network(prefix_str, strict=True)


def to_network_v6(zone: Zone) -> ipaddress.IPv6Network:
    """Construct an IPv6 network definition from a reverse IPv6 zone."""

    labels = zone.name.split(".")[:-3]

    zone_reverse_str = "".join(reversed(labels))
    if len(zone_reverse_str) % 4 != 0:
        for _ in range(4 - (len(zone_reverse_str) % 4)):
            zone_reverse_str += "0"
    prefix_str = ":".join(
        [zone_reverse_str[i : i + 4] for i in range(0, len(zone_reverse_str), 4)]
    )
    prefix_str += f"::/{len(labels) * 4}"

    return ipaddress.IPv6Network(prefix_str, strict=True)


def from_address(
    zone: Zone, ip_address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
) -> str:
    if not zone.name.endswith((".in-addr.arpa.", ".ip6.arpa.")):
        raise ValueError("Invalid reverse IPv4/IPv6 zone")

    fqdn = f"{ip_address.reverse_pointer}."

    if zone.name in fqdn:
        return fqdn

    zone_labels = zone.name.split(".")
    standard_labels = fqdn.split(".")
    for i in range(0, len(zone_labels) - len(standard_labels) + 1):
        zone_labels.insert(0, standard_labels[i])
    return ".".join(zone_labels)
