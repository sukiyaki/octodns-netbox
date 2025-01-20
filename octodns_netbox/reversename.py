import ipaddress
import re
from typing import Union

from octodns.zone import Zone


def to_network(zone: Zone) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
    """
    Convert a reverse DNS zone (either in-addr.arpa for IPv4 or ip6.arpa for IPv6)
    into its corresponding IPv4Network or IPv6Network object.

    Args:
        zone (Zone): The octoDNS Zone object representing a reverse zone.

    Returns:
        Union[ipaddress.IPv4Network, ipaddress.IPv6Network]: The inferred IP network.

    Raises:
        ValueError: If the zone name does not end with '.in-addr.arpa.' or '.ip6.arpa.'.
    """
    if zone.name.endswith(".in-addr.arpa."):
        return to_network_v4(zone)
    elif zone.name.endswith(".ip6.arpa."):
        return to_network_v6(zone)
    else:
        raise ValueError(
            f"Invalid reverse zone '{zone.name}'. "
            "Zone must end with '.in-addr.arpa.' (IPv4) or '.ip6.arpa.' (IPv6)."
        )


def to_network_v4(zone: Zone) -> ipaddress.IPv4Network:
    """
    Construct an IPv4 network definition from a reverse IPv4 zone name.

    This function supports blocks smaller than /24 (e.g., /30) as described in
    RFC 2317 (Classless IN-ADDR.ARPA delegation) and RFC 4183. It uses a regex to detect
    a non-octet boundary (e.g., '192/26') in the leftmost label if it includes a slash.

    Example:
        If the zone name is '192/26.168.10.in-addr.arpa.', then:
          - labels = ['192/26', '168', '10']
          - netmask = 26
          - The resulting network might be '10.168.192.0/26'.

    Args:
        zone (Zone): The octoDNS Zone object for an IPv4 reverse zone, e.g. '192/26.168.10.in-addr.arpa.'.

    Returns:
        ipaddress.IPv4Network: The corresponding IPv4 network object.

    Raises:
        ValueError: If the leftmost label cannot be parsed as an IPv4 octet or slash-based netmask.
    """
    labels = zone.name.split(".")[:-3]  # remove the trailing ['in-addr', 'arpa', '']
    netmask = 8 * len(labels)  # default netmask based on how many labels we have
    offset = 4 - len(
        labels
    )  # how many octets we must prepend as '0' for a full 4-octet address

    # Regex to detect optional slash-based netmask (e.g. 192/26)
    pattern = r"^(25[0-5]|2[0-4]\d|[01]?\d?\d)([/-](2[5-9]|3[0-1]))?$"
    match = re.search(pattern, labels[0])
    if not match:
        raise ValueError(
            f"Failed to parse the leftmost IPv4 label '{labels[0]}' in zone '{zone.name}' "
            "as an octet or slash-based netmask."
        )

    # If we have a slash notation in the matched group, adjust the netmask
    if match[2]:
        # Example: '192/26' => '192', netmask=26
        last_octet = match[1]
        labels[0] = last_octet
        netmask = int(match[2][1:])  # remove the '/' or '-' then convert to int

    # Prepend "0" for the missing octets
    labels = ["0"] * offset + labels

    # Reverse labels to get standard x.x.x.x format, then apply netmask
    prefix_str = ".".join(reversed(labels))
    prefix_str += f"/{netmask}"

    return ipaddress.IPv4Network(prefix_str, strict=True)


def to_network_v6(zone: Zone) -> ipaddress.IPv6Network:
    """
    Construct an IPv6 network definition from a reverse IPv6 zone name.

    For an IPv6 reverse zone (ip6.arpa.), each label typically represents one nibble (hex digit).
    This function reverses the nibble labels, groups them into 4-hex-digit blocks (hextets),
    and appends an appropriate prefix length based on the number of nibbles.

    If the total number of nibbles is not a multiple of 4, zeroes are appended to
    make it a multiple of 4 before grouping into hextets.

    Example:
        If the zone name is 'b.a.8.f.ip6.arpa.', that implies the reversed nibble string 'f8ab'.
        It then forms 'f8ab::/16' if there were exactly 4 nibbles total.

    Args:
        zone (Zone): The octoDNS Zone object for an IPv6 reverse zone, e.g. 'b.a.8.f.ip6.arpa.'.

    Returns:
        ipaddress.IPv6Network: The corresponding IPv6 network object.
    """
    labels = zone.name.split(".")[:-3]  # remove ['ip6', 'arpa', '']
    # Reverse the nibble labels to get the forward nibble string
    reversed_nibbles = "".join(reversed(labels))

    # Pad to a multiple of 4 characters (each group of 4 is one hextet)
    remainder = len(reversed_nibbles) % 4
    if remainder != 0:
        reversed_nibbles += "0" * (4 - remainder)

    # Split into hextets
    hextets = [reversed_nibbles[i : i + 4] for i in range(0, len(reversed_nibbles), 4)]
    prefix_str = ":".join(hextets)
    # Each label was 1 nibble -> each label = 4 bits => total prefix length = len(labels) * 4
    prefix_str += f"::/{len(labels) * 4}"

    return ipaddress.IPv6Network(prefix_str, strict=True)


def from_address(
    zone: Zone, ip_address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
) -> str:
    """
    Given a reverse zone and an IP address, construct the full reverse pointer (FQDN) string,
    ensuring it aligns with the zone name. If the standard reverse pointer (via ip_address.reverse_pointer)
    does not already contain the zone name, we attempt to merge them.

    This is used to generate a reverse FQDN from an ip_address that matches the zone definition.

    Args:
        zone (Zone): A zone object, presumably ending in '.in-addr.arpa.' or '.ip6.arpa.'.
        ip_address (Union[ipaddress.IPv4Address, ipaddress.IPv6Address]): An IP address object.

    Returns:
        str: The reverse FQDN (e.g. '1.0.0.127.in-addr.arpa.') that corresponds to the zone.

    Raises:
        ValueError: If the zone name is not a valid IPv4 or IPv6 reverse zone.
    """
    if not zone.name.endswith((".in-addr.arpa.", ".ip6.arpa.")):
        raise ValueError(
            f"Invalid reverse zone '{zone.name}'. "
            "Zone must end with '.in-addr.arpa.' (IPv4) or '.ip6.arpa.' (IPv6)."
        )

    # ip_address.reverse_pointer returns something like '1.0.0.127.in-addr.arpa' for 127.0.0.1
    fqdn = f"{ip_address.reverse_pointer}."

    # If the zone name is already in the FQDN, no extra fix-up needed
    if zone.name in fqdn:
        return fqdn

    # Otherwise, we try to merge the zone labels with the standard reverse pointer
    zone_labels = zone.name.split(".")
    standard_labels = fqdn.split(".")

    # Insert the standard label segments in front of the zone labels
    # to ensure the final FQDN merges both sets
    for i in range(len(zone_labels) - len(standard_labels) + 1):
        zone_labels.insert(0, standard_labels[i])

    return ".".join(zone_labels)
