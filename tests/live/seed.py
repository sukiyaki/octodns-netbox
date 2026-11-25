"""NetBox objects the live tests create before dumping zones.

The addresses cover the situations the unit tests need in one consistent data
set: in a real NetBox every query sees all of them. The unit-test fixtures in
tests/fixtures/ are recorded from this data.
"""

import ipaddress
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import requests

MGMT_VRF = "mgmt"
# A VRF that allows the same address twice, as anycast addresses need.
ANYCAST_VRF = "anycast"
# A VRF for the case that combines a VRF and tags. VRF mgmt stays out of it,
# because the vrf-name fixture holds the count of IP addresses in VRF mgmt.
TAGGED_VRF = "lab"
# The name of two VRFs, which populate_vrf_name cannot resolve to one ID.
SHARED_VRF_NAME = "shared"
TAGS = ("dns", "external")

PERF_FORWARD_ZONE = "perf.example.net."
PERF_REVERSE_ZONE = "18.198.in-addr.arpa."
_PERF_NETWORK = ipaddress.ip_network("198.18.0.0/16")
_BULK_SIZE = 500


@dataclass(frozen=True)
class Ip:
    address: str
    description: str = ""
    dns_name: str = ""
    vrf: str | None = None
    tags: tuple[str, ...] = ()
    # NetBox lets IP addresses share an address, even where the VRF enforces
    # uniqueness, when each of them has a role such as "anycast".
    role: str | None = None


IPS = (
    # Forward zones example.com. and subdomain1.example.com.
    Ip(
        "192.0.4.1/24",
        "description-host1.example.com",
        "dnsname-host1.example.com",
    ),
    Ip(
        "192.0.4.2/24",
        "description-host2.subdomain1.example.com,description-host2.subdomain2.example.com",
        "dnsname-host2.subdomain1.example.com",
    ),
    Ip(
        "192.0.4.3/24",
        "description-host3.subdomain1.example.com.jp,description-host3.subdomain2.example.com",
        "dnsname-host3.subdomain1.example.com.jp",
    ),
    Ip("192.0.4.4/24", "subdomain1.example.com", "subdomain1.example.com"),
    Ip(
        "192.0.4.5/24",
        "description-roundrobin.example.com",
        "dnsname-roundrobin.example.com",
    ),
    Ip(
        "192.0.4.6/24",
        "description-roundrobin.example.com",
        "dnsname-roundrobin.example.com",
    ),
    Ip(
        "2001:db8::1:1/64",
        "description-host1.example.com",
        "dnsname-host1.example.com",
    ),
    Ip(
        "2001:db8::1:2/64",
        "description-host2.subdomain1.example.com,description-host2.subdomain2.example.com",
        "dnsname-host2.subdomain1.example.com",
    ),
    Ip(
        "2001:db8::1:3/64",
        "description-host3.subdomain1.example.com.jp,description-host3.subdomain2.example.com",
        "dnsname-host3.subdomain1.example.com.jp",
    ),
    Ip(
        "2001:db8::1:4/64",
        "description-subdomain1.example.com",
        "dnsname-subdomain1.example.com",
    ),
    Ip(
        "2001:db8::1:5/64",
        "description-roundrobin.example.com",
        "dnsname-roundrobin.example.com",
    ),
    Ip(
        "2001:db8::1:6/64",
        "description-roundrobin.example.com",
        "dnsname-roundrobin.example.com",
    ),
    Ip("2001:db8::1:7/64", "example.com", "example.com"),
    # Issue #78: a-test.example.com. must stay out of zone test.example.com.
    Ip("192.0.4.7/24", "a-test.example.com", "a-test.example.com"),
    Ip("192.0.4.8/24", "host.test.example.com", "host.test.example.com"),
    # IPv4 reverse zones: 192.0.2.0/24, the classless 192.0.2.0/26, and the
    # same addresses in VRF mgmt.
    Ip(
        "192.0.2.1/24",
        "description-192-0-2-1.example.com",
        "dnsname-192-0-2-1.example.com",
    ),
    Ip(
        "192.0.2.2/24",
        "description-192-0-2-2.example.com,description-multiptr-192-0-2-2.example.com",
        "dnsname-192-0-2-2.example.com",
    ),
    Ip(
        "192.0.2.3/29",
        "description-192-0-2-3.example.com",
        "dnsname-192-0-2-3.example.com",
    ),
    Ip(
        "192.0.2.65/24",
        "description-192-0-2-65.example.com",
        "dnsname-192-0-2-65.example.com",
    ),
    Ip(
        "192.0.2.1/29",
        "vrf-mgmt-description-192-0-2-1.example.com",
        "vrf-mgmt-dnsname-192-0-2-1.example.com",
        vrf=MGMT_VRF,
    ),
    Ip(
        "192.0.2.2/29",
        "vrf-mgmt-description-192-0-2-2.example.com",
        "vrf-mgmt-dnsname-192-0-2-2.example.com",
        vrf=MGMT_VRF,
    ),
    Ip(
        "192.0.2.3/29",
        "vrf-mgmt-description-192-0-2-3.example.com",
        "vrf-mgmt-dnsname-192-0-2-3.example.com",
        vrf=MGMT_VRF,
    ),
    # 192.0.3.0/24: one address in the Global VRF and one in VRF mgmt.
    Ip(
        "192.0.3.1/24",
        "description-192-0-3-1.example.com",
        "dnsname-192-0-3-1.example.com",
    ),
    Ip(
        "192.0.3.2/24",
        "vrf-mgmt-description-192-0-3-2.example.com",
        "vrf-mgmt-dnsname-192-0-3-2.example.com",
        vrf=MGMT_VRF,
    ),
    # IPv6 reverse zones 2001:db8::/64 (nibble) and 2001:db8::/100.
    Ip(
        "2001:db8::2/64",
        "description-2001-0db8-2.example.com",
        "dnsname-2001-0db8-2.example.com",
    ),
    Ip(
        "2001:db8::3/100",
        "description-2001-0db8-3.example.com",
        "dnsname-2001-0db8-3.example.com",
    ),
    Ip(
        "2001:db8::1000:1/64",
        "description-2001-0db8-1000-1.example.com",
        "dnsname-2001-0db8-1000-1.example.com",
    ),
    # Tags: populate_tags [dns] and [dns, external].
    Ip("192.0.5.1/24", "tagged-dns.example.org", tags=("dns",)),
    Ip("192.0.5.2/24", "tagged-dns-external.example.org", tags=("dns", "external")),
    Ip("192.0.5.3/24", "untagged.example.org"),
    # Forward zone example.net.: names whose first label ends in "example-net",
    # which matches the zone name when "." matches any character.
    Ip("192.0.6.1/24", "web-example-net.example.net"),
    Ip("192.0.6.2/24", "example-net.example.net"),
    # Zones example.test. and 100.51.198.in-addr.arpa.: upper-case names.
    # NetBox stores dns_name in lower case, and description as written.
    Ip("198.51.100.1/24", "Host1.Example.TEST"),
    Ip("198.51.100.2/24", "Host2.example.test"),
    # Classless zone 0/26.0.192.in-addr.arpa., three labels before in-addr.arpa,
    # covers 192.0.0.0/26. 192.0.0.65 is outside it.
    Ip("192.0.0.5/26", "host-192-0-0-5.example"),
    Ip("192.0.0.6/26", "host-192-0-0-6.example,alias-192-0-0-6.example"),
    Ip("192.0.0.65/24", "host-192-0-0-65.example"),
    # Zones café.example. and 113.0.203.in-addr.arpa.: internationalized names.
    # octoDNS spells café.example. as xn--caf-dma.example., and the query
    # matches only names that spell the zone that way, in any case. The first
    # two are one name, xn--hst-sna.xn--caf-dma.example. The last has no IDNA
    # form, because IDNA allows U+200D only in a few scripts.
    Ip("203.0.113.1/24", "höst.XN--CAF-DMA.EXAMPLE"),
    Ip("203.0.113.2/24", "xn--hst-sna.xn--caf-dma.example"),
    Ip("203.0.113.3/24", "ok.xn--caf-dma.example"),
    Ip("203.0.113.4/24", "a\u200db.xn--caf-dma.example"),
    # Zone 7.0.192.in-addr.arpa.: one address in two rows of one VRF, one
    # address with the same name in two VRFs, and one with two names in two.
    Ip("192.0.7.1/24", "anycast-1-a.example", vrf=ANYCAST_VRF),
    Ip("192.0.7.1/24", "anycast-1-b.example", vrf=ANYCAST_VRF),
    Ip("192.0.7.2/24", "shared-2.example"),
    Ip("192.0.7.2/24", "shared-2.example", vrf=ANYCAST_VRF),
    Ip("192.0.7.3/24", "global-3.example"),
    Ip("192.0.7.3/24", "anycast-3.example", vrf=ANYCAST_VRF),
    # Zones ex_ample.com. and 8.0.192.in-addr.arpa.: a label that is not ASCII
    # in a zone with an underscore. IDNA does not allow "_", so a conversion of
    # the whole name fails, and a conversion of each label does not.
    Ip("192.0.8.1/24", "höst.ex_ample.com"),
    # Zones a-label.example. and 9.0.192.in-addr.arpa.: a label that starts
    # with "xn--" but is not an A-label. octoDNS cannot decode it in a record
    # name, and keeps it in a PTR value.
    Ip("192.0.9.1/24", "ok.a-label.example"),
    Ip("192.0.9.2/24", "xn--bad_label.a-label.example"),
    # Zone 10.0.192.in-addr.arpa.: anycast addresses that give a PTR record
    # more than one name from one VRF. 192.0.10.1 has the same two names in
    # the Global VRF and in VRF anycast. 192.0.10.2 has two names in the
    # Global VRF and a third in VRF anycast. VRF mgmt stays out, because the
    # vrf-name fixture holds its count of IP addresses.
    Ip("192.0.10.1/24", "anycast-10-1-a.example", role="anycast"),
    Ip("192.0.10.1/24", "anycast-10-1-b.example", role="anycast"),
    Ip("192.0.10.1/24", "anycast-10-1-a.example", vrf=ANYCAST_VRF, role="anycast"),
    Ip("192.0.10.1/24", "anycast-10-1-b.example", vrf=ANYCAST_VRF, role="anycast"),
    Ip("192.0.10.2/24", "anycast-10-2-a.example", role="anycast"),
    Ip("192.0.10.2/24", "anycast-10-2-b.example", role="anycast"),
    Ip("192.0.10.2/24", "vrf-anycast-10-2.example", vrf=ANYCAST_VRF),
    # Zones idn-case.example. and 11.0.192.in-addr.arpa.: names whose letters
    # change when they become lower case. Python's str.lower() turns a capital
    # sigma after a letter into the final sigma ς unless a letter comes next,
    # and it looks past a dot: ΑΣ alone becomes ας, and ΑΣ.α becomes ασ.α.
    Ip("192.0.11.1/24", "ΑΣ.α.idn-case.example"),
    Ip("192.0.11.2/24", "ΑΣ.idn-case.example"),
    Ip("192.0.11.3/24", "α.Σ.1.idn-case.example"),
    Ip("192.0.11.4/24", "ΑΣ.1.idn-case.example"),
    Ip("192.0.11.5/24", "ας.idn-case.example"),
    Ip("192.0.11.6/24", "ΑΣ.café.idn-case.example"),
    Ip("192.0.11.7/24", "東京.ΑΣ.idn-case.example"),
    Ip("192.0.11.8/24", "ΤΕΣΤ-テスト.idn-case.example"),
    Ip("192.0.11.9/24", "Straße.idn-case.example"),
    Ip("192.0.11.10/24", "STRAẞE.idn-case.example"),
    Ip("192.0.11.11/24", "İstanbul.idn-case.example"),
    Ip("192.0.11.12/24", "ıspanak.idn-case.example"),
    Ip("192.0.11.13/24", "DİYARBAKIR.idn-case.example"),
    # Zones vrf-tags.example. and 12.0.192.in-addr.arpa.: VRF lab with tags
    # dns and external. Only 192.0.12.1 is in VRF lab with both tags.
    Ip(
        "192.0.12.1/24",
        "lab-dns-external.vrf-tags.example",
        vrf=TAGGED_VRF,
        tags=("dns", "external"),
    ),
    Ip(
        "192.0.12.2/24",
        "global-dns-external.vrf-tags.example",
        tags=("dns", "external"),
    ),
    Ip("192.0.12.3/24", "lab-dns.vrf-tags.example", vrf=TAGGED_VRF, tags=("dns",)),
    Ip(
        "192.0.12.4/24",
        "lab-external.vrf-tags.example",
        vrf=TAGGED_VRF,
        tags=("external",),
    ),
    # Zones names.example. and 13.0.192.in-addr.arpa.: name lists with spaces
    # around commas, empty entries, and names with and without the final dot.
    Ip("192.0.13.1/24", "one.names.example. , ,two.names.example"),
    Ip("192.0.13.2/24", ",three.names.example , four.names.example.,"),
    # Zones blank-field.example. and 14.0.192.in-addr.arpa.: 192.0.14.1 has a
    # description in the zone and no DNS name.
    Ip("192.0.14.1/24", "described.blank-field.example"),
    Ip("192.0.14.2/24", dns_name="named.blank-field.example"),
    # Zones env.example., 15.0.192.in-addr.arpa., and 2001:db8:15::/64: one
    # name one label below the zone and one name in a subdomain of it.
    Ip("192.0.15.1/24", "host.env.example"),
    Ip("192.0.15.2/24", "deep.sub.env.example"),
    Ip("2001:db8:15::1/64", "host.env.example"),
    Ip("2001:db8:15::2/64", "deep.sub.env.example"),
    # Zone vrf-dup.example.: one IPv4 and one IPv6 address with one name in
    # the Global VRF and in VRF anycast, and a second IPv4 address with that
    # name. The A record gets each address once, and the AAAA record one.
    Ip("192.0.16.1/24", "host.vrf-dup.example"),
    Ip("192.0.16.1/24", "host.vrf-dup.example", vrf=ANYCAST_VRF),
    Ip("192.0.16.2/24", "host.vrf-dup.example", vrf=ANYCAST_VRF),
    Ip("2001:db8:16::1/64", "host.vrf-dup.example"),
    Ip("2001:db8:16::1/64", "host.vrf-dup.example", vrf=ANYCAST_VRF),
    # Zones free-text.example. and 17.0.192.in-addr.arpa.: free text in the
    # description next to names. octoDNS rejects "reserved for new printer."
    # as a PTR value and "see wiki" as a record name.
    Ip("192.0.17.1/24", "host.free-text.example"),
    Ip("192.0.17.2/24", "Reserved for new printer"),
    Ip("192.0.17.3/24", "host.free-text.example, see wiki.free-text.example"),
    # Zones dns-name-unusable.example. and 18.0.192.in-addr.arpa.: DNS names
    # that NetBox accepts and octoDNS rejects as PTR values. The wildcard is a
    # valid record name.
    Ip("192.0.18.1/24", dns_name="host.dns-name-unusable.example"),
    Ip("192.0.18.2/24", dns_name="gateway"),
    Ip("192.0.18.3/24", dns_name="*"),
    Ip("192.0.18.4/24", dns_name="*.dns-name-unusable.example"),
)


class NetBox:
    """The few NetBox REST calls the harness makes, independent of pynetbox."""

    def __init__(self, url: str, auth_header: str):
        self.url = url
        self.session = requests.Session()
        self.session.headers.update(
            {"Accept": "application/json", "Authorization": auth_header}
        )

    def get(self, path: str) -> Any:
        return _json(self.session.get(f"{self.url}/api/{path}", timeout=60))

    def post(self, path: str, payload: Any) -> Any:
        return _json(
            self.session.post(f"{self.url}/api/{path}", json=payload, timeout=300)
        )


def provision_token(url: str, username: str, password: str, version: int) -> str:
    """Create an API token from a username and password.

    Returns the value a client puts after "Token " (v1) or "Bearer " (v2).
    NetBox before 4.5 ignores "version" and always creates a v1 token.
    """
    body = _json(
        requests.post(
            f"{url}/api/users/tokens/provision/",
            json={"username": username, "password": password, "version": version},
            timeout=60,
        )
    )
    created = body.get("version", 1)
    if created != version:
        raise RuntimeError(f"asked for a v{version} token, NetBox created v{created}")
    if version == 1:
        # NetBox 4.5 and later return the plaintext in "token", older in "key".
        return body.get("token") or body["key"]
    return f"nbt_{body['key']}.{body['token']}"


def auth_header(token: str, version: int) -> str:
    return f"{'Bearer' if version == 2 else 'Token'} {token}"


def seed(netbox: NetBox) -> dict[str, int]:
    """Create the VRFs, tags and addresses. Returns VRF IDs by name."""
    vrf = netbox.post("ipam/vrfs/", {"name": MGMT_VRF})
    netbox.post("extras/tags/", [{"name": tag, "slug": tag} for tag in TAGS])
    anycast = netbox.post("ipam/vrfs/", {"name": ANYCAST_VRF, "enforce_unique": False})
    tagged = netbox.post("ipam/vrfs/", {"name": TAGGED_VRF})
    netbox.post("ipam/vrfs/", [{"name": SHARED_VRF_NAME}] * 2)
    vrf_ids = {
        MGMT_VRF: vrf["id"],
        ANYCAST_VRF: anycast["id"],
        TAGGED_VRF: tagged["id"],
    }
    netbox.post(
        "ipam/ip-addresses/",
        [
            {
                "address": ip.address,
                "description": ip.description,
                "dns_name": ip.dns_name,
                "vrf": vrf_ids[ip.vrf] if ip.vrf else None,
                "tags": [{"slug": tag} for tag in ip.tags],
                **({"role": ip.role} if ip.role else {}),
            }
            for ip in IPS
        ],
    )
    return vrf_ids


def seed_perf(netbox: NetBox, count: int) -> None:
    """Add `count` addresses in 198.18.0.0/16, each named in PERF_FORWARD_ZONE."""
    payload = [
        {"address": f"{host}/16", "description": f"perf-{i}.{PERF_FORWARD_ZONE[:-1]}"}
        for i, host in zip(range(count), _PERF_NETWORK.hosts(), strict=False)
    ]
    for chunk in _chunks(payload, _BULK_SIZE):
        netbox.post("ipam/ip-addresses/", chunk)


def _chunks(items: list[Any], size: int) -> Iterator[list[Any]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _json(response: requests.Response) -> Any:
    if not response.ok:
        raise RuntimeError(
            f"{response.request.method} {response.url} -> {response.status_code}: "
            f"{response.text[:2000]}"
        )
    return response.json()
