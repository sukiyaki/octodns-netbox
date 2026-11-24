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
    """Create the VRF, tags and addresses. Returns VRF IDs by name."""
    vrf = netbox.post("ipam/vrfs/", {"name": MGMT_VRF})
    netbox.post("extras/tags/", [{"name": tag, "slug": tag} for tag in TAGS])
    vrf_ids = {MGMT_VRF: vrf["id"]}
    netbox.post(
        "ipam/ip-addresses/",
        [
            {
                "address": ip.address,
                "description": ip.description,
                "dns_name": ip.dns_name,
                "vrf": vrf_ids[ip.vrf] if ip.vrf else None,
                "tags": [{"slug": tag} for tag in ip.tags],
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
