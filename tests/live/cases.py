"""The octoDNS source settings and zones the live tests dump.

Each case becomes one octoDNS config with a single NetboxSource. octoDNS treats
a configured zone inside another configured zone as a sub-zone, so only the
"subzones" case puts nested zones in the same config. run.py records each case
as tests/fixtures/<case>.json for the unit tests.
"""

from dataclasses import dataclass, field, replace
from typing import Any

import seed

V6_64 = "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."  # 2001:db8::/64
V6_100 = "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."  # /100
VRF_ZONES = ("example.com.", "2.0.192.in-addr.arpa.", "3.0.192.in-addr.arpa.")
TAG_ZONES = ("example.org.", "5.0.192.in-addr.arpa.")


@dataclass(frozen=True)
class Case:
    name: str
    zones: tuple[str, ...]
    settings: dict[str, Any] = field(default_factory=dict)
    # Text of the ValueError the source must raise while the config loads.
    init_error: str | None = None


DESCRIPTION = Case(
    "description",
    (
        "example.com.",
        "example.org.",
        "2.0.192.in-addr.arpa.",
        "3.0.192.in-addr.arpa.",
        V6_64,
    ),
)

# DESCRIPTION with a misspelled key. octoDNS must start, the source must warn
# that the key has no effect, and the dump must equal DESCRIPTION's.
MISSPELLED_KEY = "populate_tag"
MISSPELLED = replace(
    DESCRIPTION, name="misspelled-key", settings={MISSPELLED_KEY: ["prod"]}
)


def cases(vrf_ids: dict[str, int]) -> list[Case]:
    mgmt = vrf_ids[seed.MGMT_VRF]
    return [
        DESCRIPTION,
        Case(
            "dns-name",
            ("example.com.", "2.0.192.in-addr.arpa.", V6_64),
            {"field_name": "dns_name"},
        ),
        Case(
            "multivalue-ptr",
            ("2.0.192.in-addr.arpa.", V6_64),
            {"multivalue_ptr": True},
        ),
        Case(
            "classless",
            ("0/26.2.0.192.in-addr.arpa.", "0-26.2.0.192.in-addr.arpa.", V6_100),
        ),
        Case("no-subdomains", ("example.com.",), {"populate_subdomains": False}),
        Case(
            "no-subdomains-subzone",
            ("subdomain1.example.com.",),
            {"populate_subdomains": False},
        ),
        Case("subzones", ("example.com.", "subdomain1.example.com.")),
        Case("vrf-id", VRF_ZONES, {"populate_vrf_id": mgmt}),
        Case("vrf-name", VRF_ZONES, {"populate_vrf_name": seed.MGMT_VRF}),
        Case("vrf-global-id", VRF_ZONES, {"populate_vrf_id": 0}),
        Case("vrf-global-name", VRF_ZONES, {"populate_vrf_name": "Global"}),
        Case("tags", TAG_ZONES, {"populate_tags": ["dns"]}),
        Case("tags-two", TAG_ZONES, {"populate_tags": ["dns", "external"]}),
        Case("issue-78", ("test.example.com.",)),
        Case("custom-ttl", TAG_ZONES, {"ttl": 120}),
        # run.py sets NETBOX_API_URL to NETBOX_URL followed by "/api/".
        Case("url-api-suffix", ("example.org.",), {"url": "env/NETBOX_API_URL"}),
        Case("zone-like-label", ("example.net.",)),
        Case("upper-case", ("example.test.", "100.51.198.in-addr.arpa.")),
        Case("idn", ("café.example.", "113.0.203.in-addr.arpa.")),
        Case("idn-underscore", ("ex_ample.com.", "8.0.192.in-addr.arpa.")),
        Case("idn-case", ("idn-case.example.", "11.0.192.in-addr.arpa.")),
        Case("vrf-duplicate", ("7.0.192.in-addr.arpa.",)),
        Case("vrf-anycast", ("10.0.192.in-addr.arpa.",)),
        Case(
            "vrf-name-not-found",
            (),
            {"populate_vrf_name": "no-such-vrf"},
            init_error="Failed to retrieve VRF information by name",
        ),
    ]


PERF = Case(
    "perf",
    (
        seed.PERF_FORWARD_ZONE,
        seed.PERF_REVERSE_ZONE,
        "example.com.",
        "2.0.192.in-addr.arpa.",
        V6_64,
    ),
)
