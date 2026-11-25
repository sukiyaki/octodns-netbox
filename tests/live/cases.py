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
# Zones with more labels than a "::" address can hold, which do not overlap.
V6_116 = f"{'0.' * 21}8.b.d.0.1.0.0.2.ip6.arpa."  # 2001:db8::/116
V6_124 = f"0.0.0.0.0.0.1.{'0.' * 16}8.b.d.0.1.0.0.2.ip6.arpa."  # 2001:db8::1000:0/124
V6_128 = f"1.0.0.0.1.{'0.' * 19}8.b.d.0.1.0.0.2.ip6.arpa."  # 2001:db8::1:1/128
V6_15 = "0.0.0.0.5.1.0.0.8.b.d.0.1.0.0.2.ip6.arpa."  # 2001:db8:15::/64
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
        Case("classless-short", ("0/26.0.192.in-addr.arpa.",)),
        Case("idn", ("café.example.", "113.0.203.in-addr.arpa.")),
        Case("idn-underscore", ("ex_ample.com.", "8.0.192.in-addr.arpa.")),
        Case("idn-case", ("idn-case.example.", "11.0.192.in-addr.arpa.")),
        Case("invalid-a-label", ("a-label.example.", "9.0.192.in-addr.arpa.")),
        Case("vrf-duplicate", ("7.0.192.in-addr.arpa.",)),
        Case("vrf-anycast", ("10.0.192.in-addr.arpa.",)),
        Case("vrf-duplicate-forward", ("vrf-dup.example.",)),
        Case("ipv6-long-prefix", (V6_116, V6_124, V6_128)),
        Case(
            "vrf-name-not-found",
            (),
            {"populate_vrf_name": "no-such-vrf"},
            init_error="Failed to retrieve VRF information by name",
        ),
        Case(
            "vrf-name-and-tags",
            ("vrf-tags.example.", "12.0.192.in-addr.arpa."),
            {
                "populate_vrf_name": seed.TAGGED_VRF,
                "populate_tags": ["dns", "external"],
            },
        ),
        Case(
            "vrf-name-shared",
            (),
            {"populate_vrf_name": seed.SHARED_VRF_NAME},
            init_error="Failed to retrieve VRF information by name",
        ),
        # The /32 zone of 192.0.5.2, between two other addresses with names.
        Case("ipv4-host", ("2.5.0.192.in-addr.arpa.",)),
        # 192.0.4.4/31 holds 192.0.4.4 and 192.0.4.5, and not 192.0.4.3 or .6.
        Case("classless-31", ("4/31.4.0.192.in-addr.arpa.",)),
        Case("name-list", ("names.example.", "13.0.192.in-addr.arpa.")),
        Case(
            "name-list-multivalue-ptr",
            ("13.0.192.in-addr.arpa.",),
            {"multivalue_ptr": True},
        ),
        Case(
            "dns-name-blank",
            ("blank-field.example.", "14.0.192.in-addr.arpa."),
            {"field_name": "dns_name"},
        ),
        # run.py sets NETBOX_TTL to "120" and NETBOX_POPULATE_SUBDOMAINS to
        # "false".
        Case(
            "env-values",
            ("env.example.", "15.0.192.in-addr.arpa.", V6_15),
            {
                "ttl": "env/NETBOX_TTL",
                "populate_subdomains": "env/NETBOX_POPULATE_SUBDOMAINS",
            },
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
