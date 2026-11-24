"""Record what NetBox returns during a live dump, as unit-test fixtures.

tests/fixtures/<case>.json holds one case from cases.py:

    source  the NetboxSource settings, without the token
    init    the requests sent while the source loads, with their responses
    zones   for each zone, in dump order, the sub-zones octoDNS configured and
            the requests sent while populating it, with their responses

tests/test_octodns_netbox.py replays these files without importing anything
from this directory. normalize() is the only change made to what NetBox sent.
"""

import contextlib
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, NamedTuple, Tuple
from unittest import mock

import requests

FIXTURE_URL = "http://netbox.example.com"
FIXTURE_TIMESTAMP = "2000-01-01T00:00:00.000000Z"

Exchange = Tuple[requests.PreparedRequest, requests.Response]


class Recording(NamedTuple):
    """The HTTP exchanges of one case's dump."""

    sent: Dict[str, List[Exchange]]  # "init", then each dumped zone
    sub_zones: Dict[str, List[str]]  # what octoDNS passed to each Zone


@contextlib.contextmanager
def recording(into: List[Exchange]) -> Iterator[None]:
    """Append (request, response) for every HTTP request sent inside the block."""
    send = requests.Session.send

    def recording_send(session: requests.Session, request: Any, **kwargs: Any) -> Any:
        response = send(session, request, **kwargs)
        into.append((request, response))
        return response

    with mock.patch.object(requests.Session, "send", recording_send):
        yield


def fixture(
    recorded: Recording, source: Dict[str, Any], live_url: str
) -> Dict[str, Any]:
    zones = {
        zone: {
            "sub_zones": sub_zones,
            "exchanges": [_exchange(*e) for e in recorded.sent[zone]],
        }
        for zone, sub_zones in recorded.sub_zones.items()
    }
    init = [_exchange(*e) for e in recorded.sent["init"]]
    return normalize({"source": source, "init": init, "zones": zones}, live_url)


def normalize(value: Any, live_url: str) -> Any:
    """Replace the values that differ between two runs of the same NetBox image.

    - live_url, the NetBox container's address with its random port, becomes
      FIXTURE_URL wherever it appears inside a string.
    - The "created" and "last_updated" timestamps become FIXTURE_TIMESTAMP.

    Every other value, and the order of keys and list items, stays as NetBox
    sent it.
    """
    if isinstance(value, dict):
        return {
            key: (
                FIXTURE_TIMESTAMP
                if key in ("created", "last_updated") and isinstance(item, str)
                else normalize(item, live_url)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [normalize(item, live_url) for item in value]
    if isinstance(value, str):
        return value.replace(live_url, FIXTURE_URL)
    return value


def write(fixtures: Dict[str, Dict[str, Any]], directory: Path) -> None:
    """Replace the fixtures in `directory` with one file per case."""
    directory.mkdir(parents=True, exist_ok=True)
    for stale in directory.glob("*.json"):
        stale.unlink()
    for name, data in fixtures.items():
        (directory / f"{name}.json").write_text(json.dumps(data, indent=2) + "\n")


def _exchange(
    request: requests.PreparedRequest, response: requests.Response
) -> Dict[str, Any]:
    return {
        "request": {"method": request.method, "url": request.url},
        "response": {"status": response.status_code, "json": response.json()},
    }
