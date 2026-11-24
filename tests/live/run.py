"""Run octoDNS against a real NetBox and compare the zones it dumps.

    uv run tests/live/run.py --netbox 4.7 --token-version 2

Starts NetBox with Docker Compose, seeds it through the REST API, dumps every
zone in cases.py through octoDNS's Manager.dump (the call octodns-dump makes),
and compares the zones with tests/live/expected/. Then it adds
--perf-ip-count addresses and times --perf-runs full dumps.

Each run starts its own Compose project, octodns-netbox-live-<random> unless
--project-name names one, and removes it at the end, also after Ctrl-C. It
stops before starting NetBox if that project already has containers. Two runs
that start at the same moment with one --project-name both pass that check,
so give each run its own name.

Everything lands in --output-dir, by default a new directory under output/.
The run first creates run.lock there, which claims the directory until the
run ends, and it stops if run.lock exists. It refuses a directory that holds
files but no run.json. In the output of an earlier run, it replaces only
these files:

    zones/<case>/<zone>yaml  the dumped zones
    configs/<case>.yaml      the octoDNS configs (NETBOX_URL and NETBOX_TOKEN
                             come from the environment)
    perf.json                HTTP requests per zone populate, dump timings
    run.json                 versions, durations, result, errors
    diff.txt                 differences from the expected zones
    octodns.log, netbox.log  logs

Exit status: 0 when the zones match, 1 when they differ or a step fails,
2 when the expected directory holds no zones yet. In that case the actual
zones are still written, for review before they are copied there.
"""

import argparse
import contextlib
import difflib
import json
import logging
import os
import platform
import secrets
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import traceback
from importlib import metadata
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple
from unittest import mock

import requests
import yaml
from octodns.manager import Manager

import cases
import seed

HERE = Path(__file__).resolve().parent
IMAGE_TAGS = {"4.0": "v4.0.11-2.9.1", "4.7": "v4.7.5-5.1.2"}
PACKAGES = ("octodns-netbox", "octodns", "pynetbox", "pydantic", "requests")
# The file that claims --output-dir for one run. See claimed().
LOCK = "run.lock"
# The superuser compose.yaml creates.
USERNAME, PASSWORD = "admin", "admin-password"


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--netbox", choices=sorted(IMAGE_TAGS), required=True)
    parser.add_argument("--token-version", type=int, choices=(1, 2), default=1)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--expected-dir", type=Path, default=HERE / "expected")
    parser.add_argument("--perf-ip-count", type=int, default=2000)
    parser.add_argument("--perf-runs", type=int, default=5)
    parser.add_argument(
        "--project-name", default=f"octodns-netbox-live-{secrets.token_hex(4)}"
    )
    args = parser.parse_args(argv)
    if args.netbox == "4.0" and args.token_version == 2:
        parser.error("NetBox 4.0 has no v2 API tokens")
    return args


def new_output_dir(args: argparse.Namespace) -> Path:
    """Create a directory under output/ that no other run uses."""
    root = HERE / "output"
    root.mkdir(parents=True, exist_ok=True)
    prefix = f"netbox-{args.netbox}-token-v{args.token_version}-"
    return Path(tempfile.mkdtemp(prefix=prefix, dir=root))


class Stack:
    """The Docker Compose project in compose.yaml."""

    def __init__(self, project: str, image_tag: str):
        self.project = project
        self.command = ["docker", "compose", "--project-name", project]
        self.command += ["--file", str(HERE / "compose.yaml")]
        self.env = {**os.environ, "NETBOX_IMAGE_TAG": image_tag}
        # True once up() may have created something that down() must remove.
        self.started = False

    def _run(self, *args: str, **kwargs: Any) -> subprocess.CompletedProcess:
        return subprocess.run(
            [*self.command, *args], env=self.env, check=True, text=True, **kwargs
        )

    def up(self) -> str:
        """Start NetBox, wait until it is healthy, and return its URL.

        Raises instead if the project already has containers, which another
        run may be using.
        """
        containers = self._run("ps", "--all", "--quiet", stdout=subprocess.PIPE)
        if containers.stdout.strip():
            raise RuntimeError(
                f"Compose project {self.project} already has containers. "
                "Pass another --project-name."
            )
        self.started = True
        self._run("up", "--detach", "--wait", "--wait-timeout", "900")
        port = self._run("port", "netbox", "8080", stdout=subprocess.PIPE)
        return f"http://{port.stdout.strip()}"

    def save_logs(self, path: Path) -> None:
        with path.open("w") as fh:
            self._run("logs", "--no-color", "--timestamps", stdout=fh)

    def down(self) -> None:
        self._run("down", "--volumes", "--remove-orphans")


@contextlib.contextmanager
def recorded_requests(into: List[str]) -> Iterator[None]:
    """Append "METHOD /path?query" for every HTTP request sent inside the block."""
    send = requests.Session.send

    def recording_send(session: requests.Session, request: Any, **kwargs: Any) -> Any:
        into.append(f"{request.method} {request.path_url}")
        return send(session, request, **kwargs)

    with mock.patch.object(requests.Session, "send", recording_send):
        yield


def write_config(case: cases.Case, path: Path) -> None:
    source = {
        "class": "octodns_netbox.NetboxSource",
        "url": "env/NETBOX_URL",
        "token": "env/NETBOX_TOKEN",
        **case.settings,
    }
    config = {
        "providers": {"netbox": source},
        "zones": {zone: {"sources": ["netbox"], "targets": []} for zone in case.zones},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(config, sort_keys=False))


def dump(case: cases.Case, zones_dir: Path, config_path: Path) -> Dict[str, List[str]]:
    """Dump every zone of `case`. Returns the requests sent at init and per zone."""
    write_config(case, config_path)
    sent: Dict[str, List[str]] = {"init": []}
    with recorded_requests(sent["init"]):
        manager = Manager(str(config_path))
    for zone in case.zones:
        # YamlProvider writes zone 0/26.2.0.192.in-addr.arpa. to
        # 0/26.2.0.192.in-addr.arpa.yaml but does not create the "0" directory.
        (zones_dir / f"{zone}yaml").parent.mkdir(parents=True, exist_ok=True)
        sent[zone] = []
        with recorded_requests(sent[zone]):
            manager.dump(zone=zone, output_dir=str(zones_dir), sources=["netbox"])
    return sent


def zone_files(root: Path) -> Dict[str, List[str]]:
    if not root.is_dir():
        return {}
    return {
        path.relative_to(root).as_posix(): path.read_text().splitlines(keepends=True)
        for path in sorted(root.rglob("*.yaml"))
    }


def compare(expected_dir: Path, actual_dir: Path) -> Optional[List[str]]:
    """Unified diff of the two zone trees, or None when expected_dir has no zones."""
    expected = zone_files(expected_dir)
    if not expected:
        return None
    actual = zone_files(actual_dir)
    diff: List[str] = []
    for name in sorted(expected.keys() | actual.keys()):
        diff += difflib.unified_diff(
            expected.get(name, []),
            actual.get(name, []),
            f"expected/{name}",
            f"actual/{name}",
        )
    return diff


def measure_full_dumps(netbox: seed.NetBox, ip_count: int, runs: int) -> Dict[str, Any]:
    seed.seed_perf(netbox, ip_count)
    seconds = []
    for attempt in range(runs):
        with tempfile.TemporaryDirectory() as tmp:
            zones_dir = Path(tmp, "zones")
            start = time.perf_counter()
            sent = dump(cases.PERF, zones_dir, Path(tmp, "perf.yaml"))
            seconds.append(round(time.perf_counter() - start, 3))
            if attempt == 0:
                first_sent = sent
                records = {
                    zone: len(yaml.safe_load((zones_dir / f"{zone}yaml").read_text()))
                    for zone in (seed.PERF_FORWARD_ZONE, seed.PERF_REVERSE_ZONE)
                }
    if set(records.values()) != {ip_count}:
        raise RuntimeError(f"expected {ip_count} records per perf zone, got {records}")
    return {
        "extra_ip_addresses": ip_count,
        "zones": list(cases.PERF.zones),
        "records": records,
        "requests": _request_counts(first_sent),
        "seconds": seconds,
        "median_seconds": statistics.median(seconds),
    }


def _request_counts(sent: Dict[str, List[str]]) -> Dict[str, Any]:
    return {step: {"count": len(r), "requests": r} for step, r in sent.items()}


def _configure_logging(log_file: Path) -> None:
    console = logging.StreamHandler()
    console.setLevel(logging.WARNING)
    # The dump target warns on every zone that it has no root NS record.
    console.addFilter(lambda record: not record.name.startswith("YamlProvider"))
    to_file = logging.FileHandler(log_file)
    to_file.setLevel(logging.INFO)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[console, to_file],
    )


def _write_json(path: Path, data: Any) -> None:
    """Write `data` to `path` in one step.

    The text goes to <name>.partial first and then replaces `path`, so an
    interrupt while writing leaves the earlier file whole.
    """
    partial = path.with_name(f"{path.name}.partial")
    partial.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.replace(partial, path)


@contextlib.contextmanager
def _timed(durations: Dict[str, float], step: str) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        durations[step] = round(time.perf_counter() - start, 1)


@contextlib.contextmanager
def claimed(out: Path) -> Iterator[None]:
    """Hold `out` for this run until the block ends.

    Creating run.lock with O_CREAT | O_EXCL is one step that only one run can
    take, so of two runs with one --output-dir, the second exits before it
    looks at or removes anything. run.lock holds the process ID of its run.
    A run that is killed leaves run.lock behind, and every later run with
    this directory exits until someone deletes the file.
    """
    out.mkdir(parents=True, exist_ok=True)
    lock = out / LOCK
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        sys.exit(
            f"{lock} exists: another run uses {out}, or a run that was killed "
            "left the file. Pass another --output-dir, or delete the file if "
            "the process whose ID it holds has ended."
        )
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(f"{os.getpid()}\n")
        yield
    finally:
        lock.unlink()


def prepare_output_dir(out: Path) -> None:
    """Remove what an earlier run wrote in `out`, which this run has claimed.

    Exits if `out` holds files but no run.json, because they are not the
    output of a run.
    """
    others = [path for path in out.iterdir() if path.name != LOCK]
    if others and not (out / "run.json").is_file():
        sys.exit(f"{out} holds no run.json. Pass a new or empty --output-dir.")
    for child in ("zones", "configs"):
        shutil.rmtree(out / child, ignore_errors=True)
    for name in (
        "perf.json",
        "perf.json.partial",
        "run.json",
        "run.json.partial",
        "diff.txt",
        "netbox.log",
        "octodns.log",
    ):
        (out / name).unlink(missing_ok=True)


def check_netbox(
    args: argparse.Namespace,
    out: Path,
    stack: Stack,
    run: Dict[str, Any],
    durations: Dict[str, float],
) -> Tuple[int, str]:
    """Start NetBox, dump and compare every case. Returns the status and result."""
    with _timed(durations, "startup"):
        url = stack.up()
    token = seed.provision_token(url, USERNAME, PASSWORD, args.token_version)
    netbox = seed.NetBox(url, seed.auth_header(token, args.token_version))
    run["netbox_version"] = netbox.get("status/")["netbox-version"]
    with _timed(durations, "seed"):
        vrf_ids = seed.seed(netbox)

    os.environ["NETBOX_URL"] = url
    os.environ["NETBOX_TOKEN"] = token
    with _timed(durations, "dump"):
        sent = {
            case.name: _request_counts(
                dump(
                    case,
                    out / "zones" / case.name,
                    out / "configs" / f"{case.name}.yaml",
                )
            )
            for case in cases.cases(vrf_ids)
        }
    diff = compare(args.expected_dir, out / "zones")
    if diff is None:
        status, result = 2, "no-expected"
        print(
            f"No expected zones in {args.expected_dir}. Wrote the actual "
            f"zones to {out / 'zones'} for review."
        )
    elif diff:
        status, result = 1, "differs"
        (out / "diff.txt").write_text("".join(diff))
        sys.stdout.writelines(diff)
        print(f"The zones differ from {args.expected_dir}.")
    else:
        status, result = 0, "matches"
        print(f"The zones match {args.expected_dir}.")

    perf: Dict[str, Any] = {"requests_per_zone_populate": sent}
    if args.perf_runs:
        with _timed(durations, "perf"):
            perf["full_dump"] = measure_full_dumps(
                netbox, args.perf_ip_count, args.perf_runs
            )
    _write_json(out / "perf.json", perf)
    return status, result


def remove_stack(stack: Stack, out: Path, run: Dict[str, Any]) -> bool:
    """Save the NetBox log, then remove the stack. Returns False if removing fails.

    The removal runs also when saving the log fails or is interrupted.
    """
    try:
        stack.save_logs(out / "netbox.log")
    except Exception:
        run["logs_error"] = traceback.format_exc()
        logging.exception("Saving the NetBox log failed.")
    finally:
        try:
            stack.down()
            removed = True
        except Exception:
            # run["error"] keeps the error that stopped the run.
            run["cleanup_error"] = traceback.format_exc()
            logging.exception("Removing the stack failed.")
            removed = False
    return removed


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    out: Path = args.output_dir or new_output_dir(args)
    with claimed(out):
        prepare_output_dir(out)
        print(f"Writing to {out}", flush=True)
        _configure_logging(out / "octodns.log")

        durations: Dict[str, float] = {}
        run: Dict[str, Any] = {
            "netbox": args.netbox,
            "image_tag": IMAGE_TAGS[args.netbox],
            "token_version": args.token_version,
            "python": platform.python_version(),
            "packages": {name: metadata.version(name) for name in PACKAGES},
            "durations_seconds": durations,
        }
        print(json.dumps(run, indent=2), flush=True)
        # Marks the directory as run output until the final run.json replaces it.
        _write_json(out / "run.json", {**run, "result": "running"})

        stack = Stack(args.project_name, IMAGE_TAGS[args.netbox])
        status, result = 1, "error"
        try:
            with _timed(durations, "total"):
                try:
                    status, result = check_netbox(args, out, stack, run, durations)
                except Exception:
                    run["error"] = traceback.format_exc()
                    logging.exception("The live run failed.")
                finally:
                    if stack.started and not remove_stack(stack, out, run):
                        status, result = 1, "error"
        except BaseException:
            # Such as KeyboardInterrupt. If the stack started, remove_stack ran
            # down first, also when the interrupt came while it saved the log.
            result = "interrupted"
            run["error"] = traceback.format_exc()
            raise
        finally:
            run["result"] = result
            _write_json(out / "run.json", run)
        print(f"{result}: wrote {out}")
        return status


if __name__ == "__main__":
    sys.exit(main())
