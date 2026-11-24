"""Run octoDNS against a real NetBox and compare the zones it dumps.

    uv run tests/live/run.py --netbox 4.7 --token-version 2

Starts NetBox with Docker Compose, seeds it through the REST API, dumps every
zone in cases.py through octoDNS's Manager.dump (the call octodns-dump makes),
and compares the zones with tests/live/expected/. It records the NetBox
responses of those dumps as unit-test fixtures (see record.py). On NetBox 4.7
it also compares that recording with tests/fixtures/, so a NetBox change that
reaches the responses cannot leave stale fixtures behind. To rewrite them:

    uv run tests/live/run.py --netbox 4.7 --record-fixtures

It dumps the "description" case again with a misspelled key added, and fails
unless the source warns about the key and the zones and requests stay the
same. Then it adds --perf-ip-count addresses and times --perf-runs full dumps.

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
    misspelled-key/          the zones dumped with the misspelled key
    fixtures/<case>.json     the recorded responses
    configs/<case>.yaml      the octoDNS configs (NETBOX_URL, NETBOX_API_URL
                             and NETBOX_TOKEN come from the environment)
    perf.json                HTTP requests per zone populate, dump timings
    run.json                 versions, durations, result, errors, fixtures
    diff.txt                 differences from the expected zones
    fixtures.diff            differences from tests/fixtures/
    misspelled-key.log       the warnings logged for the misspelled key
    octodns.log, netbox.log  logs

Exit status: 0 when the zones and fixtures match, 1 when either differs or a
step fails, 2 when the expected directory holds no zones yet. In that case the
actual zones are still written, for review before they are copied there.
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
from collections.abc import Iterator
from importlib import metadata
from pathlib import Path
from typing import Any

import yaml
from octodns.manager import Manager

import cases
import record
import seed

HERE = Path(__file__).resolve().parent
FIXTURES_DIR = HERE.parent / "fixtures"
IMAGE_TAGS = {"4.0": "v4.0.11-2.9.1", "4.7": "v4.7.5-5.1.2"}
# The unit tests replay this release only. Older releases are checked by the
# zones they dump.
FIXTURES_NETBOX = "4.7"
PACKAGES = ("octodns-netbox", "octodns", "pynetbox", "pydantic", "requests")
# The file that claims --output-dir for one run. See claimed().
LOCK = "run.lock"
# The superuser compose.yaml creates.
USERNAME, PASSWORD = "admin", "admin-password"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
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
    parser.add_argument(
        "--record-fixtures",
        action="store_true",
        help=f"replace {FIXTURES_DIR} with this run's recording",
    )
    args = parser.parse_args(argv)
    if args.netbox == "4.0" and args.token_version == 2:
        parser.error("NetBox 4.0 has no v2 API tokens")
    if args.record_fixtures and args.netbox != FIXTURES_NETBOX:
        parser.error(f"the fixtures are recorded from NetBox {FIXTURES_NETBOX}")
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


def source_config(case: cases.Case) -> dict[str, Any]:
    return {
        "class": "octodns_netbox.NetboxSource",
        "url": "env/NETBOX_URL",
        "token": "env/NETBOX_TOKEN",
        **case.settings,
    }


def recorded_settings(case: cases.Case) -> dict[str, Any]:
    """The source settings as the unit tests pass them: no class, no token."""
    return {
        key: os.environ[value[4:]]
        if isinstance(value, str) and value.startswith("env/")
        else value
        for key, value in source_config(case).items()
        if key not in ("class", "token")
    }


def write_config(case: cases.Case, path: Path) -> None:
    config = {
        "providers": {"netbox": source_config(case)},
        "zones": {zone: {"sources": ["netbox"], "targets": []} for zone in case.zones},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(config, sort_keys=False))


def dump(case: cases.Case, zones_dir: Path, config_path: Path) -> record.Recording:
    """Dump every zone of `case`, recording the HTTP exchanges at init and per zone."""
    write_config(case, config_path)
    sent: dict[str, list[record.Exchange]] = {"init": []}
    with record.recording(sent["init"]):
        try:
            manager = Manager(str(config_path))
        except ValueError as error:
            if case.init_error and case.init_error in str(error):
                return record.Recording(sent, {})
            raise
    if case.init_error:
        raise RuntimeError(
            f"{case.name}: the config loaded without {case.init_error!r}"
        )
    for zone in case.zones:
        # YamlProvider writes zone 0/26.2.0.192.in-addr.arpa. to
        # 0/26.2.0.192.in-addr.arpa.yaml but does not create the "0" directory.
        (zones_dir / f"{zone}yaml").parent.mkdir(parents=True, exist_ok=True)
        sent[zone] = []
        with record.recording(sent[zone]):
            manager.dump(zone=zone, output_dir=str(zones_dir), sources=["netbox"])
    sub_zones = {
        zone: sorted(manager.configured_sub_zones(zone)) for zone in case.zones
    }
    return record.Recording(sent, sub_zones)


class WarningMessages(logging.Handler):
    """Keeps the message of every record logged at WARNING or above."""

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def check_misspelled_key(out: Path, base: record.Recording) -> str:
    """Dump cases.MISSPELLED and compare it with the dump of cases.DESCRIPTION.

    `base` is the recording of the DESCRIPTION dump. Raises unless the source
    warned about cases.MISSPELLED_KEY and the zones and requests are the same.
    """
    zones = out / cases.MISSPELLED.name
    warnings = WarningMessages()
    logging.getLogger().addHandler(warnings)
    try:
        misspelled = dump(
            cases.MISSPELLED, zones, out / "configs" / f"{cases.MISSPELLED.name}.yaml"
        )
    finally:
        logging.getLogger().removeHandler(warnings)
    warned = [m for m in warnings.messages if cases.MISSPELLED_KEY in m]
    (out / f"{cases.MISSPELLED.name}.log").write_text("".join(f"{m}\n" for m in warned))
    same_zones = tree_files(zones, "*.yaml") == tree_files(
        out / "zones" / cases.DESCRIPTION.name, "*.yaml"
    )
    same_requests = _request_counts(misspelled.sent) == _request_counts(base.sent)
    if not (warned and same_zones and same_requests):
        raise RuntimeError(
            f"{cases.MISSPELLED.name}: warned={warned}, same zones={same_zones}, "
            f"same requests={same_requests}"
        )
    print(f"{cases.MISSPELLED_KEY} was ignored with a warning: {warned[0]}")
    return "warned"


def tree_files(root: Path, pattern: str) -> dict[str, list[str]]:
    if not root.is_dir():
        return {}
    return {
        path.relative_to(root).as_posix(): path.read_text().splitlines(keepends=True)
        for path in sorted(root.rglob(pattern))
    }


def compare(expected_dir: Path, actual_dir: Path, pattern: str) -> list[str] | None:
    """Unified diff of the two trees, or None when expected_dir has no such files."""
    expected = tree_files(expected_dir, pattern)
    if not expected:
        return None
    actual = tree_files(actual_dir, pattern)
    diff: list[str] = []
    for name in sorted(expected.keys() | actual.keys()):
        diff += difflib.unified_diff(
            expected.get(name, []),
            actual.get(name, []),
            f"expected/{name}",
            f"actual/{name}",
        )
    return diff


def measure_full_dumps(netbox: seed.NetBox, ip_count: int, runs: int) -> dict[str, Any]:
    seed.seed_perf(netbox, ip_count)
    seconds = []
    for attempt in range(runs):
        with tempfile.TemporaryDirectory() as tmp:
            zones_dir = Path(tmp, "zones")
            start = time.perf_counter()
            sent = dump(cases.PERF, zones_dir, Path(tmp, "perf.yaml")).sent
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


def _request_counts(sent: dict[str, list[record.Exchange]]) -> dict[str, Any]:
    counts = {}
    for step, exchanges in sent.items():
        lines = [f"{request.method} {request.path_url}" for request, _ in exchanges]
        counts[step] = {"count": len(lines), "requests": lines}
    return counts


def check_fixtures(
    args: argparse.Namespace, out: Path, fixtures: dict[str, dict[str, Any]]
) -> str:
    """Record or compare the fixtures. Returns the "fixtures" entry of run.json."""
    record.write(fixtures, out / "fixtures")
    if args.record_fixtures:
        record.write(fixtures, FIXTURES_DIR)
        print(f"Rewrote {FIXTURES_DIR}.")
        return "recorded"
    if args.netbox != FIXTURES_NETBOX:
        return "not-checked"
    diff = compare(FIXTURES_DIR, out / "fixtures", "*.json")
    if diff == []:
        print(f"The recording matches {FIXTURES_DIR}.")
        return "matches"
    diff = diff or [f"{FIXTURES_DIR} holds no fixtures.\n"]
    (out / "fixtures.diff").write_text("".join(diff))
    sys.stdout.writelines(diff)
    print(
        f"The recording differs from {FIXTURES_DIR}. If NetBox changed, rewrite "
        "them with --record-fixtures and review the diff."
    )
    return "differs"


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
def _timed(durations: dict[str, float], step: str) -> Iterator[None]:
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
    output of a run: --output-dir tests would remove tests/fixtures.
    """
    others = [path for path in out.iterdir() if path.name != LOCK]
    if others and not (out / "run.json").is_file():
        sys.exit(f"{out} holds no run.json. Pass a new or empty --output-dir.")
    for child in ("zones", "fixtures", "configs", cases.MISSPELLED.name):
        shutil.rmtree(out / child, ignore_errors=True)
    for name in (
        "perf.json",
        "perf.json.partial",
        "run.json",
        "run.json.partial",
        "diff.txt",
        "fixtures.diff",
        f"{cases.MISSPELLED.name}.log",
        "netbox.log",
        "octodns.log",
    ):
        (out / name).unlink(missing_ok=True)


def check_netbox(
    args: argparse.Namespace,
    out: Path,
    stack: Stack,
    run: dict[str, Any],
    durations: dict[str, float],
) -> tuple[int, str]:
    """Start NetBox, dump and compare every case. Returns the status and result."""
    with _timed(durations, "startup"):
        url = stack.up()
    token = seed.provision_token(url, USERNAME, PASSWORD, args.token_version)
    netbox = seed.NetBox(url, seed.auth_header(token, args.token_version))
    run["netbox_version"] = netbox.get("status/")["netbox-version"]
    with _timed(durations, "seed"):
        vrf_ids = seed.seed(netbox)

    os.environ["NETBOX_URL"] = url
    os.environ["NETBOX_API_URL"] = f"{url}/api/"
    os.environ["NETBOX_TOKEN"] = token
    live_cases = cases.cases(vrf_ids)
    with _timed(durations, "dump"):
        recordings = {
            case.name: dump(
                case,
                out / "zones" / case.name,
                out / "configs" / f"{case.name}.yaml",
            )
            for case in live_cases
        }
    sent = {name: _request_counts(r.sent) for name, r in recordings.items()}
    fixtures = {
        case.name: record.fixture(recordings[case.name], recorded_settings(case), url)
        for case in live_cases
    }
    diff = compare(args.expected_dir, out / "zones", "*.yaml")
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
    run["fixtures"] = check_fixtures(args, out, fixtures)
    run["misspelled_key"] = check_misspelled_key(
        out, recordings[cases.DESCRIPTION.name]
    )
    if run["fixtures"] == "differs":
        status = 1
        result = "fixtures-differ" if result == "matches" else result

    perf: dict[str, Any] = {"requests_per_zone_populate": sent}
    if args.perf_runs:
        with _timed(durations, "perf"):
            perf["full_dump"] = measure_full_dumps(
                netbox, args.perf_ip_count, args.perf_runs
            )
    _write_json(out / "perf.json", perf)
    return status, result


def remove_stack(stack: Stack, out: Path, run: dict[str, Any]) -> bool:
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


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    out: Path = args.output_dir or new_output_dir(args)
    with claimed(out):
        prepare_output_dir(out)
        print(f"Writing to {out}", flush=True)
        _configure_logging(out / "octodns.log")

        durations: dict[str, float] = {}
        run: dict[str, Any] = {
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
