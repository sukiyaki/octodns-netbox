"""What run.py does to Docker and to --output-dir, with Docker replaced."""

import json
import subprocess
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

import run


class FakeCompose:
    """Stands in for subprocess.run and records each docker compose command."""

    def __init__(self, fail=(), containers=""):
        self.fail = fail
        self.containers = containers
        self.commands = []
        # Command name to a function that runs before the command.
        self.before = {}

    def __call__(self, command, **kwargs):
        # docker compose --project-name <name> --file <path> <command> ...
        name = command[command.index("--file") + 2]
        self.commands.append(name)
        if name in self.before:
            self.before[name]()
        if name in self.fail:
            raise subprocess.CalledProcessError(1, command)
        stdout = self.containers if name == "ps" else ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout)


@pytest.fixture
def compose(monkeypatch):
    fake = FakeCompose(fail=("up",))
    monkeypatch.setattr(run.subprocess, "run", fake)
    return fake


def main(output_dir):
    return run.main(["--netbox", "4.7", "--output-dir", str(output_dir)])


def test_each_run_gets_its_own_project_name():
    names = {run.parse_args(["--netbox", "4.7"]).project_name for _ in range(2)}
    assert len(names) == 2
    assert all(name.startswith("octodns-netbox-live-") for name in names)


def result_of(output_dir):
    return json.loads((output_dir / "run.json").read_text())


def test_each_run_gets_its_own_default_output_dir(tmp_path, monkeypatch, compose):
    monkeypatch.setattr(run, "HERE", tmp_path)
    for _ in range(2):
        assert run.main(["--netbox", "4.7"]) == 1
    outputs = sorted((tmp_path / "output").iterdir())
    assert len(outputs) == 2
    assert all(path.name.startswith("netbox-4.7-token-v1-") for path in outputs)
    assert [result_of(path)["result"] for path in outputs] == ["error", "error"]


def test_refuses_the_output_dir_of_a_run_that_has_not_ended(tmp_path, compose):
    # What a run that is still going, or that was killed, leaves behind.
    (tmp_path / "run.lock").write_text("12345\n")
    (tmp_path / "run.json").write_text('{"result": "running"}')
    fixture = tmp_path / "fixtures" / "case.json"
    fixture.parent.mkdir()
    fixture.write_text("{}")
    with pytest.raises(SystemExit, match=r"run\.lock exists"):
        main(tmp_path)
    assert fixture.read_text() == "{}"
    assert result_of(tmp_path) == {"result": "running"}
    assert (tmp_path / "run.lock").read_text() == "12345\n"
    assert compose.commands == []


def test_two_runs_that_start_together_cannot_share_an_output_dir(tmp_path, compose):
    # Two runs start on one output dir at the same moment. Both reach
    # Path.mkdir(out) before either has claimed the directory, and the second
    # goes on only once the first has written into it. The second run must
    # stop at run.lock and leave the files of the first in place.
    (tmp_path / "run.json").write_text('{"result": "matches"}')
    both_ready = threading.Barrier(2, timeout=5)
    first_wrote, second_ended = threading.Event(), threading.Event()
    gated = set()
    mkdir = Path.mkdir

    def gated_mkdir(path, *args, **kwargs):
        name = threading.current_thread().name
        if path == tmp_path and name not in gated:
            gated.add(name)
            both_ready.wait()
            if name == "second":
                assert first_wrote.wait(timeout=5)
        return mkdir(path, *args, **kwargs)

    def first_writes_and_waits():
        if threading.current_thread().name == "first":
            (tmp_path / "zones").mkdir()
            (tmp_path / "zones" / "first.yaml").write_text("")
            first_wrote.set()
            assert second_ended.wait(timeout=5)

    compose.before["up"] = first_writes_and_waits
    raised = {}

    def start():
        name = threading.current_thread().name
        try:
            main(tmp_path)
        except SystemExit as error:
            raised[name] = error
        finally:
            if name == "second":
                second_ended.set()

    with patch.object(Path, "mkdir", gated_mkdir):
        threads = [threading.Thread(target=start, name=n) for n in ("first", "second")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
    assert compose.commands.count("up") == 1
    assert sorted(raised) == ["second"]
    assert "run.lock exists" in str(raised["second"])
    assert (tmp_path / "zones" / "first.yaml").exists()
    assert result_of(tmp_path)["result"] == "error"
    assert not (tmp_path / "run.lock").exists()


def test_a_run_that_ended_leaves_the_output_dir_to_the_next_run(tmp_path, compose):
    for _ in range(2):
        assert main(tmp_path) == 1
        assert not (tmp_path / "run.lock").exists()
    assert compose.commands == ["ps", "up", "logs", "down"] * 2


def test_removes_the_stack_when_saving_its_log_fails(tmp_path, compose):
    # A directory in place of netbox.log makes opening the file fail.
    compose.before["up"] = (tmp_path / "netbox.log").mkdir
    assert main(tmp_path) == 1
    assert compose.commands == ["ps", "up", "down"]
    result = result_of(tmp_path)
    assert result["result"] == "error"
    assert "IsADirectoryError" in result["logs_error"]


def interrupt():
    raise KeyboardInterrupt


def test_records_the_result_when_the_run_is_interrupted(tmp_path, compose):
    compose.fail = ()
    compose.before["port"] = interrupt
    with pytest.raises(KeyboardInterrupt):
        main(tmp_path)
    assert compose.commands == ["ps", "up", "port", "logs", "down"]
    result = result_of(tmp_path)
    assert result["result"] == "interrupted"
    assert "KeyboardInterrupt" in result["error"]


def test_removes_the_stack_when_saving_its_log_is_interrupted(
    tmp_path, compose, monkeypatch
):
    # The zones matched, then Ctrl-C came while the run saved the NetBox log.
    def matching_run(args, out, stack, run, durations):
        stack.up()
        return 0, "matches"

    monkeypatch.setattr(run, "check_netbox", matching_run)
    compose.fail = ()
    compose.before["logs"] = interrupt
    with pytest.raises(KeyboardInterrupt):
        main(tmp_path)
    assert compose.commands == ["ps", "up", "port", "logs", "down"]
    result = result_of(tmp_path)
    assert result["result"] == "interrupted"
    assert "KeyboardInterrupt" in result["error"]
    assert not (tmp_path / "run.lock").exists()


def test_an_interrupted_final_write_leaves_run_json_whole(tmp_path, compose):
    # Ctrl-C came while the run wrote its final run.json.
    write_text = Path.write_text

    def interrupted_final_write(path, text, *args, **kwargs):
        if '"result": "error"' in text:
            write_text(path, text[: len(text) // 2], *args, **kwargs)
            raise KeyboardInterrupt
        return write_text(path, text, *args, **kwargs)

    with (
        patch.object(Path, "write_text", interrupted_final_write),
        pytest.raises(KeyboardInterrupt),
    ):
        main(tmp_path)
    assert result_of(tmp_path)["result"] == "running"
    assert main(tmp_path) == 1
    assert result_of(tmp_path)["result"] == "error"
    assert not (tmp_path / "run.json.partial").exists()


def test_refuses_an_output_dir_with_files_of_its_own(tmp_path, compose):
    fixture = tmp_path / "fixtures" / "case.json"
    fixture.parent.mkdir()
    fixture.write_text("{}")
    with pytest.raises(SystemExit, match=r"holds no run\.json"):
        main(tmp_path)
    assert fixture.read_text() == "{}"
    assert compose.commands == []


def test_empties_the_output_of_a_previous_run(tmp_path, compose):
    (tmp_path / "run.json").write_text("{}")
    (tmp_path / "zones").mkdir()
    (tmp_path / "zones" / "example.com.yaml").write_text("")
    (tmp_path / "notes.txt").write_text("mine")
    assert main(tmp_path) == 1
    assert not (tmp_path / "zones").exists()
    assert (tmp_path / "notes.txt").read_text() == "mine"
    # The run starts its own stack and removes only that one.
    assert compose.commands == ["ps", "up", "logs", "down"]


def test_refuses_a_project_that_already_has_containers(tmp_path, compose):
    compose.containers = "0123456789ab\n"
    assert main(tmp_path) == 1
    assert compose.commands == ["ps"]
    assert (
        "already has containers"
        in json.loads((tmp_path / "run.json").read_text())["error"]
    )


def test_keeps_the_first_error_when_removing_the_stack_fails(tmp_path, compose):
    compose.fail = ("up", "down")
    assert main(tmp_path) == 1
    result = json.loads((tmp_path / "run.json").read_text())
    assert result["result"] == "error"
    assert "'up'" in result["error"]
    assert "'down'" in result["cleanup_error"]
