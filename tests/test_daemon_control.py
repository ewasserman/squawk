"""Tests for squawk.daemon_control and squawk.daemon_main: starting, querying
and stopping the background service as a separate process.

These tests do not use the `squawk` command itself; the command-line tests
(`squawk daemon start | status | stop | bogus` and their output) are in
test_cli.py.
"""

import os
import shutil
import tempfile
from collections.abc import Iterator

import pytest

from squawk.config import log_path, pid_path, run_dir
from squawk.daemon_control import (
    DaemonControlError,
    daemon_status,
    start_daemon,
    stop_daemon,
)
from squawk.identity import init_identity


@pytest.fixture
def home() -> Iterator[str]:
    directory = tempfile.mkdtemp(prefix="sq-", dir="/tmp")
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def env() -> dict[str, str]:
    # No real mDNS in tests.
    return {**os.environ, "SQUAWK_NO_MDNS": "1"}


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


async def test_starts_reports_status_and_stops_the_background_service(home: str) -> None:
    init_identity(home, "cli-test")
    assert await daemon_status(home) is None

    started = await start_daemon(home, env())
    try:
        assert not started.already_running
        assert started.pid > 0 and started.pid != os.getpid()

        again = await start_daemon(home, env())
        assert again.already_running
        assert again.pid == started.pid

        status = await daemon_status(home)
        assert status is not None
        assert status["pid"] == started.pid
        assert status["name"] == "cli-test"
        assert isinstance(status["port"], int) and status["port"] > 0
        with open(pid_path(home)) as f:
            assert f.read() == f"{started.pid}\n"
    finally:
        stopped = await stop_daemon(home)
    assert stopped
    assert not alive(started.pid)
    assert await daemon_status(home) is None
    assert not os.path.exists(pid_path(home))
    with open(log_path(home)) as f:
        log = f.read()
    assert f"squawkd {started.pid} listening on" in log
    assert f"squawkd {started.pid} stopped" in log
    assert stat_mode(log_path(home)) == 0o600


def stat_mode(path: str) -> int:
    return os.stat(path).st_mode & 0o777


async def test_stop_removes_a_pid_file_left_by_a_dead_service_without_signalling_it(
    home: str,
) -> None:
    os.makedirs(run_dir(home))
    # This test process's own pid stands in for an unrelated process that
    # reused the dead service's pid.
    with open(pid_path(home), "w") as f:
        f.write(f"{os.getpid()}\n")
    assert await stop_daemon(home) is False
    assert not os.path.exists(pid_path(home))


async def test_reports_a_service_that_exits_during_startup(home: str) -> None:
    # No identity, so the service exits at once.
    with pytest.raises(DaemonControlError, match="exited during startup"):
        await start_daemon(home, env())
    with open(log_path(home)) as f:
        assert "no identity found" in f.read()
