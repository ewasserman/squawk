"""Starting, stopping and querying the background service from the CLI.

This is the Python version of src/daemon-control.ts. It works on the same
files (run/squawkd.sock, run/squawkd.pid, run/squawkd.log), so it can also
query or stop a service started by the Node version.
"""

import asyncio
import contextlib
import os
import signal
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from squawk.config import log_path, pid_path, run_dir, socket_path
from squawk.daemon import StatusResult
from squawk.rpc import RpcClient


class DaemonControlError(Exception):
    """Raised when the service could not be started or stopped."""


@dataclass(frozen=True)
class StartResult:
    pid: int
    already_running: bool


# Services this process started, by pid. A child that has exited stays a
# "zombie" until its parent collects its exit status, and a zombie still
# answers `kill(pid, 0)`; keeping the process objects lets `_is_alive`
# collect it.
_children: dict[int, subprocess.Popen[bytes]] = {}


async def connect_to_daemon(home: str) -> RpcClient | None:
    """Connects to the running service, or returns None if none answers."""
    try:
        return await RpcClient.connect(socket_path(home))
    except OSError:
        return None


async def daemon_status(home: str) -> StatusResult | None:
    """The running service's status, or None if it is not running."""
    client = await connect_to_daemon(home)
    if client is None:
        return None
    try:
        return cast(StatusResult, await client.call("status"))
    except Exception:
        return None
    finally:
        await client.close()


def _exit_text(code: int) -> str:
    if code < 0:
        try:
            return signal.Signals(-code).name
        except ValueError:
            return f"signal {-code}"
    return f"exit code {code}"


async def start_daemon(
    home: str, env: Mapping[str, str] | None = None, timeout_ms: int = 5_000
) -> StartResult:
    """Starts the service as a detached process (output to run/squawkd.log)
    and waits until it answers `status`. Does nothing if it is already running.

    `env` is the environment for the service (default: this process's);
    SQUAWK_HOME is set to `home` in it.
    """
    existing = await daemon_status(home)
    if existing is not None:
        return StartResult(pid=existing["pid"], already_running=True)
    run = run_dir(home)
    os.makedirs(run, mode=0o700, exist_ok=True)
    log = os.open(log_path(home), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        child = subprocess.Popen(
            # -P: do not put the current directory on the module search path.
            [sys.executable, "-P", "-m", "squawk.daemon_main"],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            env={**(os.environ if env is None else env), "SQUAWK_HOME": home},
            # Not the caller's folder, which the service would otherwise keep in use.
            cwd=home,
            start_new_session=True,
        )
    finally:
        os.close(log)
    _children[child.pid] = child
    deadline = time.monotonic() + timeout_ms / 1000
    while time.monotonic() < deadline:
        status = await daemon_status(home)
        if status is not None:
            return StartResult(pid=status["pid"], already_running=False)
        code = child.poll()
        if code is not None:
            raise DaemonControlError(
                f"squawkd exited during startup ({_exit_text(code)}); see {log_path(home)}"
            )
        await asyncio.sleep(0.1)
    raise DaemonControlError(
        f"squawkd did not answer within {_seconds(timeout_ms)}s; see {log_path(home)}"
    )


def _seconds(ms: int) -> str:
    """Milliseconds as seconds, written as JavaScript would (5, not 5.0)."""
    value = ms / 1000
    return str(int(value)) if value.is_integer() else str(value)


def _read_pid(home: str) -> int | None:
    try:
        with open(pid_path(home), encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return None
    digits = ""
    for ch in text.strip():
        if not ch.isdigit():
            break
        digits += ch
    pid = int(digits) if digits else 0
    return pid if pid > 0 else None


def _is_alive(pid: int) -> bool:
    child = _children.get(pid)
    if child is not None:
        if child.poll() is None:
            return True
        _children.pop(pid, None)
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # It exists but belongs to someone else.
        return True
    return True


async def stop_daemon(home: str, timeout_ms: int = 5_000) -> bool:
    """Asks the service to stop over the socket. If it answers on the socket
    but the stop call fails, sends SIGTERM to the pid in the pid file. Waits
    up to `timeout_ms` for it to exit. Returns False if it was not running (and
    then removes any pid file left behind, without signalling that pid)."""
    pid = _read_pid(home)
    client = await connect_to_daemon(home)
    asked = False
    if client is not None:
        try:
            await client.call("stop")
            asked = True
        except Exception:
            # Fall back to the signal below.
            pass
        finally:
            await client.close()
    if client is None:
        # No service answers on the socket, so a pid file is left over from
        # one that died. Its pid may now belong to an unrelated process, so
        # remove the file rather than send a signal.
        with contextlib.suppress(FileNotFoundError):
            os.remove(pid_path(home))
        return False
    if pid is None or not _is_alive(pid):
        return asked
    if not asked:
        os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout_ms / 1000
    while time.monotonic() < deadline:
        if not _is_alive(pid):
            return True
        await asyncio.sleep(0.05)
    raise DaemonControlError(f"squawkd (pid {pid}) did not exit within {_seconds(timeout_ms)}s")


async def run_daemon_foreground(home: str) -> None:
    """Runs the service in this process (for debugging) until it stops."""
    from squawk.daemon_main import run_daemon

    await run_daemon(home)
