"""Where squawk keeps its files, and where it finds the system programs it runs."""

import os
import shutil
from collections.abc import Mapping
from pathlib import Path

SYSTEM_PROGRAM_DIRS = ("/usr/bin", "/bin", "/usr/local/bin", "/run/current-system/sw/bin")
"""Where squawk looks for kdialog, zenity and notify-send on Linux. These are
the system's own folders, not PATH, so a program put earlier on PATH cannot
stand in for one (the last folder is where NixOS keeps system programs)."""


def find_system_program(name: str, dirs: tuple[str, ...] = SYSTEM_PROGRAM_DIRS) -> str | None:
    """The full path of the program `name` in `dirs`, or None if it is not there."""
    return shutil.which(name, path=os.pathsep.join(dirs))


def squawk_home(env: Mapping[str, str] | None = None) -> str:
    """The directory that holds squawk's identity, database and runtime files.

    Uses the SQUAWK_HOME environment variable when it is set, otherwise
    `~/.config/squawk`.
    """
    from_env = (os.environ if env is None else env).get("SQUAWK_HOME")
    if from_env is not None and from_env != "":
        return from_env
    return os.path.join(Path.home(), ".config", "squawk")


def identity_path(home: str) -> str:
    """Path of the file holding this machine's key pair and display name."""
    return os.path.join(home, "identity.json")


def db_path(home: str) -> str:
    """Path of the SQLite database file."""
    return os.path.join(home, "squawk.db")


def run_dir(home: str) -> str:
    """Directory for runtime files such as the background service's socket and pid file."""
    return os.path.join(home, "run")


def socket_path(home: str) -> str:
    """Path of the background service's unix socket."""
    return os.path.join(run_dir(home), "squawkd.sock")


def pid_path(home: str) -> str:
    """Path of the file holding the background service's process id."""
    return os.path.join(run_dir(home), "squawkd.pid")


def log_path(home: str) -> str:
    """Path of the background service's log file (its stdout and stderr)."""
    return os.path.join(run_dir(home), "squawkd.log")
