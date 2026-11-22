"""Tests for `squawk setup` and `squawk uninstall`. They work on a temporary
HOME and CLAUDE_CONFIG_DIR and a stand-in `claude` program, never on the
real Claude Code configuration."""

import json
import os
import shutil
import stat
import tempfile
from collections.abc import AsyncIterator
from dataclasses import dataclass

import pytest

from squawk.cli import run
from squawk.cli_io import CliIo
from squawk.cli_setup import (
    SKILL_TEXT,
    hook_command,
    is_squawk_hook,
    with_squawk_hooks,
    without_squawk_hooks,
)
from squawk.daemon_control import daemon_status, stop_daemon


@dataclass
class Result:
    code: int
    out: str
    err: str


class Machine:
    """A temporary home with a squawk home, a Claude Code folder and a fake `claude`."""

    def __init__(self, version: str = "2.1.330 (Claude Code)") -> None:
        self.root = tempfile.mkdtemp(prefix="sqs-", dir="/tmp")
        self.home = os.path.join(self.root, "h")
        self.squawk = os.path.join(self.root, "sq")
        self.claude_dir = os.path.join(self.home, "claude-config")
        self.claude_log = os.path.join(self.root, "claude.log")
        self.claude = os.path.join(self.root, "claude")
        os.makedirs(self.home)
        self.set_version(version)

    def set_version(self, version: str) -> None:
        with open(self.claude, "w") as f:
            f.write(
                "#!/bin/sh\n"
                f'echo "$@" >> "{self.claude_log}"\n'
                f'if [ "$1" = "--version" ]; then echo "{version}"; fi\n'
            )
        os.chmod(self.claude, 0o755)

    @property
    def env(self) -> dict[str, str]:
        return {
            "HOME": self.home,
            "CLAUDE_CONFIG_DIR": self.claude_dir,
            "SQUAWK_HOME": self.squawk,
            "SQUAWK_CLAUDE_BIN": self.claude,
            "SQUAWK_NO_MDNS": "1",
            "SQUAWK_PORT": "0",
            "SQUAWK_NO_NOTIFY": "1",
            "PATH": os.environ.get("PATH", ""),
        }

    @property
    def settings_path(self) -> str:
        return os.path.join(self.claude_dir, "settings.json")

    def settings(self) -> dict[str, object]:
        with open(self.settings_path) as f:
            data: dict[str, object] = json.load(f)
        return data

    def write_settings(self, data: object) -> None:
        os.makedirs(self.claude_dir, exist_ok=True)
        with open(self.settings_path, "w") as f:
            json.dump(data, f)

    async def cli(self, *args: str) -> Result:
        out: list[str] = []
        err: list[str] = []
        io = CliIo(stdout=out.append, stderr=err.append, env=self.env)
        code = await run(list(args), io)
        return Result(code, "".join(out), "".join(err))


@pytest.fixture
async def machine() -> AsyncIterator[Machine]:
    m = Machine()
    try:
        yield m
    finally:
        await stop_daemon(m.squawk)
        shutil.rmtree(m.root, ignore_errors=True)


OTHER_HOOKS = {
    "SessionStart": [
        {"matcher": "startup", "hooks": [{"type": "command", "command": "echo hello"}]}
    ],
    "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "check.sh"}]}],
}


def squawk_hooks(settings: dict[str, object]) -> dict[str, list[str]]:
    hooks = settings.get("hooks")
    assert isinstance(hooks, dict)
    found: dict[str, list[str]] = {}
    for event, groups in hooks.items():
        for group in groups:
            for handler in group["hooks"]:
                if is_squawk_hook(handler):
                    found.setdefault(event, []).append(handler["command"])
    return found


async def test_setup_creates_the_identity_starts_the_service_and_adds_hooks_and_skill(
    machine: Machine,
) -> None:
    original = {"model": "opus", "theme": "dark", "hooks": OTHER_HOOKS}
    machine.write_settings(original)

    result = await machine.cli("setup", "--name", "Alice")
    assert result.code == 0, result.err
    assert 'Created your identity "Alice"' in result.out
    assert "Started the squawk service" in result.out
    assert "Claude Code 2.1.330 supports squawk." in result.out
    assert result.err == ""
    assert await daemon_status(machine.squawk) is not None

    settings = machine.settings()
    assert settings["model"] == "opus" and settings["theme"] == "dark"
    hooks = settings["hooks"]
    assert isinstance(hooks, dict)
    assert hooks["PreToolUse"] == OTHER_HOOKS["PreToolUse"]
    assert hooks["SessionStart"][0] == OTHER_HOOKS["SessionStart"][0]
    start = hooks["SessionStart"][1]["hooks"][0]
    end = hooks["SessionEnd"][0]["hooks"][0]
    assert start["type"] == "command" and start["timeout"] == 15
    assert end["timeout"] == 5
    # The squawk home is not the default one, so the command names it.
    assert start["command"].startswith(f"SQUAWK_HOME={machine.squawk} ")
    assert start["command"].endswith(" hook session-start")
    assert end["command"].endswith(" hook session-end")
    program = start["command"].split(" ")[1]
    assert os.path.isabs(program)

    with open(machine.settings_path + ".squawk-backup") as f:
        assert json.load(f) == original

    with open(os.path.join(machine.claude_dir, "skills", "squawk", "SKILL.md")) as f:
        assert f.read() == SKILL_TEXT
    with open(machine.claude_log) as f:
        calls = f.read().splitlines()
    assert "--version" in calls
    assert "mcp remove --scope user squawk" in calls

    # Running it again changes nothing and adds no duplicates.
    again = await machine.cli("setup")
    assert again.code == 0, again.err
    assert 'Using your existing identity "Alice"' in again.out
    assert "already running" in again.out
    assert "already in" in again.out
    assert machine.settings() == settings
    with open(machine.settings_path + ".squawk-backup") as f:
        assert json.load(f) == original

    # Uninstall removes only squawk's parts and stops the service.
    removed = await machine.cli("uninstall")
    assert removed.code == 0, removed.err
    assert "Stopped the squawk service." in removed.out
    assert machine.settings() == original
    assert not os.path.exists(os.path.join(machine.claude_dir, "skills", "squawk"))
    assert await daemon_status(machine.squawk) is None
    assert os.path.isdir(machine.squawk)

    purged = await machine.cli("uninstall", "--purge")
    assert purged.code == 0
    assert not os.path.exists(machine.squawk)


async def test_setup_replaces_squawk_hooks_from_an_older_install(machine: Machine) -> None:
    machine.write_settings(
        {
            "hooks": {
                "SessionStart": [
                    {
                        "hooks": [
                            {"type": "command", "command": "/old/bin/squawk hook session-start"},
                            {"type": "command", "command": "echo kept"},
                        ]
                    }
                ],
                "SessionEnd": [
                    {
                        "hooks": [
                            {"type": "command", "command": "'/old path/squawk' hook session-end"}
                        ]
                    }
                ],
            }
        }
    )
    result = await machine.cli("setup", "--name", "A")
    assert result.code == 0, result.err
    settings = machine.settings()
    found = squawk_hooks(settings)
    assert len(found["SessionStart"]) == 1 and len(found["SessionEnd"]) == 1
    assert "/old" not in found["SessionStart"][0] + found["SessionEnd"][0]
    hooks = settings["hooks"]
    assert isinstance(hooks, dict)
    assert hooks["SessionStart"][0] == {"hooks": [{"type": "command", "command": "echo kept"}]}


async def test_setup_warns_about_settings_and_versions_that_block_squawk(
    machine: Machine,
) -> None:
    machine.write_settings(
        {"crossSessionInbound": "refuse", "permissions": {"defaultMode": "bypassPermissions"}}
    )
    machine.set_version("2.1.100 (Claude Code)")
    result = await machine.cli("setup", "--name", "A")
    assert result.code == 0
    assert "Claude Code 2.1.100 is too old for squawk" in result.err
    assert '"crossSessionInbound": "refuse"' in result.err
    assert "permission prompts skipped" in result.err

    os.remove(machine.claude)
    missing = await machine.cli("setup")
    assert "could not run" in missing.err


async def test_setup_refuses_to_touch_settings_that_are_not_valid_json(
    machine: Machine,
) -> None:
    os.makedirs(machine.claude_dir)
    with open(machine.settings_path, "w") as f:
        f.write("{ not json")
    result = await machine.cli("setup", "--name", "A")
    assert result.code == 1
    assert "is not valid JSON" in result.err
    with open(machine.settings_path) as f:
        assert f.read() == "{ not json"
    assert not os.path.exists(machine.settings_path + ".squawk-backup")


async def test_setup_without_claude_leaves_claude_code_alone(machine: Machine) -> None:
    result = await machine.cli("setup", "--name", "A", "--no-claude")
    assert result.code == 0, result.err
    assert "Skipped the Claude Code hooks and skill" in result.out
    assert not os.path.exists(machine.claude_dir)
    assert not os.path.exists(machine.claude_log)


async def test_a_new_settings_file_is_private(machine: Machine) -> None:
    assert (await machine.cli("setup", "--name", "A")).code == 0
    assert stat.S_IMODE(os.stat(machine.settings_path).st_mode) == 0o600
    assert set(squawk_hooks(machine.settings())) == {"SessionStart", "SessionEnd"}


def test_hook_entries_are_recognised_by_their_command() -> None:
    assert is_squawk_hook({"command": "/a/squawk hook session-start"})
    assert is_squawk_hook({"command": "SQUAWK_HOME=/x '/a b/squawk' hook session-end"})
    assert is_squawk_hook({"command": "/usr/bin/python3 -m squawk.cli hook session-end"})
    assert not is_squawk_hook({"command": "echo squawk"})
    assert not is_squawk_hook({"command": "squawk hook session-start && rm -rf /"})
    assert not is_squawk_hook("squawk hook session-start")
    command = hook_command("SessionStart", "/home/sq", "/home/sq", ["/opt/my bin/squawk"])
    assert command == "'/opt/my bin/squawk' hook session-start"
    settings = with_squawk_hooks({}, {"SessionStart": command, "SessionEnd": command})
    assert without_squawk_hooks(settings) == {}
