"""Tests for finding the confirmation dialog and notification programs, and
for the dialog closing itself when nobody answers."""

import asyncio
import os
import sys
import tempfile
from collections.abc import Iterator

import pytest

from squawk.confirm import DialogProgram, Draft, dialog_confirm, find_dialog
from squawk.inbox import linux_notify


@pytest.fixture
def bin_dir() -> Iterator[str]:
    with tempfile.TemporaryDirectory() as directory:
        yield directory


def program(directory: str, name: str, body: str = "") -> str:
    """Writes a Python stand-in for the program `name` and returns its path."""
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"#!{sys.executable}\nimport sys\nargs = sys.argv[1:]\n{body}\n")
    os.chmod(path, 0o755)
    return path


def test_macos_always_uses_osascript(bin_dir: str) -> None:
    assert find_dialog("darwin", {}, (bin_dir,)) == DialogProgram("osascript", "/usr/bin/osascript")


def test_kdialog_comes_first_on_kde_and_zenity_everywhere_else(bin_dir: str) -> None:
    kdialog = program(bin_dir, "kdialog")
    zenity = program(bin_dir, "zenity")
    dirs = (bin_dir,)
    kde = {"XDG_CURRENT_DESKTOP": "KDE"}
    assert find_dialog("linux", kde, dirs) == DialogProgram("kdialog", kdialog)
    gnome = {"XDG_CURRENT_DESKTOP": "ubuntu:GNOME"}
    assert find_dialog("linux", gnome, dirs) == DialogProgram("zenity", zenity)
    assert find_dialog("linux", {}, dirs) == DialogProgram("zenity", zenity)
    os.remove(zenity)
    assert find_dialog("linux", gnome, dirs) == DialogProgram("kdialog", kdialog)
    os.remove(kdialog)
    assert find_dialog("linux", kde, dirs) is None


def test_the_dialog_is_not_looked_up_on_path(bin_dir: str, monkeypatch: pytest.MonkeyPatch) -> None:
    on_path = os.path.join(bin_dir, "on-path")
    os.mkdir(on_path)
    program(on_path, "zenity")
    monkeypatch.setenv("PATH", on_path)
    empty = os.path.join(bin_dir, "system")
    os.mkdir(empty)
    assert find_dialog("linux", {}, (empty,)) is None


async def test_kdialog_is_closed_when_nobody_answers_in_time(bin_dir: str) -> None:
    started = os.path.join(bin_dir, "started")
    # kdialog has no timeout of its own: this one waits until it is killed.
    kdialog = program(
        bin_dir, "kdialog", f"open({started!r}, 'w').close()\nimport time\ntime.sleep(60)"
    )
    draft = Draft(to="k", to_name="bob", text="hello", kind="text")
    loop = asyncio.get_running_loop()
    began = loop.time()
    result = await dialog_confirm(
        draft,
        program=DialogProgram("kdialog", kdialog),
        env={"DISPLAY": ":0"},
        timeout_s=1,
    )
    assert result.action == "timeout"
    assert os.path.exists(started)
    assert loop.time() - began < 10


async def test_linux_notifications_pass_title_and_text_after_double_dash(bin_dir: str) -> None:
    saved = os.path.join(bin_dir, "args")
    notify_send = program(bin_dir, "notify-send", f"open({saved!r}, 'w').write(repr(args))")
    linux_notify("squawk: message from bob", "-u critical hi", notify_send=notify_send)
    for _ in range(400):
        if os.path.exists(saved) and os.path.getsize(saved) > 0:
            break
        await asyncio.sleep(0.025)
    with open(saved, encoding="utf-8") as f:
        args = f.read()
    assert args == repr(["--app-name=squawk", "--", "squawk: message from bob", "-u critical hi"])


def test_linux_notifications_do_nothing_without_notify_send(bin_dir: str) -> None:
    # A missing program is simply skipped.
    linux_notify("title", "text", notify_send=os.path.join(bin_dir, "missing"))
