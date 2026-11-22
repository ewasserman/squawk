"""Asking the person before a message goes out.

`squawk send` and `squawk reply` show a dialog with the recipient and the
message text in an editable field, and the buttons Cancel and Send. What is in
the field when Send is clicked is what gets sent. Nothing is sent when the
dialog cannot be shown: no dialog program, no logged-in screen session, or the
program failing for any other reason.

On macOS the dialog is AppleScript's `display dialog`, run by `osascript`. On
Linux (and other systems) it is `kdialog` or `zenity`, whichever is installed;
kdialog comes first on KDE, zenity everywhere else.

The message text never becomes part of a script or an option. osascript gets
it as an argument read by the script's `on run argv` handler, kdialog as an
argument after `--` (with each backslash doubled, because kdialog reads `\\n`
as a line break and `\\\\` as one backslash), and zenity on standard input. So
quotes, AppleScript or option-like text in a message cannot change what the
dialog does.

kdialog and zenity are looked up in the system's own folders, never on PATH,
just as osascript is run by its full path: a program put earlier on PATH cannot
stand in for the dialog and answer Send by itself.

`display dialog` shows multi-line text in its field and keeps the line breaks.
Return clicks Send; Option-Return starts a new line while editing. A very long
message makes the dialog as tall as the screen and the field scrolls. kdialog
and zenity show a scrolling text box in which Return starts a new line; kdialog
labels its Send button "OK".
"""

import asyncio
import contextlib
import os
import signal
import sys
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Literal

from squawk.config import SYSTEM_PROGRAM_DIRS, find_system_program
from squawk.envelope import MessageKind

DIALOG_TIMEOUT_S = 300
"""The dialog closes by itself, sending nothing, after this many seconds."""

# The script gets the title, the prompt, the message text and the timeout as
# arguments. It prints "SEND" and the text on the next line, "CANCEL", or
# "GAVEUP" when nobody answered in time.
DIALOG_SCRIPT = "\n".join(
    [
        "on run argv",
        "set theTitle to item 1 of argv",
        "set thePrompt to item 2 of argv",
        "set theText to item 3 of argv",
        "set theTimeout to (item 4 of argv) as integer",
        "try",
        "set answer to display dialog thePrompt default answer theText"
        ' buttons {"Cancel", "Send"} default button "Send" cancel button "Cancel"'
        " with title theTitle giving up after theTimeout",
        "on error number -128",
        'return "CANCEL"',
        "end try",
        'if gave up of answer then return "GAVEUP"',
        'return "SEND" & linefeed & (text returned of answer)',
        "end run",
    ]
)

ZENITY_TIMEOUT_EXIT = 5
"""zenity's exit code when its --timeout ran out. It prints the text then too,
so the code, not the output, tells a timeout from Send."""


DialogKind = Literal["osascript", "kdialog", "zenity"]


@dataclass(frozen=True)
class DialogProgram:
    """The program that shows the confirmation dialog, and which kind it is."""

    kind: DialogKind
    path: str


def find_dialog(
    platform: str | None = None,
    env: Mapping[str, str] | None = None,
    dirs: tuple[str, ...] = SYSTEM_PROGRAM_DIRS,
) -> DialogProgram | None:
    """The dialog program for this machine, or None when it has none.

    On macOS it is always /usr/bin/osascript. Elsewhere it is kdialog or
    zenity, found in `dirs`; kdialog first when XDG_CURRENT_DESKTOP names KDE.
    """
    platform = sys.platform if platform is None else platform
    env = os.environ if env is None else env
    if platform == "darwin":
        return DialogProgram("osascript", "/usr/bin/osascript")
    desktops = env.get("XDG_CURRENT_DESKTOP", "").lower().split(":")
    order: tuple[DialogKind, ...] = (
        ("kdialog", "zenity") if "kde" in desktops else ("zenity", "kdialog")
    )
    for kind in order:
        path = find_system_program(kind, dirs)
        if path is not None:
            return DialogProgram(kind, path)
    return None


NO_DIALOG_REASON = (
    "there is no program to show the confirmation dialog on this machine "
    "(install zenity or kdialog)"
)


@dataclass
class Draft:
    """A message about to be sent, before the person has seen it."""

    to: str
    """The recipient's key id."""
    to_name: str
    """The recipient's contact name, shown to the person."""
    text: str
    kind: MessageKind
    session: str | None = None
    thread_id: str | None = None
    in_reply_to: str | None = None


ConfirmAction = Literal["send", "cancel", "timeout", "unavailable"]


@dataclass(frozen=True)
class ConfirmResult:
    """What the person decided.

    "send": send `text` (possibly edited). "cancel": they clicked Cancel (or
    emptied the text). "timeout": nobody answered in time. "unavailable": the
    dialog could not be shown, and `reason` says why.
    """

    action: ConfirmAction
    text: str
    reason: str = ""


ConfirmFn = Callable[[Draft], Awaitable[ConfirmResult]]


def _what(draft: Draft) -> str:
    return "reply" if draft.in_reply_to is not None else "message"


def confirmation_prompt(draft: Draft, kind: DialogKind = "osascript") -> str:
    """The text shown above the editable field."""
    if kind == "osascript":
        how = "You can edit the text (Option-Return starts a new line), then click Send"
    elif kind == "kdialog":
        how = "You can edit the text, then click OK to send it"
    else:
        how = "You can edit the text, then click Send"
    return (
        f"Claude wants to send this squawk {_what(draft)} to {draft.to_name}.\n\n"
        f"Check it for anything private before sending. {how}, or click Cancel "
        "to send nothing."
    )


def _sent(text: str, draft: Draft) -> ConfirmResult:
    # An emptied field sends nothing.
    if text.strip() == "":
        return ConfirmResult("cancel", draft.text)
    return ConfirmResult("send", text)


def _parse_output(output: str, draft: Draft) -> ConfirmResult:
    """Reads what the osascript dialog printed."""
    # osascript ends what it prints with one newline of its own.
    if output.endswith("\n"):
        output = output[:-1]
    if output == "CANCEL":
        return ConfirmResult("cancel", draft.text)
    if output == "GAVEUP":
        return ConfirmResult("timeout", draft.text)
    if output.startswith("SEND\n"):
        return _sent(output[len("SEND\n") :], draft)
    return ConfirmResult("unavailable", draft.text, f"unexpected answer from osascript: {output!r}")


def _parse_answer(kind: DialogKind, code: int, output: str, draft: Draft) -> ConfirmResult | None:
    """Reads a dialog's exit code and output. None means the program failed."""
    if kind == "osascript":
        return _parse_output(output, draft) if code == 0 else None
    if code == 1:
        # Cancel, Escape or the window's close button.
        return ConfirmResult("cancel", draft.text)
    if kind == "zenity":
        if code == ZENITY_TIMEOUT_EXIT:
            return ConfirmResult("timeout", draft.text)
        # zenity prints the field's text exactly as it is.
        return _sent(output, draft) if code == 0 else None
    # kdialog ends the text with one newline of its own.
    if code == 0:
        return _sent(output[:-1] if output.endswith("\n") else output, draft)
    return None


def _kdialog_text(text: str) -> str:
    """`text` as kdialog must be given it to show it unchanged."""
    return text.replace("\\", "\\\\")


@dataclass(frozen=True)
class _Invocation:
    args: list[str]
    stdin: bytes | None
    gives_up_itself: bool
    """Whether the program closes the dialog by itself after the timeout."""


def _invocation(program: DialogProgram, draft: Draft, timeout_s: int) -> _Invocation:
    prompt = confirmation_prompt(draft, program.kind)
    if program.kind == "osascript":
        args = [
            program.path,
            "-e",
            DIALOG_SCRIPT,
            # osascript reads "--" as the end of its own options, so message
            # text starting with "-" is passed through unchanged.
            "--",
            "squawk",
            prompt,
            draft.text,
            str(timeout_s),
        ]
        return _Invocation(args, None, gives_up_itself=True)
    if program.kind == "kdialog":
        # kdialog has no timeout of its own; the dialog is closed when the
        # time is up. Its OK and Cancel buttons cannot be relabelled.
        args = [
            program.path,
            "--title",
            "squawk",
            "--textinputbox",
            _kdialog_text(prompt),
            # After "--", text starting with "-" is not read as an option.
            "--",
            _kdialog_text(draft.text),
            "640",
            "420",
        ]
        return _Invocation(args, None, gives_up_itself=False)
    # zenity's text box has no room for a prompt, so the title names the
    # recipient. The text comes on standard input.
    args = [
        program.path,
        "--text-info",
        "--editable",
        f"--title=squawk: Claude wants to send this {_what(draft)} to {draft.to_name}",
        "--width=640",
        "--height=420",
        "--ok-label=Send",
        "--cancel-label=Cancel",
        f"--timeout={timeout_s}",
    ]
    return _Invocation(args, draft.text.encode("utf-8"), gives_up_itself=True)


def _has_screen(env: Mapping[str, str]) -> bool:
    return bool(env.get("WAYLAND_DISPLAY") or env.get("DISPLAY"))


async def dialog_confirm(
    draft: Draft,
    *,
    program: DialogProgram | None,
    env: Mapping[str, str] | None = None,
    timeout_s: int = DIALOG_TIMEOUT_S,
) -> ConfirmResult:
    """Shows the confirmation dialog with `program` and waits for the answer.

    The program runs with `env` (default: this process's environment).
    SIGINT or SIGTERM while the dialog is open closes it and counts as
    cancel, so a dialog is never left on screen for a command that is gone.
    """
    env = os.environ if env is None else env
    if program is None:
        return ConfirmResult("unavailable", draft.text, NO_DIALOG_REASON)
    if program.kind != "osascript" and not _has_screen(env):
        return ConfirmResult(
            "unavailable",
            draft.text,
            "there is no screen session to show the confirmation dialog on "
            "(neither WAYLAND_DISPLAY nor DISPLAY is set)",
        )
    invocation = _invocation(program, draft, timeout_s)
    try:
        process = await asyncio.create_subprocess_exec(
            *invocation.args,
            stdin=asyncio.subprocess.DEVNULL
            if invocation.stdin is None
            else asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=dict(env),
        )
    except OSError as error:
        needs = "; the confirmation dialog needs macOS" if program.kind == "osascript" else ""
        return ConfirmResult(
            "unavailable",
            draft.text,
            f"could not run {program.path} ({error.strerror or error}){needs}",
        )

    loop = asyncio.get_running_loop()
    interrupted = False

    def interrupt() -> None:
        nonlocal interrupted
        interrupted = True
        with contextlib.suppress(ProcessLookupError):
            process.kill()

    handled: list[signal.Signals] = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
            loop.add_signal_handler(sig, interrupt)
            handled.append(sig)
    # A program that gives up by itself gets some slack; for one that does
    # not, the end of the wait is the timeout.
    wait_s = timeout_s + 30 if invocation.gives_up_itself else timeout_s
    try:
        out, err = await asyncio.wait_for(process.communicate(invocation.stdin), wait_s)
    except TimeoutError:
        interrupt()
        await process.wait()
        return ConfirmResult("timeout", draft.text)
    except asyncio.CancelledError:
        interrupt()
        raise
    finally:
        for sig in handled:
            loop.remove_signal_handler(sig)
    if interrupted:
        return ConfirmResult("cancel", draft.text, "interrupted")
    code = process.returncode if process.returncode is not None else -1
    answer = _parse_answer(program.kind, code, out.decode("utf-8", "replace"), draft)
    if answer is None:
        detail = err.decode("utf-8", "replace").strip() or f"exit code {code}"
        return ConfirmResult(
            "unavailable", draft.text, f"could not show the confirmation dialog ({detail})"
        )
    return answer
