"""Asking the person before a message goes out.

`squawk send` and `squawk reply` show a macOS dialog (through `osascript`)
with the recipient and the message text in an editable field, and the
buttons Cancel and Send. What is in the field when Send is clicked is what
gets sent. Nothing is sent when the dialog cannot be shown: no macOS, no
logged-in screen session, or osascript failing for any other reason.

The text reaches osascript as a command-line argument read by the script's
`on run argv` handler, never as part of the script itself, so quotes or
AppleScript in a message cannot change what the script does.

`display dialog` shows multi-line text in its field and keeps the line
breaks. Return clicks Send; Option-Return starts a new line while editing. A
very long message makes the dialog as tall as the screen and the field
scrolls.
"""

import asyncio
import contextlib
import signal
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal

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


def confirmation_prompt(draft: Draft) -> str:
    """The text shown above the editable field."""
    what = "reply" if draft.in_reply_to is not None else "message"
    return (
        f"Claude wants to send this squawk {what} to {draft.to_name}.\n\n"
        "Check it for anything private before sending. You can edit the text "
        "(Option-Return starts a new line), then click Send, or click Cancel to "
        "send nothing."
    )


def _parse_output(output: str, draft: Draft) -> ConfirmResult:
    # osascript ends what it prints with one newline of its own.
    if output.endswith("\n"):
        output = output[:-1]
    if output == "CANCEL":
        return ConfirmResult("cancel", draft.text)
    if output == "GAVEUP":
        return ConfirmResult("timeout", draft.text)
    if output.startswith("SEND\n"):
        text = output[len("SEND\n") :]
        if text.strip() == "":
            return ConfirmResult("cancel", draft.text)
        return ConfirmResult("send", text)
    return ConfirmResult("unavailable", draft.text, f"unexpected answer from osascript: {output!r}")


async def dialog_confirm(
    draft: Draft,
    *,
    osascript: str = "/usr/bin/osascript",
    timeout_s: int = DIALOG_TIMEOUT_S,
) -> ConfirmResult:
    """Shows the confirmation dialog and waits for the person's answer.

    SIGINT or SIGTERM while the dialog is open closes it and counts as
    cancel, so a dialog is never left on screen for a command that is gone.
    """
    args = [
        osascript,
        "-e",
        DIALOG_SCRIPT,
        # osascript reads "--" as the end of its own options, so message
        # text starting with "-" is passed through unchanged.
        "--",
        "squawk",
        confirmation_prompt(draft),
        draft.text,
        str(timeout_s),
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as error:
        return ConfirmResult(
            "unavailable",
            draft.text,
            f"could not run {osascript} ({error.strerror or error}); "
            "the confirmation dialog needs macOS",
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
    try:
        out, err = await asyncio.wait_for(process.communicate(), timeout_s + 30)
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
    if process.returncode != 0:
        detail = err.decode("utf-8", "replace").strip() or f"exit code {process.returncode}"
        return ConfirmResult(
            "unavailable", draft.text, f"could not show the confirmation dialog ({detail})"
        )
    return _parse_output(out.decode("utf-8", "replace"), draft)
