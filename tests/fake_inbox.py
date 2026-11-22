"""A stand-in for a Claude Code session's inbox socket, for tests.

It listens on a unix socket, expects each connection to start with the
auth line carrying its token, and collects the text of every user message
line after it. Tests never post into a real session's socket.
"""

import asyncio
import contextlib
import json
import os
import secrets
import shutil
import tempfile
from typing import Any


class FakeInbox:
    def __init__(self, path: str, token: str) -> None:
        self.path = path
        self.token = token
        self.messages: list[str] = []
        """The content of every user message received, in order."""
        self.problems: list[str] = []
        """Connections that broke the expected format."""
        self.connections = 0
        self._server: asyncio.Server | None = None

    @classmethod
    async def start(cls, directory: str, name: str = "inbox") -> "FakeInbox":
        inbox = cls(os.path.join(directory, f"{name}.sock"), secrets.token_hex(8))
        inbox._server = await asyncio.start_unix_server(inbox._handle, inbox.path)
        return inbox

    @property
    def env(self) -> dict[str, str]:
        """The variables Claude Code gives the session's hooks and Bash commands."""
        return {
            "CLAUDE_CODE_MESSAGING_SOCKET": self.path,
            "CLAUDE_CODE_MESSAGING_TOKEN": self.token,
        }

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        lines: list[Any] = []
        try:
            while True:
                raw = await reader.readline()
                if not raw:
                    break
                lines.append(json.loads(raw))
        except (ValueError, ConnectionError) as err:
            self.problems.append(f"bad line: {err}")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        if not lines:
            return  # A liveness check: connect and close.
        if lines[0] != {"type": "auth", "token": self.token}:
            self.problems.append(f"first line is not the auth line: {lines[0]!r}")
            return
        for line in lines[1:]:
            message = line.get("message") if isinstance(line, dict) else None
            if (
                isinstance(line, dict)
                and line.get("type") == "user"
                and isinstance(message, dict)
                and message.get("role") == "user"
                and isinstance(message.get("content"), str)
            ):
                self.messages.append(message["content"])
            else:
                self.problems.append(f"unexpected line: {line!r}")

    async def close(self, remove: bool = True) -> None:
        """Stops listening. With `remove`, the socket file goes too (as when
        a session ends); without, it stays and refuses connections (as when
        a session crashed)."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if remove:
            with contextlib.suppress(FileNotFoundError):
                os.remove(self.path)
        elif not os.path.exists(self.path):
            # Python removes the file when the server closes; put a dead one back.
            import socket

            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(self.path)
            sock.close()


class Inboxes:
    """Fake inboxes in one short temporary folder (unix socket paths must be short)."""

    def __init__(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="sqi-", dir="/tmp")
        self.all: list[FakeInbox] = []

    async def new(self, name: str) -> FakeInbox:
        inbox = await FakeInbox.start(self.dir, name)
        self.all.append(inbox)
        return inbox

    async def close(self) -> None:
        for inbox in self.all:
            await inbox.close()
        shutil.rmtree(self.dir, ignore_errors=True)
