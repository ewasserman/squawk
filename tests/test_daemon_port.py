"""The service reuses the port of its last run when it is free, so contacts'
saved addresses keep working after a restart."""

import os
import shutil
import socket
import tempfile
from collections.abc import Iterator

import pytest

from squawk.daemon import Daemon
from squawk.daemon_main import read_last_port, write_last_port
from squawk.identity import init_identity
from squawk.network import NetworkTransport


@pytest.fixture
def home() -> Iterator[str]:
    folder = tempfile.mkdtemp(prefix="sqport-", dir="/tmp")
    yield folder
    shutil.rmtree(folder, ignore_errors=True)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def _start(home: str, preferred: int) -> tuple[Daemon, NetworkTransport]:
    transport = NetworkTransport(host="127.0.0.1", discovery=False, preferred_port=preferred)
    daemon = Daemon(home, transport=transport)
    await daemon.start()
    return daemon, transport


async def test_uses_the_preferred_port_when_free_and_any_port_when_taken(home: str) -> None:
    init_identity(home, "alice")
    wanted = _free_port()
    daemon, transport = await _start(home, wanted)
    try:
        assert transport.port == wanted
    finally:
        await daemon.stop()

    blocker = socket.socket()
    blocker.bind(("127.0.0.1", wanted))
    blocker.listen()
    try:
        daemon, transport = await _start(home, wanted)
        try:
            assert transport.port not in (0, wanted)
        finally:
            await daemon.stop()
    finally:
        blocker.close()


def test_remembers_the_last_port(home: str) -> None:
    os.makedirs(os.path.join(home, "run"))
    assert read_last_port(home) == 0
    write_last_port(home, 52604)
    assert read_last_port(home) == 52604
    with open(os.path.join(home, "run", "port"), "w") as f:
        f.write("not a port\n")
    assert read_last_port(home) == 0
