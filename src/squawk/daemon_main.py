"""Entry point for the background service: runs a `Daemon` for the squawk home
directory until it receives SIGTERM or SIGINT, or a client calls `stop`.

Started by `daemon_control.start_daemon` as `python -m squawk.daemon_main`.
Reads SQUAWK_HOME (the home directory), SQUAWK_PORT (the WebSocket port; 0 or
unset picks a free one), SQUAWK_NO_MDNS=1 (turns discovery off) and
SQUAWK_NO_NOTIFY=1 (no desktop notifications, for tests).
"""

import asyncio
import os
import signal
import sys

from squawk.config import squawk_home
from squawk.daemon import Daemon
from squawk.inbox import macos_notify
from squawk.network import NetworkTransport
from squawk.pairing import Pairing
from squawk.timefmt import iso_from_ms, now_ms


def _log(text: str) -> None:
    print(f"{iso_from_ms(now_ms())} squawkd {os.getpid()} {text}", flush=True)


async def run_daemon(home: str | None = None) -> None:
    """Runs the service in this process until it stops."""
    home = squawk_home() if home is None else home
    transport = NetworkTransport(
        port=int(os.environ.get("SQUAWK_PORT") or 0),
        discovery=False if os.environ.get("SQUAWK_NO_MDNS") == "1" else None,
    )
    notify = None if os.environ.get("SQUAWK_NO_NOTIFY") == "1" else macos_notify
    daemon = Daemon(home, transport=transport, notify=notify)
    await daemon.start()
    pairing = Pairing(daemon, transport)
    pairing.start()
    loop = asyncio.get_running_loop()
    stopping: list[asyncio.Task[None]] = []

    def shutdown() -> None:
        stopping.append(asyncio.ensure_future(daemon.stop()))

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, shutdown)
    _log(f"listening on {daemon.socket_path} and port {transport.port}")
    try:
        await daemon.when_stopped()
    finally:
        pairing.stop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.remove_signal_handler(sig)
    _log("stopped")


def main() -> int:
    try:
        asyncio.run(run_daemon())
    except Exception as err:
        print(f"squawkd: {err}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
