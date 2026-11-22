"""Finding other squawk services on the local network with mDNS.

Each service advertises `_squawk._tcp` with a TXT record holding its display
name, key id, key fingerprint and WebSocket port, and browses for the same
service type. Everything learned this way is a hint: a discovered peer is
only a candidate until pairing has confirmed its key, and anyone on the
network can advertise any name or key. See docs/plan/security.md, threat 4.

On macOS the work is done by the system's mDNSResponder through the `dns-sd`
command. A process sending multicast packets itself is often refused there
(EHOSTUNREACH) by the Local Network privacy setting, while mDNSResponder is
always allowed. Elsewhere the `zeroconf` package is used.

The service type, instance names and TXT fields are fixed, so services of
every squawk version since 0.1 find each other.
"""

import asyncio
import contextlib
import inspect
import os
import re
import shutil
import socket
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, Protocol

from squawk import jsontext
from squawk.encoding import is_key_id
from squawk.timefmt import now_ms

if TYPE_CHECKING:
    from zeroconf import ServiceStateChange, Zeroconf
    from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf

SERVICE_TYPE = "squawk"
"""The DNS-SD service type, without the leading underscore or protocol."""

_ZEROCONF_TYPE = f"_{SERVICE_TYPE}._tcp.local."


@dataclass(frozen=True)
class Advertisement:
    """What we advertise about ourselves."""

    name: str
    key_id: str
    fingerprint: str
    port: int


@dataclass(frozen=True)
class DiscoveredPeer:
    """A squawk service seen on the network. Not trusted until paired."""

    name: str
    key_id: str
    fingerprint: str
    host: str
    """Host name from the SRV record, e.g. `alices-mac.local`."""
    addresses: list[str]
    """IP addresses from A/AAAA records, IPv4 first."""
    port: int
    last_seen: int
    """Milliseconds since the epoch when this peer was last announced."""


@dataclass(frozen=True)
class RawService:
    """A found or lost service, as reported by an mDNS backend."""

    name: str
    host: str
    port: int
    addresses: list[str] = field(default_factory=list)
    txt: Mapping[str, Any] = field(default_factory=dict)


class MdnsBackend(Protocol):
    """The small part of an mDNS library that discovery needs. The default
    implementations use dns-sd or zeroconf; tests pass a fake."""

    async def publish(self, instance_name: str, port: int, txt: dict[str, str]) -> None: ...

    async def browse(
        self,
        on_up: Callable[[RawService], None],
        on_down: Callable[[RawService], None],
    ) -> None: ...

    def query(self) -> None:
        """Asks the network again for services (used by `refresh`)."""
        ...

    async def destroy(self) -> None:
        """Withdraws our advertisement and stops browsing."""
        ...


def _log(text: str) -> None:
    print(f"squawkd: discovery: {text}", file=sys.stderr)


def _local_host_name() -> str:
    """This machine's name for mDNS, e.g. "hal.local." (with the final dot)."""
    host = socket.gethostname().split(".")[0] or "squawk"
    return f"{host}.local."


def _local_addresses() -> list[str]:
    """This machine's IP addresses to advertise, IPv4 first, leaving out
    loopback and IPv6 link-local addresses (which other hosts cannot dial)."""
    import ifaddr

    v4: list[str] = []
    v6: list[str] = []
    for adapter in ifaddr.get_adapters():
        for ip in adapter.ips:
            if isinstance(ip.ip, str):
                if not ip.ip.startswith("127."):
                    v4.append(ip.ip)
            else:
                address = ip.ip[0]
                if address != "::1" and not address.lower().startswith("fe80:"):
                    v6.append(address)
    return v4 + v6


async def _await_inner(result: object) -> None:
    """Waits for the task some zeroconf calls return once they have started."""
    if inspect.isawaitable(result):
        await result


class ZeroconfBackend:
    """Multicast DNS on the local network via the `zeroconf` package."""

    def __init__(self) -> None:
        self._zc: AsyncZeroconf | None = None
        self._browser: AsyncServiceBrowser | None = None
        self._infos: list[Any] = []
        self._tasks: set[asyncio.Task[None]] = set()

    def _zeroconf(self) -> "AsyncZeroconf":
        if self._zc is None:
            from zeroconf.asyncio import AsyncZeroconf

            self._zc = AsyncZeroconf()
        return self._zc

    async def publish(self, instance_name: str, port: int, txt: dict[str, str]) -> None:
        from zeroconf.asyncio import AsyncServiceInfo

        info = AsyncServiceInfo(
            _ZEROCONF_TYPE,
            f"{instance_name}.{_ZEROCONF_TYPE}",
            port=port,
            properties=txt,
            server=_local_host_name(),
            parsed_addresses=_local_addresses(),
        )
        self._infos.append(info)
        # This checks that the name is free and starts announcing the
        # service. The announcing carries on in the background (it takes a few
        # seconds), so the service can start answering meanwhile.
        announcing = await self._zeroconf().async_register_service(info, allow_name_change=True)
        if isinstance(announcing, asyncio.Task):
            self._tasks.add(announcing)
            announcing.add_done_callback(self._tasks.discard)

    async def browse(
        self,
        on_up: Callable[[RawService], None],
        on_down: Callable[[RawService], None],
    ) -> None:
        from zeroconf import ServiceStateChange
        from zeroconf.asyncio import AsyncServiceBrowser

        suffix = f".{_ZEROCONF_TYPE}"

        def instance(name: str) -> str:
            return name[: -len(suffix)] if name.endswith(suffix) else name

        async def resolve(name: str) -> None:
            from zeroconf.asyncio import AsyncServiceInfo

            info = AsyncServiceInfo(_ZEROCONF_TYPE, name)
            if not await info.async_request(self._zeroconf().zeroconf, 3000):
                return
            txt: dict[str, Any] = {}
            for key, value in info.properties.items():
                k = key.decode("utf-8", "replace") if isinstance(key, bytes) else str(key)
                txt[k] = value if value is not None else b""
            on_up(
                RawService(
                    name=instance(name),
                    host=(info.server or "").rstrip("."),
                    port=info.port or 0,
                    addresses=info.parsed_addresses(),
                    txt=txt,
                )
            )

        def on_change(
            zeroconf: "Zeroconf",
            service_type: str,
            name: str,
            state_change: "ServiceStateChange",
        ) -> None:
            if state_change is ServiceStateChange.Removed:
                on_down(RawService(name=instance(name), host="", port=0))
                return
            task = asyncio.ensure_future(resolve(name))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

        self._browser = AsyncServiceBrowser(
            self._zeroconf().zeroconf, _ZEROCONF_TYPE, handlers=[on_change]
        )

    def query(self) -> None:
        # zeroconf's browser keeps asking the network by itself.
        pass

    async def destroy(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        if self._browser is not None:
            await self._browser.async_cancel()
            self._browser = None
        if self._zc is not None:
            for info in self._infos:
                # Wait for the goodbye announcement to go out too; otherwise
                # other machines keep showing this service until their cached
                # copy expires (over an hour).
                with contextlib.suppress(Exception):
                    await _await_inner(await self._zc.async_unregister_service(info))
            await self._zc.async_close()
            self._zc = None


def parse_dns_sd_txt(line: str) -> dict[str, str]:
    """Splits the TXT line printed by `dns-sd -L` (` key=value key2=a\\\\ b`)
    into key/value pairs. Spaces inside values are escaped with a backslash."""
    out: dict[str, str] = {}
    current = ""
    items: list[str] = []
    text = jsontext.js_trim(line)
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            i += 1
            current += text[i]
        elif ch == " ":
            if current:
                items.append(current)
            current = ""
        else:
            current += ch
        i += 1
    if current:
        items.append(current)
    for item in items:
        eq = item.find("=")
        if eq > 0:
            out[item[:eq]] = item[eq + 1 :]
    return out


_BROWSE_LINE = re.compile(r"^\S+\s+(Add|Rmv)\s+\d+\s+\d+\s+\S+\s+(\S+)\s+(.+)$")
_REACHED_AT = re.compile(r"can be reached at (\S+?)\.?:(\d+)")


class DnsSdBackend:
    """The macOS backend: drives the system mDNSResponder through the `dns-sd` command."""

    def __init__(self) -> None:
        self._children: set[asyncio.subprocess.Process] = set()
        self._tasks: set[asyncio.Task[None]] = set()
        self._seen_on: dict[str, int] = {}
        """Instance name -> number of interfaces it is currently seen on."""
        self._resolved: dict[str, RawService] = {}

    async def _run(self, args: list[str]) -> asyncio.subprocess.Process:
        child = await asyncio.create_subprocess_exec(
            "dns-sd",
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self._children.add(child)
        return child

    def _spawn(self, coro: Any) -> None:
        task: asyncio.Task[None] = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _finish(self, child: asyncio.subprocess.Process) -> None:
        """Stops a child process (if it is still running) and waits for it."""
        if child.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                child.kill()
        with contextlib.suppress(Exception):
            await child.wait()
        self._children.discard(child)

    async def publish(self, instance_name: str, port: int, txt: dict[str, str]) -> None:
        await self._run(
            [
                "-R",
                instance_name,
                f"_{SERVICE_TYPE}._tcp",
                "local",
                str(port),
                *(f"{k}={v}" for k, v in txt.items()),
            ]
        )

    async def browse(
        self,
        on_up: Callable[[RawService], None],
        on_down: Callable[[RawService], None],
    ) -> None:
        child = await self._run(["-B", f"_{SERVICE_TYPE}._tcp", "local"])
        marker = f"_{SERVICE_TYPE}._tcp."

        async def read() -> None:
            assert child.stdout is not None
            async for raw in child.stdout:
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                m = _BROWSE_LINE.match(line)
                if m is None or m.group(2) != marker:
                    continue
                name = m.group(3).strip()
                count = self._seen_on.get(name, 0)
                if m.group(1) == "Add":
                    self._seen_on[name] = count + 1
                    if count == 0:
                        self._spawn(self._resolve(name, on_up))
                else:
                    left = max(0, count - 1)
                    if left > 0:
                        self._seen_on[name] = left
                        continue
                    self._seen_on.pop(name, None)
                    service = self._resolved.pop(name, None) or RawService(
                        name=name, host="", port=0
                    )
                    on_down(service)

        self._spawn(read())

    async def _resolve(self, name: str, on_up: Callable[[RawService], None]) -> None:
        """Looks up one instance's host, port and TXT record, then stops the lookup."""
        child = await self._run(["-L", name, f"_{SERVICE_TYPE}._tcp", "local"])

        async def read() -> None:
            assert child.stdout is not None
            pending: tuple[str, int] | None = None
            async for raw in child.stdout:
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                reach = _REACHED_AT.search(line)
                if reach is not None:
                    pending = (reach.group(1), int(reach.group(2)))
                    continue
                if pending is not None and line.startswith(" "):
                    service = RawService(
                        name=name,
                        host=pending[0],
                        port=pending[1],
                        addresses=[],
                        txt=parse_dns_sd_txt(line),
                    )
                    if name in self._seen_on:
                        self._resolved[name] = service
                        on_up(service)
                    return

        try:
            await asyncio.wait_for(read(), 5)
        except TimeoutError:
            pass
        finally:
            await self._finish(child)

    def query(self) -> None:
        # mDNSResponder keeps asking the network by itself.
        pass

    async def destroy(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        for child in list(self._children):
            await self._finish(child)
        self._children.clear()


def default_backend(env: Mapping[str, str] | None = None) -> MdnsBackend:
    """Picks the mDNS backend for this machine.

    SQUAWK_MDNS=zeroconf|dns-sd overrides ("bonjour", the value an earlier
    version of squawk used, also selects zeroconf).
    """
    choice = (os.environ if env is None else env).get("SQUAWK_MDNS")
    if choice in ("zeroconf", "bonjour"):
        return ZeroconfBackend()
    if choice == "dns-sd":
        return DnsSdBackend()
    if sys.platform == "darwin" and shutil.which("dns-sd") is not None:
        return DnsSdBackend()
    return ZeroconfBackend()


def _js_number(text: str) -> float | None:
    """The port in a TXT record as a number: surrounding whitespace is ignored,
    empty text counts as 0, and text that is not a number gives None."""
    stripped = jsontext.js_trim(text)
    if stripped == "":
        return 0
    try:
        return float(stripped)
    except ValueError:
        return None


def peer_from_service(service: RawService, now: int) -> DiscoveredPeer | None:
    """Reads a peer from a service's TXT record, or returns None if it is not
    a valid squawk record."""
    txt = service.txt

    def text(key: str) -> str | None:
        value = txt.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, bytes | bytearray):
            return bytes(value).decode("utf-8", "replace")
        return None

    key_id = text("id")
    name = text("name")
    fp = text("fp")
    port_text = text("port")
    port = _js_number(port_text) if port_text is not None else float(service.port)
    if not key_id or not is_key_id(key_id) or not name or not fp:
        return None
    if port is None or not port.is_integer() or port <= 0 or port > 65535:
        return None
    addresses = sorted(service.addresses, key=lambda a: ":" in a)
    return DiscoveredPeer(
        name=jsontext.js_slice(name, 64),
        key_id=key_id,
        fingerprint=jsontext.js_slice(fp, 64),
        host=service.host,
        addresses=addresses,
        port=int(port),
        last_seen=now,
    )


DiscoveryEvent = Literal["up", "down"]


class Discovery:
    """Advertises this service and keeps a list of other squawk services seen
    on the network, keyed by key id. Calls listeners added with `on` for `up`
    and `down` with a DiscoveredPeer."""

    def __init__(
        self,
        self_ad: Advertisement,
        *,
        backend: MdnsBackend | None = None,
        now: Callable[[], int] | None = None,
    ) -> None:
        self.self_ad = self_ad
        self.backend: MdnsBackend = default_backend() if backend is None else backend
        self._now = now_ms if now is None else now
        self._by_key: dict[str, DiscoveredPeer] = {}
        self._key_by_instance: dict[str, str] = {}
        """mDNS instance name -> key id, so a "down" (which may lack TXT) can be matched."""
        self._listeners: dict[DiscoveryEvent, list[Callable[[DiscoveredPeer], None]]] = {
            "up": [],
            "down": [],
        }
        self._started = False

    def on(
        self, event: DiscoveryEvent, listener: Callable[[DiscoveredPeer], None]
    ) -> Callable[[], None]:
        """Calls `listener` for each `event`. Returns a function that stops it."""
        self._listeners[event].append(listener)

        def stop() -> None:
            with contextlib.suppress(ValueError):
                self._listeners[event].remove(listener)

        return stop

    def _emit(self, event: DiscoveryEvent, peer: DiscoveredPeer) -> None:
        for listener in list(self._listeners[event]):
            try:
                listener(peer)
            except Exception as err:
                _log(f'a "{event}" listener raised {type(err).__name__}: {err}')

    def instance_name(self) -> str:
        """The mDNS instance name we advertise: display name plus a fingerprint
        prefix, so it is unique."""
        short = re.sub(r"[^0-9a-fA-F]", "", self.self_ad.fingerprint)[:8]
        return f"{jsontext.js_slice(self.self_ad.name, 40)} ({short})"

    async def start(self) -> None:
        if self._started:
            return
        self._started = True
        await self.backend.publish(
            self.instance_name(),
            self.self_ad.port,
            {
                "name": self.self_ad.name,
                "id": self.self_ad.key_id,
                "fp": self.self_ad.fingerprint,
                "port": str(self.self_ad.port),
            },
        )
        await self.backend.browse(self._handle_up, self._handle_down)

    async def stop(self) -> None:
        if not self._started:
            return
        self._started = False
        await self.backend.destroy()

    def refresh(self) -> None:
        """Asks the network again; answers arrive as `up` events."""
        self.backend.query()

    def peers(self) -> list[DiscoveredPeer]:
        """Peers currently seen, excluding ourselves, most recently seen first."""
        return sorted(self._by_key.values(), key=lambda p: p.last_seen, reverse=True)

    def peer(self, key_id: str) -> DiscoveredPeer | None:
        """The peer advertising this key, if seen."""
        return self._by_key.get(key_id)

    def _handle_up(self, service: RawService) -> None:
        peer = peer_from_service(service, self._now())
        if peer is None or peer.key_id == self.self_ad.key_id:
            return
        self._key_by_instance[service.name] = peer.key_id
        self._by_key[peer.key_id] = peer
        self._emit("up", peer)

    def _handle_down(self, service: RawService) -> None:
        key_id = self._key_by_instance.get(service.name)
        if key_id is None:
            parsed = peer_from_service(service, self._now())
            key_id = None if parsed is None else parsed.key_id
        if not key_id:
            return
        self._key_by_instance.pop(service.name, None)
        peer = self._by_key.pop(key_id, None)
        if peer is None:
            return
        self._emit("down", peer)
