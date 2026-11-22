"""Sending sealed messages between hosts over WebSocket.

Every service runs a WebSocket listener. When a connection opens, both sides
prove who they are before anything else is exchanged:

  1. Each side sends `hello` with its key id and a fresh 32-byte random
     challenge.
  2. Each side answers with `auth`: an ed25519 signature over the other
     side's challenge plus both key ids. Binding both keys means a signature
     made for one connection cannot be relayed into another.
  3. Each side checks the signature against the claimed key, then asks
     whether that key is allowed: normally only paired, unblocked contacts
     are. The side that dialled also checks that it reached the key it meant
     to reach. Otherwise the connection is closed.
  4. Each side that accepts the other sends `ok`. A side treats the
     connection as ready only when it has accepted the other side AND
     received the other side's `ok`, so neither side starts sending to a
     peer that is about to refuse it.

After that, the dialling side sends `msg` frames (a message id plus the
sealed message). The receiver opens the sealed message (which checks the
signature, the recipient, the timestamp and that the id is new), hands it to
the daemon, and answers `ack`. Messages without an ack stay in the store's
outbound queue and are retried with backoff.

A dialling side may also send `sessions-req` (with a request id); the
receiver answers `sessions` with the labels and branches of the Claude Code
sessions open on its machine, or an empty list if its person turned sharing
off. Paths and inbox tokens are never sent. This exchange is new in the
Python version; a Node service does not answer it.

Other frame types (used by pairing) can be added with `on_frame`.

This is the Python version of src/network.ts and speaks the same protocol,
so Node and Python services can send to each other.
"""

import asyncio
import contextlib
import re
import socket
import sys
import uuid
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, cast

from websockets.asyncio.client import ClientConnection, connect
from websockets.asyncio.server import Server, ServerConnection, serve
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Request, Response
from websockets.protocol import State

from squawk import jsontext
from squawk.crypto import ed25519_sign, ed25519_verify, random_bytes
from squawk.daemon import Peer, PeerSession, PeerSessions, Transport
from squawk.discovery import Advertisement, DiscoveredPeer, Discovery
from squawk.encoding import from_base64url, is_key_id, key_from_id, to_base64url
from squawk.envelope import (
    EnvelopeError,
    EnvelopeValidationError,
    ReplayGuard,
    open_sealed,
    parse_sealed,
    seal,
)
from squawk.identity import Identity, fingerprint
from squawk.store import OutboundItem
from squawk.timefmt import iso_from_ms, now_ms

if TYPE_CHECKING:
    from squawk.daemon import Daemon

PROTOCOL_VERSION = 1
_AUTH_PREFIX = "squawk ws auth v1"
_MAX_PAYLOAD = 1 << 20


@dataclass(frozen=True)
class Address:
    """Where to reach a peer's WebSocket listener."""

    host: str
    port: int


Frame = dict[str, Any]
"""A JSON frame on an authenticated connection: an object with a string "t"."""

Authorization = Literal["paired", "pairing", False]
"""What a connection's peer is allowed to do once authenticated."""


def auth_message(challenge: str, signer_key: str, other_key: str) -> bytes:
    """Text signed in `auth`: the challenge we were sent, our key, their key."""
    return jsontext.utf8(f"{_AUTH_PREFIX}\n{challenge}\n{signer_key}\n{other_key}")


REFUSED_CODE = 4001
"""WebSocket close code used when one side refuses the other during the handshake."""

NOT_PAIRED = "not a paired contact"
"""The reason given when a key is neither a paired contact nor being paired with."""


class LinkError(Exception):
    """Raised when a connection to another service fails or is refused."""


def _log(text: str) -> None:
    print(f"squawkd: {text}", file=sys.stderr)


def _is_protocol_version(value: object) -> bool:
    return (
        isinstance(value, int | float) and not isinstance(value, bool) and value == PROTOCOL_VERSION
    )


_CLOSE = object()
"""Put in a link's send queue to close the connection after the frames before it."""


class PeerLink:
    """One WebSocket connection to another squawk service, with the handshake
    described at the top of this file.

    Make one from an open connection inside a running event loop; it starts
    reading at once. `ready` completes with the other side's key id once the
    handshake is done, or fails with `LinkError`.
    """

    def __init__(
        self,
        ws: ClientConnection | ServerConnection,
        self_identity: Identity,
        authorize: Callable[[str, "PeerLink"], Authorization],
        *,
        outgoing: bool,
        expect_key: str | None = None,
        timeout_ms: int = 10_000,
        remote_address: str | None = None,
        on_ready: Callable[["PeerLink"], None] | None = None,
    ) -> None:
        """`on_ready` is called as soon as the handshake completes, before any
        later frame is processed, so frame listeners added there miss nothing."""
        self.ws = ws
        self.outgoing = outgoing
        self.remote_address = remote_address
        """The other side's IP address, for incoming connections."""
        self.peer_key: str | None = None
        """The other side's key id, once it has proved it holds that key."""
        self.authorization: Authorization = False
        loop = asyncio.get_running_loop()
        self.ready: asyncio.Future[str] = loop.create_future()
        # Nobody may wait on `ready`; mark its failure as seen so asyncio does
        # not report it.
        self.ready.add_done_callback(lambda f: f.cancelled() or f.exception())
        self._challenge = to_base64url(random_bytes(32))
        self._self = self_identity
        self._authorize = authorize
        self._expect_key = expect_key
        self._on_ready = on_ready
        self._sent_auth = False
        self._got_auth = False
        self._got_ok = False
        self._is_ready = False
        self._closed = False
        self._frame_listeners: list[Callable[[Frame], None]] = []
        self._close_listeners: list[Callable[[], None]] = []
        self._outbox: asyncio.Queue[Any] = asyncio.Queue()
        timer = loop.call_later(timeout_ms / 1000, self._fail, "handshake timed out")
        self.ready.add_done_callback(lambda _f: timer.cancel())
        self._send_raw(
            {"t": "hello", "v": PROTOCOL_VERSION, "key": self_identity.id,
             "challenge": self._challenge}
        )  # fmt: skip
        self._writer = asyncio.ensure_future(self._write_loop())
        self._reader = asyncio.ensure_future(self._read_loop())

    def send(self, frame: Frame) -> None:
        """Sends a frame. Only valid after the handshake."""
        self._send_raw(frame)

    def on_frame(self, fn: Callable[[Frame], None]) -> Callable[[], None]:
        """Calls `fn` for every frame after the handshake. Returns an unsubscribe function."""
        self._frame_listeners.append(fn)

        def stop() -> None:
            with contextlib.suppress(ValueError):
                self._frame_listeners.remove(fn)

        return stop

    def on_close(self, fn: Callable[[], None]) -> Callable[[], None]:
        """Calls `fn` once when the connection closes (at once if it already has).

        Returns an unsubscribe function.
        """
        if self._closed:
            fn()
            return lambda: None
        self._close_listeners.append(fn)

        def stop() -> None:
            with contextlib.suppress(ValueError):
                self._close_listeners.remove(fn)

        return stop

    @property
    def open(self) -> bool:
        return not self._closed and self.ws.state is State.OPEN

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self, code: int = 1000, reason: str = "") -> None:
        """Closes the connection once the frames already sent have gone out."""
        if not self._closed:
            self._outbox.put_nowait((_CLOSE, code, reason))

    def terminate(self) -> None:
        """Drops the connection at once."""
        transport = self.ws.transport
        if transport is not None:
            transport.abort()

    async def wait_closed(self) -> None:
        """Returns once the connection has closed and the link has finished reading."""
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.shield(self._reader)

    def _send_raw(self, frame: Frame) -> None:
        if not self._closed:
            self._outbox.put_nowait(jsontext.stringify(frame))

    async def _write_loop(self) -> None:
        while True:
            item = await self._outbox.get()
            try:
                if isinstance(item, tuple):
                    _, code, reason = item
                    await self.ws.close(code, reason)
                    return
                await self.ws.send(cast(str, item))
            except ConnectionClosed:
                return
            except Exception as err:
                self._fail(str(err) or type(err).__name__)
                return

    async def _read_loop(self) -> None:
        try:
            while True:
                data = await self.ws.recv()
                self._handle(data)
                # Let code waiting on `ready` run before the next frame, so
                # listeners it adds right after the handshake miss nothing.
                await asyncio.sleep(0)
        except ConnectionClosed as closed:
            rcvd = closed.rcvd
            if rcvd is not None and rcvd.code == REFUSED_CODE and rcvd.reason != "":
                self._fail(f"the other side refused the connection: {rcvd.reason}")
            else:
                self._fail("connection closed")
        except Exception as err:
            self._fail(str(err) or type(err).__name__)
        finally:
            self._mark_closed()

    def _mark_closed(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._writer.cancel()
        self._fail("connection closed")
        listeners, self._close_listeners = self._close_listeners, []
        for fn in listeners:
            try:
                fn()
            except Exception as err:
                _log(f"a connection close listener raised {type(err).__name__}: {err}")

    def _fail(self, reason: str) -> None:
        if not self.ready.done():
            self.ready.set_exception(LinkError(reason))

    def _refuse(self, reason: str) -> None:
        self._fail(reason)
        self.close(REFUSED_CODE, jsontext.js_slice(reason, 100))

    def _handle(self, data: str | bytes) -> None:
        try:
            text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
            frame = jsontext.parse(text)
            if not isinstance(frame, dict) or not isinstance(frame.get("t"), str):
                raise ValueError("no type")
        except ValueError:
            self._refuse("bad frame")
            return
        t = frame["t"]
        if t == "hello":
            key = frame.get("key")
            challenge = frame.get("challenge")
            if (
                self.peer_key is not None
                or not _is_protocol_version(frame.get("v"))
                or not isinstance(key, str)
                or not is_key_id(key)
                or not isinstance(challenge, str)
                or jsontext.js_length(challenge) < 32
                or jsontext.js_length(challenge) > 128
            ):
                self._refuse("bad hello")
                return
            if self._expect_key is not None and key != self._expect_key:
                self._refuse("reached a different key than expected")
                return
            if key == self._self.id:
                self._refuse("connected to myself")
                return
            self.peer_key = key
            sig = ed25519_sign(auth_message(challenge, self._self.id, key), self._self.secret_key)
            self._send_raw({"t": "auth", "sig": to_base64url(sig)})
            self._sent_auth = True
            self._maybe_ready()
            return
        if t == "auth":
            peer_key = self.peer_key
            sig_text = frame.get("sig")
            if peer_key is None or self._got_auth or not isinstance(sig_text, str):
                self._refuse("unexpected auth")
                return
            try:
                valid = ed25519_verify(
                    from_base64url(sig_text),
                    auth_message(self._challenge, peer_key, self._self.id),
                    key_from_id(peer_key),
                )
            except Exception:
                valid = False
            if not valid:
                self._refuse("bad signature")
                return
            authorization = self._authorize(peer_key, self)
            if not authorization:
                self._refuse(NOT_PAIRED)
                return
            self.authorization = authorization
            self._got_auth = True
            self._send_raw({"t": "ok"})
            self._maybe_ready()
            return
        if t == "ok":
            if self.peer_key is None or self._got_ok:
                self._refuse("unexpected ok")
                return
            self._got_ok = True
            self._maybe_ready()
            return
        if not self._got_auth or not self._sent_auth or not self._got_ok:
            self._refuse("frame before handshake")
            return
        for fn in list(self._frame_listeners):
            try:
                fn(frame)
            except Exception as err:
                _log(f"a frame listener raised {type(err).__name__}: {err}")

    def _maybe_ready(self) -> None:
        if (
            self._sent_auth
            and self._got_auth
            and self._got_ok
            and self.peer_key is not None
            and not self._is_ready
        ):
            self._is_ready = True
            if self._on_ready is not None:
                self._on_ready(self)
            if not self.ready.done():
                self.ready.set_result(self.peer_key)


DEFAULT_MAX_QUEUE_AGE_MS = 7 * 24 * 60 * 60 * 1000
"""Default for `NetworkTransport`'s `max_queue_age_ms`: 7 days."""


_LINK_LOCAL = re.compile(r"fe[89ab][0-9a-f]:", re.IGNORECASE)


def dialable(host: str) -> bool:
    """False for addresses squawk cannot put in a WebSocket URL: IPv6
    link-local addresses (fe80::/10), whether or not they carry a
    "%interface" zone. URLs cannot express the zone, and without one the
    address cannot be routed."""
    return not ("%" in host or _LINK_LOCAL.match(host) is not None)


def address_setting_key(key_id: str) -> str:
    """The settings key under which a contact's last known address is kept."""
    return f"address:{key_id}"


def _listening_socket(host: str | None, port: int) -> socket.socket:
    """A bound TCP socket for the listener. With no host it accepts IPv4 and
    IPv6 on one port (as Node does), falling back to IPv4 only."""
    if host is not None:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        return sock
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind(("::", port))
        return sock
    except OSError:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        return sock


async def _discard(link: PeerLink) -> None:
    """Closes a link that failed its handshake. A refusal has already started
    closing it with the reason, which is given a moment to reach the other
    side before the connection is dropped."""
    link.close()
    try:
        await asyncio.wait_for(link.wait_closed(), 1)
    except TimeoutError:
        link.terminate()


def _error_text(err: BaseException) -> str:
    return str(err) or type(err).__name__


SESSIONS_REQUEST = "sessions-req"
SESSIONS_ANSWER = "sessions"
MAX_PEER_SESSIONS = 100


def parse_sessions_answer(frame: Frame) -> PeerSessions:
    """Checks a `sessions` frame from another service and keeps only what is
    expected: at most 100 sessions, each a label and an optional branch."""
    raw = frame.get("sessions")
    sessions: list[PeerSession] = []
    if isinstance(raw, list):
        for item in raw[:MAX_PEER_SESSIONS]:
            if not isinstance(item, dict):
                continue
            label = item.get("label")
            branch = item.get("branch")
            if not isinstance(label, str) or label == "":
                continue
            sessions.append(
                {
                    "label": jsontext.js_slice(label, 256),
                    "branch": jsontext.js_slice(branch, 256) if isinstance(branch, str) else None,
                }
            )
    return {"shared": frame.get("shared") is not False, "sessions": sessions}


class NetworkTransport(Transport):
    """The daemon's transport: a WebSocket listener for other hosts, mDNS
    discovery, and delivery of the outbound queue with retries.

    Options:
      port: TCP port for the WebSocket listener; 0 picks a free one.
      host: interface to listen on; defaults to all.
      discovery: a `Discovery`, or False to turn mDNS off (tests); default is real mDNS.
      resolve: extra address lookup tried before discovery (tests use this).
      retry_interval_ms: how often due messages are retried.
      ack_timeout_ms: how long to wait for an ack.
      handshake_timeout_ms: how long the connection handshake may take.
      max_queue_age_ms: how long a message may wait in the outbound queue
        before squawk gives up and marks it failed. Default 7 days.
      sessions_timeout_ms: how long to wait for a contact's list of sessions.
    """

    def __init__(
        self,
        *,
        port: int = 0,
        host: str | None = None,
        discovery: Discovery | Literal[False] | None = None,
        resolve: Callable[[str], Address | None] | None = None,
        retry_interval_ms: int = 1000,
        ack_timeout_ms: int = 10_000,
        handshake_timeout_ms: int = 10_000,
        max_queue_age_ms: int = DEFAULT_MAX_QUEUE_AGE_MS,
        sessions_timeout_ms: int = 5_000,
    ) -> None:
        self._port_option = port
        self._host = host
        self._discovery_option = discovery
        self._resolve = resolve
        self._retry_interval_ms = retry_interval_ms
        self._ack_timeout_ms = ack_timeout_ms
        self._handshake_timeout_ms = handshake_timeout_ms
        self._max_queue_age_ms = max_queue_age_ms
        self._sessions_timeout_ms = sessions_timeout_ms
        self._daemon: Daemon | None = None
        self._server: Server | None = None
        self.discovery: Discovery | None = None
        self._timer: asyncio.Task[None] | None = None
        self._guard: ReplayGuard | None = None
        self._links: dict[str, PeerLink] = {}
        self._delivering: dict[str, asyncio.Task[None]] = {}
        """Deliveries in progress, by recipient key."""
        self._stopped = False
        self._incoming_links: set[PeerLink] = set()
        self._listen_port = 0
        self._tasks: set[asyncio.Task[Any]] = set()
        self.unpaired_policy: Callable[[str, PeerLink], Authorization] | None = None
        """Decides on keys that are not paired contacts (pairing sets this)."""
        self.on_link: Callable[[PeerLink], None] | None = None
        """Called for every authenticated link, incoming or outgoing."""

    @property
    def port(self) -> int:
        """The port the WebSocket listener is bound to."""
        return self._listen_port

    def _spawn(self, coro: Coroutine[Any, Any, Any]) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def start(self, daemon: "Daemon") -> None:
        self._daemon = daemon
        self._guard = ReplayGuard(seen=daemon.store.seen_ids())

        def process_request(connection: ServerConnection, request: Request) -> Response | None:
            if request.headers.get("Upgrade", "").lower() != "websocket":
                return connection.respond(426, "squawk speaks WebSocket\n")
            return None

        sock = _listening_socket(self._host, self._port_option)
        try:
            self._server = await serve(
                self._accept_incoming,
                sock=sock,
                max_size=_MAX_PAYLOAD,
                compression=None,
                process_request=process_request,
            )
        except BaseException:
            sock.close()
            raise
        self._listen_port = int(self._server.sockets[0].getsockname()[1])

        if self._discovery_option is not False:
            identity = daemon.identity
            self.discovery = self._discovery_option or Discovery(
                Advertisement(
                    name=identity.name,
                    key_id=identity.id,
                    fingerprint=fingerprint(identity.public_key),
                    port=self._listen_port,
                )
            )
            self.discovery.on("up", self._peer_came_online)
            await self.discovery.start()
        self._timer = asyncio.ensure_future(self._tick())
        self.flush()

    async def _tick(self) -> None:
        while True:
            await asyncio.sleep(self._retry_interval_ms / 1000)
            self.flush()

    async def stop(self) -> None:
        self._stopped = True
        if self._timer is not None:
            self._timer.cancel()
        if self.discovery is not None:
            await self.discovery.stop()
        for link in [*self._links.values(), *self._incoming_links]:
            link.close(1001, "shutting down")
        self._links.clear()
        self._incoming_links.clear()
        server = self._server
        if server is not None:
            server.close(close_connections=True)
            try:
                await asyncio.wait_for(server.wait_closed(), 5)
            except TimeoutError:
                for connection in server.connections:
                    if connection.transport is not None:
                        connection.transport.abort()
        await asyncio.gather(*self._delivering.values(), return_exceptions=True)
        for task in list(self._tasks):
            task.cancel()

    def kick(self, envelope: Any = None) -> None:
        self.flush()

    def peers(self) -> list[Peer]:
        """Peers seen on the network, with whether each one is a paired contact."""
        store = None if self._daemon is None else self._daemon.store
        result: list[Peer] = []
        for p in [] if self.discovery is None else self.discovery.peers():
            contact = None if store is None else store.get_contact(p.key_id)
            result.append(
                {
                    "name": p.name,
                    "key_id": p.key_id,
                    "fingerprint": p.fingerprint,
                    "host": p.host,
                    "port": p.port,
                    "paired": contact is not None and contact.trust == "paired",
                }
            )
        return result

    def disconnect(self, key_id: str) -> None:
        """Closes every connection with this key (used when a contact is blocked)."""
        for link in [*self._links.values(), *self._incoming_links]:
            if link.peer_key == key_id:
                link.close(REFUSED_CODE, "blocked")
        self._links.pop(key_id, None)

    def find_peer(self, name_or_key: str) -> DiscoveredPeer | None:
        """A discovered peer by name or key id, for pairing."""
        everyone = [] if self.discovery is None else self.discovery.peers()
        return next((p for p in everyone if p.key_id == name_or_key), None) or next(
            (p for p in everyone if p.name == name_or_key), None
        )

    def resolve(self, key_id: str) -> Address | None:
        """Where to reach a key: the first of `candidates`."""
        found = self.candidates(key_id)
        return found[0] if found else None

    def candidates(self, key_id: str) -> list[Address]:
        """Every address worth trying for a key, best first: the test resolver,
        then what mDNS advertises, then the last address that worked. mDNS
        advertisements are not authenticated, so the saved address is always
        kept as a fallback: another host advertising this key cannot stop
        delivery. Addresses that cannot be dialled are left out."""
        found: list[Address] = []

        def add(address: Address | None) -> None:
            if address is not None and dialable(address.host) and address not in found:
                found.append(address)

        if self._resolve is not None:
            add(self._resolve(key_id))
        seen = None if self.discovery is None else self.discovery.peer(key_id)
        if seen is not None:
            for host in seen.addresses:
                add(Address(host, seen.port))
            add(Address(seen.host, seen.port))
        saved = None if self._daemon is None else self._daemon.store.get_setting(
            address_setting_key(key_id)
        )  # fmt: skip
        if saved:
            host, _, port = saved.rpartition(":")
            with contextlib.suppress(ValueError):
                add(Address(host, int(port)))
        return found

    async def dial(self, address: Address, expect_key: str | None = None) -> PeerLink:
        """Opens and authenticates a connection to `address`, expecting `expect_key` if given."""
        daemon = self._require_daemon()
        host = f"[{address.host}]" if ":" in address.host else address.host
        timeout = self._handshake_timeout_ms / 1000
        try:
            ws = await connect(
                f"ws://{host}:{address.port}/",
                max_size=_MAX_PAYLOAD,
                compression=None,
                proxy=None,
                open_timeout=timeout,
            )
        except TimeoutError:
            raise LinkError("handshake timed out") from None
        except OSError as err:
            raise LinkError(_error_text(err)) from err
        except Exception as err:
            raise LinkError(_error_text(err)) from err
        link = PeerLink(
            ws,
            daemon.identity,
            self._authorize,
            outgoing=True,
            expect_key=expect_key,
            timeout_ms=self._handshake_timeout_ms,
        )
        try:
            await link.ready
        except BaseException:
            await _discard(link)
            raise
        if self.on_link is not None:
            self.on_link(link)
        return link

    def flush(self) -> "asyncio.Future[Any]":
        """Starts delivering every due message, one connection per recipient.

        Recipients are handled independently: a recipient whose delivery is
        still in progress (for example a slow dial) is skipped this time and
        does not hold up the others. Safe to call often. The result completes
        when the deliveries in progress have finished; callers may ignore it.
        """
        daemon = self._daemon
        if daemon is None or self._stopped:
            return asyncio.gather()
        daemon.store.fail_expired(self._max_queue_age_ms)
        if self._guard is not None:
            self._guard.prune()
        by_recipient: dict[str, list[OutboundItem]] = {}
        for item in daemon.store.due_outbound():
            if item.recipient in self._delivering:
                continue
            by_recipient.setdefault(item.recipient, []).append(item)
        for recipient, items in by_recipient.items():
            task = asyncio.ensure_future(self._deliver_to(recipient, items))
            self._delivering[recipient] = task

            def done(_task: "asyncio.Task[None]", recipient: str = recipient) -> None:
                self._delivering.pop(recipient, None)
                # Pick up anything queued for this recipient meanwhile.
                self.flush()

            task.add_done_callback(done)
        return asyncio.gather(*self._delivering.values(), return_exceptions=True)

    async def _deliver_to(self, recipient: str, items: list[OutboundItem]) -> None:
        store = self._require_daemon().store
        try:
            contact = store.get_contact(recipient)
            if contact is None or contact.trust != "paired":
                raise LinkError("recipient is not a paired contact")
            link = await self._link_to(recipient)
            results = await asyncio.gather(
                *(self._send_one(link, item) for item in items), return_exceptions=True
            )
            failure = next((r for r in results if isinstance(r, BaseException)), None)
            if failure is not None:
                raise failure
        except Exception as err:
            error = _error_text(err)
            for item in items:
                with contextlib.suppress(Exception):
                    if store.get_outbound(item.message_id) is not None:
                        store.record_attempt(item.message_id, error=error)

    async def _link_to(self, recipient: str) -> PeerLink:
        existing = self._links.get(recipient)
        if existing is not None and existing.open:
            return existing
        addresses = self.candidates(recipient)
        if not addresses:
            raise LinkError("recipient is not on the network")
        link: PeerLink | None = None
        address: Address | None = None
        last_error: BaseException | None = None
        for candidate in addresses:
            try:
                link = await self.dial(candidate, recipient)
                address = candidate
                break
            except Exception as err:
                last_error = err
        if link is None or address is None:
            assert last_error is not None
            raise last_error
        if link.authorization != "paired":
            link.close()
            raise LinkError("recipient is not a paired contact")
        self._links[recipient] = link

        def forget() -> None:
            if self._links.get(recipient) is link:
                self._links.pop(recipient, None)

        link.on_close(forget)
        self._require_daemon().store.set_setting(
            address_setting_key(recipient), f"{address.host}:{address.port}"
        )
        return link

    async def _send_one(self, link: PeerLink, item: OutboundItem) -> None:
        daemon = self._require_daemon()
        store = daemon.store
        # Sealed afresh with the current time, so a message that waited in the
        # queue is still within the receiver's freshness window.
        envelope = cast(Any, {**item.envelope, "sent_at": iso_from_ms(now_ms())})
        sealed = seal(envelope, daemon.identity)
        loop = asyncio.get_running_loop()
        answer: asyncio.Future[None] = loop.create_future()

        def settle(error: str | None) -> None:
            if answer.done():
                return
            if error is None:
                answer.set_result(None)
            else:
                answer.set_exception(LinkError(error))

        def on_frame(frame: Frame) -> None:
            if frame.get("id") != item.message_id:
                return
            if frame["t"] == "ack":
                store.mark_acknowledged(item.message_id)
                settle(None)
            elif frame["t"] == "nack":
                settle(f"refused: {_js_string(frame.get('error'))}")

        stop_frames = link.on_frame(on_frame)
        stop_close = link.on_close(lambda: settle("connection closed before acknowledgement"))
        timer = loop.call_later(self._ack_timeout_ms / 1000, settle, "no acknowledgement")
        try:
            link.send({"t": "msg", "id": item.message_id, "sealed": sealed})
            await answer
        finally:
            timer.cancel()
            stop_frames()
            stop_close()

    async def request_sessions(self, key_id: str) -> PeerSessions:
        """Asks a paired contact's service which Claude Code sessions are open
        there. Raises `LinkError` if it cannot be reached or does not answer
        in time (a Node service never answers)."""
        store = self._require_daemon().store
        contact = store.get_contact(key_id)
        if contact is None or contact.trust != "paired":
            raise LinkError("not a paired contact")
        link = await self._link_to(key_id)
        request_id = str(uuid.uuid4())
        loop = asyncio.get_running_loop()
        answer: asyncio.Future[PeerSessions] = loop.create_future()

        def on_frame(frame: Frame) -> None:
            if (
                frame["t"] == SESSIONS_ANSWER
                and frame.get("id") == request_id
                and not answer.done()
            ):
                answer.set_result(parse_sessions_answer(frame))

        def on_close() -> None:
            if not answer.done():
                answer.set_exception(LinkError("connection closed before an answer"))

        stop_frames = link.on_frame(on_frame)
        stop_close = link.on_close(on_close)
        try:
            link.send({"t": SESSIONS_REQUEST, "id": request_id})
            return await asyncio.wait_for(answer, self._sessions_timeout_ms / 1000)
        except TimeoutError:
            raise LinkError(
                "their squawk service did not answer (it may be an older version that "
                "cannot list sessions)"
            ) from None
        finally:
            stop_frames()
            stop_close()

    def _answer_sessions(self, link: PeerLink, frame: Frame) -> None:
        request_id = frame.get("id")
        if link.authorization != "paired" or not isinstance(request_id, str):
            return
        answer = self._require_daemon().sessions_for_peer()
        link.send(
            {
                "t": SESSIONS_ANSWER,
                "id": jsontext.js_slice(request_id, 128),
                "shared": answer["shared"],
                "sessions": answer["sessions"],
            }
        )

    def _authorize(self, key: str, link: PeerLink) -> Authorization:
        contact = None if self._daemon is None else self._daemon.store.get_contact(key)
        if contact is not None and contact.trust == "blocked":
            return False
        if contact is not None and contact.trust == "paired":
            return "paired"
        if self.unpaired_policy is None:
            return False
        return self.unpaired_policy(key, link)

    async def _accept_incoming(self, ws: ServerConnection) -> None:
        daemon = self._require_daemon()
        remote = ws.remote_address
        remote_address: str | None = None
        if isinstance(remote, tuple) and remote:
            remote_address = str(remote[0]).removeprefix("::ffff:")

        def on_frame(ready: PeerLink, frame: Frame) -> None:
            if frame["t"] == "msg":
                self._receive(ready, frame)
            elif frame["t"] == SESSIONS_REQUEST:
                self._answer_sessions(ready, frame)

        def on_ready(ready: PeerLink) -> None:
            ready.on_frame(lambda frame: on_frame(ready, frame))
            if self.on_link is not None:
                self.on_link(ready)

        link = PeerLink(
            ws,
            daemon.identity,
            self._authorize,
            outgoing=False,
            timeout_ms=self._handshake_timeout_ms,
            remote_address=remote_address,
            on_ready=on_ready,
        )
        self._incoming_links.add(link)
        link.on_close(lambda: self._incoming_links.discard(link))
        try:
            await link.ready
        except LinkError:
            await _discard(link)
        await link.wait_closed()

    def _receive(self, link: PeerLink, frame: Frame) -> None:
        daemon = self._require_daemon()
        raw_id = frame.get("id")
        id = raw_id if isinstance(raw_id, str) else None

        def nack(error: str) -> None:
            reply: Frame = {"t": "nack"}
            if id is not None:
                reply["id"] = id
            reply["error"] = error
            link.send(reply)

        if link.authorization != "paired":
            nack("not a paired contact")
            return
        try:
            sealed = parse_sealed(frame.get("sealed"))
        except EnvelopeValidationError:
            sealed = None
        if sealed is None or id is None:
            nack("malformed")
            return
        if sealed["from"] != link.peer_key:
            nack("sender does not match the connection")
            return
        guard = self._require_guard()
        try:
            # Checks freshness and that the id is new, without recording it.
            envelope = open_sealed(sealed, daemon.identity, guard)
            if envelope["id"] != id:
                nack("id does not match the message")
                return
            conflict = daemon.store.incoming_conflict(envelope)
            if conflict is not None:
                nack(conflict)
                return
            daemon.deliver_incoming(envelope, remote_address=link.remote_address or "")
            # Recorded only once stored: if storing failed, the sender's retry
            # must not be refused as a replay.
            guard.record(envelope)
            link.send({"t": "ack", "id": id})
        except Exception as err:
            # A repeat of a message we already stored from this sender: it
            # missed our ack, so acknowledge again to stop it retrying.
            stored = daemon.store.get_message(id)
            if (
                isinstance(err, EnvelopeError)
                and err.code == "replay"
                and stored is not None
                and stored.direction == "in"
                and stored.peer == link.peer_key
            ):
                link.send({"t": "ack", "id": id})
                return
            nack(err.code if isinstance(err, EnvelopeError) else "error")

    def _peer_came_online(self, peer: DiscoveredPeer) -> None:
        if self._daemon is None:
            return
        contact = self._daemon.store.get_contact(peer.key_id)
        if contact is not None and contact.trust == "paired":
            self.flush()

    def _require_guard(self) -> ReplayGuard:
        if self._guard is None:
            raise RuntimeError("transport is not started")
        return self._guard

    def _require_daemon(self) -> "Daemon":
        if self._daemon is None:
            raise RuntimeError("transport is not started")
        return self._daemon


def _js_string(value: object) -> str:
    """`String(value)` as JavaScript writes it, for the common JSON values."""
    if value is None:
        return "undefined"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    return jsontext.stringify(value)
