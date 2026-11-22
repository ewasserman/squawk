"""The service's connection to its relay (docs/plan/relay.md).

The service keeps one WebSocket connection to the relay it is set to use,
and reconnects with backoff (1 second, doubling to at most 5 minutes, with
random jitter) when it drops. After proving its key, it sends its allow
list (its paired, unblocked contacts) and asks for waiting messages; from
then on the relay pushes each new message as it arrives. The allow list is
sent again whenever the contacts change.

For each message the relay delivers, the client:

  1. opens it (checking the signature and that it is addressed to us);
  2. checks that the signed sender is a paired, unblocked contact. On the
     local network the sender must be the key that proved itself on the
     connection; here the connection is to the relay, so the signed sender
     inside the envelope is what counts;
  3. checks its age (up to 7 days, see `envelope.MAX_RELAYED_AGE_MS`) and
     that its id is new;
  4. stores it and passes it on with `Daemon.deliver_incoming`;
  5. sends the sender a signed receipt (`ack`, or `nack` with the reason
     when it is refused for good), through the relay;
  6. tells the relay to delete it.

If anything fails before the receipt is on its way, the message is not
deleted and comes back after the next reconnection; the replay check then
turns it into a second receipt rather than a second copy.

A receipt that arrives marks the message it answers delivered (`ack`) or
failed (`nack`), but only if it is a message this service sent to that same
contact.

Messages whose signature or encryption does not check out, and messages
from keys that are not paired contacts, are deleted without a receipt: we
cannot tell who sent them, or do not answer them.

Pairing through the relay (`create_invite`, `join_invite`) runs in a pairing
room: the relay passes frames between the two sides unchanged. A `RoomLink`
offers the same calls as a direct connection (`PeerLink`), so pairing.py
runs the same exchange over either. The relay, not a signed handshake, says
which key is on the other side, so the 6-digit code comparison is what
catches a relay that lies (docs/plan/security.md, threat 13).
"""

import asyncio
import contextlib
import random
import sys
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Any

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed

from squawk import jsontext
from squawk.crypto import ed25519_sign
from squawk.encoding import is_key_id, to_base64url
from squawk.envelope import (
    LIVE_KINDS,
    RECEIPT_KINDS,
    Envelope,
    EnvelopeError,
    ReceiptKind,
    ReplayGuard,
    Sealed,
    create_receipt,
    open_sealed,
    parse_receipt,
    seal,
)
from squawk.network import LinkError, auth_message
from squawk.relay_url import check_relay_url

if TYPE_CHECKING:
    from squawk.daemon import Daemon

RELAY_URL_KEY = "relay_url"
"""Setting key holding the URL of the relay this service uses."""

RELAY_ALLOW_PLAIN_KEY = "relay_allow_plain"
"""Setting key holding "on" when the person allowed a plain ws:// relay URL."""

PROTOCOL_VERSION = 1
_MAX_FRAME = 1 << 20

PERMANENT_REFUSALS = frozenset({"malformed", "sender-mismatch", "too-large"})
"""Relay refusals that sending the same message again cannot change. The
others ("not-allowed", "mailbox-full", "rate-limited", "offline", "error")
can clear up: "not-allowed" can mean the recipient has not connected to this
relay yet, or has not added us to its allow list yet."""


def _log(text: str) -> None:
    print(f"squawkd: relay: {text}", file=sys.stderr, flush=True)


class RelayRefused(LinkError):
    """The relay refused a request; `reason` is its reason code."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"the relay refused it: {reason}")
        self.reason = reason

    @property
    def permanent(self) -> bool:
        return self.reason in PERMANENT_REFUSALS


class RoomLink:
    """The pairing frames exchanged with one other service through a
    pairing room at the relay. Frames are sent in order; `close` ends the
    room (`pair-end`)."""

    outgoing = False

    def __init__(self, client: "RelayClient", room: str, peer_key: str) -> None:
        self.room = room
        self.peer_key: str | None = peer_key
        """The other side's key id, as the relay reports it."""
        self.remote_address: str | None = None
        self._client = client
        self._frame_listeners: list[Callable[[dict[str, Any]], None]] = []
        self._close_listeners: list[Callable[[], None]] = []
        self._last_send: asyncio.Task[None] | None = None
        self.closed = False

    def send(self, frame: dict[str, Any]) -> None:
        if not self.closed:
            self._send_in_order({"t": "pair", "room": self.room, "frame": frame})

    def _send_in_order(self, wrapped: dict[str, Any]) -> None:
        previous = self._last_send

        async def go() -> None:
            if previous is not None:
                await asyncio.gather(previous, return_exceptions=True)
            with contextlib.suppress(LinkError):
                await self._client._send(wrapped)

        self._last_send = self._client._spawn(go())

    def on_frame(self, fn: Callable[[dict[str, Any]], None]) -> Callable[[], None]:
        self._frame_listeners.append(fn)

        def stop() -> None:
            if fn in self._frame_listeners:
                self._frame_listeners.remove(fn)

        return stop

    def on_close(self, fn: Callable[[], None]) -> Callable[[], None]:
        self._close_listeners.append(fn)

        def stop() -> None:
            if fn in self._close_listeners:
                self._close_listeners.remove(fn)

        return stop

    def close(self, code: int = 1000, reason: str = "") -> None:
        """Ends the room. (`code` and `reason` are accepted for the same calls
        as `PeerLink.close` and not sent.)"""
        if not self.closed:
            self._send_in_order({"t": "pair-end", "room": self.room})
        self._ended()

    def _deliver(self, frame: object) -> None:
        if self.closed or not isinstance(frame, dict) or not isinstance(frame.get("t"), str):
            return
        for fn in list(self._frame_listeners):
            try:
                fn(frame)
            except Exception as err:
                _log(f"a pairing frame listener raised {type(err).__name__}: {err}")

    def _ended(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._client._rooms.pop(self.room, None)
        for fn in list(self._close_listeners):
            with contextlib.suppress(Exception):
                fn()


class RelayClient:
    """Keeps the service connected to one relay.

    `url` must pass `check_relay_url` (plain ws:// only with `allow_plain`).
    Timings are in milliseconds and can be shortened for tests.
    """

    def __init__(
        self,
        url: str,
        *,
        allow_plain: bool = False,
        request_timeout_ms: int = 10_000,
        backoff_min_ms: int = 1_000,
        backoff_max_ms: int = 5 * 60_000,
        allow_check_interval_ms: int = 1_000,
    ) -> None:
        self.url = check_relay_url(url, allow_plain=allow_plain)
        self._request_timeout_ms = request_timeout_ms
        self._backoff_min_ms = backoff_min_ms
        self._backoff_max_ms = backoff_max_ms
        self._allow_check_interval_ms = allow_check_interval_ms
        self._daemon: Daemon | None = None
        self._guard: ReplayGuard | None = None
        self._ws: ClientConnection | None = None
        self._ready = False
        self._stopped = False
        self._runner: asyncio.Task[None] | None = None
        self._tasks: set[asyncio.Task[Any]] = set()
        self._pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._next_req = 0
        self._sent_allow: list[str] | None = None
        self._allow_changed = asyncio.Event()
        self.relay_key: str | None = None
        """The relay's key id, from its last `hello`."""
        self.last_error: str | None = None
        """Why the last connection attempt failed or the connection dropped."""
        self.on_ready: list[Callable[[], None]] = []
        """Called each time the connection is ready (after `ok`, the allow
        list and `fetch` have been sent)."""
        self._rooms: dict[str, RoomLink] = {}
        self._invite_waiters: dict[str, asyncio.Future[RoomLink]] = {}
        self.on_live: Callable[[Envelope], None] | None = None
        """Called with each live request or answer (`forward`ed to us) from a
        paired contact, already opened and checked."""

    # Starting and stopping.

    async def start(self, daemon: "Daemon") -> None:
        self._daemon = daemon
        self._guard = ReplayGuard(seen=daemon.store.seen_ids())
        self._runner = asyncio.ensure_future(self._run())

    async def stop(self) -> None:
        self._stopped = True
        tasks = [t for t in (self._runner, *self._tasks) if t is not None]
        for task in tasks:
            task.cancel()
        if self._ws is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._ws.close(1001, "shutting down"), 2)
        await asyncio.gather(*tasks, return_exceptions=True)

    @property
    def connected(self) -> bool:
        """True while the connection is up and the relay accepted our key."""
        return self._ready

    def refresh_allow_list(self) -> None:
        """Sends the allow list now if the contacts changed (it is also
        checked every second)."""
        self._allow_changed.set()

    # Requests.

    async def deposit(self, message_id: str, sealed: Sealed) -> None:
        """Leaves a sealed message in its recipient's mailbox. Returns once
        the relay has stored it; raises `RelayRefused` if the relay refused
        it, or `LinkError` if the relay cannot be reached now."""
        answer = await self._request({"t": "deposit", "id": message_id, "sealed": sealed})
        if answer.get("t") != "deposited":
            raise LinkError(f"unexpected answer from the relay: {answer.get('t')}")

    async def forward(self, sealed: Sealed) -> None:
        """Passes a sealed live request or answer to a recipient that is
        connected now. Raises `RelayRefused` ("offline" when the recipient
        is not connected) or `LinkError`."""
        answer = await self._request({"t": "forward", "sealed": sealed})
        if answer.get("t") != "forwarded":
            raise LinkError(f"unexpected answer from the relay: {answer.get('t')}")

    async def create_invite(self) -> tuple[str, str, "asyncio.Future[RoomLink]"]:
        """Asks the relay for a one-time invite code. Returns the code, when it
        expires (ISO time), and a future that completes with the pairing room
        once someone joins with the code (or fails if the connection drops)."""
        req = self._new_req()
        joined: asyncio.Future[RoomLink] = asyncio.get_running_loop().create_future()
        joined.add_done_callback(lambda f: f.cancelled() or f.exception())
        self._invite_waiters[req] = joined
        joined.add_done_callback(lambda _f: self._invite_waiters.pop(req, None))
        try:
            answer = await self._request({"t": "invite-create"}, req)
        except BaseException:
            joined.cancel()
            raise
        code, expires_at = answer.get("code"), answer.get("expires_at")
        if answer.get("t") != "invite" or not isinstance(code, str):
            joined.cancel()
            raise LinkError("unexpected answer from the relay")
        return code, str(expires_at), joined

    async def join_invite(self, code: str) -> RoomLink:
        """Joins someone's invite. Returns the pairing room; raises
        `RelayRefused` ("no-such-invite") for an unknown, expired or used code."""
        answer = await self._request({"t": "invite-join", "code": code})
        room = self._open_room(answer)
        if room is None:
            raise LinkError("unexpected answer from the relay")
        return room

    def _open_room(self, frame: dict[str, Any]) -> RoomLink | None:
        room_id, peer = frame.get("room"), frame.get("peer")
        if frame.get("t") != "invite-joined" or not isinstance(room_id, str) or not is_key_id(peer):
            return None
        assert isinstance(peer, str)
        room = RoomLink(self, room_id, peer)
        self._rooms[room_id] = room
        return room

    def _new_req(self) -> str:
        self._next_req += 1
        return f"r{self._next_req}"

    async def _request(self, frame: dict[str, Any], req: str | None = None) -> dict[str, Any]:
        ws = self._ws
        if ws is None or not self._ready:
            raise LinkError("not connected to the relay")
        req = req or self._new_req()
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[req] = future
        try:
            await ws.send(jsontext.stringify({**frame, "req": req}))
            answer = await asyncio.wait_for(future, self._request_timeout_ms / 1000)
        except ConnectionClosed as err:
            raise LinkError("the connection to the relay closed") from err
        except TimeoutError as err:
            raise LinkError("the relay did not answer") from err
        finally:
            self._pending.pop(req, None)
        if answer.get("t") == "refused":
            raise RelayRefused(str(answer.get("reason")))
        return answer

    async def _send(self, frame: dict[str, Any]) -> None:
        ws = self._ws
        if ws is None:
            raise LinkError("not connected to the relay")
        try:
            await ws.send(jsontext.stringify(frame))
        except ConnectionClosed as err:
            raise LinkError("the connection to the relay closed") from err

    # The connection.

    async def _run(self) -> None:
        delay = self._backoff_min_ms
        while not self._stopped:
            was_ready = False
            try:
                async with connect(
                    self.url,
                    max_size=_MAX_FRAME,
                    compression=None,
                    open_timeout=self._request_timeout_ms / 1000,
                    ping_interval=30,
                    ping_timeout=60,
                ) as ws:
                    self._ws = ws
                    await self._handshake(ws)
                    was_ready = True
                    await self._session(ws)
                self.last_error = "the relay closed the connection"
            except asyncio.CancelledError:
                raise
            except Exception as err:
                self.last_error = str(err) or type(err).__name__
            finally:
                self._disconnected()
            if self._stopped:
                return
            if was_ready:
                delay = self._backoff_min_ms
            _log(f"disconnected ({self.last_error}); trying again")
            await asyncio.sleep(delay * random.uniform(0.8, 1.2) / 1000)
            delay = min(delay * 2, self._backoff_max_ms)

    def _disconnected(self) -> None:
        self._ready = False
        self._ws = None
        self._sent_allow = None
        for future in self._pending.values():
            if not future.done():
                future.set_exception(LinkError("the connection to the relay closed"))
        self._pending.clear()
        for waiter in list(self._invite_waiters.values()):
            if not waiter.done():
                waiter.set_exception(LinkError("the connection to the relay closed"))
        for room in list(self._rooms.values()):
            room._ended()

    async def _handshake(self, ws: ClientConnection) -> None:
        daemon = self._require_daemon()
        timeout = self._request_timeout_ms / 1000
        hello = _parse(await asyncio.wait_for(ws.recv(), timeout))
        key = hello.get("key")
        challenge = hello.get("challenge")
        if (
            hello.get("t") != "hello"
            or hello.get("v") != PROTOCOL_VERSION
            or not is_key_id(key)
            or not isinstance(challenge, str)
        ):
            raise LinkError("the relay did not say hello")
        assert isinstance(key, str)
        identity = daemon.identity
        sig = ed25519_sign(auth_message(challenge, identity.id, key), identity.secret_key)
        await ws.send(
            jsontext.stringify(
                {"t": "auth", "v": PROTOCOL_VERSION, "key": identity.id, "sig": to_base64url(sig)}
            )
        )
        ok = _parse(await asyncio.wait_for(ws.recv(), timeout))
        if ok.get("t") != "ok":
            raise LinkError("the relay did not accept our key")
        self.relay_key = key
        self.last_error = None

    async def _session(self, ws: ClientConnection) -> None:
        reader = asyncio.ensure_future(self._read(ws))
        try:
            # The allow list goes first: anything waiting was deposited
            # under the old list, and new deposits need the new one.
            self._ready = True
            await self._publish_allow_list()
            await self._send({"t": "fetch", "req": "fetch"})
            _log(f"connected to {self.url}")
            for fn in list(self.on_ready):
                try:
                    fn()
                except Exception as err:
                    _log(f"a listener raised {type(err).__name__}: {err}")
            allow_watch = asyncio.ensure_future(self._watch_allow_list())
            try:
                await reader
            finally:
                allow_watch.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await allow_watch
        finally:
            reader.cancel()
            with contextlib.suppress(asyncio.CancelledError, ConnectionClosed):
                await reader

    async def _read(self, ws: ClientConnection) -> None:
        with contextlib.suppress(ConnectionClosed):
            async for data in ws:
                try:
                    frame = _parse(data)
                except ValueError:
                    continue
                self._handle(frame)

    def _handle(self, frame: dict[str, Any]) -> None:
        t = frame.get("t")
        req = frame.get("req")
        if isinstance(req, str) and req in self._pending:
            future = self._pending[req]
            if not future.done():
                future.set_result(frame)
            return
        if t == "invite-joined" and isinstance(req, str) and req in self._invite_waiters:
            waiter = self._invite_waiters[req]
            room = self._open_room(frame)
            if room is not None and not waiter.done():
                waiter.set_result(room)
            return
        if t in ("pair", "pair-end"):
            room_id = frame.get("room")
            target = self._rooms.get(room_id) if isinstance(room_id, str) else None
            if target is not None:
                if t == "pair":
                    target._deliver(frame.get("frame"))
                else:
                    target._ended()
            return
        if t == "deliver":
            rid = frame.get("rid")
            if isinstance(rid, int) and not isinstance(rid, bool):
                self._spawn(self._receive(rid, frame.get("sealed")))
        elif t == "live":
            self._receive_live(frame.get("sealed"))
        elif t == "refused" and req == "fetch":
            _log(f"the relay refused to send waiting messages: {frame.get('reason')}")

    # The allow list.

    def _allow_list(self) -> list[str]:
        store = self._require_daemon().store
        return sorted(c.public_key for c in store.list_contacts() if c.trust == "paired")

    async def _publish_allow_list(self) -> None:
        senders = self._allow_list()
        try:
            await self._request({"t": "allow", "senders": senders})
        except RelayRefused as err:
            _log(f"the relay refused the allow list: {err.reason}")
            return
        self._sent_allow = senders

    async def _watch_allow_list(self) -> None:
        while True:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(
                    self._allow_changed.wait(), self._allow_check_interval_ms / 1000
                )
            self._allow_changed.clear()
            if self._ready and self._allow_list() != self._sent_allow:
                with contextlib.suppress(LinkError):
                    await self._publish_allow_list()

    # Receiving.

    async def _receive(self, rid: int, sealed: object) -> None:
        daemon = self._require_daemon()
        store = daemon.store
        guard = self._require_guard()
        try:
            envelope = open_sealed(sealed, daemon.identity)
        except EnvelopeError as err:
            _log(f"deleting a message that could not be opened ({err.code})")
            await self._delete(rid)
            return
        contact = store.get_contact(envelope["from"])
        if contact is None or contact.trust != "paired":
            _log("deleting a message from a key that is not a paired contact")
            await self._delete(rid)
            return
        kind = envelope["kind"]
        if kind in RECEIPT_KINDS:
            self._apply_receipt(envelope)
            await self._delete(rid)
            return
        if kind in LIVE_KINDS:
            # Live requests come by `forward`, never from a mailbox.
            await self._delete(rid)
            return
        try:
            try:
                guard.check(envelope, "relay")
            except EnvelopeError as err:
                stored = store.get_message(envelope["id"])
                if (
                    err.code == "replay"
                    and stored is not None
                    and stored.direction == "in"
                    and stored.peer == envelope["from"]
                ):
                    # We have it already: our receipt was lost, so send it again.
                    await self._send_receipt(envelope, "ack")
                else:
                    await self._send_receipt(envelope, "nack", err.code)
                await self._delete(rid)
                return
            conflict = store.incoming_conflict(envelope)
            if conflict is not None:
                await self._send_receipt(envelope, "nack", conflict)
                await self._delete(rid)
                return
            daemon.deliver_incoming(envelope, remote_address="relay")
            # Recorded only once stored, as for the local network.
            guard.record(envelope)
            await self._send_receipt(envelope, "ack")
            await self._delete(rid)
        except LinkError as err:
            # Not deleted: it comes back after reconnecting, and the replay
            # check then sends the receipt again.
            _log(f"message {envelope['id']}: receipt not sent ({err}); will answer later")
        except Exception as err:
            _log(f"message {envelope['id']} could not be stored: {type(err).__name__}: {err}")

    async def _send_receipt(self, message: Envelope, status: ReceiptKind, reason: str = "") -> None:
        daemon = self._require_daemon()
        receipt = create_receipt(
            from_=daemon.identity.id, message=message, status=status, reason=reason
        )
        try:
            await self.deposit(receipt["id"], seal(receipt, daemon.identity))
        except RelayRefused as err:
            if not err.permanent:
                raise
            _log(f"receipt for {message['id']} refused for good: {err.reason}")

    async def _delete(self, rid: int) -> None:
        with contextlib.suppress(LinkError):
            await self._send({"t": "delete", "rid": rid})

    def _apply_receipt(self, envelope: Envelope) -> None:
        store = self._require_daemon().store
        try:
            target = store.receipt_target(envelope)
            receipt = parse_receipt(envelope)
        except EnvelopeError:
            return
        if target is None:
            return
        if receipt["status"] == "ack":
            store.mark_acknowledged(receipt["of"])
        else:
            if store.mark_failed(receipt["of"], f"refused: {receipt['reason']}"):
                _log(f"message {receipt['of']} failed: refused: {receipt['reason']}")

    def _receive_live(self, sealed: object) -> None:
        daemon = self._require_daemon()
        try:
            envelope = open_sealed(sealed, daemon.identity)
        except EnvelopeError:
            return
        contact = daemon.store.get_contact(envelope["from"])
        if contact is None or contact.trust != "paired" or envelope["kind"] not in LIVE_KINDS:
            return
        if self.on_live is not None:
            try:
                self.on_live(envelope)
            except Exception as err:
                _log(f"a live request handler raised {type(err).__name__}: {err}")

    # Helpers.

    def _spawn(self, coro: Coroutine[Any, Any, Any]) -> "asyncio.Task[Any]":
        task: asyncio.Task[Any] = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _require_daemon(self) -> "Daemon":
        if self._daemon is None:
            raise RuntimeError("relay client is not started")
        return self._daemon

    def _require_guard(self) -> ReplayGuard:
        if self._guard is None:
            raise RuntimeError("relay client is not started")
        return self._guard


def _parse(data: str | bytes) -> dict[str, Any]:
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    frame = jsontext.parse(text)
    if not isinstance(frame, dict):
        raise ValueError("not an object")
    return frame


def relay_client_from_settings(get_setting: Callable[[str], str | None]) -> RelayClient | None:
    """The relay client for the relay set in the service's settings, or None
    if no relay is set. A stored URL that no longer passes the checks (for
    example plain ws:// without the opt-in) is logged and ignored."""
    url = get_setting(RELAY_URL_KEY)
    if not url:
        return None
    try:
        return RelayClient(url, allow_plain=get_setting(RELAY_ALLOW_PLAIN_KEY) == "on")
    except ValueError as err:
        _log(f"not using the relay: {err}")
        return None
