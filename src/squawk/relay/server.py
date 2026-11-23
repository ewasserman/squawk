"""The relay server: holds sealed messages for services that cannot reach
each other directly, and passes live requests and pairing frames between
them. The protocol is described in docs/plan/relay.md.

Each connection starts with the relay's `hello` (its key and a random
challenge); the client answers `auth` with its key and a signature over
`auth_message(challenge, client key, relay key)` from `squawk.network`, and
the relay asks its access policy (`squawk.relay.access`) whether the key
may use it, and answers `ok` or closes the connection. After that every
frame is handled by one of the `_on_*` methods below.

All state that must survive a restart (the relay's key, mailboxes, allow
lists, waiting messages, open invites) is in SQLite (`RelayStore`). What
belongs to a connection (deliveries outstanding, the open invite's request
id, pairing rooms) and the rate limit counters are kept in memory.
"""

import asyncio
import contextlib
import itertools
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

from websockets.asyncio.server import Server, ServerConnection, serve
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Request, Response

from squawk import jsontext
from squawk.crypto import ed25519_verify, random_bytes
from squawk.encoding import from_base64url, is_key_id, key_from_id, to_base64url
from squawk.envelope import EnvelopeValidationError, Sealed, parse_sealed
from squawk.identity import Identity, identity_from_secret_key
from squawk.network import REFUSED_CODE, auth_message
from squawk.relay.access import NOT_PERMITTED_CODE, AccessPolicy, Decision, OpenAccess
from squawk.relay.invite_code import code_hash, new_code, normalize_code
from squawk.relay.limits import Rate, RateLimiter, RelayLimits
from squawk.relay.storage import RelayStore
from squawk.timefmt import iso_from_ms, now_ms
from squawk.version import VERSION

PROTOCOL_VERSION = 1

REPLACED_CODE = 4002
"""Close code for an older connection when the same key connects again."""

Frame = dict[str, Any]

# Reason codes for `refused` (docs/plan/relay.md).
MALFORMED = "malformed"
NOT_ALLOWED = "not-allowed"
SENDER_MISMATCH = "sender-mismatch"
TOO_LARGE = "too-large"
MAILBOX_FULL = "mailbox-full"
RATE_LIMITED = "rate-limited"
OFFLINE = "offline"
NO_SUCH_INVITE = "no-such-invite"
ERROR = "error"

# Names of the rate limit counters.
_DEPOSIT = "deposit"
_FORWARD = "forward"
_ALLOW = "allow"
_INVITE_CREATE = "invite-create"
_JOIN_PER_CONNECTION = "invite-join-connection"
_JOIN_PER_IP = "invite-join-ip"
_CONNECT = "connect"

# Frames that must carry a `req`.
_NEEDS_REQ = frozenset({"allow", "deposit", "fetch", "forward", "invite-create", "invite-join"})


def _log(text: str) -> None:
    print(f"squawk relay: {text}", file=sys.stderr, flush=True)


def _is_protocol_version(value: object) -> bool:
    return (
        isinstance(value, int | float) and not isinstance(value, bool) and value == PROTOCOL_VERSION
    )


def _remote_ip(connection: ServerConnection, trust_forwarded_for: bool = False) -> str:
    """The client's IP address, used for per-address limits. Behind a proxy
    (for TLS) every connection comes from the proxy, so with
    `trust_forwarded_for` the last address in the X-Forwarded-For header,
    the one the proxy added, is used instead."""
    if trust_forwarded_for and connection.request is not None:
        forwarded = connection.request.headers.get("X-Forwarded-For", "")
        last = forwarded.rsplit(",", 1)[-1].strip()
        if last:
            return last
    address = connection.remote_address
    if isinstance(address, tuple) and address:
        return str(address[0])
    return "unknown"


_connection_numbers = itertools.count(1)


class _Client:
    """One authenticated connection. Frames to it go through a queue, so that
    a slow reader never holds up the code handling another connection."""

    def __init__(
        self, ws: ServerConnection, key: str, ip: str, max_queued_bytes: int = 8 << 20
    ) -> None:
        self.ws = ws
        self.key = key
        self.ip = ip
        self.number = str(next(_connection_numbers))
        """Distinguishes connections from the same key, for per-connection rate limits."""
        self.fetching = False
        """True once the client sent `fetch`: new deposits are then sent as they arrive."""
        self.outstanding: set[int] = set()
        """Relay ids sent in `deliver` and not yet deleted."""
        self.last_sent_rid = 0
        self.invite_hash: str | None = None
        """Hash of this connection's open invite code, if it has one."""
        self.invite_req: str | None = None
        """The `req` of the `invite-create` that made the open invite."""
        self.rooms: set[str] = set()
        self.dropped = False
        """True once the relay has stopped treating this as the key's connection."""
        self._queue: asyncio.Queue[str | tuple[int, str]] = asyncio.Queue()
        self._queued_bytes = 0
        self._max_queued_bytes = max_queued_bytes
        self._closing = False

    def send(self, frame: Frame) -> None:
        if self._closing:
            return
        text = jsontext.stringify(frame)
        self._queued_bytes += len(text)
        if self._queued_bytes > self._max_queued_bytes:
            # The client is not reading. Closing politely would wait behind
            # everything already queued, so drop the connection at once.
            self._closing = True
            _log(f"dropping a connection that stopped reading ({self.key})")
            if self.ws.transport is not None:
                self.ws.transport.abort()
            return
        self._queue.put_nowait(text)

    def close(self, code: int, reason: str) -> None:
        """Closes the connection after the frames already queued."""
        if not self._closing:
            self._closing = True
            self._queue.put_nowait((code, reason))

    async def write_loop(self) -> None:
        with contextlib.suppress(ConnectionClosed):
            while True:
                item = await self._queue.get()
                if isinstance(item, tuple):
                    await self.ws.close(*item)
                    return
                self._queued_bytes -= len(item)
                await self.ws.send(item)


@dataclass
class _Room:
    """A pairing room joining an invite's creator and the person who joined it."""

    id: str
    creator: _Client
    joiner: _Client
    expires_at: int
    frames: int = field(default=0)

    def other(self, client: _Client) -> _Client | None:
        if client is self.creator:
            return self.joiner
        if client is self.joiner:
            return self.creator
        return None


class RelayServer:
    """The relay. `start` opens (or creates) the database in `data_dir` and
    starts listening; `stop` closes every connection and the database.

    `now` returns the current time in milliseconds since the epoch; it is
    used for message and invite expiry and for rate limits, so tests can pass
    a fake clock. Port 0 picks a free port (see `port`).
    """

    def __init__(
        self,
        data_dir: str,
        *,
        host: str = "127.0.0.1",
        port: int = 8765,
        limits: RelayLimits | None = None,
        now: Callable[[], int] | None = None,
        trust_forwarded_for: bool = False,
        access: AccessPolicy | None = None,
    ) -> None:
        self._data_dir = data_dir
        self.access: AccessPolicy = OpenAccess() if access is None else access
        self._trust_forwarded_for = trust_forwarded_for
        self._host = host
        self._port = port
        self.limits = RelayLimits() if limits is None else limits
        self._now = now_ms if now is None else now
        self._rates = RateLimiter(self._now)
        self._clients: dict[str, _Client] = {}
        self._rooms: dict[str, _Room] = {}
        self._store: RelayStore | None = None
        self._server: Server | None = None
        self._purge_task: asyncio.Task[None] | None = None
        self._access_task: asyncio.Task[None] | None = None
        self.identity: Identity | None = None

    # Starting and stopping.

    async def start(self) -> None:
        store = RelayStore.open(self._data_dir)
        self._store = store
        self.identity = identity_from_secret_key("relay", store.secret_key())
        store.delete_all_invites()
        self.purge()
        self._server = await serve(
            self._handle,
            self._host,
            self._port,
            max_size=self.limits.max_frame_bytes,
            compression=None,
            process_request=self._process_request,
            ping_interval=self.limits.ping_interval_s,
            ping_timeout=self.limits.ping_timeout_s,
        )
        self._purge_task = asyncio.create_task(self._purge_loop())
        self._access_task = asyncio.create_task(self._access_loop())

    async def stop(self) -> None:
        for task in (self._purge_task, self._access_task):
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        self._purge_task = self._access_task = None
        server = self._server
        if server is not None:
            self._server = None
            server.close(close_connections=True)
            try:
                await asyncio.wait_for(server.wait_closed(), 5)
            except TimeoutError:
                for connection in server.connections:
                    if connection.transport is not None:
                        connection.transport.abort()
        if self._store is not None:
            self._store.close()
            self._store = None

    async def __aenter__(self) -> "RelayServer":
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.stop()

    @property
    def port(self) -> int:
        """The port the relay listens on (the real one when 0 was asked for)."""
        assert self._server is not None, "the relay is not running"
        return int(self._server.sockets[0].getsockname()[1])

    @property
    def key_id(self) -> str:
        """The relay's own key id, sent in `hello`."""
        assert self.identity is not None, "the relay is not running"
        return self.identity.id

    @property
    def store(self) -> RelayStore:
        assert self._store is not None, "the relay is not running"
        return self._store

    # Expiry.

    async def _purge_loop(self) -> None:
        while True:
            await asyncio.sleep(self.limits.purge_interval_s)
            try:
                self.purge()
            except Exception as err:
                _log(f"purging expired items failed: {type(err).__name__}: {err}")

    def purge(self) -> None:
        """Deletes expired messages and invites, ends pairing rooms that have
        run out of time, and forgets rate limit counters that have refilled."""
        now = self._now()
        self.store.purge(now, self.limits.message_ttl_ms)
        for room in list(self._rooms.values()):
            if room.expires_at <= now:
                self._end_room(room, notify=[room.creator, room.joiner])
        self._rates.forget_full(self._rate_table())

    # Access.

    async def _access_loop(self) -> None:
        while True:
            await asyncio.sleep(self.limits.access_check_interval_s)
            try:
                self.reload_access(force=False)
            except Exception as err:
                _log(f"checking the access file failed: {type(err).__name__}: {err}")

    def reload_access(self, force: bool = True) -> None:
        """Has the access policy reread its file, then closes the connections
        and deletes the mailboxes of keys it now refuses. The relay does this
        every `access_check_interval_s` with `force` False, so that taking
        keys out waits for a second reading of the file; SIGHUP and other
        explicit requests apply the file at once."""
        if self.access.reload(force):
            self._enforce_access()

    def reload_access_logged(self) -> None:
        """`reload_access` for a signal handler: logs a failure instead of raising."""
        try:
            self.reload_access()
        except Exception as err:
            _log(f"rereading the access file failed: {type(err).__name__}: {err}")

    def _enforce_access(self) -> None:
        refused = Decision.REFUSED
        for client in list(self._clients.values()):
            if self.access.decide(client.key) is refused:
                self._drop(client)
                client.close(NOT_PERMITTED_CODE, "not permitted")
        for key in self.store.mailbox_keys():
            if self.access.decide(key) is refused:
                self.store.delete_mailbox(key)
                _log(f"deleted the mailbox of {key}, which may no longer use the relay")

    def _rate_table(self) -> dict[str, Rate]:
        """Each rate limit counter's name and its limit."""
        limits = self.limits
        return {
            _DEPOSIT: limits.deposit_rate,
            _FORWARD: limits.forward_rate,
            _ALLOW: limits.allow_rate,
            _INVITE_CREATE: limits.invite_create_rate,
            _JOIN_PER_CONNECTION: limits.invite_join_rate_per_connection,
            _JOIN_PER_IP: limits.invite_join_rate_per_ip,
            _CONNECT: limits.connect_rate_per_ip,
        }

    def _oldest_kept(self) -> int:
        """Messages that arrived before this time have expired."""
        return self._now() - self.limits.message_ttl_ms

    # Plain HTTP requests and new connections.

    def _process_request(self, connection: ServerConnection, request: Request) -> Response | None:
        if request.path.split("?", 1)[0] == "/healthz":
            body = jsontext.stringify({"status": "ok", "version": VERSION}) + "\n"
            response = connection.respond(200, body)
            del response.headers["Content-Type"]
            response.headers["Content-Type"] = "application/json"
            return response
        if request.headers.get("Upgrade", "").lower() != "websocket":
            return connection.respond(426, "the squawk relay speaks WebSocket\n")
        retry_after = self._rates.take(
            _CONNECT,
            _remote_ip(connection, self._trust_forwarded_for),
            self.limits.connect_rate_per_ip,
        )
        if retry_after is not None:
            response = connection.respond(429, "too many connections\n")
            response.headers["Retry-After"] = str(retry_after)
            return response
        return None

    async def _handle(self, ws: ServerConnection) -> None:
        key = await self._authenticate(ws)
        if key is None:
            return
        if self.access.decide(key) is not Decision.ADMITTED:
            # Signing in for unknown keys comes with the github mode; until
            # then an unknown key is refused like any other.
            await ws.close(NOT_PERMITTED_CODE, "not permitted")
            return
        client = _Client(
            ws, key, _remote_ip(ws, self._trust_forwarded_for), self.limits.max_queued_bytes
        )
        writer = asyncio.create_task(client.write_loop())
        try:
            self._admit(client)
            async for data in ws:
                self._on_data(client, data)
        except ConnectionClosed:
            pass
        finally:
            self._drop(client)
            writer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await writer

    async def _authenticate(self, ws: ServerConnection) -> str | None:
        """Runs hello/auth. Returns the client's key id, or None after
        closing a connection that did not prove a key in time."""
        challenge = to_base64url(random_bytes(32))
        try:
            await ws.send(
                jsontext.stringify(
                    {
                        "t": "hello",
                        "v": PROTOCOL_VERSION,
                        "key": self.key_id,
                        "challenge": challenge,
                        "access": self.access.mode,
                    }
                )
            )
            data = await asyncio.wait_for(ws.recv(), self.limits.auth_timeout_s)
        except TimeoutError:
            await ws.close(REFUSED_CODE, "authentication timed out")
            return None
        except ConnectionClosed:
            return None
        frame = _parse_frame(data)
        if frame is None or frame["t"] != "auth":
            await ws.close(REFUSED_CODE, "expected auth")
            return None
        key = frame.get("key")
        sig = frame.get("sig")
        if (
            not _is_protocol_version(frame.get("v"))
            or not is_key_id(key)
            or not isinstance(sig, str)
        ):
            await ws.close(REFUSED_CODE, "bad auth")
            return None
        assert isinstance(key, str)
        try:
            valid = ed25519_verify(
                from_base64url(sig), auth_message(challenge, key, self.key_id), key_from_id(key)
            )
        except Exception:
            valid = False
        if not valid:
            await ws.close(REFUSED_CODE, "bad signature")
            return None
        return key

    def _admit(self, client: _Client) -> None:
        """Makes `client` the connection for its key, closing any older one."""
        older = self._clients.get(client.key)
        if older is not None:
            self._drop(older)
            older.close(REPLACED_CODE, "replaced")
        self._clients[client.key] = client
        self.store.touch_mailbox(client.key, self._now())
        waiting = self.store.usage(client.key, self._oldest_kept()).messages
        client.send({"t": "ok", "waiting": waiting})

    def _drop(self, client: _Client) -> None:
        """Forgets everything tied to a connection that closed or was replaced:
        its open invite and its pairing rooms. Safe to call twice."""
        if client.dropped:
            return
        client.dropped = True
        if self._clients.get(client.key) is client:
            del self._clients[client.key]
        if client.invite_hash is not None and self._store is not None:
            # (The store is gone if the relay is stopping; invites are all
            # deleted at the next start anyway.)
            if self._store.invite_creator(client.invite_hash) == client.key:
                self._store.delete_invites_of(client.key)
            client.invite_hash = None
        for room_id in list(client.rooms):
            room = self._rooms.get(room_id)
            if room is not None:
                other = room.other(client)
                self._end_room(room, notify=[] if other is None else [other])

    # Frames after `ok`.

    def _on_data(self, client: _Client, data: str | bytes) -> None:
        if client.dropped:
            return
        frame = _parse_frame(data)
        if frame is None:
            _refuse(client, None, MALFORMED)
            return
        t = frame["t"]
        raw_req = frame.get("req")
        req = (
            raw_req
            if isinstance(raw_req, str) and jsontext.js_length(raw_req) <= self.limits.max_req_chars
            else None
        )
        handler = self._handlers.get(t)
        if handler is None or (t in _NEEDS_REQ and req is None):
            _refuse(client, req, MALFORMED)
            return
        try:
            handler(self, client, frame, req)
        except Exception as err:
            _log(f"handling {t!r} failed: {type(err).__name__}: {err}")
            _refuse(client, req, ERROR)

    def _on_allow(self, client: _Client, frame: Frame, req: str | None) -> None:
        senders = frame.get("senders")
        if not isinstance(senders, list) or not all(is_key_id(s) for s in senders):
            _refuse(client, req, MALFORMED)
            return
        if len(senders) > self.limits.max_allow_list:
            _refuse(client, req, TOO_LARGE)
            return
        if self._rate_limited(client, req, _ALLOW, client.key):
            return
        self.store.set_allowed(client.key, [str(s) for s in senders])
        client.send({"t": "allowed", "req": req})

    def _check_sealed(self, client: _Client, frame: Frame, req: str | None) -> Sealed | None:
        """The checks shared by `deposit` and `forward`, in the documented
        order up to (not including) the rate limit. Refuses and returns None
        when one fails."""
        try:
            sealed = parse_sealed(frame.get("sealed"))
        except EnvelopeValidationError:
            _refuse(client, req, MALFORMED)
            return None
        if sealed["from"] != client.key:
            _refuse(client, req, SENDER_MISMATCH)
            return None
        if not self.store.is_allowed(sealed["to"], client.key):
            _refuse(client, req, NOT_ALLOWED)
            return None
        if len(jsontext.utf8(jsontext.stringify(sealed))) > self.limits.max_sealed_bytes:
            _refuse(client, req, TOO_LARGE)
            return None
        return sealed

    def _on_deposit(self, client: _Client, frame: Frame, req: str | None) -> None:
        message_id = frame.get("id")
        if (
            not isinstance(message_id, str)
            or message_id == ""
            or jsontext.js_length(message_id) > self.limits.max_id_chars
        ):
            _refuse(client, req, MALFORMED)
            return
        sealed = self._check_sealed(client, frame, req)
        if sealed is None or self._rate_limited(client, req, _DEPOSIT, client.key):
            return
        store = self.store
        recipient = sealed["to"]
        if not store.has_message(client.key, message_id, recipient, self._oldest_kept()):
            # A copy that expired or names another recipient is replaced.
            store.delete_message_copies(client.key, message_id)
            text = jsontext.stringify(sealed)
            usage = store.usage(recipient, self._oldest_kept())
            if (
                usage.messages + 1 > self.limits.max_mailbox_messages
                or usage.bytes + len(jsontext.utf8(text)) > self.limits.max_mailbox_bytes
            ):
                _refuse(client, req, MAILBOX_FULL)
                return
            store.add_message(client.key, recipient, message_id, text, self._now())
        client.send({"t": "deposited", "req": req, "id": message_id})
        to_client = self._clients.get(recipient)
        if to_client is not None:
            self._pump(to_client)

    def _on_fetch(self, client: _Client, frame: Frame, req: str | None) -> None:
        client.fetching = True
        self._pump(client)

    def _pump(self, client: _Client) -> None:
        """Sends a fetching client its waiting messages, oldest first, while
        fewer than the limit are outstanding."""
        if not client.fetching or client.dropped:
            return
        room = self.limits.max_outstanding - len(client.outstanding)
        if room <= 0:
            return
        for message in self.store.messages_after(
            client.key, client.last_sent_rid, self._oldest_kept(), room
        ):
            client.outstanding.add(message.rid)
            client.last_sent_rid = message.rid
            client.send(
                {
                    "t": "deliver",
                    "rid": message.rid,
                    "sealed": jsontext.parse(message.sealed),
                    "deposited_at": iso_from_ms(message.arrived_at_ms),
                }
            )

    def _on_delete(self, client: _Client, frame: Frame, req: str | None) -> None:
        rid = frame.get("rid")
        if not isinstance(rid, int) or isinstance(rid, bool):
            _refuse(client, req, MALFORMED)
            return
        self.store.delete_message(client.key, rid)
        client.outstanding.discard(rid)
        self._pump(client)

    def _on_forward(self, client: _Client, frame: Frame, req: str | None) -> None:
        sealed = self._check_sealed(client, frame, req)
        if sealed is None or self._rate_limited(client, req, _FORWARD, client.key):
            return
        to_client = self._clients.get(sealed["to"])
        if to_client is None:
            _refuse(client, req, OFFLINE)
            return
        to_client.send({"t": "live", "sealed": sealed})
        client.send({"t": "forwarded", "req": req})

    def _on_invite_create(self, client: _Client, frame: Frame, req: str | None) -> None:
        if self._rate_limited(client, req, _INVITE_CREATE, client.key):
            return
        code = new_code()
        hashed = code_hash(code.replace("-", ""))
        expires_at = self._now() + self.limits.invite_ttl_ms
        # Storing the new invite removes the creator's previous one, if any.
        self.store.add_invite(hashed, client.key, expires_at)
        client.invite_hash = hashed
        client.invite_req = req
        client.send(
            {"t": "invite", "req": req, "code": code, "expires_at": iso_from_ms(expires_at)}
        )

    def _on_invite_join(self, client: _Client, frame: Frame, req: str | None) -> None:
        code = frame.get("code")
        if not isinstance(code, str) or jsontext.js_length(code) > 64:
            _refuse(client, req, MALFORMED)
            return
        if self._rate_limited(
            client, req, _JOIN_PER_CONNECTION, client.number
        ) or self._rate_limited(client, req, _JOIN_PER_IP, client.ip):
            return
        normalized = normalize_code(code)
        if normalized is None:
            _refuse(client, req, NO_SUCH_INVITE)
            return
        hashed = code_hash(normalized)
        if self.store.invite_creator(hashed) == client.key:
            # Joining your own invite would pair you with yourself.
            _refuse(client, req, NO_SUCH_INVITE)
            return
        creator_key = self.store.take_invite(hashed, self._now())
        creator = None if creator_key is None else self._clients.get(creator_key)
        if creator is None or creator.invite_hash != hashed:
            _refuse(client, req, NO_SUCH_INVITE)
            return
        creator.invite_hash = None
        room = _Room(
            id=to_base64url(random_bytes(16)),
            creator=creator,
            joiner=client,
            expires_at=self._now() + self.limits.room_ttl_ms,
        )
        self._rooms[room.id] = room
        creator.rooms.add(room.id)
        client.rooms.add(room.id)
        client.send({"t": "invite-joined", "req": req, "room": room.id, "peer": creator.key})
        creator.send(
            {"t": "invite-joined", "req": creator.invite_req, "room": room.id, "peer": client.key}
        )

    def _room_of(self, client: _Client, frame: Frame, req: str | None) -> _Room | None:
        """The live pairing room a `pair` or `pair-end` frame names, if the
        client is in it. For a room that is unknown, over or not the
        client's, answers `pair-end` so the client stops using it."""
        room_id = frame.get("room")
        if not isinstance(room_id, str):
            _refuse(client, req, MALFORMED)
            return None
        room = self._rooms.get(room_id)
        if room is not None and room.other(client) is not None:
            if room.expires_at > self._now():
                return room
            self._end_room(room, notify=[room.creator, room.joiner])
            return None
        client.send({"t": "pair-end", "room": room_id})
        return None

    def _on_pair(self, client: _Client, frame: Frame, req: str | None) -> None:
        inner = frame.get("frame")
        if not isinstance(inner, dict):
            _refuse(client, req, MALFORMED)
            return
        room = self._room_of(client, frame, req)
        if room is None:
            return
        room.frames += 1
        if room.frames > self.limits.max_pair_frames:
            self._end_room(room, notify=[room.creator, room.joiner])
            return
        other = room.other(client)
        assert other is not None
        other.send({"t": "pair", "room": room.id, "frame": inner})

    def _on_pair_end(self, client: _Client, frame: Frame, req: str | None) -> None:
        room_id = frame.get("room")
        if not isinstance(room_id, str):
            _refuse(client, req, MALFORMED)
            return
        room = self._rooms.get(room_id)
        if room is None:
            return
        other = room.other(client)
        if other is not None:
            self._end_room(room, notify=[other])

    def _end_room(self, room: _Room, notify: list[_Client]) -> None:
        """Forgets a pairing room and sends `pair-end` to the clients in `notify`."""
        if self._rooms.pop(room.id, None) is None:
            return
        room.creator.rooms.discard(room.id)
        room.joiner.rooms.discard(room.id)
        for client in notify:
            client.send({"t": "pair-end", "room": room.id})

    def _rate_limited(self, client: _Client, req: str | None, kind: str, who: str) -> bool:
        """Counts one event of `kind` for `who`; refuses with `rate-limited`
        and returns True when over the limit."""
        retry_after = self._rates.take(kind, who, self._rate_table()[kind])
        if retry_after is None:
            return False
        _refuse(client, req, RATE_LIMITED, retry_after=retry_after)
        return True

    _handlers: ClassVar[dict[str, Callable[["RelayServer", _Client, Frame, str | None], None]]] = {
        "allow": _on_allow,
        "deposit": _on_deposit,
        "fetch": _on_fetch,
        "delete": _on_delete,
        "forward": _on_forward,
        "invite-create": _on_invite_create,
        "invite-join": _on_invite_join,
        "pair": _on_pair,
        "pair-end": _on_pair_end,
    }


def _parse_frame(data: str | bytes) -> Frame | None:
    """The frame as a JSON object with a string `t`, or None. Binary frames are refused."""
    if not isinstance(data, str):
        return None
    try:
        frame = jsontext.parse(data)
    except ValueError:
        return None
    if not isinstance(frame, dict) or not isinstance(frame.get("t"), str):
        return None
    return frame


def _refuse(
    client: _Client, req: str | None, reason: str, *, retry_after: int | None = None
) -> None:
    frame: Frame = {"t": "refused", "req": req, "reason": reason}
    if retry_after is not None:
        frame["retry_after"] = retry_after
    client.send(frame)
