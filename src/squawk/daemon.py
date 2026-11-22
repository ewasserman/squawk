"""squawkd: the background service. It owns the identity and the database,
listens on a unix socket for local clients (Claude Code sessions, the CLI,
`squawk tail`) speaking newline-delimited JSON-RPC 2.0, and routes incoming
messages to those sessions.

Network transports (mDNS discovery, the WebSocket listener) plug in through
`deliver_incoming` (for messages that arrive) and the `Transport` class (for
messages to send), so routing does not depend on how a message travels.

This is the Python version of src/daemon.ts. Its socket methods take and
return the same JSON, so clients of either version work with either service.
"""

import asyncio
import contextlib
import inspect
import os
import sys
import unicodedata
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, NotRequired, TypedDict, cast

from squawk import jsontext
from squawk.config import db_path, pid_path, run_dir, socket_path
from squawk.encoding import is_key_id, key_from_id
from squawk.envelope import MESSAGE_KINDS, Envelope, MessageKind, create_envelope
from squawk.identity import Identity, fingerprint, load_identity
from squawk.rpc import RpcClient, RpcConnection, RpcError, RpcErrorCode, RpcHandler, RpcServer
from squawk.store import (
    DEFAULT_INBOUND_POLICY_KEY,
    UNSET,
    Contact,
    InboundPolicy,
    Store,
    StoredMessage,
)
from squawk.timefmt import iso_from_ms, now_ms

if TYPE_CHECKING:
    from squawk.store import _Unset


class Peer(TypedDict):
    """A peer seen on the network."""

    name: str
    key_id: str
    fingerprint: str
    host: str
    port: int
    paired: bool


class Transport:
    """Sends queued outbound messages to other hosts. The daemon calls `kick`
    after it adds a message to the store's outbound queue; the transport then
    reads due items with `store.due_outbound()` and delivers them.

    This base class sends nothing: messages stay in the outbound queue.
    Subclasses override what they need.
    """

    async def start(self, daemon: "Daemon") -> None:
        """Called once when the daemon starts, after the store is open."""

    async def stop(self) -> None:
        """Called when the daemon stops, before the store is closed."""

    def kick(self, envelope: Envelope) -> Awaitable[None] | None:
        """The outbound queue has a new item (`envelope`, already in the store)."""
        return None

    def peers(self) -> list[Peer]:
        """Other services seen on the network."""
        return []

    @property
    def port(self) -> int | None:
        """The TCP port other hosts connect to, if there is one."""
        return None


no_transport = Transport()
"""A transport that sends nothing; messages stay in the outbound queue."""


@dataclass(frozen=True)
class IncomingResult:
    """What `deliver_incoming` did with a message."""

    stored: bool
    """False if a message with the same id was already stored (nothing else happens)."""
    delivered_to: str | None
    """The label of the session it was pushed to, or None if it stays queued."""


class MessageNotification(TypedDict):
    """Params of the `message` notification sent to sessions and subscribers."""

    envelope: Envelope
    from_name: str | None
    """The sender's contact name, or None if the sender is not a contact."""
    policy: InboundPolicy


class SendParams(TypedDict):
    to: str
    """A contact name or key identifier."""
    body: str
    kind: NotRequired[MessageKind]
    thread_id: NotRequired[str]
    in_reply_to: NotRequired[str]
    session: NotRequired[str]
    """The label of the recipient's session that should get the message."""


class SendResult(TypedDict):
    id: str
    thread_id: str
    state: Literal["queued"]


class MessageInfo(TypedDict):
    """A stored message as returned by the `get_message` method."""

    id: str
    direction: Literal["in", "out"]
    """"in" for a message received, "out" for one this machine sent."""
    peer: str
    """The other party's key identifier: the sender for "in", the recipient for "out"."""
    peer_name: str | None
    """The other party's contact name, or None if they are not a contact."""
    session: str | None
    thread_id: str
    in_reply_to: str | None
    kind: MessageKind
    body: str
    created_at: str
    state: str


class ContactInfo(TypedDict):
    """A contact as returned by the `contacts` method."""

    name: str
    key_id: str
    fingerprint: str
    trust: Literal["paired", "blocked"]
    auto_send: bool
    inbound_policy: InboundPolicy
    """The policy that applies to this contact's messages (their own or the default)."""
    policy_is_default: bool
    """True when the contact has no policy of its own and follows the default."""


class SessionInfo(TypedDict):
    label: str
    last_active: str


class StatusResult(TypedDict):
    name: str
    key_id: str
    fingerprint: str
    pid: int
    sessions: list[SessionInfo]
    queued_inbound: int
    queued_outbound: int
    port: int | None
    """TCP port for other hosts, or None when the service has no network transport."""


@dataclass
class _Session:
    id: str
    label: str
    connection: RpcConnection
    registered_seq: int
    """Order of registration; larger is newer."""
    active_seq: int
    """Order of the last call on this connection; larger is more recent."""
    last_active: int


# Checking params. These follow the zod schemas in src/daemon.ts: unknown
# fields are ignored, an optional field may be left out but not set to null
# (unless it says so), and string lengths count UTF-16 code units. The error
# texts are plain descriptions rather than zod's wording; clients rely only on
# the error code.

_INBOUND_POLICIES = ("show_first", "auto_answer")


def _invalid(problem: str) -> RpcError:
    return RpcError(RpcErrorCode.INVALID_PARAMS, f"invalid params: {problem}")


def _params_object(params: Any, optional: bool = False) -> dict[str, Any] | None:
    if params is None:
        if optional:
            return None
        raise _invalid("expected an object")
    if not isinstance(params, dict):
        raise _invalid("expected an object")
    return cast(dict[str, Any], params)


def _string_field(
    obj: Mapping[str, Any],
    key: str,
    *,
    required: bool,
    min_length: int = 0,
    max_length: int | None = None,
) -> str | None:
    if key not in obj:
        if required:
            raise _invalid(f"{key}: required")
        return None
    value = obj[key]
    if not isinstance(value, str):
        raise _invalid(f"{key}: expected a string")
    length = jsontext.js_length(value)
    if length < min_length:
        raise _invalid(f"{key}: must have at least {min_length} characters")
    if max_length is not None and length > max_length:
        raise _invalid(f"{key}: must have at most {max_length} characters")
    return value


def _bool_field(obj: Mapping[str, Any], key: str) -> bool | None:
    if key not in obj:
        return None
    value = obj[key]
    if not isinstance(value, bool):
        raise _invalid(f"{key}: expected a boolean")
    return value


def _enum_field(obj: Mapping[str, Any], key: str, allowed: tuple[str, ...]) -> str | None:
    if key not in obj:
        return None
    value = obj[key]
    if value not in allowed:
        raise _invalid(f"{key}: expected one of {', '.join(allowed)}")
    return cast(str, value)


def parse_send_params(params: Any) -> SendParams:
    """Checks the params of the `send` method."""
    obj = _params_object(params)
    assert obj is not None
    result: dict[str, Any] = {
        "to": _string_field(obj, "to", required=True, min_length=1),
        "body": _string_field(obj, "body", required=True),
    }
    kind = _enum_field(obj, "kind", MESSAGE_KINDS)
    if kind is not None:
        result["kind"] = kind
    for key, min_length, max_length in (
        ("thread_id", 1, 128),
        ("in_reply_to", 1, 128),
        ("session", 0, 256),
    ):
        value = _string_field(
            obj, key, required=False, min_length=min_length, max_length=max_length
        )
        if value is not None:
            result[key] = value
    return cast(SendParams, result)


class DaemonRunningError(Exception):
    """Raised by `Daemon.start` when another service is already listening on the socket."""

    def __init__(self, path: str) -> None:
        super().__init__(f"squawkd is already running (socket {path})")


async def _socket_answers(path: str) -> bool:
    """True if a server answers on the socket at `path`."""
    try:
        client = await RpcClient.connect(path)
    except OSError:
        return False
    await client.close()
    return True


def _name_sort_key(name: str) -> tuple[str, str, str]:
    """Orders names roughly as JavaScript's `localeCompare` does: ignoring
    accents and case first, then accents, then lower case before upper case."""
    decomposed = unicodedata.normalize("NFD", name)
    base = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return base.casefold(), decomposed.casefold(), name.swapcase()


class Daemon:
    """The service core. `home` is the squawk home directory (identity,
    database, run/); `now` returns the current time in milliseconds since the
    epoch."""

    def __init__(
        self,
        home: str,
        *,
        transport: Transport | None = None,
        now: Callable[[], int] | None = None,
    ) -> None:
        self.home = home
        self.socket_path = socket_path(home)
        self.transport: Transport = no_transport if transport is None else transport
        self._now = now_ms if now is None else now
        self._sessions: dict[RpcConnection, _Session] = {}
        self._subscribers: set[RpcConnection] = set()
        self._identity: Identity | None = None
        self._store: Store | None = None
        self._server: RpcServer | None = None
        self._seq = 0
        self._stopping: asyncio.Task[None] | None = None
        self._stopped = asyncio.Event()

    @property
    def identity(self) -> Identity:
        if self._identity is None:
            raise RuntimeError("daemon not started")
        return self._identity

    @property
    def store(self) -> Store:
        if self._store is None:
            raise RuntimeError("daemon not started")
        return self._store

    async def when_stopped(self) -> None:
        """Returns once the daemon has stopped (by `stop()` or the `stop` method)."""
        await self._stopped.wait()

    async def start(self) -> None:
        """Loads the identity, opens the store, and listens on the socket.

        Raises `DaemonRunningError` if another service answers on the socket.
        """
        self._identity = load_identity(self.home)
        run = run_dir(self.home)
        os.makedirs(run, mode=0o700, exist_ok=True)
        os.chmod(run, 0o700)
        if await _socket_answers(self.socket_path):
            raise DaemonRunningError(self.socket_path)
        # Nothing answered, so any socket file left behind is stale.
        with contextlib.suppress(FileNotFoundError):
            os.remove(self.socket_path)

        self._store = Store.open(db_path(self.home), now=self._now)
        server = RpcServer(on_call=lambda connection, _method: self._touch(connection))
        self._register_methods(server)
        await server.listen(self.socket_path)
        os.chmod(self.socket_path, 0o600)
        self._server = server
        fd = os.open(pid_path(self.home), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"{os.getpid()}\n")
        try:
            await self.transport.start(self)
        except BaseException:
            # Do not keep running half-started (answering on the socket with no
            # network): shut down and report the failure.
            await self.stop()
            raise

    async def stop(self) -> None:
        """Stops listening, closes every connection and the store. Safe to call twice."""
        if self._stopping is None:
            self._stopping = asyncio.ensure_future(self._stop())
        await asyncio.shield(self._stopping)

    async def _stop(self) -> None:
        try:
            await self.transport.stop()
        finally:
            if self._server is not None:
                await self._server.close()
            self._sessions.clear()
            self._subscribers.clear()
            if self._server is not None:
                for path in (self.socket_path, pid_path(self.home)):
                    with contextlib.suppress(FileNotFoundError):
                        os.remove(path)
            if self._store is not None:
                self._store.close()
            self._stopped.set()

    def deliver_incoming(
        self,
        envelope: Envelope,
        *,
        received_at: int | None = None,
        remote_address: str | None = None,
    ) -> IncomingResult:
        """Saves a message that arrived from another host and routes it:
          1. to the session whose label the envelope names, if one is open;
          2. otherwise to the most recently active session;
          3. with no session open, it stays queued and is pushed when a session registers.
        Every subscriber also gets it. A duplicate (same id) is ignored.

        `received_at` (milliseconds since the epoch) defaults to now;
        `remote_address` is where it came from, for logging.
        """
        stored = self.store.save_incoming(
            envelope, self._now() if received_at is None else received_at
        )
        if not stored:
            return IncomingResult(stored=False, delivered_to=None)
        notification = self._notification(envelope)
        for subscriber in list(self._subscribers):
            subscriber.notify("message", notification)
        target = self._session_by_label(envelope.get("session")) or self._most_recently_active()
        if target is not None and self._push(target, envelope["id"], notification):
            return IncomingResult(stored=True, delivered_to=target.label)
        return IncomingResult(stored=True, delivered_to=None)

    async def send(self, params: SendParams) -> SendResult:
        """Creates, saves and queues a message to a contact, then tells the transport.

        Raises `RpcError` if `to` is not a known contact, or is a blocked one
        (such a message could never be delivered).
        """
        contact = self.resolve_contact(params["to"])
        if contact.trust != "paired":
            raise RpcError(
                RpcErrorCode.APPLICATION_ERROR,
                f'"{contact.name}" is blocked; run `squawk unblock {contact.name}` '
                "before sending to them",
            )
        # A reply joins the thread of the message it answers, unless told otherwise.
        thread = params.get("thread_id")
        in_reply_to = params.get("in_reply_to")
        if thread is None and in_reply_to is not None:
            answered = self.store.get_message(in_reply_to)
            thread = None if answered is None else answered.thread_id
        envelope = create_envelope(
            from_=self.identity.id,
            to=contact.public_key,
            body=params["body"],
            kind=params.get("kind", "text"),
            session=params.get("session"),
            thread_id=thread,
            in_reply_to=in_reply_to,
            created_at=self._now(),
        )
        self.store.queue_outgoing(envelope)
        try:
            kicked = self.transport.kick(envelope)
            if inspect.isawaitable(kicked):
                await kicked
        except Exception as err:
            # The message is safely queued; the transport retries later.
            print(f"squawkd: transport failed: {err}", file=sys.stderr)
        return {"id": envelope["id"], "thread_id": envelope["thread_id"], "state": "queued"}

    def resolve_contact(self, to: str) -> Contact:
        """Finds a contact by key identifier, or else by name (exact, then
        ignoring case). Raises `RpcError` if there is none or the name is ambiguous."""
        if is_key_id(to):
            by_key = self.store.get_contact(to)
            if by_key is not None:
                return by_key
        contacts = self.store.list_contacts()
        matches = [c for c in contacts if c.name == to]
        if not matches:
            lower = to.lower()
            matches = [c for c in contacts if c.name.lower() == lower]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise RpcError(
                RpcErrorCode.APPLICATION_ERROR,
                f'more than one contact is named "{to}"; use the key id instead',
            )
        raise RpcError(
            RpcErrorCode.APPLICATION_ERROR,
            f'unknown contact "{to}"; pair with them first or use a contact name from '
            '"squawk contacts"',
        )

    def peers(self) -> list[Peer]:
        """Peers seen on the network (empty without discovery)."""
        return self.transport.peers()

    def handle(self, method: str, handler: RpcHandler) -> None:
        """Adds a JSON-RPC method to the local socket. Transports call this from
        `start` to offer their own methods (pairing, for example)."""
        if self._server is None:
            raise RuntimeError("the service is not started")
        self._server.handle(method, handler)

    def contacts(self) -> list[ContactInfo]:
        """Every contact, paired or blocked, sorted by name."""
        infos: list[ContactInfo] = [
            {
                "name": c.name,
                "key_id": c.public_key,
                "fingerprint": fingerprint(key_from_id(c.public_key)),
                "trust": c.trust,
                "auto_send": c.auto_send,
                "inbound_policy": self.store.inbound_policy_for(c.public_key),
                "policy_is_default": c.inbound_policy is None,
            }
            for c in self.store.list_contacts()
        ]
        return sorted(infos, key=lambda c: _name_sort_key(c["name"]))

    def status(self) -> StatusResult:
        sessions = sorted(self._sessions.values(), key=lambda s: s.active_seq, reverse=True)
        return {
            "name": self.identity.name,
            "key_id": self.identity.id,
            "fingerprint": fingerprint(self.identity.public_key),
            "pid": os.getpid(),
            "sessions": [
                {"label": s.label, "last_active": iso_from_ms(s.last_active)} for s in sessions
            ],
            "queued_inbound": self.store.count_undelivered_incoming(),
            "queued_outbound": self.store.count_outbound(),
            "port": self.transport.port,
        }

    def _register_methods(self, server: RpcServer) -> None:
        def register_session(params: Any, connection: RpcConnection) -> dict[str, str]:
            obj = _params_object(params)
            assert obj is not None
            label = _string_field(obj, "label", required=True, min_length=1, max_length=256)
            assert label is not None
            return self._register_session(connection, label)

        async def send(params: Any, _connection: RpcConnection) -> SendResult:
            return await self.send(parse_send_params(params))

        def update_contact(params: Any, _connection: RpcConnection) -> dict[str, Any]:
            obj = _params_object(params)
            assert obj is not None
            name = _string_field(obj, "contact", required=True, min_length=1)
            assert name is not None
            auto_send = _bool_field(obj, "auto_send")
            # null clears the contact's own policy so the default applies.
            policy: InboundPolicy | _Unset | None = UNSET
            if "inbound_policy" in obj:
                if obj["inbound_policy"] is None:
                    policy = None
                else:
                    policy = cast(
                        InboundPolicy, _enum_field(obj, "inbound_policy", _INBOUND_POLICIES)
                    )
            contact = self.resolve_contact(name)
            self.store.update_contact(
                contact.public_key, auto_send=auto_send, inbound_policy=policy
            )
            return {
                "contact": next(
                    (c for c in self.contacts() if c["key_id"] == contact.public_key), None
                )
            }

        def set_default_policy(params: Any, _connection: RpcConnection) -> dict[str, str]:
            obj = _params_object(params)
            assert obj is not None
            if "policy" not in obj:
                raise _invalid("policy: required")
            policy = _enum_field(obj, "policy", _INBOUND_POLICIES)
            assert policy is not None
            self.store.set_setting(DEFAULT_INBOUND_POLICY_KEY, policy)
            return {"policy": policy}

        def get_message(params: Any, _connection: RpcConnection) -> dict[str, MessageInfo]:
            obj = _params_object(params)
            assert obj is not None
            id = _string_field(obj, "id", required=True, min_length=1, max_length=128)
            assert id is not None
            message = self.store.get_message(id)
            if message is None:
                raise RpcError(RpcErrorCode.APPLICATION_ERROR, f'no message with id "{id}"')
            return {"message": self._message_info(message)}

        def inbox(params: Any, _connection: RpcConnection) -> dict[str, Any]:
            obj = _params_object(params, optional=True)
            mark_read = None if obj is None else _bool_field(obj, "mark_read")
            messages = self.store.inbox()
            if mark_read and messages:
                self.store.mark_read([m.id for m in messages])
            return {
                "messages": [self._notification(self._envelope_of(m)) for m in messages],
            }

        def subscribe(_params: Any, connection: RpcConnection) -> dict[str, bool]:
            self._subscribers.add(connection)
            connection.on_close(lambda: self._subscribers.discard(connection))
            return {"ok": True}

        def stop(_params: Any, _connection: RpcConnection) -> dict[str, bool]:
            # Answer first, then shut down.
            loop = asyncio.get_running_loop()
            loop.call_soon(lambda: self._spawn_stop())
            return {"ok": True}

        server.handle("register_session", register_session)
        server.handle("send", send)
        server.handle("peers", lambda _p, _c: {"peers": self.peers()})
        server.handle("contacts", lambda _p, _c: {"contacts": self.contacts()})
        server.handle("update_contact", update_contact)
        server.handle("set_default_policy", set_default_policy)
        server.handle("get_message", get_message)
        server.handle("inbox", inbox)
        server.handle("subscribe", subscribe)
        server.handle("status", lambda _p, _c: self.status())
        server.handle("stop", stop)

    def _spawn_stop(self) -> None:
        if self._stopping is None:
            self._stopping = asyncio.ensure_future(self._stop())

    def _register_session(self, connection: RpcConnection, label: str) -> dict[str, str]:
        is_new = connection not in self._sessions
        self._seq += 1
        session = _Session(
            id=str(uuid.uuid4()),
            label=label,
            connection=connection,
            registered_seq=self._seq,
            active_seq=self._seq,
            last_active=self._now(),
        )
        self._sessions[connection] = session
        if is_new:
            connection.on_close(lambda: self._sessions.pop(connection, None))
        # Push queued messages after the response has been written.
        asyncio.get_running_loop().call_soon(self._flush_queued, session)
        return {"session_id": session.id, "label": label}

    def _flush_queued(self, registered: _Session) -> None:
        """Pushes undelivered incoming messages now that `registered` has opened."""
        if self._store is None or self._stopping is not None or registered.connection.closed:
            return
        for message in self.store.undelivered_incoming():
            target = self._session_by_label(message.session) or registered
            envelope = self._envelope_of(message)
            self._push(target, message.id, self._notification(envelope))

    def _push(self, session: _Session, message_id: str, notification: MessageNotification) -> bool:
        if not session.connection.notify("message", notification):
            return False
        self.store.mark_delivered(message_id)
        return True

    def _touch(self, connection: RpcConnection) -> None:
        session = self._sessions.get(connection)
        if session is None:
            return
        self._seq += 1
        session.active_seq = self._seq
        session.last_active = self._now()

    def _session_by_label(self, label: str | None) -> _Session | None:
        """The newest registration with this label, if any is open."""
        if label is None:
            return None
        best: _Session | None = None
        for session in self._sessions.values():
            if session.label == label and (
                best is None or session.registered_seq > best.registered_seq
            ):
                best = session
        return best

    def _most_recently_active(self) -> _Session | None:
        best: _Session | None = None
        for session in self._sessions.values():
            if best is None or session.active_seq > best.active_seq:
                best = session
        return best

    def _notification(self, envelope: Envelope) -> MessageNotification:
        contact = self.store.get_contact(envelope["from"])
        return {
            "envelope": envelope,
            "from_name": None if contact is None else contact.name,
            "policy": self.store.inbound_policy_for(envelope["from"]),
        }

    def _message_info(self, message: StoredMessage) -> MessageInfo:
        contact = self.store.get_contact(message.peer)
        return {
            "id": message.id,
            "direction": message.direction,
            "peer": message.peer,
            "peer_name": None if contact is None else contact.name,
            "session": message.session,
            "thread_id": message.thread_id,
            "in_reply_to": message.in_reply_to,
            "kind": message.kind,
            "body": message.body,
            "created_at": message.created_at,
            "state": message.state,
        }

    def _envelope_of(self, message: StoredMessage) -> Envelope:
        """Rebuilds the envelope of a stored incoming message."""
        envelope: dict[str, Any] = {
            "id": message.id,
            "from": message.peer,
            "to": self.identity.id,
            "thread_id": message.thread_id,
            "created_at": message.created_at,
            "kind": message.kind,
            "body": message.body,
        }
        if message.session is not None:
            envelope["session"] = message.session
        if message.in_reply_to is not None:
            envelope["in_reply_to"] = message.in_reply_to
        return cast(Envelope, envelope)
