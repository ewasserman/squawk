"""squawkd: the background service. It owns the identity and the database,
listens on a unix socket for local clients (the CLI, `squawk tail`, and the
Claude Code session hooks) speaking newline-delimited JSON-RPC 2.0, and
delivers incoming messages into Claude Code sessions.

Claude Code sessions register through their SessionStart hook (`squawk hook
session-start`), giving their inbox socket and token (see squawk.inbox), and
unregister through SessionEnd. Registrations are kept in the database, so a
restarted service still knows them; a session whose socket file is gone is
forgotten. An incoming message goes to:

  1. the local session that sent or received earlier messages in the same
     conversation (thread), if it is open;
  2. otherwise the session the sender named (by label, or by repository name
     when exactly one open session has that repository);
  3. otherwise the session the person chose to take messages nobody else
     takes (`squawk sessions --catch-all <label>`);
  4. otherwise no session: it waits unread, and a desktop notification tells
     the person. It is delivered later if a session it matches registers.

Network transports (mDNS discovery, the WebSocket listener) plug in through
`deliver_incoming` (for messages that arrive) and the `Transport` class (for
messages to send), so routing does not depend on how a message travels.

The methods squawk 0.1 also had take and return the same JSON as there; the
session methods and `status`'s session list were added later.
"""

import asyncio
import contextlib
import inspect
import os
import sys
import unicodedata
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, NotRequired, TypedDict, cast

from squawk import jsontext
from squawk.config import db_path, pid_path, run_dir, socket_path
from squawk.encoding import is_key_id, key_from_id
from squawk.envelope import MESSAGE_KINDS, Envelope, MessageKind, create_envelope
from squawk.identity import Identity, fingerprint, load_identity
from squawk.inbox import (
    Notifier,
    delivery_text,
    find_session,
    inbox_state,
    notification_text,
    post_to_inbox,
    unique_label,
)
from squawk.rpc import RpcClient, RpcConnection, RpcError, RpcErrorCode, RpcHandler, RpcServer
from squawk.store import (
    DEFAULT_AUTO_SEND_KEY,
    DEFAULT_INBOUND_POLICY_KEY,
    UNSET,
    Contact,
    InboundPolicy,
    SessionRecord,
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


CATCH_ALL_KEY = "catch_all_session"
"""Setting key holding the label of the session that takes messages no other
session takes (absent: none)."""

SHARE_SESSIONS_KEY = "share_sessions"
"""Setting key holding "off" when paired contacts may not list this
machine's sessions (absent or "on": they may)."""


class PeerSession(TypedDict):
    """A session as another machine sees it: no paths, no tokens."""

    label: str
    branch: str | None


class PeerSessions(TypedDict):
    shared: bool
    """False when that person turned off sharing their session list."""
    sessions: list[PeerSession]


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

    async def request_sessions(self, key_id: str) -> PeerSessions:
        """Asks a contact's service for its list of sessions."""
        raise RpcError(RpcErrorCode.APPLICATION_ERROR, "this service has no network transport")


no_transport = Transport()
"""A transport that sends nothing; messages stay in the outbound queue."""


@dataclass(frozen=True)
class IncomingResult:
    """What `deliver_incoming` did with a message."""

    stored: bool
    """False if a message with the same id was already stored (nothing else happens)."""
    delivery: "asyncio.Future[str | None] | None" = None
    """Completes with the label of the session the message was written into,
    or None if no session took it (it then waits unread). None when the
    message was not stored."""


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
    from_socket: NotRequired[str]
    """The inbox socket of the local Claude Code session sending it (from
    CLAUDE_CODE_MESSAGING_SOCKET), so replies come back to that session."""


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
    """Whether messages to this contact go out without asking the person first
    (the contact's own setting, or the default)."""
    auto_send_is_default: bool
    """True when the contact has no auto-send setting of its own and follows
    the default. Not sent by squawk 0.1."""
    inbound_policy: InboundPolicy
    """The policy that applies to this contact's messages (their own or the default)."""
    policy_is_default: bool
    """True when the contact has no policy of its own and follows the default."""


class SessionInfo(TypedDict):
    """A local Claude Code session, as the `sessions` and `status` methods list it."""

    label: str
    repo: str | None
    branch: str | None
    cwd: str
    reachable: bool
    """Whether its inbox socket accepted a connection at the last check."""
    catch_all: bool
    """Whether it takes messages no other session takes."""
    registered_at: str


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
    catch_all: str | None
    """The label chosen to take messages no other session takes, if any."""


# Checking params. Unknown fields are ignored, an optional field may be left
# out but not set to null (unless it says so), and string lengths count
# UTF-16 code units. The error texts are plain descriptions; clients rely
# only on the error code.

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
        ("from_socket", 1, 1024),
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


def _log(text: str) -> None:
    print(f"squawkd: {text}", file=sys.stderr, flush=True)


def _optional_string(obj: Mapping[str, Any], key: str, max_length: int) -> str | None:
    """A string field that may be missing or null."""
    if obj.get(key) is None:
        return None
    return _string_field(obj, key, required=False, max_length=max_length)


def _name_sort_key(name: str) -> tuple[str, str, str]:
    """Orders names ignoring accents and case first, then by accents, then
    with lower case before upper case."""
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
        notify: Notifier | None = None,
        session_check_interval_s: float = 60.0,
        unreachable_grace_ms: int = 10 * 60_000,
    ) -> None:
        """`notify` shows a desktop notification for a message no session
        took (default: none; the service process passes the macOS one).
        Sessions are checked every `session_check_interval_s` seconds; one
        whose socket file is there but refuses connections for longer than
        `unreachable_grace_ms` is forgotten."""
        self.home = home
        self.socket_path = socket_path(home)
        self.transport: Transport = no_transport if transport is None else transport
        self._now = now_ms if now is None else now
        self._notify = notify
        self._check_interval_s = session_check_interval_s
        self._unreachable_grace_ms = unreachable_grace_ms
        self._sessions: dict[str, SessionRecord] = {}
        """Registered Claude Code sessions, by Claude session id."""
        self._unreachable_since: dict[str, int] = {}
        """Sessions whose inbox refused the last connection, and since when."""
        self._delivery_lock = asyncio.Lock()
        self._tasks: set[asyncio.Task[Any]] = set()
        self._subscribers: set[RpcConnection] = set()
        self._identity: Identity | None = None
        self._store: Store | None = None
        self._server: RpcServer | None = None
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
        self._sessions = {s.session_id: s for s in self._store.list_sessions()}
        server = RpcServer()
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
        # Re-check the sessions registered before a restart, deliver what
        # waited meanwhile, and keep checking.
        self._spawn(self._watch_sessions())

    async def stop(self) -> None:
        """Stops listening, closes every connection and the store. Safe to call twice."""
        if self._stopping is None:
            self._stopping = asyncio.ensure_future(self._stop())
        await asyncio.shield(self._stopping)

    async def _stop(self) -> None:
        try:
            await self.transport.stop()
        finally:
            for task in list(self._tasks):
                task.cancel()
            await asyncio.gather(*self._tasks, return_exceptions=True)
            if self._server is not None:
                await self._server.close()
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
        """Saves a message that arrived from another host, passes it to every
        subscriber, and starts delivering it into a session (see the module
        description for which one). A duplicate (same id) is ignored.

        Must be called from inside the running event loop. `received_at`
        (milliseconds since the epoch) defaults to now; `remote_address` is
        where it came from, for logging.
        """
        stored = self.store.save_incoming(
            envelope, self._now() if received_at is None else received_at
        )
        if not stored:
            return IncomingResult(stored=False)
        notification = self._notification(envelope)
        for subscriber in list(self._subscribers):
            subscriber.notify("message", notification)
        delivery = self._spawn(self._deliver_new(envelope["id"]))
        return IncomingResult(stored=True, delivery=delivery)

    # Sessions

    def _spawn(self, coro: Coroutine[Any, Any, Any]) -> "asyncio.Task[Any]":
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _is_reachable(self, session_id: str) -> bool:
        return session_id not in self._unreachable_since

    def _open_sessions(self) -> list[SessionRecord]:
        """Registered sessions whose inbox answered at the last check."""
        return [s for s in self._sessions.values() if self._is_reachable(s.session_id)]

    def catch_all_label(self) -> str | None:
        return self.store.get_setting(CATCH_ALL_KEY)

    def shares_sessions(self) -> bool:
        return self.store.get_setting(SHARE_SESSIONS_KEY) != "off"

    def register_session(
        self,
        *,
        session_id: str,
        socket: str,
        token: str,
        cwd: str,
        base_label: str,
        repo: str | None = None,
        branch: str | None = None,
    ) -> SessionRecord:
        """Records a Claude Code session (or updates it, when the same session
        registers again) and starts delivering messages waiting for it.

        The label is `base_label`, with "-2", "-3", ... added when another
        open session already has it. A session registering again keeps its
        label.
        """
        previous = self._sessions.get(session_id)
        # Another registration with the same socket is a session that ended
        # without unregistering; its socket now belongs to this one.
        for other in list(self._sessions.values()):
            if other.socket_path == socket and other.session_id != session_id:
                self._forget(other.session_id)
        if previous is not None and previous.base_label == base_label:
            label = previous.label
        else:
            label = unique_label(
                base_label,
                (s.label for s in self._sessions.values() if s.session_id != session_id),
            )
        record = SessionRecord(
            session_id=session_id,
            label=label,
            base_label=base_label,
            repo=repo,
            branch=branch,
            cwd=cwd,
            socket_path=socket,
            token=token,
            registered_at=previous.registered_at
            if previous is not None
            else iso_from_ms(self._now()),
        )
        self.store.save_session(record)
        self._sessions[session_id] = record
        self._unreachable_since.pop(session_id, None)
        self._spawn(self._deliver_waiting())
        return record

    def unregister_session(self, session_id: str) -> bool:
        """Forgets a session that ended. Returns False if it was not registered."""
        known = session_id in self._sessions
        self._forget(session_id)
        return known

    def _forget(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        self._unreachable_since.pop(session_id, None)
        self.store.delete_session(session_id)

    def session_by_socket(self, path: str | None) -> SessionRecord | None:
        if not path:
            return None
        return next((s for s in self._sessions.values() if s.socket_path == path), None)

    async def check_sessions(self) -> None:
        """Checks every session's inbox socket: forgets sessions whose socket
        file is gone (or has refused connections for too long), and marks the
        rest reachable or not. Delivers waiting messages if a session became
        reachable."""
        became_reachable = False
        for session in list(self._sessions.values()):
            state = await inbox_state(session.socket_path)
            if session.session_id not in self._sessions:
                continue  # unregistered meanwhile
            if state == "gone":
                _log(f"session {session.label} ended (its inbox socket is gone)")
                self._forget(session.session_id)
            elif state == "refused":
                since = self._unreachable_since.setdefault(session.session_id, self._now())
                if self._now() - since >= self._unreachable_grace_ms:
                    _log(f"session {session.label} ended (its inbox refuses connections)")
                    self._forget(session.session_id)
            elif self._unreachable_since.pop(session.session_id, None) is not None:
                became_reachable = True
        if became_reachable:
            await self._deliver_waiting()

    async def _watch_sessions(self) -> None:
        while True:
            try:
                await self.check_sessions()
                await self._deliver_waiting()
            except asyncio.CancelledError:
                raise
            except Exception as err:
                _log(f"checking sessions failed: {err}")
            await asyncio.sleep(self._check_interval_s)

    def set_catch_all(self, label: str | None) -> None:
        """Chooses (by label) the session that takes messages no other session
        takes, or with None clears the choice. Delivers waiting messages to it."""
        if label is None:
            self.store.delete_setting(CATCH_ALL_KEY)
        else:
            self.store.set_setting(CATCH_ALL_KEY, label)
            self._spawn(self._deliver_waiting())

    def route(
        self, message: StoredMessage, exclude: set[str] | None = None
    ) -> SessionRecord | None:
        """The session an incoming message goes to, or None (see the module
        description). Sessions in `exclude` (by id) are not considered."""
        candidates = [
            s for s in self._open_sessions() if exclude is None or s.session_id not in exclude
        ]
        bound = self.store.thread_session(message.thread_id)
        if bound is not None:
            owner = next((s for s in candidates if s.session_id == bound), None)
            if owner is not None:
                return owner
        named = find_session(candidates, message.session)
        if named is not None:
            return named
        return find_session(candidates, self.catch_all_label())

    async def _deliver_new(self, message_id: str) -> str | None:
        """Delivers a message that just arrived; notifies the person if no
        session takes it."""
        delivered = await self._deliver_waiting([message_id])
        label = delivered.get(message_id)
        if label is None and self._notify is not None:
            message = self.store.get_message(message_id)
            if message is not None and message.delivered_at is None:
                envelope = self._envelope_of(message)
                try:
                    self._notify(
                        *notification_text(self._notification(envelope)["from_name"], envelope)
                    )
                except Exception as err:
                    _log(f"could not show a notification: {err}")
        return label

    async def _deliver_waiting(self, ids: list[str] | None = None) -> dict[str, str | None]:
        """Writes waiting incoming messages (all of them, or those in `ids`)
        into the sessions they go to. Returns the label each one went to,
        or None for those that keep waiting."""
        results: dict[str, str | None] = {}
        async with self._delivery_lock:
            if self._store is None or self._stopping is not None:
                return results
            waiting = self.store.undelivered_incoming()
            if ids is not None:
                waiting = [m for m in waiting if m.id in ids]
            for message in waiting:
                results[message.id] = await self._deliver_one(message)
        return results

    async def _deliver_one(self, message: StoredMessage) -> str | None:
        tried: set[str] = set()
        envelope = self._envelope_of(message)
        notification = self._notification(envelope)
        auto_send, _ = self.store.auto_send_for(message.peer)
        text = delivery_text(
            envelope,
            from_name=notification["from_name"],
            policy=notification["policy"],
            auto_send=auto_send,
        )
        while True:
            target = self.route(message, tried)
            if target is None:
                return None
            tried.add(target.session_id)
            try:
                await post_to_inbox(target.socket_path, target.token, text)
            except (OSError, TimeoutError) as err:
                _log(f"could not write message {message.id} into session {target.label}: {err}")
                if os.path.exists(target.socket_path):
                    self._unreachable_since.setdefault(target.session_id, self._now())
                else:
                    self._forget(target.session_id)
                continue
            self.store.mark_delivered(message.id)
            self.store.bind_thread(message.thread_id, target.session_id)
            return target.label

    def session_infos(self) -> list[SessionInfo]:
        """The registered sessions, oldest first."""
        catch_all = find_session(self._open_sessions(), self.catch_all_label())
        return [
            {
                "label": s.label,
                "repo": s.repo,
                "branch": s.branch,
                "cwd": s.cwd,
                "reachable": self._is_reachable(s.session_id),
                "catch_all": catch_all is not None and catch_all.session_id == s.session_id,
                "registered_at": s.registered_at,
            }
            for s in self._sessions.values()
        ]

    def sessions_for_peer(self) -> PeerSessions:
        """What a paired contact may see of this machine's sessions: labels
        and branches of reachable ones, or nothing if sharing is off."""
        if not self.shares_sessions():
            return {"shared": False, "sessions": []}
        return {
            "shared": True,
            "sessions": [{"label": s.label, "branch": s.branch} for s in self._open_sessions()],
        }

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
        # Answers in this conversation come back to the session that sent it.
        sender = self.session_by_socket(params.get("from_socket"))
        if sender is not None:
            self.store.bind_thread(envelope["thread_id"], sender.session_id)
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
        infos: list[ContactInfo] = []
        for c in self.store.list_contacts():
            auto_send, auto_send_is_default = self.store.auto_send_for(c.public_key)
            infos.append(
                {
                    "name": c.name,
                    "key_id": c.public_key,
                    "fingerprint": fingerprint(key_from_id(c.public_key)),
                    "trust": c.trust,
                    "auto_send": auto_send,
                    "auto_send_is_default": auto_send_is_default,
                    "inbound_policy": self.store.inbound_policy_for(c.public_key),
                    "policy_is_default": c.inbound_policy is None,
                }
            )
        return sorted(infos, key=lambda c: _name_sort_key(c["name"]))

    def default_auto_send(self) -> bool:
        """Whether messages to contacts with no auto-send setting of their own
        go out without asking (off unless the person turned it on)."""
        return self.store.get_setting(DEFAULT_AUTO_SEND_KEY) == "on"

    def status(self) -> StatusResult:
        return {
            "name": self.identity.name,
            "key_id": self.identity.id,
            "fingerprint": fingerprint(self.identity.public_key),
            "pid": os.getpid(),
            "sessions": self.session_infos(),
            "queued_inbound": self.store.count_undelivered_incoming(),
            "queued_outbound": self.store.count_outbound(),
            "port": self.transport.port,
            "catch_all": self.catch_all_label(),
        }

    def _register_methods(self, server: RpcServer) -> None:
        def register_session(params: Any, _connection: RpcConnection) -> dict[str, Any]:
            obj = _params_object(params)
            assert obj is not None

            def required(key: str, max_length: int, min_length: int = 1) -> str:
                value = _string_field(
                    obj, key, required=True, min_length=min_length, max_length=max_length
                )
                assert value is not None
                return value

            record = self.register_session(
                session_id=required("session_id", 256),
                socket=required("socket", 1024),
                token=required("token", 1024, 0),
                cwd=required("cwd", 4096, 0),
                base_label=required("base_label", 256),
                repo=_optional_string(obj, "repo", 256),
                branch=_optional_string(obj, "branch", 256),
            )
            catch_all = find_session(self._open_sessions(), self.catch_all_label())
            return {
                "label": record.label,
                "catch_all": catch_all is not None and catch_all.session_id == record.session_id,
            }

        def unregister_session(params: Any, _connection: RpcConnection) -> dict[str, bool]:
            obj = _params_object(params)
            assert obj is not None
            session_id = _string_field(obj, "session_id", required=True, min_length=1)
            assert session_id is not None
            return {"removed": self.unregister_session(session_id)}

        async def sessions(_params: Any, _connection: RpcConnection) -> dict[str, Any]:
            await self.check_sessions()
            return {
                "sessions": self.session_infos(),
                "catch_all": self.catch_all_label(),
                "share": self.shares_sessions(),
            }

        def set_catch_all(params: Any, _connection: RpcConnection) -> dict[str, Any]:
            obj = _params_object(params)
            assert obj is not None
            if "label" not in obj:
                raise _invalid("label: required")
            label = _optional_string(obj, "label", 256)
            self.set_catch_all(label or None)
            match = find_session(self._open_sessions(), self.catch_all_label())
            return {"catch_all": self.catch_all_label(), "open": match is not None}

        def set_share_sessions(params: Any, _connection: RpcConnection) -> dict[str, bool]:
            obj = _params_object(params)
            assert obj is not None
            share = _bool_field(obj, "share")
            if share is None:
                raise _invalid("share: required")
            self.store.set_setting(SHARE_SESSIONS_KEY, "on" if share else "off")
            return {"share": share}

        async def peer_sessions(params: Any, _connection: RpcConnection) -> dict[str, Any]:
            obj = _params_object(params)
            assert obj is not None
            name = _string_field(obj, "peer", required=True, min_length=1)
            assert name is not None
            contact = self.resolve_contact(name)
            if contact.trust != "paired":
                raise RpcError(RpcErrorCode.APPLICATION_ERROR, f'"{contact.name}" is blocked')
            try:
                result = await self.transport.request_sessions(contact.public_key)
            except RpcError:
                raise
            except Exception as err:
                raise RpcError(
                    RpcErrorCode.APPLICATION_ERROR,
                    f"could not get {contact.name}'s sessions: {err or type(err).__name__}",
                ) from err
            return {"contact": contact.name, **result}

        async def status(_params: Any, _connection: RpcConnection) -> StatusResult:
            await self.check_sessions()
            return self.status()

        async def send(params: Any, _connection: RpcConnection) -> SendResult:
            return await self.send(parse_send_params(params))

        def update_contact(params: Any, _connection: RpcConnection) -> dict[str, Any]:
            obj = _params_object(params)
            assert obj is not None
            name = _string_field(obj, "contact", required=True, min_length=1)
            assert name is not None
            # null clears the contact's own auto-send setting so the default applies.
            auto_send: bool | _Unset | None = UNSET
            if "auto_send" in obj:
                auto_send = None if obj["auto_send"] is None else _bool_field(obj, "auto_send")
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

            def update() -> None:
                self.store.update_contact(contact.public_key, inbound_policy=policy)
                if auto_send is not UNSET:
                    self.store.set_auto_send(contact.public_key, auto_send)

            self.store.transaction(update)
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

        def set_default_auto_send(params: Any, _connection: RpcConnection) -> dict[str, bool]:
            obj = _params_object(params)
            assert obj is not None
            if "auto_send" not in obj:
                raise _invalid("auto_send: required")
            value = _bool_field(obj, "auto_send")
            self.store.set_setting(DEFAULT_AUTO_SEND_KEY, "on" if value else "off")
            return {"auto_send": bool(value)}

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
        server.handle("unregister_session", unregister_session)
        server.handle("sessions", sessions)
        server.handle("set_catch_all", set_catch_all)
        server.handle("set_share_sessions", set_share_sessions)
        server.handle("peer_sessions", peer_sessions)
        server.handle("send", send)
        server.handle("peers", lambda _p, _c: {"peers": self.peers()})
        server.handle(
            "contacts",
            lambda _p, _c: {
                "contacts": self.contacts(),
                "default_auto_send": self.default_auto_send(),
            },
        )
        server.handle("update_contact", update_contact)
        server.handle("set_default_policy", set_default_policy)
        server.handle("set_default_auto_send", set_default_auto_send)
        server.handle("get_message", get_message)
        server.handle("inbox", inbox)
        server.handle("subscribe", subscribe)
        server.handle("status", status)
        server.handle("stop", stop)

    def _spawn_stop(self) -> None:
        if self._stopping is None:
            self._stopping = asyncio.ensure_future(self._stop())

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
