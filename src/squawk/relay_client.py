"""The service's connection to its relay (docs/plan/relay.md).

The service keeps one WebSocket connection to the relay it is set to use,
and reconnects with backoff (1 second, doubling to at most 5 minutes, with
random jitter) when it drops. A relay that does not admit its key (close
code 4003) or wants its owner to sign in (`login-required`) is tried again
only every 6 hours, or at once when `retry_now` is called.

After proving its key, it sends its allow list (its paired, unblocked
contacts) and asks for waiting messages; from then on the relay pushes each
new message as it arrives. The allow list is
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
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

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
from squawk.relay.access import NOT_PERMITTED_CODE
from squawk.relay_url import check_relay_url

if TYPE_CHECKING:
    from squawk.daemon import Daemon

RELAY_URL_KEY = "relay_url"
"""Setting key holding the URL of the relay this service uses."""

RELAY_ALLOW_PLAIN_KEY = "relay_allow_plain"
"""Setting key holding "on" when the person allowed a plain ws:// relay URL."""

PROTOCOL_VERSION = 1

AccessProblem = Literal["not-permitted", "needs-sign-in"]
"""Why a relay that is reachable does not let this service in
(docs/plan/relay-access.md, "The client")."""

NOT_PERMITTED_TEXT = "not permitted by this relay; ask the person who runs it"
NEEDS_SIGN_IN_TEXT = "needs sign-in: run `squawk relay login`"

REFUSED_RETRY_MS = 6 * 60 * 60_000
"""How long the client waits before trying a relay that refused its key
again, in case the operator admitted it in the meantime."""
_MAX_FRAME = 1 << 20

PERMANENT_REFUSALS = frozenset({"malformed", "sender-mismatch", "too-large"})
"""Relay refusals that sending the same message again cannot change. The
others ("not-allowed", "mailbox-full", "rate-limited", "offline", "error")
can clear up: "not-allowed" can mean the recipient has not connected to this
relay yet, or has not added us to its allow list yet."""


def _log(text: str) -> None:
    print(f"squawkd: relay: {text}", file=sys.stderr, flush=True)


class _AccessRefused(LinkError):
    """The relay will not let this service's key in until something changes."""

    def __init__(self, problem: AccessProblem, reason: str = "") -> None:
        super().__init__(NOT_PERMITTED_TEXT if problem == "not-permitted" else NEEDS_SIGN_IN_TEXT)
        self.problem: AccessProblem = problem
        self.reason = reason
        """The `login-failed` reason, when a sign-in was tried."""

    def __str__(self) -> str:
        return LOGIN_FAILURES.get(self.reason, super().__str__())


LOGIN_FAILURES: dict[str, str] = {
    "not-permitted": "the relay does not permit this GitHub account; ask the person who runs it",
    "denied": "the sign-in was declined on GitHub",
    "expired": "the code expired before it was approved; run `squawk relay login` again",
    "busy": "the relay has too many sign-ins in progress; try again in a few minutes",
    "error": "the relay could not reach GitHub; try again later",
}
"""What each `login-failed` reason means, for the person signing in."""


class RelayLoginFailed(LinkError):
    """Signing in to the relay did not work; `reason` is the relay's reason
    code (`LOGIN_FAILURES`), or empty when the connection failed instead."""

    def __init__(self, message: str, reason: str = "") -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class LoginPrompt:
    """What the person must do to sign in: open `verification_uri` and enter
    `user_code` before `expires_at` (ISO time)."""

    verification_uri: str
    user_code: str
    expires_at: str


class _Login:
    """A sign-in asked for with `RelayClient.start_login`. `prompt` completes
    with the code to show (or None when the relay let the key in without
    one); `result` with the GitHub login the person signed in as."""

    def __init__(self) -> None:
        loop = asyncio.get_running_loop()
        self.prompt: asyncio.Future[LoginPrompt | None] = loop.create_future()
        self.result: asyncio.Future[str | None] = loop.create_future()
        for future in (self.prompt, self.result):
            # Mark failures as seen, so that one nobody waits for is not logged.
            future.add_done_callback(lambda f: f.cancelled() or f.exception())

    def fail(self, err: BaseException) -> None:
        for future in (self.prompt, self.result):
            if not future.done():
                future.set_exception(err)

    @property
    def done(self) -> bool:
        return self.result.done()


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
        self._held: list[object] = []
        """Frames that arrived before anyone listened; passed on to the first listener."""
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
        if self._held:
            # Frames can arrive between the relay saying someone joined and
            # pairing starting to listen; they are passed on, in order, now.
            held, self._held = self._held, []

            def pass_on() -> None:
                for frame in held:
                    self._deliver(frame)

            asyncio.get_running_loop().call_soon(pass_on)

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
        if not self._frame_listeners:
            self._held.append(frame)
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
        refused_retry_ms: int = REFUSED_RETRY_MS,
    ) -> None:
        self.url = check_relay_url(url, allow_plain=allow_plain)
        self._request_timeout_ms = request_timeout_ms
        self._backoff_min_ms = backoff_min_ms
        self._backoff_max_ms = backoff_max_ms
        self._allow_check_interval_ms = allow_check_interval_ms
        self._refused_retry_ms = refused_retry_ms
        self._retry_now = asyncio.Event()
        self.access_problem: AccessProblem | None = None
        """Set while the relay refuses this service's key or wants its owner
        to sign in; the client then tries again only every
        `refused_retry_ms` or when `retry_now` is called."""
        self._daemon: Daemon | None = None
        self._guard: ReplayGuard | None = None
        self._ws: ClientConnection | None = None
        self._ready = False
        self._setting_up = False
        """True after the relay accepted our key, while the allow list and
        `fetch` are being sent; requests are allowed, `connected` is not yet true."""
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
        self._login: _Login | None = None
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
        if self._login is not None:
            self._login.fail(RelayLoginFailed("the service stopped using this relay"))
        tasks = [t for t in (self._runner, *self._tasks) if t is not None]
        for task in tasks:
            task.cancel()
        if self._ws is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._ws.close(1001, "shutting down"), 2)
        await asyncio.gather(*tasks, return_exceptions=True)

    async def start_login(self, timeout_s: float = 30.0) -> LoginPrompt | None:
        """Connects to the relay to sign in with GitHub (docs/plan/relay-access.md,
        "The client"). Returns what the person must do, or None when the relay
        let this service in without a sign-in (it is connected, or the relay
        is not in github mode). Raises `RelayLoginFailed` if the relay refuses
        or cannot be reached. Then call `wait_login`."""
        if self._ready or self._setting_up:
            return None
        if self._stopped:
            raise RelayLoginFailed("the service stopped using this relay")
        login = self._login
        if login is None or login.done:
            login = self._login = _Login()
            self.retry_now()
        try:
            return await asyncio.wait_for(asyncio.shield(login.prompt), timeout_s)
        except TimeoutError:
            raise RelayLoginFailed(
                f"the relay did not answer ({self.last_error or 'still connecting'})"
            ) from None

    async def wait_login(self) -> str | None:
        """Waits for the sign-in started by `start_login` to end. Returns the
        GitHub login the person signed in as (None if no sign-in was needed);
        raises `RelayLoginFailed` if it did not work."""
        login = self._login
        if login is None:
            if self._ready:
                return None
            raise RelayLoginFailed("no sign-in has been started; run `squawk relay login`")
        return await asyncio.shield(login.result)

    def retry_now(self) -> None:
        """Ends the wait before the next connection attempt."""
        self._retry_now.set()

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
        if ws is None or not (self._ready or self._setting_up):
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
            problem: AccessProblem | None = None
            ws: ClientConnection | None = None
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
            except _AccessRefused as err:
                problem = err.problem
                if self._login is not None:
                    self._login.fail(RelayLoginFailed(str(err), err.reason))
            except Exception as err:
                self.last_error = str(err) or type(err).__name__
                if self._login is not None:
                    self._login.fail(RelayLoginFailed(f"cannot reach the relay: {self.last_error}"))
            finally:
                self._disconnected()
            if ws is not None and ws.close_code == NOT_PERMITTED_CODE:
                problem = "not-permitted"
            if self._stopped:
                return
            self.access_problem = problem
            if problem is not None:
                self.last_error = str(_AccessRefused(problem))
                _log(
                    f"{self.last_error}; trying again in {self._refused_retry_ms // 60_000} minutes"
                )
                await self._wait_before_retry(self._refused_retry_ms)
                delay = self._backoff_min_ms
                continue
            if was_ready:
                delay = self._backoff_min_ms
            _log(f"disconnected ({self.last_error}); trying again")
            await self._wait_before_retry(delay * random.uniform(0.8, 1.2))
            delay = min(delay * 2, self._backoff_max_ms)

    async def _wait_before_retry(self, ms: float) -> None:
        """Waits `ms` milliseconds, or until `retry_now` is called."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._retry_now.wait(), ms / 1000)
        # Cleared after the wait, so that a request made during the
        # connection attempt before it is not lost.
        self._retry_now.clear()

    def _disconnected(self) -> None:
        self._ready = False
        self._setting_up = False
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
        try:
            ok = _parse(await asyncio.wait_for(ws.recv(), timeout))
        except ConnectionClosed as err:
            if err.rcvd is not None and err.rcvd.code == NOT_PERMITTED_CODE:
                raise _AccessRefused("not-permitted") from err
            raise
        if ok.get("t") == "login-required":
            login = self._login
            if login is None or login.done:
                raise _AccessRefused("needs-sign-in")
            ok = await self._sign_in(ws, login)
        if ok.get("t") != "ok":
            raise LinkError("the relay did not accept our key")
        self.relay_key = key
        self.last_error = None
        self.access_problem = None
        if self._login is not None and not self._login.done:
            # Let in without a sign-in (or after one: `_sign_in` set the result).
            user = ok.get("user")
            if not self._login.prompt.done():
                self._login.prompt.set_result(None)
            self._login.result.set_result(user if isinstance(user, str) else None)

    async def _sign_in(self, ws: ClientConnection, login: _Login) -> dict[str, Any]:
        """Runs a sign-in after `login-required`: sends `login-start`, hands the
        relay's code to `login.prompt`, and returns the relay's `ok` once the
        person has approved on GitHub. Raises `_AccessRefused` with the
        reason if the relay sends `login-failed` or closes the connection."""
        timeout = self._request_timeout_ms / 1000
        await ws.send(jsontext.stringify({"t": "login-start"}))
        try:
            frame = _parse(await asyncio.wait_for(ws.recv(), timeout))
            if frame.get("t") == "login":
                uri, code, expires_at = (
                    frame.get("verification_uri"),
                    frame.get("user_code"),
                    frame.get("expires_at"),
                )
                if not (isinstance(uri, str) and isinstance(code, str)):
                    raise LinkError("the relay sent a sign-in without a code")
                # The relay chooses what is shown; a dishonest one could point
                # the person at another site or send terminal control codes.
                uri, code = _printable(uri), _printable(code)
                if not uri.startswith(GITHUB_PREFIX):
                    raise LinkError(f"the relay sent a sign-in address not on GitHub: {uri}")
                if not login.prompt.done():
                    login.prompt.set_result(LoginPrompt(uri, code, _printable(str(expires_at))))
                # No time limit here: the relay ends the sign-in when GitHub's
                # code expires, and pings keep the connection alive meanwhile.
                frame = _parse(await ws.recv())
        except ConnectionClosed as err:
            if err.rcvd is not None and err.rcvd.code == NOT_PERMITTED_CODE:
                raise _AccessRefused("not-permitted", "not-permitted") from err
            raise LinkError("the relay closed the connection during the sign-in") from err
        if frame.get("t") == "login-failed":
            reason = frame.get("reason")
            reason = reason if isinstance(reason, str) and reason in LOGIN_FAILURES else "error"
            problem: AccessProblem = (
                "not-permitted" if reason == "not-permitted" else "needs-sign-in"
            )
            raise _AccessRefused(problem, reason)
        if frame.get("t") != "ok":
            what = _printable(str(frame.get("t")))
            reason = frame.get("reason")
            if isinstance(reason, str):
                what += f" ({_printable(reason)})"
            raise LinkError(f"the relay answered the sign-in with {what}")
        user = frame.get("user")
        if isinstance(user, str):
            frame["user"] = _printable(user)
        return frame

    async def _session(self, ws: ClientConnection) -> None:
        reader = asyncio.ensure_future(self._read(ws))
        try:
            # The allow list goes first: anything waiting was deposited
            # under the old list, and new deposits need the new one.
            self._setting_up = True
            try:
                await self._publish_allow_list()
                await self._send({"t": "fetch", "req": "fetch"})
            finally:
                self._setting_up = False
            self._ready = True
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
        if t == "invite-joined":
            waiter = self._invite_waiters.get(req) if isinstance(req, str) else None
            room = self._open_room(frame)
            if room is None:
                return
            if waiter is not None and not waiter.done():
                waiter.set_result(room)
            else:
                # The invite was replaced or cancelled here: tell the joiner
                # at once rather than leave them waiting.
                room.close()
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


GITHUB_PREFIX = "https://github.com/"


def _printable(text: str, limit: int = 200) -> str:
    """`text` without control characters (which could change what a terminal
    shows), cut to `limit` characters."""
    return "".join(c for c in text if c.isprintable())[:limit]


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
