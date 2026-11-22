"""Pairing: two people confirm each other's keys once, after which their
services accept each other's connections and messages.

One person runs `squawk pair --accept` (the responder), the other runs
`squawk pair <peer>` (the initiator). The initiator's service dials the
responder's. The WebSocket handshake (network.py) already proves that each
side holds the private key it claims; pairing then decides whether that key
is the person you think it is:

  1. initiator -> responder  `pair-commit`: SHA-256 over the initiator's key
     and a random 32-byte nonce, without revealing the nonce.
  2. responder -> initiator  `pair-nonce`: the responder's random nonce.
  3. initiator -> responder  `pair-reveal`: the initiator's nonce. The
     responder checks it against the commitment from step 1.
  4. Both sides show a 6-digit code computed from both keys and both
     nonces. Each person checks that the two screens show the same code and
     answers yes or no.
  5. Each side sends `pair-confirm` once its person said yes. The contact is
     saved only when the local person AND the other side have confirmed. A
     "no", a timeout or a mismatch saves nothing.

An attacker relaying traffic between the two people has to use keys of its
own on each side, so the codes are computed from different inputs. The
commitment in step 1 makes the attacker fix its choices before it learns the
other side's nonce, so it gets a single one-in-a-million guess at matching
codes instead of trying keys until the codes happen to match. See
docs/plan/security.md, threat 5.

The pairing exchange is the same as in squawk 0.1, so services of either
version can pair with each other.
"""

import asyncio
import hashlib
import hmac
import re
import uuid
from collections.abc import Awaitable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, TypedDict, TypeVar

from squawk import jsontext
from squawk.crypto import random_bytes
from squawk.encoding import from_base64url, key_from_id, to_base64url
from squawk.identity import fingerprint
from squawk.network import (
    NOT_PAIRED,
    Address,
    Frame,
    NetworkTransport,
    PeerLink,
    address_setting_key,
    dialable,
)
from squawk.rpc import RpcConnection, RpcError, RpcErrorCode
from squawk.store import Contact, Trust

if TYPE_CHECKING:
    from squawk.daemon import Daemon

_COMMIT_PREFIX = b"squawk pair commit v1"
_CODE_PREFIX = b"squawk pair code v1"

DEFAULT_PAIRING_TIMEOUT_MS = 120_000
"""How long each step may take before pairing gives up, in milliseconds."""

_T = TypeVar("_T")


def pair_commitment(key_id: str, nonce: bytes) -> bytes:
    """The commitment the initiator sends before revealing its nonce."""
    return hashlib.sha256(_COMMIT_PREFIX + key_from_id(key_id) + nonce).digest()


def pair_code(
    initiator_key: str, responder_key: str, initiator_nonce: bytes, responder_nonce: bytes
) -> str:
    """The 6-digit code both people compare."""
    digest = hashlib.sha256(
        _CODE_PREFIX
        + key_from_id(initiator_key)
        + key_from_id(responder_key)
        + initiator_nonce
        + responder_nonce
    ).digest()
    n = int.from_bytes(digest[:8], "big")
    return str(n % 1_000_000).zfill(6)


class PairingOffer(TypedDict):
    """What a person is shown when the code is ready."""

    pairing_id: str
    code: str
    peer_name: str
    peer_key: str
    peer_fingerprint: str


class PairingError(Exception):
    """Raised when pairing fails; the message is meant for the person."""


def _future() -> "asyncio.Future[Any]":
    future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
    # Nobody may wait on it; mark a failure as seen so asyncio does not report it.
    future.add_done_callback(lambda f: f.cancelled() or f.exception())
    return future


@dataclass
class _Session:
    id: str
    role: Literal["initiator", "responder"]
    link: PeerLink
    peer_key: str
    peer_name: str
    peer_address: Address | None
    """The other side's listening address, saved with the contact."""
    code: str | None
    local_confirmed: bool
    remote_confirmed: bool
    finished: bool
    code_ready: "asyncio.Future[PairingOffer]"
    """Settles when the code is ready (or pairing fails first)."""
    done: "asyncio.Future[Contact]"
    """Settles when both sides have confirmed (or pairing fails)."""
    timer: asyncio.TimerHandle | None


def _bytes_field(frame: Frame, key: str, length: int) -> bytes:
    value = frame.get(key)
    if not isinstance(value, str):
        raise PairingError(f"missing {key}")
    data = from_base64url(value)
    if len(data) != length:
        raise PairingError(f"bad {key}")
    return data


def _name_field(frame: Frame) -> str:
    value = frame.get("name")
    if isinstance(value, str) and jsontext.js_trim(value) != "":
        return jsontext.js_slice(jsontext.js_trim(value), 64)
    return "unnamed"


def _port_field(value: object) -> int | None:
    """The port number in a frame, or None if it is not a whole number in 1-65535."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float) and float(value).is_integer() and 0 < value < 65536:
        return int(value)
    if isinstance(value, str):
        try:
            number = float(jsontext.js_trim(value))
        except ValueError:
            return None
        if number.is_integer() and 0 < number < 65536:
            return int(number)
    return None


_HOST_PORT = re.compile(r"^\[?([^\]]+?)\]?:(\d+)$")


class Pairing:
    """Runs pairing inside the service. Created and started by the daemon
    entry point next to the network transport; offers the `pair_start`,
    `pair_accept`, `pair_confirm`, `pair_cancel`, `block` and `unblock`
    methods on the local socket."""

    def __init__(
        self,
        daemon: "Daemon",
        transport: NetworkTransport,
        *,
        timeout_ms: int = DEFAULT_PAIRING_TIMEOUT_MS,
    ) -> None:
        self._daemon = daemon
        self._transport = transport
        self._timeout_ms = timeout_ms
        self._sessions: dict[str, _Session] = {}
        self._accepting: asyncio.Future[PairingOffer] | None = None
        """Set while `pair --accept` is waiting for someone to pair with us."""
        self._accept_timer: asyncio.TimerHandle | None = None
        self._dialling = 0
        """How many pairing dials are in their handshake right now."""

    def start(self) -> None:
        """Hooks into the transport and adds the socket methods.

        Call after the daemon has started.
        """

        def unpaired_policy(_key: str, link: PeerLink) -> Literal["pairing", False]:
            if link.outgoing:
                return "pairing" if self._dialling > 0 else False
            return "pairing" if self._accepting is not None else False

        def on_link(link: PeerLink) -> None:
            # Only links admitted for pairing: a paired contact connecting to
            # deliver a message while we wait must be left alone.
            if (
                not link.outgoing
                and self._accepting is not None
                and link.authorization == "pairing"
            ):
                self._respond(link)

        self._transport.unpaired_policy = unpaired_policy
        self._transport.on_link = on_link

        async def pair_start(params: Any, _connection: RpcConnection) -> PairingOffer:
            peer = params.get("peer") if isinstance(params, dict) else None
            if not isinstance(peer, str) or peer == "":
                raise RpcError(RpcErrorCode.INVALID_PARAMS, "peer is required")
            return await self._wrap(self.initiate(peer))

        async def pair_accept(_params: Any, _connection: RpcConnection) -> PairingOffer:
            return await self._wrap(self.accept())

        async def pair_confirm(params: Any, _connection: RpcConnection) -> dict[str, Any]:
            p = params if isinstance(params, dict) else {}
            pairing_id = p.get("pairing_id")
            match = p.get("match")
            if not isinstance(pairing_id, str) or not isinstance(match, bool):
                raise RpcError(RpcErrorCode.INVALID_PARAMS, "pairing_id and match are required")
            contact = await self._wrap(self.confirm(pairing_id, match))
            return {
                "status": "paired",
                "contact": {
                    "name": contact.name,
                    "key_id": contact.public_key,
                    "fingerprint": fingerprint(key_from_id(contact.public_key)),
                },
            }

        def set_trust(trust: Trust) -> Any:
            def handler(params: Any, _connection: RpcConnection) -> dict[str, str]:
                name = params.get("contact") if isinstance(params, dict) else None
                if not isinstance(name, str):
                    raise RpcError(RpcErrorCode.INVALID_PARAMS, "contact is required")
                contact = self._daemon.resolve_contact(name)
                updated = self._daemon.store.update_contact(contact.public_key, trust=trust)
                if trust == "blocked":
                    self._transport.disconnect(contact.public_key)
                return {"name": updated.name, "key_id": updated.public_key, "trust": trust}

            return handler

        def pair_cancel(_params: Any, _connection: RpcConnection) -> dict[str, bool]:
            self._cancel_all("cancelled")
            return {"ok": True}

        self._daemon.handle("pair_start", pair_start)
        self._daemon.handle("pair_accept", pair_accept)
        self._daemon.handle("pair_confirm", pair_confirm)
        self._daemon.handle("block", set_trust("blocked"))
        self._daemon.handle("unblock", set_trust("paired"))
        self._daemon.handle("pair_cancel", pair_cancel)

    def stop(self) -> None:
        """Gives up on every pairing in progress."""
        self._cancel_all("the service stopped")

    async def initiate(self, peer: str) -> PairingOffer:
        """Starts pairing with a peer: a discovered peer's name or key id, or a
        `host:port` address. Returns when the code is ready to compare."""
        self_identity = self._daemon.identity
        address: Address | None = None
        expect_key: str | None = None
        found = self._transport.find_peer(peer)
        if found is not None:
            address = Address(
                next((a for a in found.addresses if dialable(a)), found.host), found.port
            )
            expect_key = found.key_id
        else:
            m = _HOST_PORT.match(peer)
            if m is not None:
                address = Address(m.group(1), int(m.group(2)))
        if address is None:
            raise PairingError(
                f'no squawk service called "{peer}" is visible on the network '
                "(try `squawk peers`, or give host:port)"
            )

        self._dialling += 1
        try:
            link = await self._transport.dial(address, expect_key)
        except Exception as err:
            reason = str(err) or type(err).__name__
            if reason.endswith(NOT_PAIRED):
                raise PairingError(
                    f"{peer} is not waiting to pair. Ask them to run `squawk pair --accept` "
                    "(it waits for 2 minutes), then try again."
                ) from None
            raise PairingError(f"could not connect to {peer}: {reason}") from None
        finally:
            self._dialling -= 1
        session = self._new_session("initiator", link, address)
        nonce = random_bytes(32)

        def on_frame(frame: Frame) -> None:
            try:
                if frame["t"] == "pair-nonce":
                    if session.code is not None:
                        raise PairingError("repeated nonce")
                    their_nonce = _bytes_field(frame, "nonce", 32)
                    session.peer_name = _name_field(frame)
                    session.link.send({"t": "pair-reveal", "nonce": to_base64url(nonce)})
                    self._code_is_ready(
                        session, pair_code(self_identity.id, session.peer_key, nonce, their_nonce)
                    )
                else:
                    self._handle_common(session, frame)
            except Exception as err:
                self._abort(session, err)

        session.link.on_frame(on_frame)
        link.send(
            {
                "t": "pair-commit",
                "commit": to_base64url(pair_commitment(self_identity.id, nonce)),
                "name": self_identity.name,
                "port": self._transport.port,
            }
        )
        return await asyncio.shield(session.code_ready)

    async def accept(self) -> PairingOffer:
        """Waits for someone to start pairing with us. Returns when the code is ready."""
        if self._accepting is not None:
            raise PairingError("already waiting for a pairing request")
        waiting: asyncio.Future[PairingOffer] = _future()
        self._accepting = waiting

        def time_out() -> None:
            if self._accepting is waiting:
                self._accepting = None
                if not waiting.done():
                    waiting.set_exception(PairingError("nobody asked to pair before the timeout"))

        self._accept_timer = asyncio.get_running_loop().call_later(
            self._timeout_ms / 1000, time_out
        )

        def clear(_future: "asyncio.Future[PairingOffer]") -> None:
            if self._accepting is waiting:
                self._accepting = None
            if self._accept_timer is not None:
                self._accept_timer.cancel()

        waiting.add_done_callback(clear)
        return await asyncio.shield(waiting)

    async def confirm(self, pairing_id: str, match: bool) -> Contact:
        """Records the local person's answer. Returns the saved contact once
        both sides have said yes."""
        session = self._sessions.get(pairing_id)
        if session is None or session.code is None:
            raise PairingError("there is no pairing waiting for confirmation")
        if not match:
            session.link.send({"t": "pair-abort", "reason": "the codes did not match"})
            self._finish(session, PairingError("pairing cancelled: the codes did not match"))
            return await asyncio.shield(session.done)
        session.local_confirmed = True
        session.link.send({"t": "pair-confirm"})
        self._maybe_complete(session)
        return await asyncio.shield(session.done)

    def _respond(self, link: PeerLink) -> None:
        waiting = self._accepting
        if waiting is None:
            return
        self_identity = self._daemon.identity
        session = self._new_session("responder", link, None)

        def pass_on(ready: "asyncio.Future[PairingOffer]") -> None:
            if waiting.done():
                return
            error = ready.exception()
            if error is not None:
                waiting.set_exception(error)
            else:
                waiting.set_result(ready.result())

        session.code_ready.add_done_callback(pass_on)
        commitment: list[bytes] = []
        nonce = random_bytes(32)

        def on_frame(frame: Frame) -> None:
            try:
                if frame["t"] == "pair-commit":
                    if commitment:
                        raise PairingError("repeated commitment")
                    commitment.append(_bytes_field(frame, "commit", 32))
                    session.peer_name = _name_field(frame)
                    port = _port_field(frame.get("port"))
                    host = link.remote_address
                    if host and dialable(host) and port is not None:
                        session.peer_address = Address(host, port)
                    link.send(
                        {
                            "t": "pair-nonce",
                            "nonce": to_base64url(nonce),
                            "name": self_identity.name,
                        }
                    )
                elif frame["t"] == "pair-reveal":
                    if not commitment or session.code is not None:
                        raise PairingError("reveal out of order")
                    their_nonce = _bytes_field(frame, "nonce", 32)
                    expected = pair_commitment(session.peer_key, their_nonce)
                    if not hmac.compare_digest(expected, commitment[0]):
                        link.send({"t": "pair-abort", "reason": "commitment mismatch"})
                        raise PairingError(
                            "pairing refused: the other side's commitment did not match "
                            "(possible tampering)"
                        )
                    self._code_is_ready(
                        session, pair_code(session.peer_key, self_identity.id, their_nonce, nonce)
                    )
                else:
                    self._handle_common(session, frame)
            except Exception as err:
                self._abort(session, err)

        link.on_frame(on_frame)

    def _new_session(
        self,
        role: Literal["initiator", "responder"],
        link: PeerLink,
        peer_address: Address | None,
    ) -> _Session:
        peer_key = link.peer_key
        if not peer_key:
            raise PairingError("connection is not authenticated")
        session = _Session(
            id=str(uuid.uuid4()),
            role=role,
            link=link,
            peer_key=peer_key,
            peer_name="unnamed",
            peer_address=peer_address,
            code=None,
            local_confirmed=False,
            remote_confirmed=False,
            finished=False,
            code_ready=_future(),
            done=_future(),
            timer=None,
        )
        session.timer = asyncio.get_running_loop().call_later(
            self._timeout_ms / 1000,
            lambda: self._finish(session, PairingError("pairing timed out")),
        )
        self._sessions[session.id] = session
        link.on_close(
            lambda: self._finish(
                session, PairingError("the other side disconnected before pairing finished")
            )
        )
        return session

    def _handle_common(self, session: _Session, frame: Frame) -> None:
        if frame["t"] == "pair-confirm":
            if session.code is None:
                raise PairingError("confirm before code")
            session.remote_confirmed = True
            self._maybe_complete(session)
        elif frame["t"] == "pair-abort":
            raw = frame.get("reason")
            reason = jsontext.js_slice(raw, 200) if isinstance(raw, str) else ""
            self._finish(
                session,
                PairingError(f"the other side cancelled pairing{f': {reason}' if reason else ''}"),
            )

    def _code_is_ready(self, session: _Session, code: str) -> None:
        session.code = code
        if not session.code_ready.done():
            session.code_ready.set_result(
                {
                    "pairing_id": session.id,
                    "code": code,
                    "peer_name": session.peer_name,
                    "peer_key": session.peer_key,
                    "peer_fingerprint": fingerprint(key_from_id(session.peer_key)),
                }
            )

    def _maybe_complete(self, session: _Session) -> None:
        if session.finished or not session.local_confirmed or not session.remote_confirmed:
            return
        store = self._daemon.store
        contact = store.upsert_contact(session.peer_key, session.peer_name, trust="paired")
        if session.peer_address is not None:
            store.set_setting(
                address_setting_key(session.peer_key),
                f"{session.peer_address.host}:{session.peer_address.port}",
            )
        self._finish(session, contact)

    def _abort(self, session: _Session, err: BaseException) -> None:
        message = str(err)
        if not session.finished:
            session.link.send({"t": "pair-abort", "reason": jsontext.js_slice(message, 200)})
        self._finish(session, err if isinstance(err, PairingError) else PairingError(message))

    def _finish(self, session: _Session, outcome: Contact | PairingError) -> None:
        """Ends a session with a saved contact or an error, and closes its connection."""
        if session.finished:
            return
        session.finished = True
        if session.timer is not None:
            session.timer.cancel()
        self._sessions.pop(session.id, None)
        if isinstance(outcome, PairingError):
            for future in (session.code_ready, session.done):
                if not future.done():
                    future.set_exception(outcome)
        elif not session.done.done():
            session.done.set_result(outcome)
        # Give the last frame a moment to go out before closing.
        asyncio.get_running_loop().call_later(0.1, session.link.close, 1000, "pairing finished")

    def _cancel_all(self, reason: str) -> None:
        for session in list(self._sessions.values()):
            session.link.send({"t": "pair-abort", "reason": reason})
            self._finish(session, PairingError(f"pairing cancelled: {reason}"))
        accepting = self._accepting
        if accepting is not None:
            self._accepting = None
            if not accepting.done():
                accepting.set_exception(PairingError(f"pairing cancelled: {reason}"))

    async def _wrap(self, work: Awaitable[_T]) -> _T:
        """Turns PairingError into an RPC error the CLI can print."""
        try:
            return await work
        except PairingError as err:
            raise RpcError(RpcErrorCode.APPLICATION_ERROR, str(err)) from None
