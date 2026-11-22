"""The message envelope and how it is sealed (signed, then encrypted) for one
recipient and opened again.

Sealing:
  1. The envelope is serialised to JSON and signed with the sender's ed25519
     key. The signature covers a fixed prefix plus the exact JSON text, so
     the receiver verifies the same bytes that were signed.
  2. A fresh (ephemeral) x25519 key pair is made. Its secret key and the
     recipient's x25519 public key (derived from their ed25519 key) give a
     shared secret; HKDF-SHA256 turns that into a 32-byte key.
  3. `{"envelope": ..., "sig": ...}` is encrypted with XChaCha20-Poly1305
     under that key and a random 24-byte nonce. The plaintext routing fields
     (version, sender, recipient, ephemeral key) are passed as associated
     data, so changing any of them makes decryption fail.

Only the routing fields are readable on the wire; the envelope, including
its body, is inside the ciphertext.

Messages arrive by one of two routes (`Route`): directly from the sender's
service on the local network, or through a relay that may hold them for up
to 7 days. A message sent directly is sealed again with a fresh `sent_at` at
each attempt, so it must be no more than 5 minutes from the local clock. A
message held by a relay cannot be sealed again, so through the relay a
`sent_at` up to 7 days (plus the 5 minutes) old is accepted. Seen ids are
kept long enough to refuse a replay on either route. See docs/plan/relay.md.

Besides the messages people write (`MessageKind`), an envelope can be a
receipt (`ReceiptKind`): the recipient's signed answer saying it stored the
message ("ack") or refused it for good ("nack"), sent back through the relay.

Envelopes and sealed messages are plain dicts with the same field names as
the JSON that travels (described by the `Envelope` and `Sealed` types). The
`parse_*` functions check a value received from elsewhere and return a new
dict with the fields in a fixed order; they raise `EnvelopeValidationError`,
a `ValueError`, when the value does not have the expected shape.

The format is fixed: a message sealed by any squawk version since 0.1 must
open in every other.
"""

import re
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any, Literal, NotRequired, Protocol, TypedDict, cast

from squawk import jsontext
from squawk.crypto import (
    ed25519_public_to_x25519,
    ed25519_sign,
    ed25519_verify,
    hkdf_sha256,
    random_bytes,
    x25519_public_key,
    x25519_shared_secret,
    xchacha20poly1305_decrypt,
    xchacha20poly1305_encrypt,
)
from squawk.encoding import from_base64url, is_key_id, key_from_id, to_base64url
from squawk.identity import Identity
from squawk.timefmt import is_iso_datetime, iso_from_ms, ms_from_datetime, now_ms, parse_iso_ms

WIRE_VERSION = 1
"""Wire format version written into every sealed message."""

MAX_CLOCK_SKEW_MS = 5 * 60 * 1000
"""Messages whose sent_at (or created_at) is further than this from the local clock are rejected."""

RELAY_HOLD_MS = 7 * 24 * 60 * 60 * 1000
"""How long a relay keeps a message waiting for its recipient: 7 days."""

MAX_RELAYED_AGE_MS = RELAY_HOLD_MS + MAX_CLOCK_SKEW_MS
"""A message that arrives through a relay is refused if its sent_at (or
created_at) is more than this far in the past. It is still refused if it is
more than MAX_CLOCK_SKEW_MS in the future."""

SEEN_ID_RETENTION_MS = RELAY_HOLD_MS + 2 * MAX_CLOCK_SKEW_MS
"""How long accepted message ids are remembered: longer than any copy of a
message could still pass the time check on either route."""

Route = Literal["direct", "relay"]
"""How a message arrived: straight from the sender's service, or through a relay."""

SIGNATURE_PREFIX = "squawk envelope v1\n"
HKDF_INFO = b"squawk v1 xchacha20poly1305 key"

MessageKind = Literal["text", "question", "answer"]
MESSAGE_KINDS: tuple[MessageKind, ...] = ("text", "question", "answer")
"""Kinds of message a person writes. Only these are stored and shown."""

ReceiptKind = Literal["ack", "nack"]
RECEIPT_KINDS: tuple[ReceiptKind, ...] = ("ack", "nack")
"""Kinds of receipt: the recipient stored the message, or refused it for good."""

LiveKind = Literal["sessions-request", "sessions"]
LIVE_KINDS: tuple[LiveKind, ...] = ("sessions-request", "sessions")
"""Kinds of request and answer passed through a relay only while both sides
are online. Never stored or shown."""

EnvelopeKind = MessageKind | ReceiptKind | LiveKind
ENVELOPE_KINDS: tuple[EnvelopeKind, ...] = (*MESSAGE_KINDS, *RECEIPT_KINDS, *LIVE_KINDS)

# The functional form is needed because "from" is a Python keyword.
Envelope = TypedDict(
    "Envelope",
    {
        "id": str,
        "from": str,
        "to": str,
        "session": NotRequired[str],
        "thread_id": str,
        "in_reply_to": NotRequired[str],
        "created_at": str,
        # When this copy was sealed for sending. A message waiting in the
        # outbound queue is sealed again at each attempt with a new sent_at, so
        # it stays within the receiver's freshness window however long it
        # waited. Absent means the same as created_at.
        "sent_at": NotRequired[str],
        # A message (MessageKind), a receipt (ReceiptKind) or a live request
        # or answer (LiveKind). The last two travel only through a relay.
        "kind": EnvelopeKind,
        # Markdown text; for a receipt, empty ("ack") or the reason ("nack").
        "body": str,
    },
)
"""The message as the sender wrote it. Travels only inside the ciphertext."""

Sealed = TypedDict(
    "Sealed",
    {
        "v": int,
        # Sender's key identifier.
        "from": str,
        # Recipient's key identifier; the receiving service uses it to pick its key.
        "to": str,
        # Ephemeral x25519 public key, base64url.
        "epk": str,
        # 24-byte XChaCha20 nonce, base64url.
        "nonce": str,
        # Ciphertext with the Poly1305 tag, base64url.
        "ct": str,
    },
)
"""What goes over the network. Everything except `ct` is readable by anyone."""


class EnvelopeValidationError(ValueError):
    """Raised when an envelope or sealed message does not have the expected shape."""


EnvelopeErrorCode = Literal[
    # The sealed object or decrypted content does not have the expected shape.
    "malformed",
    # Decryption failed: the ciphertext or routing fields were changed, or the wrong key was used.
    "tampered",
    # The message is addressed to someone other than the opener.
    "wrong_recipient",
    # The signature does not verify against the claimed sender's key.
    "bad_signature",
    # The signed sender does not match the sender named on the outside.
    "sender_mismatch",
    # This message id has been accepted before.
    "replay",
    # sent_at (or created_at) is too far from the local clock.
    "stale",
]


class EnvelopeError(Exception):
    """Raised when a message cannot be sealed or opened, with a `code` saying why."""

    def __init__(self, code: EnvelopeErrorCode, message: str) -> None:
        super().__init__(message)
        self.code: EnvelopeErrorCode = code


# Validation. String lengths are counted in UTF-16 code units, so that every
# squawk peer accepts exactly the same envelopes.

_ENVELOPE_FIELDS = (
    "id",
    "from",
    "to",
    "session",
    "thread_id",
    "in_reply_to",
    "created_at",
    "sent_at",
    "kind",
    "body",
)
_SEALED_FIELDS = ("v", "from", "to", "epk", "nonce", "ct")
_INNER_FIELDS = ("envelope", "sig")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*")


def _object(value: object, fields: tuple[str, ...], what: str) -> dict[str, Any]:
    """Checks that `value` is a JSON object with no fields other than `fields`."""
    if not isinstance(value, dict):
        raise EnvelopeValidationError(f"{what} must be an object")
    unknown = [key for key in value if key not in fields]
    if unknown:
        raise EnvelopeValidationError(
            f"{what} has unrecognized keys: {', '.join(map(str, unknown))}"
        )
    return cast(dict[str, Any], value)


def _string(
    obj: Mapping[str, Any], field: str, min_length: int = 0, max_length: int | None = None
) -> str:
    value = obj.get(field)
    if not isinstance(value, str):
        raise EnvelopeValidationError(f"{field} must be a string")
    length = jsontext.js_length(value)
    if length < min_length:
        raise EnvelopeValidationError(f"{field} must have at least {min_length} characters")
    if max_length is not None and length > max_length:
        raise EnvelopeValidationError(f"{field} must have at most {max_length} characters")
    return value


def _key_id(obj: Mapping[str, Any], field: str) -> str:
    value = obj.get(field)
    if not is_key_id(value):
        raise EnvelopeValidationError(f"{field}: not a squawk key identifier")
    return cast(str, value)


def _datetime(obj: Mapping[str, Any], field: str) -> str:
    value = obj.get(field)
    if not is_iso_datetime(value):
        raise EnvelopeValidationError(f"{field} must be an ISO 8601 date and time with a time zone")
    return cast(str, value)


def _base64url_bytes(obj: Mapping[str, Any], field: str, length: int | None = None) -> str:
    value = obj.get(field)
    if not isinstance(value, str) or _BASE64URL.fullmatch(value) is None:
        raise EnvelopeValidationError(f"{field}: not base64url")
    if length is not None and len(from_base64url(value)) != length:
        raise EnvelopeValidationError(f"{field}: expected {length} bytes")
    return value


def parse_envelope(value: object) -> Envelope:
    """Checks that `value` is a valid envelope and returns a copy with its fields in order."""
    obj = _object(value, _ENVELOPE_FIELDS, "envelope")
    checked: dict[str, Any] = {}
    checked["id"] = _string(obj, "id", 1, 128)
    checked["from"] = _key_id(obj, "from")
    checked["to"] = _key_id(obj, "to")
    if "session" in obj:
        checked["session"] = _string(obj, "session", 0, 256)
    checked["thread_id"] = _string(obj, "thread_id", 1, 128)
    if "in_reply_to" in obj:
        checked["in_reply_to"] = _string(obj, "in_reply_to", 1, 128)
    checked["created_at"] = _datetime(obj, "created_at")
    if "sent_at" in obj:
        checked["sent_at"] = _datetime(obj, "sent_at")
    kind = obj.get("kind")
    if kind not in ENVELOPE_KINDS:
        raise EnvelopeValidationError(f"kind must be one of {', '.join(ENVELOPE_KINDS)}")
    checked["kind"] = kind
    checked["body"] = _string(obj, "body")
    return cast(Envelope, checked)


def _is_wire_version(value: object) -> bool:
    # JSON has one number type, so 1.0 is the same as 1; true is not a number.
    return isinstance(value, int | float) and not isinstance(value, bool) and value == WIRE_VERSION


def parse_sealed(value: object) -> Sealed:
    """Checks that `value` is a sealed message and returns a copy with its fields in order."""
    obj = _object(value, _SEALED_FIELDS, "sealed message")
    if not _is_wire_version(obj.get("v")):
        raise EnvelopeValidationError(f"v must be {WIRE_VERSION}")
    return {
        "v": WIRE_VERSION,
        "from": _key_id(obj, "from"),
        "to": _key_id(obj, "to"),
        "epk": _base64url_bytes(obj, "epk", 32),
        "nonce": _base64url_bytes(obj, "nonce", 24),
        "ct": _base64url_bytes(obj, "ct"),
    }


def _parse_inner(value: object) -> tuple[str, str]:
    """What is encrypted: the envelope's JSON text and the signature over it."""
    obj = _object(value, _INNER_FIELDS, "decrypted content")
    return _string(obj, "envelope"), _base64url_bytes(obj, "sig", 64)


def _timestamp_text(value: datetime | int) -> str:
    return iso_from_ms(value if isinstance(value, int) else ms_from_datetime(value))


def create_envelope(
    *,
    from_: str,
    to: str,
    body: str,
    kind: EnvelopeKind = "text",
    session: str | None = None,
    thread_id: str | None = None,
    in_reply_to: str | None = None,
    created_at: datetime | int | None = None,
) -> Envelope:
    """Makes a validated envelope with a fresh random id.

    `thread_id` defaults to the new message's own id (a new thread).
    `created_at` (a datetime, or milliseconds since the epoch) defaults to
    the current time.
    """
    id = str(uuid.uuid4())
    envelope: dict[str, Any] = {
        "id": id,
        "from": from_,
        "to": to,
        "thread_id": id if thread_id is None else thread_id,
        "created_at": _timestamp_text(now_ms() if created_at is None else created_at),
        "kind": kind,
        "body": body,
    }
    if session is not None:
        envelope["session"] = session
    if in_reply_to is not None:
        envelope["in_reply_to"] = in_reply_to
    return parse_envelope(envelope)


def _associated_data(v: int, from_: str, to: str, epk: str) -> bytes:
    return jsontext.utf8(f"squawk/{v}\n{from_}\n{to}\n{epk}")


def _derive_key(shared: bytes, epk: bytes, recipient_x: bytes) -> bytes:
    return hkdf_sha256(shared, epk + recipient_x, HKDF_INFO, 32)


def seal(envelope: Envelope, sender: Identity) -> Sealed:
    """Signs `envelope` with the sender's key and encrypts it to the recipient.

    `envelope["from"]` must be the sender's id and `envelope["to"]` the recipient's.
    """
    parsed = parse_envelope(envelope)
    if parsed["from"] != sender.id:
        raise EnvelopeError("sender_mismatch", "envelope.from is not the sealing identity's key")
    recipient_x = ed25519_public_to_x25519(key_from_id(parsed["to"]))

    envelope_json = jsontext.stringify(parsed)
    sig = ed25519_sign(jsontext.utf8(SIGNATURE_PREFIX + envelope_json), sender.secret_key)
    inner = jsontext.stringify({"envelope": envelope_json, "sig": to_base64url(sig)})

    ephemeral_secret = random_bytes(32)
    epk = x25519_public_key(ephemeral_secret)
    key = _derive_key(x25519_shared_secret(ephemeral_secret, recipient_x), epk, recipient_x)
    nonce = random_bytes(24)
    epk_text = to_base64url(epk)
    aad = _associated_data(WIRE_VERSION, parsed["from"], parsed["to"], epk_text)
    ct = xchacha20poly1305_encrypt(key, nonce, aad, jsontext.utf8(inner))

    return {
        "v": WIRE_VERSION,
        "from": parsed["from"],
        "to": parsed["to"],
        "epk": epk_text,
        "nonce": to_base64url(nonce),
        "ct": to_base64url(ct),
    }


def open_sealed(
    sealed: object,
    recipient: Identity,
    guard: "ReplayGuard | None" = None,
    route: Route = "direct",
) -> Envelope:
    """Decrypts and checks a sealed message addressed to `recipient`.

    Checks, in order: wire shape, outer recipient, decryption, envelope shape,
    signature by the claimed sender, that the signed `from`/`to` match the
    outer sender and the opener, and finally (when a guard is given) the
    timestamp (with the allowance for `route`) and that the id is new. It
    does not record the id: the caller
    calls `guard.record(envelope)` once the message is safely stored, so a
    message that failed to store can be accepted when the sender retries.
    Raises `EnvelopeError` on any failure.

    (Not called `open`, so that it does not hide Python's built-in `open`.)
    """
    try:
        s = parse_sealed(sealed)
    except EnvelopeValidationError as err:
        raise EnvelopeError("malformed", "not a sealed squawk message") from err
    if s["to"] != recipient.id:
        raise EnvelopeError("wrong_recipient", "message is addressed to a different key")

    try:
        epk = from_base64url(s["epk"])
        key = _derive_key(
            x25519_shared_secret(recipient.x25519_secret_key, epk),
            epk,
            recipient.x25519_public_key,
        )
        aad = _associated_data(s["v"], s["from"], s["to"], s["epk"])
        plaintext = xchacha20poly1305_decrypt(
            key, from_base64url(s["nonce"]), aad, from_base64url(s["ct"])
        )
    except Exception as err:
        raise EnvelopeError("tampered", "message could not be decrypted") from err

    try:
        # Invalid UTF-8 is replaced and a leading byte order mark is dropped,
        # so every squawk peer reads the same text.
        text = plaintext.decode("utf-8", "replace").removeprefix("\ufeff")
        envelope_text, sig = _parse_inner(jsontext.parse(text))
        envelope = parse_envelope(jsontext.parse(envelope_text))
    except Exception as err:
        raise EnvelopeError("malformed", "decrypted content is not valid") from err

    signed_bytes = jsontext.utf8(SIGNATURE_PREFIX + envelope_text)
    if not ed25519_verify(from_base64url(sig), signed_bytes, key_from_id(envelope["from"])):
        raise EnvelopeError("bad_signature", "signature does not match the claimed sender")
    if envelope["from"] != s["from"]:
        raise EnvelopeError("sender_mismatch", "signed sender differs from the outer sender")
    if envelope["to"] != recipient.id:
        raise EnvelopeError("wrong_recipient", "signed recipient is not the opener")

    if guard is not None:
        guard.check(envelope, route)
    return envelope


class SeenIdStore(Protocol):
    """Storage for message ids that have already been accepted."""

    def has(self, id: str) -> bool: ...

    def add(self, id: str, at_ms: int) -> None:
        """Records `id` at time `at_ms`, so the store can later forget ids too old
        to be replayed."""
        ...

    def prune(self, cutoff_ms: int) -> object:
        """Forgets ids recorded with a time before `cutoff_ms`."""
        ...


class MemorySeenIds:
    """A `SeenIdStore` kept in memory. Contents are lost when the process exits."""

    def __init__(self) -> None:
        self._ids: dict[str, int] = {}

    def has(self, id: str) -> bool:
        return id in self._ids

    def add(self, id: str, at_ms: int) -> None:
        self._ids[id] = at_ms

    def prune(self, cutoff_ms: int) -> None:
        """Forgets ids recorded before `cutoff_ms`."""
        self._ids = {id: at for id, at in self._ids.items() if at >= cutoff_ms}


def _js_number(value: float) -> str:
    """A number as text, with no ".0" for whole numbers (300, not 300.0)."""
    return str(int(value)) if float(value).is_integer() else repr(value)


class ReplayGuard:
    """Rejects messages whose id was accepted before from the same sender
    (`replay`) or whose sent_at (or created_at, when there is no sent_at) is
    too far from the local clock (`stale`). For a message that arrived
    directly, too far means more than `max_skew_ms` (default 5 minutes) in
    either direction. For one that arrived through a relay, it means more
    than `max_skew_ms` in the future or more than `max_relayed_age_ms`
    (default 7 days and 5 minutes) in the past.

    Because old messages are refused on time, the seen-id store only needs to
    keep ids for `retention_ms` (default 7 days and 10 minutes, longer than
    the relay allowance); `prune` forgets the rest.

    Ids are recorded per sender, because each sender chooses its own ids: one
    contact reusing an id must not make another contact's message look like a
    replay.

    `now` returns the current time in milliseconds since the epoch.
    """

    def __init__(
        self,
        *,
        seen: SeenIdStore | None = None,
        now: Callable[[], int] | None = None,
        max_skew_ms: int = MAX_CLOCK_SKEW_MS,
        max_relayed_age_ms: int = MAX_RELAYED_AGE_MS,
        retention_ms: int = SEEN_ID_RETENTION_MS,
    ) -> None:
        self.seen: SeenIdStore = MemorySeenIds() if seen is None else seen
        self._now = now_ms if now is None else now
        self._max_skew_ms = max_skew_ms
        self._max_relayed_age_ms = max_relayed_age_ms
        self._retention_ms = max(retention_ms, 2 * max_skew_ms, max_relayed_age_ms + max_skew_ms)

    def check(self, envelope: Mapping[str, Any], route: Route = "direct") -> None:
        """Raises `stale` or `replay` if the envelope must be refused. Does not record it.

        Uses the envelope's "id", "from", "created_at" and "sent_at" fields.
        """
        sent_at = envelope.get("sent_at")
        time = sent_at if sent_at is not None else envelope["created_at"]
        sent = parse_iso_ms(time) if isinstance(time, str) else None
        now = self._now()
        if sent is None or sent - now > self._max_skew_ms:
            raise EnvelopeError(
                "stale",
                f"sent at {time}, more than {_js_number(self._max_skew_ms / 1000)}s "
                "from the local clock",
            )
        max_age_ms = self._max_relayed_age_ms if route == "relay" else self._max_skew_ms
        if now - sent > max_age_ms:
            if route == "relay":
                raise EnvelopeError(
                    "stale", f"sent at {time}, longer ago than a relay keeps messages"
                )
            raise EnvelopeError(
                "stale",
                f"sent at {time}, more than {_js_number(self._max_skew_ms / 1000)}s "
                "from the local clock",
            )
        if self.seen.has(_seen_key(envelope)):
            raise EnvelopeError("replay", f"message {envelope['id']} was already received")

    def record(self, envelope: Mapping[str, Any]) -> None:
        """Records the envelope's id as seen. Call after the message is stored."""
        self.seen.add(_seen_key(envelope), self._now())

    def accept(self, envelope: Mapping[str, Any]) -> None:
        """Checks the envelope and, if it passes, records its id as seen."""
        self.check(envelope)
        self.record(envelope)

    def prune(self) -> None:
        """Forgets ids recorded more than `retention_ms` ago."""
        self.seen.prune(self._now() - self._retention_ms)


def _seen_key(envelope: Mapping[str, Any]) -> str:
    """The seen-id key: the sender's key and the message id."""
    return f"{envelope['from']} {envelope['id']}"


# Receipts


class Receipt(TypedDict):
    """What a receipt says about one message this service sent."""

    # The id of the message the receipt answers.
    of: str
    status: ReceiptKind
    # Why the message was refused; empty for "ack".
    reason: str


def create_receipt(
    *, from_: str, message: Envelope, status: ReceiptKind, reason: str = ""
) -> Envelope:
    """Makes the receipt that the recipient of `message` (whose key id is
    `from_`) sends back to its sender. Seal it with `seal` like any envelope."""
    if from_ != message["to"]:
        raise EnvelopeError("sender_mismatch", "only the recipient of a message can answer it")
    return create_envelope(
        from_=from_,
        to=message["from"],
        body="" if status == "ack" else jsontext.js_slice(reason or "refused", 200),
        kind=status,
        thread_id=message["thread_id"],
        in_reply_to=message["id"],
    )


def parse_receipt(envelope: Envelope) -> Receipt:
    """Reads a receipt out of an opened envelope. Raises `EnvelopeError`
    ("malformed") if the envelope is not a well-formed receipt.

    This does not say whether the receipt is about a message this service
    actually sent to its signer; the caller checks that against its store.
    """
    kind = envelope["kind"]
    if kind not in RECEIPT_KINDS:
        raise EnvelopeError("malformed", "not a receipt")
    of = envelope.get("in_reply_to")
    if of is None:
        raise EnvelopeError("malformed", "receipt does not name a message")
    if kind == "ack" and envelope["body"] != "":
        raise EnvelopeError("malformed", "an ack has no body")
    status: ReceiptKind = "ack" if kind == "ack" else "nack"
    return {"of": of, "status": status, "reason": envelope["body"]}
