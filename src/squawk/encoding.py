"""Conversions between raw key bytes and the text forms squawk stores and sends.

Public keys are identified everywhere by the base64url (no padding) encoding
of the 32-byte ed25519 public key.
"""

import base64
import re

_BASE64_CHARS = re.compile(r"[^A-Za-z0-9+/_-]")


def to_base64url(data: bytes) -> str:
    """Encodes bytes as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_base64url(text: str) -> bytes:
    """Decodes a base64url string (padding optional) to bytes.

    The decoding rules are fixed, so every squawk peer reads the same text as
    the same bytes: decoding stops at the first "=", characters outside the
    base64 alphabets are skipped, both the "+/" and "-_" alphabets are accepted, a single
    leftover character at the end is ignored, and unused low bits in the last
    character are ignored.
    """
    cleaned = _BASE64_CHARS.sub("", text.split("=", 1)[0])
    cleaned = cleaned.replace("-", "+").replace("_", "/")
    if len(cleaned) % 4 == 1:
        cleaned = cleaned[:-1]
    cleaned += "=" * (-len(cleaned) % 4)
    return base64.b64decode(cleaned)


_KEY_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")


def key_id(public_key: bytes) -> str:
    """The text identifier for an ed25519 public key (base64url of its 32 bytes)."""
    if len(public_key) != 32:
        raise ValueError(f"expected a 32-byte public key, got {len(public_key)}")
    return to_base64url(public_key)


def is_key_id(text: object) -> bool:
    """True when `text` is exactly what `key_id` produces for some 32 bytes.

    The last of the 43 characters carries 2 unused bits, so up to four
    spellings decode to the same key; only the one with those bits zero is
    accepted, so that each key has one identifier and text comparisons of ids
    are safe.
    """
    return (
        isinstance(text, str)
        and _KEY_ID_PATTERN.fullmatch(text) is not None
        and to_base64url(from_base64url(text)) == text
    )


def key_from_id(id: str) -> bytes:
    """Turns a key identifier back into the 32 raw public-key bytes."""
    if not is_key_id(id):
        raise ValueError(f"not a squawk key identifier: {id}")
    return from_base64url(id)
