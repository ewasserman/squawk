"""Invite codes for pairing through the relay.

A code is 8 characters from Crockford's base32 alphabet (40 random bits),
shown as two groups of four with a hyphen ("K7QM-4XRT"). When a code is
typed back, case and hyphens are ignored. The relay keeps only the SHA-256
hash of the code without its hyphen, in upper case.
"""

import hashlib

from squawk.crypto import random_bytes

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
"""Crockford's base32 alphabet: digits and letters without I, L, O and U."""

CODE_LENGTH = 8


def new_code() -> str:
    """A fresh random code in its display form, such as "K7QM-4XRT"."""
    number = int.from_bytes(random_bytes(5), "big")
    chars = [ALPHABET[(number >> (5 * i)) & 31] for i in reversed(range(CODE_LENGTH))]
    text = "".join(chars)
    return f"{text[:4]}-{text[4:]}"


def normalize_code(text: str) -> str | None:
    """The code without hyphens and in upper case, or None if what is left
    is not 8 characters of the alphabet."""
    cleaned = text.replace("-", "").upper()
    if len(cleaned) != CODE_LENGTH or any(c not in ALPHABET for c in cleaned):
        return None
    return cleaned


def code_hash(normalized: str) -> str:
    """The hex SHA-256 of a normalized code: what the relay stores."""
    return hashlib.sha256(normalized.encode("ascii")).hexdigest()
