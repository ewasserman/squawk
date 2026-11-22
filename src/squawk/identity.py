"""This machine's identity: its key pairs and display name, kept in identity.json."""

import contextlib
import hashlib
import os
import pwd
import re
import socket
from dataclasses import dataclass

from squawk import jsontext
from squawk.config import identity_path
from squawk.crypto import (
    ed25519_public_key,
    ed25519_public_to_x25519,
    ed25519_random_secret_key,
    ed25519_secret_to_x25519,
)
from squawk.encoding import from_base64url, key_id, to_base64url
from squawk.timefmt import iso_from_ms, now_ms


@dataclass(frozen=True)
class Identity:
    """One ed25519 key pair used for signing, the x25519 key pair derived from it
    for encryption, and a display name."""

    name: str
    id: str
    """base64url of the ed25519 public key; used as the address in messages."""
    public_key: bytes
    secret_key: bytes
    """The 32-byte ed25519 secret key (the seed the key pair is made from)."""
    x25519_public_key: bytes
    x25519_secret_key: bytes


class IdentityExistsError(Exception):
    """Raised by `init_identity` when an identity file already exists."""

    def __init__(self, path: str) -> None:
        super().__init__(f"an identity already exists at {path}; refusing to overwrite it")
        self.path = path


class NoIdentityError(Exception):
    """Raised by `load_identity` when there is no identity file yet."""

    def __init__(self, path: str) -> None:
        super().__init__(f'no identity found at {path}; run "squawk init" first')
        self.path = path


def default_display_name() -> str:
    """The name used when `squawk init` is not given one, e.g. "alice@laptop"."""
    full_host = socket.gethostname()
    host = full_host.split(".")[0] or full_host
    user = ""
    # There is no passwd entry for some users; use the host alone then.
    with contextlib.suppress(KeyError):
        user = pwd.getpwuid(os.getuid()).pw_name
    return f"{user}@{host}" if user else host


def identity_from_secret_key(name: str, secret_key: bytes) -> Identity:
    """Builds a full identity (including the derived x25519 keys) from an ed25519 secret key."""
    public_key = ed25519_public_key(secret_key)
    return Identity(
        name=name,
        id=key_id(public_key),
        public_key=public_key,
        secret_key=secret_key,
        x25519_public_key=ed25519_public_to_x25519(public_key),
        x25519_secret_key=ed25519_secret_to_x25519(secret_key),
    )


def _make_home(home: str) -> None:
    """Creates `home` with mode 0700 if it does not exist; an existing one is left alone."""
    parent = os.path.dirname(os.path.abspath(home))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    try:
        os.mkdir(home, 0o700)
    except FileExistsError:
        return
    # mkdir's mode is applied after the umask, so set it again on a directory
    # this call created.
    os.chmod(home, 0o700)


def init_identity(home: str, name: str | None = None) -> Identity:
    """Creates a new key pair and writes it, with the display name, to the
    identity file under `home`.

    The file gets mode 0600, and the directory mode 0700 if this call creates
    it (an existing directory's permissions are left alone). Raises
    `IdentityExistsError` if the file is already there.
    """
    trimmed = jsontext.js_trim(default_display_name() if name is None else name)
    if trimmed == "":
        raise ValueError("display name must not be empty")
    _make_home(home)

    secret_key = ed25519_random_secret_key()
    identity = identity_from_secret_key(trimmed, secret_key)
    file = {
        "version": 1,
        "name": trimmed,
        "publicKey": to_base64url(identity.public_key),
        "secretKey": to_base64url(secret_key),
        "createdAt": iso_from_ms(now_ms()),
    }
    path = identity_path(home)
    try:
        # O_EXCL fails if the file exists, so two concurrent inits cannot both succeed.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise IdentityExistsError(path) from None
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(jsontext.stringify(file, indent="\t") + "\n")
    os.chmod(path, 0o600)
    return identity


_SECRET_KEY_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")


def load_identity(home: str) -> Identity:
    """Reads the identity file under `home`. Raises `NoIdentityError` if it is missing."""
    path = identity_path(home)
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except FileNotFoundError:
        raise NoIdentityError(path) from None
    try:
        file = jsontext.parse(text)
    except ValueError:
        file = {}
    if not (
        isinstance(file, dict)
        and _is_one(file.get("version"))
        and isinstance(file.get("name"), str)
        and isinstance(file.get("secretKey"), str)
        and isinstance(file.get("publicKey"), str)
        and _SECRET_KEY_PATTERN.fullmatch(file["secretKey"]) is not None
    ):
        raise ValueError(f"identity file {path} is not in a format squawk understands")
    identity = identity_from_secret_key(file["name"], from_base64url(file["secretKey"]))
    if identity.id != file["publicKey"]:
        raise ValueError(
            f"identity file {path} is inconsistent: its public key does not match its secret key"
        )
    return identity


def _is_one(value: object) -> bool:
    """True for the JSON number 1 (written as 1 or 1.0), not for `true`."""
    return isinstance(value, int | float) and not isinstance(value, bool) and value == 1


def fingerprint(public_key: bytes) -> str:
    """A short fingerprint of an ed25519 public key for people to compare by eye.

    The first 16 bytes of its SHA-256 hash as hex, in dash-separated groups of
    four characters (e.g. "3f2a-91c0-...").
    """
    hex_text = hashlib.sha256(public_key).digest()[:16].hex()
    return "-".join(hex_text[i : i + 4] for i in range(0, len(hex_text), 4))
