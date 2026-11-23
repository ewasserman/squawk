"""Who may use the relay (docs/plan/relay-access.md).

After a client proves its key, the relay asks its access policy about that
key. The operator chooses the policy with `squawk relay serve --access`:

- `open`: every key is admitted (the relay's behaviour before access control);
- `keys`: keys listed in a file are admitted;
- `github`: keys whose owner signed in with GitHub as a listed user are admitted.
"""

import ipaddress
import os
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Literal, Protocol, get_args

from squawk.encoding import is_key_id

AccessMode = Literal["open", "keys", "github"]
ACCESS_MODES: tuple[AccessMode, ...] = get_args(AccessMode)

NOT_PERMITTED_CODE = 4003
"""Close code for a key the relay does not admit."""

OPEN_WARNING = "Access: open. Anyone who can reach this relay can open a mailbox on it."


class Decision(Enum):
    """What the access policy says about a key that proved itself."""

    ADMITTED = "admitted"
    REFUSED = "refused"
    UNKNOWN = "unknown"
    """The relay has not seen this key before and needs its owner to sign in."""


class AccessPolicy(Protocol):
    @property
    def mode(self) -> AccessMode:
        """The mode, sent to clients in `hello`."""
        ...

    def decide(self, key: str) -> Decision:
        """Whether `key` may use the relay."""
        ...

    def reload(self) -> bool:
        """Rereads whatever the policy is based on, if it changed. Returns
        True if the policy's answers may have changed; the relay then closes
        the connections and deletes the mailboxes of keys now refused."""
        ...


class OpenAccess:
    """Admits every key."""

    @property
    def mode(self) -> AccessMode:
        return "open"

    def decide(self, key: str) -> Decision:
        return Decision.ADMITTED

    def reload(self) -> bool:
        return False


class AllowedKeysError(Exception):
    """The allowed keys file cannot be read or has lines that are not keys."""


@dataclass(frozen=True)
class _FileVersion:
    """Enough about a file to notice that it changed."""

    inode: int
    size: int
    mtime_ns: int


def _file_version(path: str) -> _FileVersion:
    st = os.stat(path)
    return _FileVersion(st.st_ino, st.st_size, st.st_mtime_ns)


def parse_allowed_keys(text: str) -> dict[str, str]:
    """The keys in an allowed keys file, each with the name written after it
    (empty if none). One key id per line; text after `#` and blank lines are
    ignored. Raises `AllowedKeysError` naming every line that does not
    start with a key id."""
    keys: dict[str, str] = {}
    problems: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        key, *rest = content.split(maxsplit=1)
        if not is_key_id(key):
            problems.append(f"line {number}: {key!r} is not a squawk key id")
            continue
        keys[key] = rest[0] if rest else ""
    if problems:
        raise AllowedKeysError("; ".join(problems))
    return keys


def read_allowed_keys(path: str) -> dict[str, str]:
    """Reads and parses an allowed keys file (see `parse_allowed_keys`)."""
    try:
        with open(path, encoding="utf-8") as file:
            text = file.read()
    except (OSError, UnicodeDecodeError) as err:
        raise AllowedKeysError(f"cannot read {path}: {err}") from err
    try:
        return parse_allowed_keys(text)
    except AllowedKeysError as err:
        raise AllowedKeysError(f"{path}: {err}") from err


class KeysAccess:
    """Admits the keys listed in a file and refuses every other key.

    `reload` rereads the file when it has changed. If the new version cannot
    be read or has a line that is not a key, the relay keeps using the keys
    it last read and logs why: a half-saved or mistyped file then changes
    nothing, instead of locking people out and deleting their mailboxes."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._version = _file_version_or_none(path)
        self.keys = read_allowed_keys(path)

    @property
    def mode(self) -> AccessMode:
        return "keys"

    def decide(self, key: str) -> Decision:
        return Decision.ADMITTED if key in self.keys else Decision.REFUSED

    def reload(self) -> bool:
        version = _file_version_or_none(self.path)
        if version == self._version:
            return False
        try:
            keys = read_allowed_keys(self.path)
        except AllowedKeysError as err:
            _log(f"keeping the allowed keys read before: {err}")
            self._version = version
            return False
        self._version = version
        if keys == self.keys:
            return False
        added = len(keys.keys() - self.keys.keys())
        removed = len(self.keys.keys() - keys.keys())
        _log(f"reread {self.path}: {len(keys)} keys ({added} added, {removed} removed)")
        self.keys = keys
        return True


def _file_version_or_none(path: str) -> _FileVersion | None:
    try:
        return _file_version(path)
    except OSError:
        return None


def _log(text: str) -> None:
    print(f"squawk relay: {text}", file=sys.stderr, flush=True)


def is_loopback_host(host: str) -> bool:
    """True if listening on `host` accepts connections only from this machine."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def default_access_mode(host: str, trust_forwarded_for: bool) -> AccessMode | None:
    """The mode to use when the operator did not give `--access`: `open` for
    a relay that only this machine can reach, otherwise None, meaning the
    operator must choose. A relay behind a proxy listens on loopback but is
    reached from elsewhere; `trust_forwarded_for` is the sign of a proxy."""
    if is_loopback_host(host) and not trust_forwarded_for:
        return "open"
    return None
