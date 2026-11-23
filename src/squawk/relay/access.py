"""Who may use the relay (docs/plan/relay-access.md).

After a client proves its key, the relay asks its access policy about that
key. The operator chooses the policy with `squawk relay serve --access`:

- `open`: every key is admitted (the relay's behaviour before access control);
- `keys`: keys listed in a file are admitted;
- `github`: keys whose owner signed in with GitHub as a listed user are admitted.
"""

import ipaddress
from enum import Enum
from typing import Literal, Protocol, get_args

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


class OpenAccess:
    """Admits every key."""

    @property
    def mode(self) -> AccessMode:
        return "open"

    def decide(self, key: str) -> Decision:
        return Decision.ADMITTED


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
