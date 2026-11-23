"""Who may use the relay (docs/plan/relay-access.md).

After a client proves its key, the relay asks its access policy about that
key. The operator chooses the policy with `squawk relay serve --access`:

- `open`: every key is admitted (the relay's behaviour before access control);
- `keys`: keys listed in a file are admitted;
- `github`: keys whose owner signed in with GitHub as a listed user are admitted.
"""

import asyncio
import ipaddress
import re
import sys
import time
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Literal, Protocol, get_args

from squawk.encoding import is_key_id
from squawk.relay.github import DeviceCode, GitHub, GitHubUser, SignInOutcome, sign_in
from squawk.relay.storage import RelayStore

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

    def reload(self, force: bool = False) -> bool:
        """Rereads whatever the policy is based on. Returns True if the
        policy's answers may have changed; the relay then closes the
        connections and deletes the mailboxes of keys now refused. A policy
        may wait for a second reading before refusing keys it admitted
        before; `force` (the operator sent SIGHUP) applies the change at once."""
        ...


class OpenAccess:
    """Admits every key."""

    @property
    def mode(self) -> AccessMode:
        return "open"

    def decide(self, key: str) -> Decision:
        return Decision.ADMITTED

    def reload(self, force: bool = False) -> bool:
        return False


class AllowedKeysError(Exception):
    """The allowed keys file cannot be read or has lines that are not keys."""


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

    `reload` rereads the file and compares what it lists with the keys in
    use. Keys added to the file are admitted at once. Taking keys out is
    applied only when two checks in a row read the same list (or when the
    operator asks with SIGHUP), because an editor saving the file may leave
    it empty or cut short for a moment, and a removal closes connections and
    deletes mailboxes. If the file cannot be read or has a line that is not
    a key, the relay keeps the keys it read before and logs why."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.keys = read_allowed_keys(path)
        if not self.keys:
            raise AllowedKeysError(f"{path} lists no keys, so the relay would refuse everyone")
        self._pending: dict[str, str] | None = None
        """A list that takes keys out, read at the last check and not yet applied."""
        self._last_problem: str | None = None

    @property
    def mode(self) -> AccessMode:
        return "keys"

    def decide(self, key: str) -> Decision:
        return Decision.ADMITTED if key in self.keys else Decision.REFUSED

    def reload(self, force: bool = False) -> bool:
        try:
            keys = read_allowed_keys(self.path)
        except AllowedKeysError as err:
            if str(err) != self._last_problem:
                _log(f"keeping the allowed keys read before: {err}")
            self._last_problem = str(err)
            self._pending = None
            return False
        self._last_problem = None
        if keys == self.keys:
            self._pending = None
            return False
        removed = len(self.keys.keys() - keys.keys())
        if removed and not force and keys != self._pending:
            self._pending = keys
            return False
        self._pending = None
        added = len(keys.keys() - self.keys.keys())
        _log(f"reread {self.path}: {len(keys)} keys ({added} added, {removed} removed)")
        self.keys = keys
        return True


DEFAULT_MAX_KEYS_PER_USER = 5

# A GitHub login: letters, digits and hyphens, not starting with a hyphen,
# at most 39 characters.
_GITHUB_LOGIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", re.ASCII)


class AllowedUsersError(Exception):
    """The allowed users file cannot be read or has lines that are not users."""


def parse_allowed_users(text: str) -> dict[str, int | None]:
    """The GitHub users in an allowed users file, each with the numeric
    GitHub id written after it (None if none). One user per line; text after
    `#` and blank lines are ignored. The logins are returned in lower case,
    because GitHub logins do not depend on case. Raises `AllowedUsersError`
    naming every line that is not a login optionally followed by an id."""
    users: dict[str, int | None] = {}
    problems: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        content = line.split("#", 1)[0].strip()
        if not content:
            continue
        login, *rest = content.split()
        if not _GITHUB_LOGIN.fullmatch(login):
            problems.append(f"line {number}: {login!r} is not a GitHub user name")
            continue
        if len(rest) > 1 or (rest and not (rest[0].isascii() and rest[0].isdigit())):
            problems.append(
                f"line {number}: after the user name there can only be a numeric GitHub id"
            )
            continue
        github_id = int(rest[0]) if rest else None
        if github_id == 0:
            problems.append(f"line {number}: 0 is not a GitHub id")
            continue
        if login.lower() in users:
            problems.append(f"line {number}: {login!r} is listed more than once")
            continue
        users[login.lower()] = github_id
    if problems:
        raise AllowedUsersError("; ".join(problems))
    return users


def read_allowed_users(path: str) -> dict[str, int | None]:
    """Reads and parses an allowed users file (see `parse_allowed_users`)."""
    try:
        with open(path, encoding="utf-8") as file:
            text = file.read()
    except (OSError, UnicodeDecodeError) as err:
        raise AllowedUsersError(f"cannot read {path}: {err}") from err
    try:
        return parse_allowed_users(text)
    except AllowedUsersError as err:
        raise AllowedUsersError(f"{path}: {err}") from err


class GitHubAccess:
    """Admits keys whose owner signed in with GitHub as a user listed in a file.

    A key that has never signed in is UNKNOWN: the relay then asks its owner
    to sign in (`request_device_code` and `wait_for_approval`) and, if GitHub
    says who they are, asks `admit_signed_in` whether that account may use
    the relay. Which account owns each key is kept in the relay's database,
    which the relay hands over with `use_store` when it starts.

    The file is reread like the allowed keys file (see `KeysAccess`): users
    added are admitted at once, taking users out waits for two readings
    that agree (or SIGHUP), and a version that cannot be read or has a bad
    line changes nothing.

    `github` makes the requests to GitHub; `sleep` and `clock` (in seconds)
    are used while waiting for the person to approve, so tests can replace
    them."""

    def __init__(
        self,
        path: str,
        github: GitHub,
        *,
        max_keys_per_user: int = DEFAULT_MAX_KEYS_PER_USER,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.path = path
        self.github = github
        self.max_keys_per_user = max_keys_per_user
        self._sleep = sleep
        self._clock = clock
        self.users = read_allowed_users(path)
        """Each allowed login, in lower case, with the GitHub id it is pinned to."""
        if not self.users:
            raise AllowedUsersError(f"{path} lists no users, so the relay would refuse everyone")
        self._pending: dict[str, int | None] | None = None
        self._last_problem: str | None = None
        self._store: RelayStore | None = None

    @property
    def mode(self) -> AccessMode:
        return "github"

    def use_store(self, store: RelayStore | None) -> None:
        """Gives the policy the relay's database, where the owner of each key
        is kept (None when the relay stops)."""
        self._store = store

    @property
    def store(self) -> RelayStore:
        assert self._store is not None, "the relay has not handed over its database"
        return self._store

    def decide(self, key: str) -> Decision:
        owner = self.store.key_owner(key)
        if owner is None:
            return Decision.UNKNOWN
        if self._permits(owner.login, owner.github_id):
            return Decision.ADMITTED
        return Decision.REFUSED

    def _permits(self, login: str, github_id: int) -> bool:
        """Whether the file admits the GitHub account `github_id`, last seen
        with the name `login`: a line pins that id (under whatever name, so
        that renaming the account and its line keeps it admitted), or a line
        lists `login` without an id."""
        if github_id in self.users.values():
            return True
        return login.lower() in self.users and self.users[login.lower()] is None

    async def request_device_code(self) -> DeviceCode:
        """Asks GitHub for a code for the person to enter (raises `GitHubError`)."""
        return await self.github.request_device_code()

    async def wait_for_approval(self, code: DeviceCode) -> SignInOutcome:
        """Waits for the person to approve `code` on GitHub and reads who they are."""
        return await sign_in(self.github, code, sleep=self._sleep, clock=self._clock)

    def admit_signed_in(self, key: str, user: GitHubUser, now: int) -> bool:
        """Decides whether `key`, whose owner just signed in as `user`, may
        use the relay, and if so records that `user` owns it (`now` is in
        milliseconds since the epoch). Logs why when it may not."""
        store = self.store
        refused = f"refused a sign-in by GitHub user {user.login} (id {user.id})"
        owner = store.key_owner(key)
        if owner is not None and owner.github_id != user.id:
            # Two sign-ins with the same key at once, as different accounts.
            _log(f"{refused}: key {key} already belongs to GitHub id {owner.github_id}")
            return False
        if not self._permits(user.login, user.id):
            if user.login.lower() in self.users:
                _log(f"{refused}: {self.path} gives another id for that name")
            else:
                _log(f"{refused}: not listed in {self.path}")
            return False
        if user.id not in self.users.values():
            others = [i for i in store.github_ids_named(user.login) if i != user.id]
            if others:
                _log(
                    f"{refused}: that name first signed in here as GitHub id {others[0]};"
                    f" to admit this account instead, write its id after the name in {self.path}"
                )
                return False
        if owner is None and store.count_keys_of(user.id) >= self.max_keys_per_user:
            _log(f"{refused}: that user already has {self.max_keys_per_user} keys")
            return False
        first = store.record_sign_in(key, user.id, user.login, now)
        if first and user.id not in self.users.values():
            _log(
                f"GitHub user {user.login} signed in for the first time; their GitHub id is"
                f" {user.id}. To pin it, write {user.login} {user.id} on their line in"
                f" {self.path}"
            )
        elif first:
            _log(f"GitHub user {user.login} (id {user.id}) signed in for the first time")
        else:
            _log(f"GitHub user {user.login} (id {user.id}) signed in with a new key {key}")
        return True

    def reload(self, force: bool = False) -> bool:
        try:
            users = read_allowed_users(self.path)
        except AllowedUsersError as err:
            if str(err) != self._last_problem:
                _log(f"keeping the allowed users read before: {err}")
            self._last_problem = str(err)
            self._pending = None
            return False
        self._last_problem = None
        if users == self.users:
            self._pending = None
            return False
        # Taking a user out, or changing the id a user is pinned to, can
        # refuse keys: wait for a second reading that agrees (see `KeysAccess`).
        narrows = any(
            login not in users or (users[login] is not None and users[login] != pinned)
            for login, pinned in self.users.items()
        )
        if narrows and not force and users != self._pending:
            self._pending = users
            return False
        self._pending = None
        added = len(users.keys() - self.users.keys())
        removed = len(self.users.keys() - users.keys())
        _log(f"reread {self.path}: {len(users)} users ({added} added, {removed} removed)")
        self.users = users
        return True


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
