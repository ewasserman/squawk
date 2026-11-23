"""Signing a person in with GitHub's device flow (docs/plan/relay-access.md).

GitHub's device flow lets a program without a web server sign a person in.
The program asks GitHub for a device code, shows the person a short user code
and a web address, and then asks GitHub every few seconds whether the person
has approved. Once they have, GitHub hands over a token, and the program uses
it to read who the person is.

The relay runs this flow on behalf of a client, so the token never leaves the
relay. This module holds the part that talks to GitHub:

- `GitHub` describes the three requests the flow needs, so tests can supply
  their own answers;
- `UrllibGitHub` makes those requests over the network with the standard
  library;
- `sign_in` runs the whole flow, from a device code to the person's GitHub
  login and numeric id.

The token is kept only in local variables and dropped as soon as the user has
been read. It is never logged, written to disk, put in an exception message or
shown by `repr`.
"""

import asyncio
import http.client
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

DEVICE_CODE_URL = "https://github.com/login/device/code"
ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_URL = "https://api.github.com/user"
DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

REQUEST_TIMEOUT = 10.0
"""Seconds to wait for GitHub to answer one request."""

SLOW_DOWN_SECONDS = 5
"""How much longer to wait between polls when GitHub asks us to slow down and
does not say the new interval itself."""

_MAX_RESPONSE_BYTES = 64 * 1024
_USER_AGENT = "squawk-relay"
_ERROR_CODE = re.compile(r"[a-z_]{1,64}")


class GitHubError(Exception):
    """GitHub could not be reached, or gave an answer we could not use.

    The message says what went wrong in plain words. It never contains the
    token or the device code.
    """


@dataclass(frozen=True)
class DeviceCode:
    """GitHub's answer to a request for a device code.

    The relay shows the person `user_code` and `verification_uri`, and tells
    them they have `expires_in` seconds to approve. `device_code` is the secret
    the relay uses when asking for the token, so it is left out of `repr`.
    """

    device_code: str = field(repr=False)
    user_code: str
    verification_uri: str
    expires_in: int
    """Seconds until the codes stop working."""
    interval: int
    """Seconds to wait between polls for the token."""


@dataclass(frozen=True)
class Token:
    """The person approved, and GitHub gave this token."""

    token: str = field(repr=False)


@dataclass(frozen=True)
class Pending:
    """The person has not approved yet."""


@dataclass(frozen=True)
class SlowDown:
    """GitHub asks us to poll less often.

    `interval` is the new number of seconds between polls, when GitHub says it.
    """

    interval: int | None


@dataclass(frozen=True)
class Expired:
    """The device code has expired."""


@dataclass(frozen=True)
class Denied:
    """The person declined on GitHub."""


PollAnswer = Token | Pending | SlowDown | Expired | Denied
"""What one poll for the token can return. Any other answer raises
`GitHubError`."""


@dataclass(frozen=True)
class GitHubUser:
    """A GitHub account: its login (which can be renamed) and its numeric id
    (which never changes)."""

    login: str
    id: int


class GitHub(Protocol):
    """The requests the device flow makes to GitHub.

    Each method raises `GitHubError` if GitHub cannot be reached or its answer
    cannot be used.
    """

    async def request_device_code(self) -> DeviceCode:
        """Ask GitHub for a new device code and user code, with no scopes."""
        ...

    async def poll_token(self, device_code: str) -> PollAnswer:
        """Ask GitHub once whether the person has approved `device_code`."""
        ...

    async def read_user(self, token: str) -> GitHubUser:
        """Read the login and numeric id of the account `token` belongs to."""
        ...


class UrllibGitHub:
    """Makes the device flow's requests to GitHub with `urllib.request`.

    Each request runs in a worker thread so it does not hold up the event
    loop, and gives up after `timeout` seconds.
    """

    def __init__(self, client_id: str, *, timeout: float = REQUEST_TIMEOUT) -> None:
        self._client_id = client_id
        self._timeout = timeout

    def __repr__(self) -> str:
        return f"UrllibGitHub(client_id={self._client_id!r})"

    async def request_device_code(self) -> DeviceCode:
        # No `scope` field: a token without scopes can read only the user's
        # public profile.
        data = await asyncio.to_thread(
            self._request,
            "request a device code",
            DEVICE_CODE_URL,
            form={"client_id": self._client_id},
        )
        error = data.get("error")
        if error is not None:
            raise GitHubError(
                f"GitHub refused to give a device code ({_describe_error_code(error)})"
            )
        try:
            return DeviceCode(
                device_code=_string(data, "device_code"),
                user_code=_string(data, "user_code"),
                verification_uri=_string(data, "verification_uri"),
                expires_in=_integer(data, "expires_in"),
                interval=_integer(data, "interval"),
            )
        except ValueError as exc:
            raise GitHubError(f"GitHub's device code answer is not usable: {exc}") from None

    async def poll_token(self, device_code: str) -> PollAnswer:
        data = await asyncio.to_thread(
            self._request,
            "poll for the token",
            ACCESS_TOKEN_URL,
            form={
                "client_id": self._client_id,
                "device_code": device_code,
                "grant_type": DEVICE_GRANT_TYPE,
            },
        )
        token = data.get("access_token")
        if isinstance(token, str) and token:
            return Token(token)
        error = data.get("error")
        if error == "authorization_pending":
            return Pending()
        if error == "slow_down":
            interval = data.get("interval")
            if isinstance(interval, int) and not isinstance(interval, bool) and interval > 0:
                return SlowDown(interval)
            return SlowDown(None)
        if error == "expired_token":
            return Expired()
        if error == "access_denied":
            return Denied()
        if error is None:
            raise GitHubError("GitHub's token answer has neither a token nor an error")
        raise GitHubError(f"GitHub refused to give a token ({_describe_error_code(error)})")

    async def read_user(self, token: str) -> GitHubUser:
        data = await asyncio.to_thread(self._request, "read the user", USER_URL, token=token)
        try:
            return GitHubUser(login=_string(data, "login"), id=_integer(data, "id"))
        except ValueError as exc:
            raise GitHubError(f"GitHub's user answer is not usable: {exc}") from None

    def _request(
        self,
        purpose: str,
        url: str,
        *,
        form: dict[str, str] | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        """Send one request and return the JSON object GitHub answers with.

        A form makes it a POST; otherwise it is a GET. `purpose` names the
        request in error messages. Any failure raises `GitHubError` with a
        message that leaves out the request's form and headers, which hold the
        device code or the token.
        """
        headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}
        body: bytes | None = None
        if form is not None:
            body = urllib.parse.urlencode(form).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            url, data=body, headers=headers, method="POST" if form is not None else "GET"
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                status = response.status
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise GitHubError(f"GitHub answered {exc.code} when asked to {purpose}") from None
        except urllib.error.URLError as exc:
            raise GitHubError(f"Could not reach GitHub to {purpose}: {exc.reason}") from None
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise GitHubError(
                f"Could not reach GitHub to {purpose}: {type(exc).__name__}"
            ) from None
        if not 200 <= status < 300:
            raise GitHubError(f"GitHub answered {status} when asked to {purpose}")
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise GitHubError(f"GitHub's answer was too long when asked to {purpose}")
        try:
            data = json.loads(raw)
        except ValueError:
            raise GitHubError(f"GitHub's answer was not JSON when asked to {purpose}") from None
        if not isinstance(data, dict):
            raise GitHubError(f"GitHub's answer was not a JSON object when asked to {purpose}")
        return data


def _string(data: dict[str, Any], name: str) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} is missing or not text")
    return value


def _integer(data: dict[str, Any], name: str) -> int:
    value = data.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} is missing or not a positive whole number")
    return value


def _describe_error_code(error: object) -> str:
    """GitHub's error code, if it looks like one; otherwise a fixed text.

    Only short codes such as `incorrect_device_code` are repeated, so nothing
    else GitHub sends ends up in a message.
    """
    if isinstance(error, str) and _ERROR_CODE.fullmatch(error):
        return error
    return "unrecognised error"


@dataclass(frozen=True)
class SignedIn:
    """The person approved, and this is their GitHub account."""

    user: GitHubUser


@dataclass(frozen=True)
class SignInDenied:
    """The person declined on GitHub."""


@dataclass(frozen=True)
class SignInExpired:
    """The person did not approve before the code expired."""


@dataclass(frozen=True)
class SignInError:
    """GitHub could not be reached or gave an answer we could not use."""

    message: str


SignInOutcome = SignedIn | SignInDenied | SignInExpired | SignInError


async def sign_in(
    github: GitHub,
    code: DeviceCode,
    *,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> SignInOutcome:
    """Wait for the person to approve `code` on GitHub, then read who they are.

    Polls GitHub every `code.interval` seconds, waiting longer whenever GitHub
    asks us to slow down, and gives up once `code.expires_in` seconds have
    passed since this function was called. `sleep` and `clock` (in seconds)
    can be replaced so tests do not have to wait.

    The token GitHub gives is used once, to read the user, and then dropped.
    """
    deadline = clock() + code.expires_in
    interval = code.interval
    try:
        while True:
            if clock() + interval > deadline:
                return SignInExpired()
            await sleep(interval)
            answer = await github.poll_token(code.device_code)
            match answer:
                case Token():
                    user = await github.read_user(answer.token)
                    del answer
                    return SignedIn(user)
                case Pending():
                    pass
                case SlowDown(interval=new_interval):
                    interval = (
                        new_interval if new_interval is not None else interval + SLOW_DOWN_SECONDS
                    )
                case Expired():
                    return SignInExpired()
                case Denied():
                    return SignInDenied()
    except GitHubError as exc:
        return SignInError(str(exc))
