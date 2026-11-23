"""Tests for the GitHub device flow client (squawk.relay.github)."""

import io
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from squawk.relay import github as github_module
from squawk.relay.github import (
    ACCESS_TOKEN_URL,
    DEVICE_CODE_URL,
    DEVICE_GRANT_TYPE,
    USER_URL,
    Denied,
    DeviceCode,
    Expired,
    GitHubError,
    GitHubUser,
    Pending,
    PollAnswer,
    SignedIn,
    SignInDenied,
    SignInError,
    SignInExpired,
    SlowDown,
    Token,
    UrllibGitHub,
    sign_in,
)

TOKEN = "gho_secret_token_value"
DEVICE = "device-code-secret-value"
ALICE = GitHubUser(login="alice", id=12345678)


def device_code(*, expires_in: int = 900, interval: int = 5) -> DeviceCode:
    return DeviceCode(
        device_code=DEVICE,
        user_code="ABCD-1234",
        verification_uri="https://github.com/login/device",
        expires_in=expires_in,
        interval=interval,
    )


class FakeClock:
    """A clock that moves only when the code under test sleeps."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


@dataclass
class FakeGitHub:
    """Gives the poll answers it was set up with, in order; once they run out,
    the person is still deciding."""

    answers: list[PollAnswer | GitHubError]
    user: GitHubUser | GitHubError = ALICE
    polled_with: list[str] = field(default_factory=list)
    tokens_read: list[str] = field(default_factory=list)

    async def request_device_code(self) -> DeviceCode:
        return device_code()

    async def poll_token(self, device_code: str) -> PollAnswer:
        self.polled_with.append(device_code)
        answer = self.answers.pop(0) if self.answers else Pending()
        if isinstance(answer, GitHubError):
            raise answer
        return answer

    async def read_user(self, token: str) -> GitHubUser:
        self.tokens_read.append(token)
        if isinstance(self.user, GitHubError):
            raise self.user
        return self.user


async def test_signed_in_after_pending_answers() -> None:
    clock = FakeClock()
    github = FakeGitHub([Pending(), Pending(), Token(TOKEN)])
    outcome = await sign_in(github, device_code(), sleep=clock.sleep, clock=clock)
    assert outcome == SignedIn(ALICE)
    assert clock.sleeps == [5, 5, 5]
    assert github.polled_with == [DEVICE] * 3
    assert github.tokens_read == [TOKEN]


async def test_slow_down_uses_the_interval_github_gives() -> None:
    clock = FakeClock()
    github = FakeGitHub([Pending(), SlowDown(10), Pending(), Token(TOKEN)])
    outcome = await sign_in(github, device_code(), sleep=clock.sleep, clock=clock)
    assert outcome == SignedIn(ALICE)
    assert clock.sleeps == [5, 5, 10, 10]


async def test_slow_down_without_an_interval_adds_five_seconds() -> None:
    clock = FakeClock()
    github = FakeGitHub([SlowDown(None), SlowDown(None), Token(TOKEN)])
    outcome = await sign_in(github, device_code(), sleep=clock.sleep, clock=clock)
    assert outcome == SignedIn(ALICE)
    assert clock.sleeps == [5, 10, 15]


async def test_access_denied_is_denied() -> None:
    clock = FakeClock()
    github = FakeGitHub([Pending(), Denied()])
    outcome = await sign_in(github, device_code(), sleep=clock.sleep, clock=clock)
    assert outcome == SignInDenied()
    assert github.tokens_read == []


async def test_expired_token_is_expired() -> None:
    clock = FakeClock()
    github = FakeGitHub([Pending(), Expired()])
    outcome = await sign_in(github, device_code(), sleep=clock.sleep, clock=clock)
    assert outcome == SignInExpired()


async def test_stops_when_the_code_runs_out_of_time() -> None:
    clock = FakeClock()
    github = FakeGitHub([])
    outcome = await sign_in(
        github, device_code(expires_in=60, interval=5), sleep=clock.sleep, clock=clock
    )
    assert outcome == SignInExpired()
    assert len(github.polled_with) == 12
    assert clock.now - 1000.0 <= 60


async def test_an_error_while_polling_is_an_error() -> None:
    clock = FakeClock()
    github = FakeGitHub([Pending(), GitHubError("Could not reach GitHub to poll for the token")])
    outcome = await sign_in(github, device_code(), sleep=clock.sleep, clock=clock)
    assert outcome == SignInError("Could not reach GitHub to poll for the token")


async def test_an_error_while_reading_the_user_is_an_error() -> None:
    clock = FakeClock()
    github = FakeGitHub([Token(TOKEN)], user=GitHubError("GitHub answered 502"))
    outcome = await sign_in(github, device_code(), sleep=clock.sleep, clock=clock)
    assert isinstance(outcome, SignInError)
    assert TOKEN not in outcome.message


def test_secrets_are_left_out_of_repr() -> None:
    assert TOKEN not in repr(Token(TOKEN))
    assert DEVICE not in repr(device_code())
    assert "ABCD-1234" in repr(device_code())


# The real implementation, with urlopen replaced so nothing goes to the network.


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, status: int = 200) -> None:
        super().__init__(body)
        self.status = status


@dataclass
class FakeUrlopen:
    responses: list[FakeResponse | Exception]
    requests: list[urllib.request.Request] = field(default_factory=list)
    timeouts: list[float] = field(default_factory=list)

    def __call__(self, request: urllib.request.Request, timeout: float) -> FakeResponse:
        self.requests.append(request)
        self.timeouts.append(timeout)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def json_response(data: Any, status: int = 200) -> FakeResponse:
    return FakeResponse(json.dumps(data).encode(), status)


@pytest.fixture
def urlopen(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeUrlopen]:
    fake = FakeUrlopen([])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    yield fake


def form_of(request: urllib.request.Request) -> dict[str, list[str]]:
    assert isinstance(request.data, bytes)
    return urllib.parse.parse_qs(request.data.decode())


async def test_request_device_code_sends_no_scope(urlopen: FakeUrlopen) -> None:
    urlopen.responses.append(
        json_response(
            {
                "device_code": DEVICE,
                "user_code": "ABCD-1234",
                "verification_uri": "https://github.com/login/device",
                "expires_in": 900,
                "interval": 5,
            }
        )
    )
    code = await UrllibGitHub("client-1").request_device_code()
    assert code == device_code()
    [request] = urlopen.requests
    assert request.full_url == DEVICE_CODE_URL
    assert request.get_method() == "POST"
    assert form_of(request) == {"client_id": ["client-1"]}
    assert request.get_header("Accept") == "application/json"
    assert request.get_header("Content-type") == "application/x-www-form-urlencoded"
    assert urlopen.timeouts == [github_module.REQUEST_TIMEOUT]


async def test_request_device_code_rejects_a_malformed_answer(urlopen: FakeUrlopen) -> None:
    urlopen.responses.append(json_response({"device_code": DEVICE, "user_code": "ABCD-1234"}))
    with pytest.raises(GitHubError) as caught:
        await UrllibGitHub("client-1").request_device_code()
    assert DEVICE not in str(caught.value)


async def test_request_device_code_reports_github_refusing(urlopen: FakeUrlopen) -> None:
    urlopen.responses.append(json_response({"error": "unauthorized_client"}))
    with pytest.raises(GitHubError, match="unauthorized_client"):
        await UrllibGitHub("client-1").request_device_code()


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ({"access_token": TOKEN, "token_type": "bearer", "scope": ""}, Token(TOKEN)),
        ({"error": "authorization_pending"}, Pending()),
        ({"error": "slow_down", "interval": 10}, SlowDown(10)),
        ({"error": "slow_down"}, SlowDown(None)),
        ({"error": "expired_token"}, Expired()),
        ({"error": "access_denied"}, Denied()),
    ],
)
async def test_poll_token_reads_each_answer(
    urlopen: FakeUrlopen, body: dict[str, Any], expected: PollAnswer
) -> None:
    urlopen.responses.append(json_response(body))
    answer = await UrllibGitHub("client-1").poll_token(DEVICE)
    assert answer == expected
    [request] = urlopen.requests
    assert request.full_url == ACCESS_TOKEN_URL
    assert request.get_method() == "POST"
    assert form_of(request) == {
        "client_id": ["client-1"],
        "device_code": [DEVICE],
        "grant_type": [DEVICE_GRANT_TYPE],
    }
    assert request.get_header("Accept") == "application/json"


@pytest.mark.parametrize(
    "body",
    [
        {"error": "incorrect_device_code", "error_description": DEVICE},
        {"error": "unsupported_grant_type"},
        {},
        {"access_token": ""},
    ],
)
async def test_poll_token_other_answers_are_errors(
    urlopen: FakeUrlopen, body: dict[str, Any]
) -> None:
    urlopen.responses.append(json_response(body))
    with pytest.raises(GitHubError) as caught:
        await UrllibGitHub("client-1").poll_token(DEVICE)
    assert DEVICE not in str(caught.value)


async def test_read_user_sends_the_token_and_reads_login_and_id(urlopen: FakeUrlopen) -> None:
    urlopen.responses.append(json_response({"login": "alice", "id": 12345678, "name": "Alice"}))
    user = await UrllibGitHub("client-1").read_user(TOKEN)
    assert user == ALICE
    [request] = urlopen.requests
    assert request.full_url == USER_URL
    assert request.get_method() == "GET"
    assert request.data is None
    assert request.get_header("Authorization") == f"Bearer {TOKEN}"


@pytest.mark.parametrize(
    "body",
    [{"login": "alice"}, {"login": "alice", "id": "12"}, {"id": 1}, {"login": "a", "id": True}],
)
async def test_read_user_rejects_a_malformed_answer(
    urlopen: FakeUrlopen, body: dict[str, Any]
) -> None:
    urlopen.responses.append(json_response(body))
    with pytest.raises(GitHubError):
        await UrllibGitHub("client-1").read_user(TOKEN)


@pytest.mark.parametrize(
    "failure",
    [
        urllib.error.HTTPError(USER_URL, 401, "Unauthorized", {}, None),  # type: ignore[arg-type]
        urllib.error.URLError("connection refused"),
        TimeoutError("timed out"),
        FakeResponse(b"not json"),
        FakeResponse(b"[1, 2]"),
        FakeResponse(b"{}", status=204),
        FakeResponse(b" " * (70 * 1024)),
    ],
)
async def test_failures_become_github_errors_without_the_token(
    urlopen: FakeUrlopen, failure: FakeResponse | Exception
) -> None:
    urlopen.responses.append(failure)
    with pytest.raises(GitHubError) as caught:
        await UrllibGitHub("client-1").read_user(TOKEN)
    assert TOKEN not in str(caught.value)
    assert TOKEN not in repr(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None or caught.value.__suppress_context__


async def test_sign_in_with_the_real_client(urlopen: FakeUrlopen) -> None:
    urlopen.responses.extend(
        [
            json_response({"error": "authorization_pending"}),
            json_response({"error": "slow_down", "interval": 10}),
            json_response({"access_token": TOKEN, "token_type": "bearer", "scope": ""}),
            json_response({"login": "alice", "id": 12345678}),
        ]
    )
    clock = FakeClock()
    outcome = await sign_in(UrllibGitHub("client-1"), device_code(), sleep=clock.sleep, clock=clock)
    assert outcome == SignedIn(ALICE)
    assert TOKEN not in repr(outcome)
    assert clock.sleeps == [5, 5, 10]
