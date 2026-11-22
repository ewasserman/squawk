import pytest

from squawk.relay_url import RelayUrlError, check_relay_url


def test_accepts_wss() -> None:
    assert check_relay_url(" wss://relay.example.com/ ") == "wss://relay.example.com"


def test_refuses_plain_ws_without_the_opt_in() -> None:
    with pytest.raises(RelayUrlError, match="--allow-plain"):
        check_relay_url("ws://localhost:8765")


def test_accepts_plain_ws_with_the_opt_in() -> None:
    assert check_relay_url("ws://localhost:8765", allow_plain=True) == "ws://localhost:8765"


@pytest.mark.parametrize(
    "url",
    [
        "https://relay.example.com",
        "relay.example.com",
        "wss://",
        "wss://user:pw@relay.example.com",
        "wss://relay.example.com/?x=1",
        "wss://relay.example.com:notaport",
        "wss://relay.example.com:0",
    ],
)
def test_refuses_urls_that_are_not_relay_urls(url: str) -> None:
    with pytest.raises(RelayUrlError):
        check_relay_url(url, allow_plain=True)
