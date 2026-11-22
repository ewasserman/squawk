"""Checking the URL of the relay a service uses.

A deployed relay is reached over `wss://` (TLS). Plain `ws://` sends
everything, including who talks to whom, unencrypted on the network path to
the relay, so it is refused unless the person opted in when setting the
relay (`--allow-plain`), which is meant for testing against a relay on this
machine or in Docker. Messages are sealed either way. See
docs/plan/relay.md, "Transport", and docs/plan/security.md, threat 15.
"""

from urllib.parse import urlsplit


class RelayUrlError(ValueError):
    """Raised when a relay URL cannot be used; the message is meant for the person."""


def check_relay_url(url: str, *, allow_plain: bool = False) -> str:
    """Returns `url` without surrounding spaces or a trailing slash if it can
    be used as a relay URL, or raises `RelayUrlError` saying why not."""
    text = url.strip().rstrip("/")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as err:
        raise RelayUrlError(f'"{url}" is not a valid relay URL') from err
    if parts.scheme not in ("ws", "wss") or not parts.hostname:
        raise RelayUrlError(
            f'"{url}" is not a relay URL; it should look like wss://relay.example.com'
        )
    if parts.username is not None or parts.password is not None:
        raise RelayUrlError("a relay URL must not contain a user name or password")
    if parts.query or parts.fragment:
        raise RelayUrlError("a relay URL must not contain a query or fragment")
    if port == 0:
        raise RelayUrlError(f'"{url}" has no usable port')
    if parts.scheme == "ws" and not allow_plain:
        raise RelayUrlError(
            f'"{url}" is not encrypted (ws://). Use a wss:// URL, or, for testing '
            "against a local relay, allow it explicitly with --allow-plain."
        )
    return text
