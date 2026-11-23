"""The relay's limits (the table in docs/plan/relay.md) and its in-memory
rate limiter.

Every limit is a field of `RelayLimits`, so tests can make them small or
short. Rate limits use the relay's clock (milliseconds since the epoch), so
a test that moves a fake clock forward also refills them.
"""

import math
from collections.abc import Callable
from dataclasses import dataclass, field

MINUTE_MS = 60_000
HOUR_MS = 60 * MINUTE_MS
DAY_MS = 24 * HOUR_MS


@dataclass(frozen=True)
class Rate:
    """At most `count` events per `per_ms` milliseconds, with at most `burst`
    of them at once (`burst` defaults to `count`).

    Counted as a token bucket: the bucket holds up to `burst` tokens, each
    event takes one, and tokens come back at `count / per_ms` per
    millisecond.
    """

    count: int
    per_ms: int
    burst: int | None = None

    @property
    def capacity(self) -> int:
        return self.count if self.burst is None else self.burst


@dataclass(frozen=True)
class RelayLimits:
    """Everything the relay limits. The defaults are the values in docs/plan/relay.md."""

    max_frame_bytes: int = 1 << 20
    """Largest WebSocket frame. A larger frame closes the connection (code 1009)."""
    max_sealed_bytes: int = 512 * 1024
    """Largest sealed message in a deposit or forward, as UTF-8 JSON text."""
    max_req_chars: int = 64
    max_id_chars: int = 128
    max_mailbox_messages: int = 1_000
    max_mailbox_bytes: int = 50 * (1 << 20)
    message_ttl_ms: int = 7 * DAY_MS
    """How long a message waits at the relay, from when it arrived."""
    deposit_rate: Rate = field(default_factory=lambda: Rate(60, MINUTE_MS, burst=20))
    forward_rate: Rate = field(default_factory=lambda: Rate(30, MINUTE_MS))
    max_allow_list: int = 1_000
    allow_rate: Rate = field(default_factory=lambda: Rate(30, MINUTE_MS))
    max_outstanding: int = 32
    max_queued_bytes: int = 8 * (1 << 20)
    """Frames waiting to be written to one connection. A client that stops
    reading while more than this is waiting is disconnected, so it cannot
    make the relay hold an ever-growing amount of memory."""
    """Deliveries sent on one connection and not yet deleted."""
    invite_create_rate: Rate = field(default_factory=lambda: Rate(10, HOUR_MS))
    invite_join_rate_per_connection: Rate = field(default_factory=lambda: Rate(10, MINUTE_MS))
    invite_join_rate_per_ip: Rate = field(default_factory=lambda: Rate(30, HOUR_MS))
    invite_ttl_ms: int = 10 * MINUTE_MS
    room_ttl_ms: int = 10 * MINUTE_MS
    max_pair_frames: int = 20
    """`pair` frames carried in one pairing room, from both sides together."""
    connect_rate_per_ip: Rate = field(default_factory=lambda: Rate(30, MINUTE_MS))
    auth_timeout_s: float = 10.0
    ping_interval_s: float = 30.0
    ping_timeout_s: float = 60.0
    purge_interval_s: float = 60.0
    """How often expired messages, invites and pairing rooms are removed."""
    access_check_interval_s: float = 30.0
    """How often the relay checks whether its allowed keys or allowed users
    file changed (docs/plan/relay-access.md asks for at least once a minute)."""
    # Signing in with GitHub (the limits in docs/plan/relay-access.md).
    login_start_timeout_s: float = 30.0
    """How long a client has to send `login-start` after `login-required`."""
    sign_in_rate_per_ip: Rate = field(default_factory=lambda: Rate(10, HOUR_MS))
    """Sign-ins started from one IP address."""
    max_sign_ins_per_ip: int = 2
    """Sign-ins in progress at once from one IP address."""
    max_sign_ins: int = 20
    """Sign-ins in progress at once on the whole relay."""


class RateLimiter:
    """Token buckets kept in memory, one per (kind of event, who)."""

    def __init__(self, now: Callable[[], int]) -> None:
        self._now = now
        self._buckets: dict[tuple[str, str], tuple[float, int]] = {}
        """(kind, who) -> (tokens left, time they were counted)."""

    def _tokens(self, key: tuple[str, str], rate: Rate, at: int) -> float:
        bucket = self._buckets.get(key)
        if bucket is None:
            return float(rate.capacity)
        tokens, then = bucket
        refilled = tokens + max(0, at - then) * rate.count / rate.per_ms
        return min(float(rate.capacity), refilled)

    def take(self, kind: str, who: str, rate: Rate) -> int | None:
        """Counts one event. Returns None when it is allowed, otherwise the
        whole number of seconds until it would be (at least 1)."""
        at = self._now()
        key = (kind, who)
        tokens = self._tokens(key, rate, at)
        if tokens >= 1:
            self._buckets[key] = (tokens - 1, at)
            return None
        self._buckets[key] = (tokens, at)
        wait_ms = (1 - tokens) * rate.per_ms / rate.count
        return max(1, math.ceil(wait_ms / 1000))

    def forget_full(self, rates: dict[str, Rate]) -> None:
        """Drops buckets that have refilled completely, so memory does not
        grow with every key or address ever seen. `rates` maps each kind to
        its rate; buckets of other kinds are kept."""
        at = self._now()
        for key in list(self._buckets):
            rate = rates.get(key[0])
            if rate is not None and self._tokens(key, rate, at) >= rate.capacity:
                del self._buckets[key]
