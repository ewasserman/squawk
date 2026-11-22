"""Timestamps in squawk's text form.

Squawk writes times as ISO 8601 text in UTC, always with exactly three
digits of milliseconds and a "Z" ("2026-11-21T12:00:00.000Z"; this is the
format of JavaScript's `Date.prototype.toISOString`), and reads them back to
milliseconds since the epoch. The exact text matters because signatures
cover it and stored timestamps are compared as text. The arithmetic is done
on whole numbers rather than with `datetime`, so that years `datetime`
cannot hold (such as year 0, which an offset can produce) still work.
"""

import re
import time
from datetime import UTC, datetime

_MS_PER_DAY = 86_400_000

# The form envelopes allow for created_at and sent_at: a date and a time with
# seconds, optional fractional seconds, and "Z" or a "+hh:mm"/"-hh:mm" offset.
# The pattern also checks month lengths and leap days.
_DATE = (
    r"(?:(?:\d\d[2468][048]|\d\d[13579][26]|\d\d0[48]|[02468][048]00|[13579][26]00)-02-29"
    r"|\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\d|30)"
    r"|(?:02)-(?:0[1-9]|1\d|2[0-8])))"
)
_TIME = r"(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?"
_OFFSET = r"(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)"
ISO_DATETIME = re.compile(f"{_DATE}T{_TIME}{_OFFSET}", re.ASCII)

_PARTS = re.compile(
    r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?(?:(Z)|([+-])(\d\d):(\d\d))",
    re.ASCII,
)


def is_iso_datetime(text: object) -> bool:
    """True when `text` is an ISO 8601 date and time in the form envelopes allow."""
    return isinstance(text, str) and ISO_DATETIME.fullmatch(text) is not None


def _days_from_civil(year: int, month: int, day: int) -> int:
    """Days from 1970-01-01 to the given date in the proleptic Gregorian calendar."""
    year -= month <= 2
    era = year // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _civil_from_days(days: int) -> tuple[int, int, int]:
    """The (year, month, day) that is `days` after 1970-01-01."""
    days += 719468
    era = days // 146097
    doe = days - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + (3 if mp < 10 else -9)
    return yoe + era * 400 + (month <= 2), month, day


def parse_iso_ms(text: str) -> int | None:
    """Milliseconds since the epoch for an ISO date and time, or None if it is not one.

    Accepts the form `is_iso_datetime` describes. Fractional seconds beyond
    milliseconds are dropped (not rounded).
    """
    if not is_iso_datetime(text):
        return None
    m = _PARTS.fullmatch(text)
    if m is None:
        return None
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    fraction = (m.group(7) or "")[:3].ljust(3, "0")
    ms = (
        _days_from_civil(year, month, day) * _MS_PER_DAY
        + ((hour * 60 + minute) * 60 + second) * 1000
        + int(fraction)
    )
    if m.group(8) is None:
        offset = (int(m.group(10)) * 60 + int(m.group(11))) * 60_000
        ms -= offset if m.group(9) == "+" else -offset
    return ms


def iso_from_ms(ms: int) -> str:
    """`ms` as squawk's timestamp text, e.g. "2026-11-21T12:00:00.000Z"."""
    days, rest = divmod(ms, _MS_PER_DAY)
    year, month, day = _civil_from_days(days)
    seconds, millis = divmod(rest, 1000)
    minutes, second = divmod(seconds, 60)
    hour, minute = divmod(minutes, 60)
    # Years outside 0-9999 are written with a sign and six digits.
    sign = "-" if year < 0 else "+"
    year_text = f"{year:04d}" if 0 <= year <= 9999 else f"{sign}{abs(year):06d}"
    return f"{year_text}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}.{millis:03d}Z"


def ms_from_datetime(value: datetime) -> int:
    """Milliseconds since the epoch for `value`, dropping anything finer.

    A datetime without a time zone is taken as local time, as Python does
    elsewhere.
    """
    delta = value.astimezone(UTC) - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86_400 + delta.seconds) * 1000 + delta.microseconds // 1000


def now_ms() -> int:
    """The current time in whole milliseconds since the epoch."""
    return time.time_ns() // 1_000_000
