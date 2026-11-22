"""JSON text and string handling that matches what the Node version does.

Squawk's signatures cover exact JSON text, and the Node and Python versions
must read and write each other's messages and database rows. These helpers
reproduce the behaviour of JavaScript's `JSON.stringify`, `JSON.parse`,
`TextEncoder` and string lengths where Python's defaults differ.
"""

import json
import re
from typing import Any

_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def stringify(value: object, indent: str | None = None) -> str:
    """The text JavaScript's `JSON.stringify(value, null, indent)` produces for plain data.

    Without `indent`, no spaces between items. Non-ASCII characters are
    written as they are, and a lone UTF-16 surrogate (which can only come
    from a "\\udXXX" escape in parsed JSON) is written as a lowercase escape,
    as JavaScript does.
    """
    separators = (",", ":") if indent is None else (",", ": ")
    text = json.dumps(
        value, ensure_ascii=False, separators=separators, indent=indent, allow_nan=False
    )
    return _LONE_SURROGATE.sub(lambda m: f"\\u{ord(m.group()):04x}", text)


def parse(text: str) -> Any:
    """Parses JSON text as JavaScript's `JSON.parse` does.

    Unlike Python's default, NaN, Infinity and -Infinity are refused.
    """
    return json.loads(text, parse_constant=_reject_constant)


def utf8(text: str) -> bytes:
    """UTF-8 bytes of `text`, as JavaScript's `TextEncoder` produces them.

    A lone surrogate becomes U+FFFD instead of raising an error.
    """
    return _LONE_SURROGATE.sub("\ufffd", text).encode("utf-8")


def js_length(text: str) -> int:
    """The length JavaScript reports for `text`: its number of UTF-16 code units."""
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def js_slice(text: str, end: int) -> str:
    """JavaScript's `text.slice(0, end)`, counting UTF-16 code units.

    If the cut splits a surrogate pair, the leftover half becomes U+FFFD,
    which is what it turns into when the Node version writes it as UTF-8.
    """
    units = text.encode("utf-16-le", "surrogatepass")[: 2 * end]
    return units.decode("utf-16-le", "replace")


# The characters JavaScript's `String.prototype.trim` and regex `\s` treat as
# white space. Python's `str.strip` uses a different set.
JS_WHITESPACE = (
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006"
    "\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)


def js_trim(text: str) -> str:
    """JavaScript's `text.trim()`."""
    return text.strip(JS_WHITESPACE)
