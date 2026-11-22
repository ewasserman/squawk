"""JSON text and string handling in squawk's exact formats.

Squawk's signatures cover exact JSON text, and every squawk peer must read
and write the same messages, as must databases written by earlier versions.
These helpers fix the JSON text, the UTF-8 encoding and the way string
lengths are counted (in UTF-16 code units) where Python's defaults differ.
"""

import json
import re
from typing import Any

_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


def stringify(value: object, indent: str | None = None) -> str:
    """Squawk's JSON text for plain data (the same text as JavaScript's
    `JSON.stringify(value, null, indent)`).

    Without `indent`, no spaces between items. Non-ASCII characters are
    written as they are, and a lone UTF-16 surrogate (which can only come
    from a "\\udXXX" escape in parsed JSON) is written as a lowercase escape.
    """
    separators = (",", ":") if indent is None else (",", ": ")
    text = json.dumps(
        value, ensure_ascii=False, separators=separators, indent=indent, allow_nan=False
    )
    return _LONE_SURROGATE.sub(lambda m: f"\\u{ord(m.group()):04x}", text)


def parse(text: str) -> Any:
    """Parses JSON text strictly.

    Unlike Python's default, NaN, Infinity and -Infinity are refused.
    """
    return json.loads(text, parse_constant=_reject_constant)


def utf8(text: str) -> bytes:
    """UTF-8 bytes of `text`.

    A lone surrogate becomes U+FFFD instead of raising an error.
    """
    return _LONE_SURROGATE.sub("\ufffd", text).encode("utf-8")


def js_length(text: str) -> int:
    """The length of `text` in UTF-16 code units, the unit squawk's length
    limits are counted in."""
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def js_slice(text: str, end: int) -> str:
    """The first `end` UTF-16 code units of `text`.

    If the cut splits a surrogate pair, the leftover half becomes U+FFFD,
    which is what it would turn into when written as UTF-8.
    """
    units = text.encode("utf-16-le", "surrogatepass")[: 2 * end]
    return units.decode("utf-16-le", "replace")


# The characters squawk treats as white space when trimming text: the set
# that JavaScript's `String.prototype.trim` and regex `\s` use. Python's
# `str.strip` uses a different set.
JS_WHITESPACE = (
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006"
    "\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)


def js_trim(text: str) -> str:
    """`text` without leading and trailing white space (see JS_WHITESPACE)."""
    return text.strip(JS_WHITESPACE)
