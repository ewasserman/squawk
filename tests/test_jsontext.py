"""The helpers for squawk's exact JSON text, string and date formats.

The expected values were checked against the output of squawk 0.1.
Characters are built with chr() so the test text stays plain ASCII.
"""

import pytest

from squawk import jsontext
from squawk.encoding import from_base64url
from squawk.timefmt import iso_from_ms, parse_iso_ms

LONE_HIGH = chr(0xD800)
EMOJI = chr(0x1F600)


def test_stringify_writes_compact_json_without_escaping_non_ascii() -> None:
    value = {"a": [1, "x"], "b": "caf" + chr(0xE9), "c": None, "d": True}
    assert jsontext.stringify(value) == '{"a":[1,"x"],"b":"caf' + chr(0xE9) + '","c":null,"d":true}'


def test_stringify_escapes_control_characters() -> None:
    assert (
        jsontext.stringify('\b\f\n\r\t\x00\x1f\x7f"\\')
        == '"\\b\\f\\n\\r\\t\\u0000\\u001f\x7f\\"\\\\"'
    )


def test_stringify_escapes_a_lone_surrogate_in_lowercase() -> None:
    assert jsontext.stringify(LONE_HIGH + EMOJI) == '"\\ud800' + EMOJI + '"'


def test_stringify_with_a_tab_indent() -> None:
    assert jsontext.stringify({"version": 1, "name": "a"}, indent="\t") == (
        '{\n\t"version": 1,\n\t"name": "a"\n}'
    )


@pytest.mark.parametrize("text", ["NaN", "Infinity", "-Infinity", "[NaN]"])
def test_parse_refuses_nan_and_infinity(text: str) -> None:
    with pytest.raises(ValueError):
        jsontext.parse(text)


def test_utf8_replaces_a_lone_surrogate() -> None:
    assert jsontext.utf8("a" + LONE_HIGH) == b"a\xef\xbf\xbd"


def test_lengths_and_slices_count_utf16_code_units() -> None:
    assert jsontext.js_length(EMOJI) == 2
    assert jsontext.js_slice("a" + EMOJI, 2) == "a" + chr(0xFFFD)
    assert jsontext.js_slice("a" + EMOJI, 3) == "a" + EMOJI


def test_trim_uses_squawks_white_space() -> None:
    # U+FEFF is white space to squawk but not to Python's str.strip; U+001C is the reverse.
    assert jsontext.js_trim(chr(0xFEFF) + " a ") == "a"
    assert jsontext.js_trim(chr(0x1C) + "a") == chr(0x1C) + "a"


@pytest.mark.parametrize(
    ("text", "hex_bytes"),
    [
        ("YQ==YQ", "61"),
        ("Y Q", "61"),
        ("YWJj!ZA", "61626364"),
        ("YWJjZ", "616263"),
        ("a+/_-b", "6beffff9"),
        ("", ""),
    ],
)
def test_base64url_decoding_rules(text: str, hex_bytes: str) -> None:
    assert from_base64url(text).hex() == hex_bytes


@pytest.mark.parametrize(
    ("ms", "text"),
    [
        (0, "1970-01-01T00:00:00.000Z"),
        (-1, "1969-12-31T23:59:59.999Z"),
        (1795262400123, "2026-11-21T12:00:00.123Z"),
        (-62162121600000, "0000-02-29T00:00:00.000Z"),
        (-62198755200000, "-000001-01-01T00:00:00.000Z"),
        (253402300800000, "+010000-01-01T00:00:00.000Z"),
    ],
)
def test_iso_from_ms_writes_squawks_text_form(ms: int, text: str) -> None:
    assert iso_from_ms(ms) == text


@pytest.mark.parametrize(
    ("text", "ms"),
    [
        ("2026-11-21T12:00:00.123456789Z", 1795262400123),
        ("2026-11-21T12:00:00.9999Z", 1795262400999),
        ("2026-11-21T12:00:00+05:30", 1795242600000),
        ("2026-11-21T23:59:59.5-23:59", 1795391939500),
        ("0000-02-29T00:00:00Z", -62162121600000),
        ("2026-11-21T12:00Z", None),
        ("2026-11-21 12:00:00Z", None),
        ("2026-02-29T12:00:00Z", None),
    ],
)
def test_parse_iso_ms_reads_squawks_text_form(text: str, ms: int | None) -> None:
    assert parse_iso_ms(text) == ms
