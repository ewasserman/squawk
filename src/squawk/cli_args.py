"""Reads command-line options the way Node's `util.parseArgs` does in strict
mode, so the Python `squawk` command accepts the same arguments and prints
the same error messages as the Node version.

What it accepts: `--name value`, `--name=value`, `-n value`, `-nvalue`,
grouped short flags (`-up`), options before or after positionals, and `--`
to end options. A string option whose value starts with "-" must be written
as `--name=-x` (or `-n-x`), as in Node.
"""

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

OptionType = Literal["string", "boolean"]


@dataclass(frozen=True)
class Opt:
    """One option a command accepts."""

    type: OptionType
    short: str | None = None


class ParseArgsError(Exception):
    """The arguments do not fit the command's options. The message is Node's wording."""


@dataclass
class _Token:
    name: str
    raw_name: str
    value: str | None
    inline_value: bool


def _long_for_short(short: str, options: Mapping[str, Opt]) -> str:
    for name, opt in options.items():
        if opt.short == short:
            return name
    return short


def _type_of(name: str, options: Mapping[str, Opt]) -> OptionType | None:
    opt = options.get(name)
    return None if opt is None else opt.type


def _is_option_like(value: str | None) -> bool:
    return value is not None and len(value) > 1 and value[0] == "-"


def parse_args(
    args: Sequence[str],
    options: Mapping[str, Opt] | None = None,
    *,
    allow_positionals: bool = False,
) -> tuple[dict[str, str | bool], list[str]]:
    """Returns the option values (a string, or True for a boolean that was
    given; options not given are absent) and the positional arguments.

    Raises `ParseArgsError` for an unknown option, a missing or unexpected
    option value, or a positional argument when `allow_positionals` is False.
    """
    opts: Mapping[str, Opt] = {} if options is None else options
    values: dict[str, str | bool] = {}
    positionals: list[str] = []
    remaining = list(args)

    def check(token: _Token) -> None:
        opt = opts.get(token.name)
        if opt is None:
            message = f"Unknown option '{token.raw_name}'"
            if allow_positionals:
                # The missing closing quote is in Node's message too.
                quoted = json.dumps(token.raw_name, ensure_ascii=False)
                message += (
                    ". To specify a positional argument starting with a '-', place it at "
                    f"the end of the command after '--', as in '-- {quoted}"
                )
            raise ParseArgsError(message)
        short_and_long = f"-{opt.short}, --{token.name}" if opt.short else f"--{token.name}"
        if opt.type == "string" and token.value is None:
            raise ParseArgsError(f"Option '{short_and_long} <value>' argument missing")
        if opt.type == "boolean" and token.value is not None:
            raise ParseArgsError(f"Option '{short_and_long}' does not take an argument")
        if not token.inline_value and _is_option_like(token.value):
            if token.raw_name.startswith("--"):
                example = f"'{token.raw_name}=-XYZ'"
            else:
                example = f"'--{token.name}=-XYZ' or '{token.raw_name}-XYZ'"
            raise ParseArgsError(
                f"Option '{token.raw_name}' argument is ambiguous.\n"
                f"Did you forget to specify the option argument for '{token.raw_name}'?\n"
                f"To specify an option argument starting with a dash use {example}."
            )
        values[token.name] = True if token.value is None else token.value

    def positional(arg: str) -> None:
        if not allow_positionals:
            raise ParseArgsError(
                f"Unexpected argument '{arg}'. This command does not take positional arguments"
            )
        positionals.append(arg)

    while remaining:
        arg = remaining.pop(0)
        if arg == "--":
            for rest in remaining:
                positional(rest)
            break
        if len(arg) == 2 and arg[0] == "-" and arg[1] != "-":
            # -n, with the value in the next argument for a string option.
            name = _long_for_short(arg[1], opts)
            value: str | None = None
            if _type_of(name, opts) == "string" and remaining:
                value = remaining.pop(0)
            check(_Token(name, arg, value, False))
            continue
        if len(arg) > 2 and arg[0] == "-" and arg[1] != "-":
            name = _long_for_short(arg[1], opts)
            if _type_of(name, opts) != "string":
                # A group of short flags, such as -up. A string option inside
                # the group takes the rest of it as its value.
                expanded: list[str] = []
                for index in range(1, len(arg)):
                    short = arg[index]
                    long = _long_for_short(short, opts)
                    if _type_of(long, opts) != "string" or index == len(arg) - 1:
                        expanded.append(f"-{short}")
                    else:
                        expanded.extend([f"-{short}", arg[index + 1 :]])
                        break
                remaining[0:0] = expanded
                continue
            # -nvalue
            check(_Token(name, f"-{arg[1]}", arg[2:], True))
            continue
        if len(arg) > 2 and arg.startswith("--"):
            if "=" in arg:
                index = arg.index("=")
                name = arg[2:index]
                check(_Token(name, f"--{name}", arg[index + 1 :], True))
            else:
                name = arg[2:]
                value = None
                if _type_of(name, opts) == "string" and remaining:
                    value = remaining.pop(0)
                check(_Token(name, arg, value, False))
            continue
        positional(arg)
    return values, positionals


def string_value(values: Mapping[str, str | bool], name: str) -> str | None:
    """The value of a string option, or None if it was not given."""
    value = values.get(name)
    return value if isinstance(value, str) else None
