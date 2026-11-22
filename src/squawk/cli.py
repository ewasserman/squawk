"""The `squawk` command.

Only `--version` is here so far; the other subcommands are still in the
Node version (src/cli.ts) and will be ported later.
"""

import sys
from collections.abc import Sequence

from squawk.version import VERSION


def main(argv: Sequence[str] | None = None) -> int:
    """Runs the command line `argv` (default: the process arguments) and returns an exit code."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--version"]:
        print(VERSION)
        return 0
    print("usage: squawk --version", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
