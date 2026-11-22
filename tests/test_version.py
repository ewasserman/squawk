import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from squawk.cli import main
from squawk.version import VERSION


def test_is_a_semantic_version_string() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", VERSION)


def test_matches_the_node_package_version() -> None:
    package = json.loads((Path(__file__).parent.parent / "package.json").read_text())
    assert package["version"] == VERSION


def test_cli_prints_the_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out == f"{VERSION}\n"


def test_module_entry_point_prints_the_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "squawk.cli", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == f"{VERSION}\n"


def test_cli_rejects_other_arguments() -> None:
    assert main(["frobnicate"]) == 2
