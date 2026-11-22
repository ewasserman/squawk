import json
import os
import re
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from squawk.config import db_path, identity_path, run_dir, squawk_home
from squawk.crypto import ed25519_sign, ed25519_verify, x25519_shared_secret
from squawk.encoding import from_base64url, is_key_id, key_from_id, key_id
from squawk.identity import (
    IdentityExistsError,
    NoIdentityError,
    fingerprint,
    init_identity,
    load_identity,
)


@pytest.fixture
def base(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def home(base: Path) -> str:
    return str(base / "home")


def mode(path: str) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


class TestConfig:
    def test_uses_squawk_home_when_set(self) -> None:
        assert squawk_home({"SQUAWK_HOME": "/x/y"}) == "/x/y"

    def test_falls_back_to_dot_config_squawk(self) -> None:
        assert squawk_home({}) == os.path.join(Path.home(), ".config", "squawk")
        assert squawk_home({"SQUAWK_HOME": ""}) == os.path.join(Path.home(), ".config", "squawk")

    def test_builds_paths_under_the_home_directory(self) -> None:
        assert identity_path("/h") == "/h/identity.json"
        assert db_path("/h") == "/h/squawk.db"
        assert run_dir("/h") == "/h/run"


class TestIdentity:
    def test_creates_a_key_pair_that_can_sign_and_verify(self, home: str) -> None:
        id = init_identity(home, "alice")
        assert id.name == "alice"
        assert len(id.public_key) == 32
        sig = ed25519_sign(b"hello", id.secret_key)
        assert ed25519_verify(sig, b"hello", id.public_key)

    def test_derives_x25519_keys_that_agree_on_a_shared_secret(self, base: Path) -> None:
        a = init_identity(str(base / "a"), "a")
        b = init_identity(str(base / "b"), "b")
        ab = x25519_shared_secret(a.x25519_secret_key, b.x25519_public_key)
        ba = x25519_shared_secret(b.x25519_secret_key, a.x25519_public_key)
        assert ab == ba

    def test_reloads_the_same_identity(self, home: str) -> None:
        created = init_identity(home, "alice")
        loaded = load_identity(home)
        assert loaded.name == "alice"
        assert loaded.id == created.id
        assert loaded.secret_key == created.secret_key
        assert loaded.x25519_public_key == created.x25519_public_key
        assert loaded == created

    def test_trims_the_display_name_and_refuses_an_empty_one(self, base: Path) -> None:
        assert init_identity(str(base / "a"), "  alice\n").name == "alice"
        with pytest.raises(ValueError, match="display name must not be empty"):
            init_identity(str(base / "b"), " \t")

    def test_refuses_to_overwrite_an_existing_identity(self, home: str) -> None:
        first = init_identity(home, "alice")
        with pytest.raises(IdentityExistsError, match="refusing to overwrite"):
            init_identity(home, "mallory")
        loaded = load_identity(home)
        assert loaded.id == first.id
        assert loaded.name == "alice"

    def test_writes_the_key_file_as_0600_and_the_directory_as_0700(self, home: str) -> None:
        init_identity(home, "alice")
        assert mode(identity_path(home)) == 0o600
        assert mode(home) == 0o700

    def test_leaves_the_permissions_of_an_existing_directory_alone(self, home: str) -> None:
        os.mkdir(home, 0o755)
        os.chmod(home, 0o755)
        init_identity(home, "alice")
        assert mode(home) == 0o755
        assert mode(identity_path(home)) == 0o600

    def test_writes_the_same_file_format_as_the_node_version(self, home: str) -> None:
        id = init_identity(home, "alice")
        text = Path(identity_path(home)).read_text()
        assert text.endswith("}\n")
        assert text.startswith('{\n\t"version": 1,\n\t"name": "alice",\n')
        raw = json.loads(text)
        assert list(raw) == ["version", "name", "publicKey", "secretKey", "createdAt"]
        assert raw["publicKey"] == id.id
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", raw["createdAt"])

    def test_reports_a_damaged_identity_file_clearly(self, home: str) -> None:
        init_identity(home, "alice")
        path = Path(identity_path(home))
        text = path.read_text()
        for broken in [
            text[:20],
            "null",
            "[]",
            text.replace('"version": 1', '"version": true'),
            re.sub(r'"secretKey": "[^"]+"', '"secretKey": "abc"', text),
        ]:
            path.write_text(broken)
            with pytest.raises(ValueError, match="is not in a format squawk understands"):
                load_identity(home)

    def test_reports_a_public_key_that_does_not_match(self, home: str) -> None:
        init_identity(home, "alice")
        path = Path(identity_path(home))
        raw = json.loads(path.read_text())
        raw["publicKey"] = key_id(bytes(32))
        path.write_text(json.dumps(raw))
        with pytest.raises(ValueError, match="is inconsistent"):
            load_identity(home)

    def test_reports_a_missing_identity(self, home: str) -> None:
        with pytest.raises(NoIdentityError, match='run "squawk init" first'):
            load_identity(home)

    def test_uses_a_default_display_name_when_none_is_given(self, home: str) -> None:
        id = init_identity(home)
        assert len(id.name) > 0

    def test_formats_the_fingerprint_as_eight_groups_of_four_hex_characters(
        self, home: str
    ) -> None:
        id = init_identity(home, "alice")
        assert re.fullmatch(r"([0-9a-f]{4}-){7}[0-9a-f]{4}", fingerprint(id.public_key))

    def test_identities_can_be_copied_with_changes(self, home: str) -> None:
        id = init_identity(home, "alice")
        assert replace(id, name="bob").public_key == id.public_key


class TestKeyIdentifiers:
    def test_accepts_only_the_one_canonical_spelling_of_each_key(self) -> None:
        id = key_id(bytes([7] * 32))
        assert is_key_id(id)
        # The last character carries 2 unused bits; other spellings that
        # decode to the same 32 bytes are refused.
        alias = id[:42] + ("d" if id.endswith("c") else "c")
        assert from_base64url(alias) == from_base64url(id)
        assert not is_key_id(alias)
        with pytest.raises(ValueError, match="not a squawk key identifier"):
            key_from_id(alias)

    def test_refuses_wrong_lengths_and_non_strings(self) -> None:
        with pytest.raises(ValueError, match="expected a 32-byte public key, got 31"):
            key_id(bytes(31))
        assert not is_key_id(key_id(bytes(32)) + "A")
        assert not is_key_id(key_id(bytes(32)) + "\n")
        assert not is_key_id(None)
