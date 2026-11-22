"""Tests for squawk.project: a session's project and root, and the allow and
deny patterns."""

import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator

import pytest

from squawk.project import is_visible, pattern_matches, project_from_remote, session_project
from squawk.store import SessionRecord


def session(
    *,
    project: str | None = None,
    repo: str | None = "api-server",
    base_label: str = "api-server@main",
    root: str | None = "/Users/me/src/some-org/api-server",
    cwd: str = "/Users/me/worktrees/api-server/feature",
) -> SessionRecord:
    return SessionRecord(
        session_id="s-1",
        label=base_label,
        base_label=base_label,
        repo=repo,
        branch="main",
        cwd=cwd,
        socket_path="/tmp/s.sock",
        token="t",
        registered_at="2026-01-01T00:00:00.000Z",
        project=project,
        root=root,
    )


@pytest.mark.parametrize(
    ("url", "project"),
    [
        ("https://github.com/some-org/api-server.git", "some-org/api-server"),
        ("https://github.com/some-org/api-server", "some-org/api-server"),
        ("https://user:secret@github.com/some-org/api-server.git/", "some-org/api-server"),
        ("git@github.com:some-org/api-server.git", "some-org/api-server"),
        ("github.com:some-org/api-server", "some-org/api-server"),
        ("ssh://git@github.com:2222/some-org/api-server.git", "some-org/api-server"),
        ("https://gitlab.com/group/team/tool.git", "group/team/tool"),
        ("git@host:tool.git", "tool"),
        ("git@github.com:/some-org/api-server.git", "some-org/api-server"),
        ("  git@github.com:a/b.git\n", "a/b"),
        ("/Users/me/src/api-server", None),
        ("../api-server.git", None),
        ("file:///Users/me/src/api-server.git", None),
        ("https://github.com/", None),
        ("", None),
    ],
)
def test_the_project_is_the_path_of_the_remote_without_host_or_dot_git(
    url: str, project: str | None
) -> None:
    assert project_from_remote(url) == project


def test_a_pattern_is_compared_with_the_project_and_the_repository_name() -> None:
    s = session(project="some-org/api-server")
    for pattern in ("some-org/*", "some-org/api-server", "SOME-ORG/*", "*/api-*", "api-server",
                    "api-serve?", "*", "some-org", "some-*"):  # fmt: skip
        assert pattern_matches(pattern, s), pattern
    for pattern in ("other-org/*", "some", "some-org/api", "api", "api-server@main", "main"):
        assert not pattern_matches(pattern, s), pattern
    # Without a remote there is only the repository's name.
    local = session(project=None)
    assert pattern_matches("api-server", local)
    assert not pattern_matches("some-org/*", local)
    # Outside git, the folder's name.
    plain = session(project=None, repo=None, base_label="notes", root="/Users/me/notes")
    assert pattern_matches("notes", plain) and pattern_matches("n*", plain)
    assert not pattern_matches("api-server", plain)


def test_a_pattern_starting_with_a_slash_or_tilde_is_compared_with_the_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", "/Users/me")
    s = session(project="some-org/api-server")
    for pattern in (
        "/Users/me/src/some-org/api-server",
        "/Users/me/src/some-org/api-server/",
        "/Users/me/src/some-org",
        "/Users/me/src/some-org/*",
        "~/src/some-org",
        "~/src//some-org/../some-org/",
        "~/src/*/api-server",
        "~",
        "/",
        "/users/ME/src",
    ):
        assert pattern_matches(pattern, s), pattern
    for pattern in (
        "/Users/me/src/some",
        "/Users/me/src/other-org/*",
        "~/worktrees/*",  # the worktree's own folder is not what counts
        "/some-org/*",
    ):
        assert not pattern_matches(pattern, s), pattern
    # A session registered before squawk recorded roots is compared by its folder.
    old = session(root=None, cwd="/Users/me/src/some-org/api-server/sub")
    assert pattern_matches("~/src/some-org", old)


def test_a_session_is_visible_only_if_allowed_and_not_denied() -> None:
    work = session(project="cadena/app")
    secret = session(project="cadena/secret")
    other = session(project="some-org/api-server")
    unknown = session(project=None, repo="scratch")
    # Nothing is visible until something is allowed.
    assert not is_visible(work, [], [])
    assert not is_visible(work, [], ["some-org/*"])
    assert all(is_visible(s, ["*"], []) for s in (work, secret, other, unknown))
    assert is_visible(work, ["cadena/*"], [])
    assert not is_visible(other, ["cadena/*"], [])
    assert not is_visible(unknown, ["cadena/*"], [])
    # Deny wins over allow.
    assert not is_visible(secret, ["cadena/*"], ["cadena/secret"])
    assert is_visible(work, ["cadena/*"], ["cadena/secret"])
    assert not is_visible(other, ["*"], ["some-org/*"])
    assert is_visible(unknown, ["*"], ["some-org/*"])
    assert not is_visible(work, ["*"], ["*"])


@pytest.fixture
def folder() -> Iterator[str]:
    path = os.path.realpath(tempfile.mkdtemp(prefix="sq-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def git(cwd: str, *args: str) -> None:
    subprocess.run(
        ["git", "-C", cwd, *args],
        check=True,
        capture_output=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
    )


def test_the_project_and_root_are_the_same_in_every_worktree(folder: str) -> None:
    repo = os.path.join(folder, "myrepo")
    os.makedirs(os.path.join(repo, "sub"))
    git(repo, "init", "-q", "-b", "main")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty",
        "-m", "x")  # fmt: skip
    worktree = os.path.join(folder, "elsewhere")
    git(repo, "worktree", "add", "-q", "-b", "feature/x", worktree)

    # No remote yet: no project.
    assert session_project(repo) == (None, repo)
    git(repo, "remote", "add", "upstream", "https://github.com/their-org/myrepo.git")
    assert session_project(repo) == (None, repo)
    git(repo, "remote", "add", "origin", "git@github.com:some-org/myrepo.git")
    assert session_project(repo) == ("some-org/myrepo", repo)
    assert session_project(os.path.join(repo, "sub")) == ("some-org/myrepo", repo)
    assert session_project(worktree) == ("some-org/myrepo", repo)

    plain = os.path.join(folder, "plain")
    os.makedirs(plain)
    assert session_project(plain + "/") == (None, plain)
    assert session_project(os.path.join(folder, "missing")) == (
        None,
        os.path.join(folder, "missing"),
    )
