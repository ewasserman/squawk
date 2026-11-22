"""Which project a Claude Code session belongs to, and the allow and deny
lists that decide whether paired contacts may see and address it.

A session's project is the path of its git repository's `origin` remote
without the host, such as "some-org/api-server". Its root is the folder of
the repository's main checkout (the same for every worktree), or outside git
the folder the session started in.

A pattern is a shell-style glob (`*`, `?`, `[...]`; `*` also matches "/"),
compared without regard to case:

  - a pattern starting with "/" or "~" is compared with the session's root,
    and matches that folder and everything below it;
  - any other pattern is compared with the project, with each leading part
    of it (so "some-org" matches like "some-org/*"), and with the name of
    the repository's folder (outside git, the session's folder).

A session is hidden unless it matches an allow pattern and no deny pattern.
With an empty allow list, which is how squawk starts, every session is
hidden; the pattern "*" allows every session. The lists are kept and applied
by the service of the machine the sessions are on; nothing another machine
sends can change them.
"""

import fnmatch
import os
import re
import subprocess
from collections.abc import Sequence

from squawk.store import SessionRecord

GIT_TIMEOUT_S = 2.0

PATTERN_MAX = 1024
"""The longest pattern accepted, in characters."""

MAX_PATTERNS = 100
"""The most patterns each list holds."""


class GitNotRunError(Exception):
    """git could not be started, or did not finish in time: its answer is
    unknown, which is not the same as "not a repository"."""


def _git(cwd: str, *args: str) -> str | None:
    """What `git <args>` prints when run in `cwd`, or None if it reports an
    error or prints nothing. Raises `GitNotRunError` if git did not run to
    the end."""
    try:
        result = subprocess.run(
            ["git", "-C", cwd, *args],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_S,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as err:
        raise GitNotRunError(str(err)) from err
    out = result.stdout.strip()
    return out if result.returncode == 0 and out else None


def git(cwd: str, *args: str) -> str | None:
    """What `git <args>` prints when run in `cwd`, or None if it fails or
    prints nothing."""
    try:
        return _git(cwd, *args)
    except GitNotRunError:
        return None


def _common_dir(cwd: str) -> str | None:
    common = _git(cwd, "rev-parse", "--git-common-dir")
    return None if common is None else os.path.normpath(os.path.join(cwd, common))


def common_dir(cwd: str) -> str | None:
    """The git directory shared by every worktree of the repository `cwd` is
    in, or None outside git."""
    try:
        return _common_dir(cwd)
    except GitNotRunError:
        return None


_SCP_LIKE = re.compile(r"^(?:[^@/]+@)?[^:/]+:(.+)$")
"""A remote written as "git@host:owner/repo.git"."""


def project_from_remote(url: str) -> str | None:
    """The project a git remote URL names: its path without the host and
    without ".git", such as "owner/repo". None for a remote that is a folder
    on this machine, which names no owner."""
    url = url.strip()
    if "://" in url:
        scheme, rest = url.split("://", 1)
        if scheme == "file":
            return None
        path = rest.partition("/")[2]
    else:
        match = _SCP_LIKE.match(url)
        if match is None:
            return None
        path = match.group(1)
    path = path.strip("/").removesuffix(".git").strip("/")
    return path[:256] or None


def session_project(cwd: str) -> tuple[str | None, str | None]:
    """The project and root of a session started in `cwd` (see the module
    description). Both are None when git did not answer, so that the caller
    does not record a repository as a plain folder."""
    try:
        common = _common_dir(cwd)
        if common is None:
            return None, os.path.normpath(cwd)[:4096]
        remote = _git(cwd, "remote", "get-url", "origin")
    except GitNotRunError:
        return None, None
    # A bare repository, such as "project.git", is its own root.
    root = os.path.dirname(common) if os.path.basename(common) == ".git" else common
    return None if remote is None else project_from_remote(remote), root[:4096]


def is_path_pattern(pattern: str) -> bool:
    """Whether the pattern is compared with a session's root, not its project."""
    return pattern.startswith(("/", "~"))


def _glob(text: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(text.casefold(), pattern.casefold())


def pattern_matches(pattern: str, session: SessionRecord) -> bool:
    """Whether `pattern` matches the session (see the module description)."""
    if is_path_pattern(pattern):
        # A session registered by an older squawk has no root yet.
        folder = os.path.normpath(session.root or session.cwd)
        wanted = os.path.normpath(os.path.expanduser(pattern))
        return _glob(folder, wanted) or _glob(folder, wanted.rstrip("/") + "/*")
    names = [session.base_label if session.repo is None else session.repo]
    if session.project is not None:
        parts = session.project.split("/")
        names += ["/".join(parts[:n]) for n in range(1, len(parts) + 1)]
    return any(_glob(name, pattern) for name in names)


def is_visible(session: SessionRecord, allow: Sequence[str], deny: Sequence[str]) -> bool:
    """Whether paired contacts may see and address the session: it matches an
    allow pattern and no deny pattern."""
    if any(pattern_matches(p, session) for p in deny):
        return False
    return any(pattern_matches(p, session) for p in allow)
