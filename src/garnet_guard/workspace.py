"""Find lockfiles, read base versions from git, and turn them into changes.

Runs ``git show`` on the user's own repository to read a base lockfile. It
never runs anything from a package.
"""

from __future__ import annotations

import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .lockfiles import LockfileError, Pin, diff_pins, parse
from .lockfiles.base import MAX_LOCKFILE_BYTES
from .lockfiles.diff import new_unchecked
from .lockfiles.yarn import is_berry
from .models import Change

_DIRECT = ("uv.lock", "poetry.lock", "pylock.toml")
# Only the npm formats Garnet parses. pnpm-lock.yaml, and a yarn.lock from
# Yarn 2 or later, need a YAML parser, so they aren't picked up yet.
_NPM = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock")


@dataclass(frozen=True)
class Unchecked:
    """A lockfile entry Garnet can't check, reported instead of skipped."""

    change: Change
    rule_id: str  # GRN-E004 or GRN-E005
    detail: str


def _present(path: Path) -> bool:
    # Symlinks are listed too, so the caller refuses them instead of skipping.
    return path.is_file() or path.is_symlink()


def _yarn_berry(path: Path, root: Path) -> bool:
    """True for a regular yarn.lock written by Yarn 2 or later."""
    if not plain_file(path, root):
        return False  # listed, so the caller refuses it
    try:
        with path.open("rb") as fh:
            return is_berry(fh.read(65536))
    except OSError:
        return False


def discover(root: Path) -> list[Path]:
    """Lockfiles in ``root`` (and ``requirements/``), in a stable order:
    Python's, then npm's.

    Symlinked entries are returned, not followed; check them with
    :func:`plain_file` before reading.
    """
    found: list[Path] = []
    for name in _DIRECT:
        if _present(root / name):
            found.append(root / name)
    found += sorted(p for p in root.glob("pylock.*.toml") if _present(p))
    found += sorted(p for p in root.glob("requirements*.txt") if _present(p))
    req_dir = root / "requirements"
    if req_dir.is_dir():
        found += sorted(p for p in req_dir.glob("*.txt") if _present(p))
    for name in _NPM:
        path = root / name
        if _present(path) and not (name == "yarn.lock" and _yarn_berry(path, root)):
            found.append(path)
    return found


def plain_file(path: Path, root: Path) -> bool:
    """True if ``path`` is a regular file reached without following a symlink.

    A pull request can replace a lockfile, or the ``requirements/`` folder,
    with a symlink to a file on the CI runner; reading it would put that
    file's contents in a public report. Every component below ``root`` is
    checked, and the file itself always is.
    """
    full = path if path.is_absolute() else root / path
    try:
        parts = full.relative_to(root).parts
    except ValueError:
        parts = ()
    current = root
    for part in parts[:-1]:
        current = current / part
        if current.is_symlink():
            return False
    try:
        mode = full.lstat().st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode)


def read_lockfile(path: Path) -> bytes:
    """A lockfile's bytes, refusing one too large to be real before reading it."""
    if path.stat().st_size > MAX_LOCKFILE_BYTES:
        raise LockfileError(f"{path.name} is larger than 64 MiB, the most Garnet reads")
    return path.read_bytes()


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
    cmd = ["git", *args]
    return subprocess.run(cmd, cwd=cwd, capture_output=True, check=False)  # noqa: S603


def git_show(ref: str, path: Path, *, cwd: Path) -> bytes | None:
    """The file's content at ``ref``, or None if it didn't exist there."""
    if ref.startswith("-"):
        raise LockfileError(f"invalid git ref: {ref!r}")
    top = _git(["rev-parse", "--show-toplevel"], cwd)
    if top.returncode != 0:
        raise LockfileError("--git-base needs a git repository")
    root = Path(top.stdout.decode().strip()).resolve()
    rel = path.resolve().relative_to(root).as_posix()
    shown = _git(["show", f"{ref}:{rel}"], cwd)
    if shown.returncode == 0:
        return shown.stdout
    if _git(["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], cwd).returncode != 0:
        raise LockfileError(f"unknown git ref: {ref!r}")
    return None  # the lockfile is new in head


def changes_for(
    head_name: str, head: bytes, base: bytes | None
) -> tuple[list[Change], list[Unchecked]]:
    """The changes to check in one lockfile, and the new entries Garnet can't check.

    ``base`` is None when the lockfile is new, so every entry is a change.
    Each change carries its pin's ecosystem.
    """
    head_pins = parse(head_name, head)
    base_pins: list[Pin] = []
    if base is not None:
        try:
            base_pins = parse(head_name, base)
        except LockfileError as err:
            raise LockfileError(f"{err} (in the base version)") from err
    changes = [
        Change(c.ecosystem, c.package, c.baseline, c.candidate, lockfile=head_name, line=c.line)
        for c in diff_pins(base_pins, head_pins)
    ]
    unchecked = []
    for p in new_unchecked(base_pins, head_pins):
        rule = "GRN-E004" if p.source == "unpinned" else "GRN-E005"
        what = (
            f"not pinned with == ({p.detail})"
            if p.source == "unpinned" and p.detail
            else "not pinned with =="
            if p.source == "unpinned"
            else p.detail or "unsupported source"
        )
        change = Change(
            p.ecosystem,
            p.package,
            None,
            p.version or ("unpinned" if p.source == "unpinned" else "unchecked"),
            lockfile=head_name,
            line=p.line,
        )
        unchecked.append(Unchecked(change, rule, what))
    return changes, unchecked


def dedupe(changes: list[Change]) -> list[Change]:
    """One change per (ecosystem, package, baseline, candidate), keeping the first lockfile."""
    seen: dict[tuple[str, str, str | None, str], Change] = {}
    for c in changes:
        seen.setdefault((c.ecosystem, c.package, c.baseline, c.candidate), c)
    return list(seen.values())
