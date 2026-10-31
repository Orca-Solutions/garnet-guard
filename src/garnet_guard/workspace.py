"""Find lockfiles, read base versions from git, and turn them into changes.

Runs ``git show`` on the user's own repository to read a base lockfile. It
never runs anything from a package.
"""

from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from .lockfiles import LockfileError, Pin, detect, diff_pins, parse, requirements
from .lockfiles.base import MAX_LOCKFILE_BYTES
from .lockfiles.diff import new_unchecked
from .lockfiles.registries import (
    NONE,
    NPMRC,
    PNPM_WORKSPACE,
    YARNRC,
    Registries,
    npmrc,
    pnpm_workspace,
    yarnrc,
)
from .lockfiles.yarn import is_berry_text
from .models import Change

_DIRECT = ("uv.lock", "poetry.lock", "pylock.toml")
_NPM = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
# Registry settings files are a few KB; anything this size isn't one.
MAX_SETTINGS_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Unchecked:
    """A lockfile entry Garnet can't check, reported instead of skipped."""

    change: Change
    rule_id: str  # GRN-E004 or GRN-E005
    detail: str


def _present(path: Path) -> bool:
    # Symlinks are listed too, so the caller refuses them instead of skipping.
    return path.is_file() or path.is_symlink()


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
        if _present(root / name):
            found.append(root / name)
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


def registry_settings(lockfile: Path, data: bytes, root: Path) -> Registries:
    """What the repository says about registries for this lockfile: the
    .npmrc and pnpm-workspace.yaml beside a pnpm-lock.yaml, or the
    .yarnrc.yml beside a Yarn 2+ yarn.lock. Other formats record the
    registry themselves.

    Only the registry keys are read, and nothing from the files is shown. A
    settings file that is a symlink is refused, as a lockfile is.
    """
    try:
        fmt = detect(lockfile.name, data)
    except LockfileError:
        return NONE  # parse reports it
    if fmt == "pnpm-lock.yaml":
        files = [(NPMRC, npmrc), (PNPM_WORKSPACE, pnpm_workspace)]
    elif fmt == "yarn.lock" and _berry(data):
        files = [(YARNRC, yarnrc)]
    else:
        return NONE
    found = []
    for name, read in files:
        settings = _settings_file(lockfile.parent / name, read, lockfile, root)
        if settings is not None:
            found.append(settings)
    if not found:
        return NONE
    first, *rest = found
    return replace(first, also=rest[0]) if rest else first


def _berry(data: bytes) -> bool:
    """True if ``yarn.parse`` reads ``data`` as a Yarn 2+ lockfile."""
    try:
        return is_berry_text(data.decode("utf-8"))
    except UnicodeDecodeError:
        return False  # parse reports it


def _settings_file(
    path: Path, read: Callable[[str], Registries], lockfile: Path, root: Path
) -> Registries | None:
    if not (path.exists() or path.is_symlink()):
        return None
    shown = os.path.relpath(path, root) if path.is_absolute() else path.as_posix()
    if not plain_file(path, root):
        raise LockfileError(
            f"{shown} is not a regular file, so Garnet can't tell which registry "
            f"{lockfile.name} installs from"
        )
    if path.stat().st_size > MAX_SETTINGS_BYTES:
        raise LockfileError(f"{shown} is larger than 1 MiB, the most Garnet reads")
    try:
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as err:
        raise LockfileError(f"{shown} is not UTF-8") from err
    try:
        return read(text)
    except LockfileError as err:
        raise LockfileError(f"{shown}: {err}") from err


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
    head_name: str, head: bytes, base: bytes | None, *, registries: Registries | None = None
) -> tuple[list[Change], list[Unchecked]]:
    """The changes to check in one lockfile, and the new entries Garnet can't check.

    ``base`` is None when the lockfile is new, so every entry is a change.
    Each change carries its pin's ecosystem. ``registries`` (from
    :func:`registry_settings`) applies to both versions.
    """
    head_pins = parse(head_name, head, registries=registries)
    base_pins: list[Pin] = []
    if base is not None:
        try:
            base_pins = parse(head_name, base, registries=registries)
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


PinTable = dict[tuple[str, str], tuple[str, ...]]


# The lockfiles whose pins GRN-C008 reads. npm lockfiles aren't among them:
# a package can sit in the tree several times, aliased or bundled, so a
# young npm dependency's range is read instead.
_PIN_FORMATS = frozenset({"requirements.txt", "uv.lock", "poetry.lock", "pylock.toml"})


def pinned_versions(
    head_name: str, head: bytes, *, registries: Registries | None = None
) -> PinTable:
    """What a lockfile says about the packages GRN-C008 may read for a young
    dependency, by (ecosystem, name).

    For a Python lockfile, the versions it pins from PyPI, read instead of
    the dependency's whole range. A package with an entry under an
    environment marker, or that isn't pinned with ``==``, is left out, so
    the range is read. An npm lockfile's versions aren't used: a package can
    sit in its tree several times, aliased or bundled. A lockfile that
    ``installs_elsewhere`` gives nothing; the change carries that instead.
    """
    try:
        fmt = detect(head_name, head)
        if fmt not in _PIN_FORMATS or installs_elsewhere(head_name, head, registries=registries):
            return {}
        pins = parse(head_name, head, registries=registries)
    except LockfileError:
        return {}  # changes_for reports it
    out: dict[tuple[str, str], set[str]] = {}
    unsure: set[str] = set()
    for p in pins:
        if p.ecosystem == "pypi" and p.source == "registry" and p.version and not p.marker:
            out.setdefault(("pypi", p.package), set()).add(p.version)
        else:
            unsure.add(p.package)
    return {k: tuple(sorted(v)) for k, v in out.items() if k[1] not in unsure}


def installs_elsewhere(
    head_name: str, head: bytes, *, registries: Registries | None = None
) -> str | None:
    """What in a lockfile means a package may install from somewhere other
    than the registry, or None. GRN-C008 then reads nothing for a young
    dependency of a change from that lockfile and keeps its severity.

    In a requirements file, any option line but ``--hash`` and any URL,
    path or editable line (``requirements.unsure_source``). In any lockfile,
    any entry from outside the registry (git, a URL, a path, another index,
    an npm alias whose tarball is another package, a bundled copy): which
    name it installs under, or which dependency it serves, isn't modelled.
    """
    try:
        fmt = detect(head_name, head)
        if fmt == "requirements.txt":
            found = requirements.unsure_source(head.decode("utf-8", "replace"))
            if found is not None:
                return found
        pins = parse(head_name, head, registries=registries)
    except LockfileError:
        return None  # changes_for reports it
    if any(p.source == "unsupported" for p in pins):
        return "an entry from outside the registry"
    return None


def merge_pins(tables: list[PinTable]) -> PinTable:
    """The pins a change can rely on when it comes from several lockfiles: a
    package every one of them pins, with all their versions. A package one
    of them doesn't pin is left out, so GRN-C008 reads its range, unless one
    of them installs it from outside the registry (``()``), which wins."""
    if not tables:
        return {}
    outside = {k for t in tables for k, v in t.items() if not v}
    keys = set(tables[0]).intersection(*tables[1:]) - outside
    merged: PinTable = {k: tuple(sorted({v for t in tables for v in t[k]})) for k in keys}
    merged.update(dict.fromkeys(outside, ()))
    return merged


def dedupe(changes: list[Change]) -> list[Change]:
    """One change per (ecosystem, package, baseline, candidate), keeping the first lockfile."""
    seen: dict[tuple[str, str, str | None, str], Change] = {}
    for c in changes:
        seen.setdefault((c.ecosystem, c.package, c.baseline, c.candidate), c)
    return list(seen.values())
