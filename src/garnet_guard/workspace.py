"""Find lockfiles, read base versions from git, and turn them into changes.

Runs ``git show`` on the user's own repository to read a base lockfile. It
never runs anything from a package.
"""

from __future__ import annotations

import os
import posixpath
import re
import stat
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from .lockfiles import LockfileError, Pin, detect, diff_pins, parse
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
from .lockfiles.requirements import Included, describe, file_options
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


# --- Requirements files brought in with -r and -c --------------------------

# pip reads a -r or -c file as part of the file that names it, and applies
# its index options to every requirement it reads. Garnet follows them as far
# as this, inside the directory it checks, and never through a symlink.
MAX_INCLUDE_DEPTH = 10
MAX_INCLUDES = 100  # include lines in one tree
MAX_INCLUDE_BYTES = MAX_LOCKFILE_BYTES  # read across one tree
_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


class IncludeRefused(Exception):
    """An include Garnet won't read; the message says why, without its content."""


# A root-relative POSIX path to the file's bytes, None when it doesn't exist.
IncludeReader = Callable[[str], bytes | None]


def disk_reader(root: Path) -> IncludeReader:
    """Read includes from the working tree, refusing symlinks as
    :func:`plain_file` does."""
    root = root.absolute()

    def read(rel: str) -> bytes | None:
        path = root / rel
        if not (path.exists() or path.is_symlink()):
            return None
        if not plain_file(path, root):
            raise IncludeRefused("it is a symlink or not a regular file")
        if path.stat().st_size > MAX_LOCKFILE_BYTES:
            raise IncludeRefused("it is larger than 64 MiB")
        return path.read_bytes()

    return read


def git_reader(ref: str, root: Path) -> IncludeReader:
    """Read includes as they were at ``ref``, refusing a symlink or anything
    that isn't a regular file there."""
    if ref.startswith("-"):
        raise LockfileError(f"invalid git ref: {ref!r}")
    top = _git(["rev-parse", "--show-toplevel"], root)
    if top.returncode != 0:
        raise LockfileError("--git-base needs a git repository")
    prefix = root.resolve().relative_to(Path(top.stdout.decode().strip()).resolve()).as_posix()

    def read(rel: str) -> bytes | None:
        path = rel if prefix == "." else f"{prefix}/{rel}"
        listed = _git(["ls-tree", "-z", "--full-tree", ref, "--", path], root)
        if listed.returncode != 0:
            raise IncludeRefused("git can't read it")
        entry = listed.stdout.split(b"\0", 1)[0]
        if not entry:
            return None
        meta, _, _ = entry.partition(b"\t")
        mode, kind, sha = meta.split(b" ")
        if kind != b"blob" or mode not in (b"100644", b"100755"):
            raise IncludeRefused("it is a symlink or not a regular file")
        size = _git(["cat-file", "-s", sha.decode()], root)
        if size.returncode != 0 or int(size.stdout or b"0") > MAX_LOCKFILE_BYTES:
            raise IncludeRefused("git can't read it, or it is larger than 64 MiB")
        return _git(["cat-file", "blob", sha.decode()], root).stdout

    return read


def _resolve(including: str, value: str) -> tuple[str | None, str | None]:
    """(root-relative path, None) for an include, as pip resolves it beside
    the file that names it, or (None, why Garnet doesn't follow it).

    A ``..`` part is never followed: ``link/../x.txt`` through a symlinked
    folder names a file outside it, and folding the path first would hide
    that from the symlink check."""
    if "${" in value:
        return None, "it uses an environment variable"
    if _URL.match(value):
        return None, "it is a URL"
    if not value or posixpath.isabs(value):
        return None, "it is outside the directory Garnet checks"
    if ".." in value.split("/"):
        return None, "its path has a .. part"
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(including), value))
    if ".." in joined.split("/"):
        return None, "it is outside the directory Garnet checks"
    return joined, None


@dataclass(frozen=True)
class _Found:
    where: str  # the file it is in, root-relative
    option: str  # an option in FileOptions.moves, or "-r"/"-c" not followed
    value: str | None  # the option's value (never shown), or why it wasn't followed


class _TooBig(Exception):
    """The include tree is past ``MAX_INCLUDES`` or ``MAX_INCLUDE_BYTES``."""


def _memo(read: IncludeReader) -> Callable[[str], tuple[bytes | None, str | None]]:
    """``read`` asked once per path: (bytes, None), (None, None) when the
    file doesn't exist, or (None, why it was refused)."""
    seen: dict[str, tuple[bytes | None, str | None]] = {}

    def get(rel: str) -> tuple[bytes | None, str | None]:
        if rel not in seen:
            try:
                seen[rel] = (read(rel), None)
            except IncludeRefused as err:
                seen[rel] = (None, str(err))
        return seen[rel]

    return get


def _tree(
    top: str, data: bytes, get: Callable[[str], tuple[bytes | None, str | None]]
) -> tuple[list[_Found], set[str]]:
    """Everything in ``top``'s include tree that can move pins off PyPI, in
    the order pip reads it, and the files in the tree. Past
    ``MAX_INCLUDES`` include lines or ``MAX_INCLUDE_BYTES`` read, the walk
    stops, and that is a reason too."""
    found: list[_Found] = []
    members = {top}
    count = size = 0

    def visit(rel: str, text: str, stack: tuple[str, ...]) -> None:
        nonlocal count, size
        opts = file_options(text)
        found.extend(_Found(rel, o, v) for o, v in opts.moves)
        for short, value in opts.includes:
            count += 1
            if count > MAX_INCLUDES:
                found.append(_Found(rel, short, f"the files include more than {MAX_INCLUDES}"))
                raise _TooBig
            target, problem = _resolve(rel, value)
            body: bytes | None = None
            if target is not None and target in stack:
                problem = "the files include each other"
            elif target is not None and len(stack) > MAX_INCLUDE_DEPTH:
                problem = f"it is more than {MAX_INCLUDE_DEPTH} includes deep"
            elif target is not None and target in members:
                continue  # read already through another include
            elif target is not None:
                body, problem = get(target)
                if body is None and problem is None:
                    problem = "it doesn't exist"
            if target is None or body is None:
                found.append(_Found(rel, short, problem))
                continue
            size += len(body)
            if size > MAX_INCLUDE_BYTES:
                found.append(_Found(rel, short, "the files it brings in are larger than 64 MiB"))
                raise _TooBig
            try:
                inner = body.decode("utf-8")
            except UnicodeDecodeError:
                found.append(_Found(rel, short, "it isn't UTF-8"))
                continue
            members.add(target)
            visit(target, inner, (*stack, target))

    try:
        visit(top, data.decode("utf-8", "replace"), (top,))
    except _TooBig:
        pass
    return found, members


def _where(f: _Found, top: str, me: str) -> str:
    if f.where == me:
        return "this file"
    if top == me:
        return f"{f.where}, which this file brings in"
    if f.where == top:
        return f"{top}, which brings in this file"
    return f"{f.where}, which {top} brings in"


def requirement_includes(files: Mapping[str, bytes], read: IncludeReader) -> dict[str, Included]:
    """For each requirements file (root-relative POSIX path to its bytes;
    other formats are left out), what the files pip reads with it say about
    its index: its own -r and -c files, followed through ``read``, and every
    other file in ``files`` whose include tree holds it, since pip applies a
    tree's index options to all of it. An include that can't be followed (a
    URL, a ``..`` part, outside the root, missing, a symlink, a cycle, more
    than ``MAX_INCLUDE_DEPTH`` deep, a tree past ``MAX_INCLUDES`` or
    ``MAX_INCLUDE_BYTES``) is a reason too. Each path is read once.
    """
    reqs = {}
    for rel, data in files.items():
        try:
            if detect(rel, data) == "requirements.txt":
                reqs[posixpath.normpath(rel)] = data
        except LockfileError:
            continue
    get = _memo(read)
    trees = {rel: _tree(rel, data, get) for rel, data in sorted(reqs.items())}
    out: dict[str, Included] = {}
    for me in sorted(reqs):
        tops = [me] + [t for t in sorted(reqs) if t != me and me in trees[t][1]]
        notes: list[tuple[str, str]] = []
        for top in tops:
            for f in trees[top][0]:
                if f.where == me and f.option not in ("-r", "-c"):
                    continue  # the file's own options; parse reads those
                if f.option in ("-r", "-c"):
                    where = _where(f, top, me)
                    comma = "" if where == "this file" else ","
                    why = (
                        f"{f.option} in {where}{comma} brings in a file Garnet can't "
                        f"follow ({f.value}), which can set another index"
                    )
                else:
                    why = describe(f.option, f.value, _where(f, top, me))
                notes.append((why, f"{f.where} {f.option} {f.value or ''}"))
        out[me] = Included(
            notes[0][0] if notes else None, tuple(dict.fromkeys(o for _, o in notes))
        )
    return out


def changes_for(
    head_name: str,
    head: bytes,
    base: bytes | None,
    *,
    registries: Registries | None = None,
    included: Included | None = None,
    base_included: Included | None = None,
) -> tuple[list[Change], list[Unchecked]]:
    """The changes to check in one lockfile, and the new entries Garnet can't check.

    ``base`` is None when the lockfile is new, so every entry is a change.
    Each change carries its pin's ecosystem. ``registries`` (from
    :func:`registry_settings`) applies to both versions; ``included`` and
    ``base_included`` (from :func:`requirement_includes`) to a requirements
    file's head and base.
    """
    head_pins = parse(head_name, head, registries=registries, included=included)
    base_pins: list[Pin] = []
    if base is not None:
        try:
            base_pins = parse(head_name, base, registries=registries, included=base_included)
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
