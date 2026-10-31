"""Shared lockfile types, format detection and dispatch."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePath
from typing import Literal

PYPI_INDEXES = frozenset(
    {
        "https://pypi.org/simple",
        "https://pypi.org/simple/",
        "https://pypi.python.org/simple",
        "https://pypi.python.org/simple/",
    }
)
PYPI_FILE_HOST = "https://files.pythonhosted.org/"

Format = Literal[
    "uv.lock", "poetry.lock", "pylock.toml", "requirements.txt", "package-lock.json", "yarn.lock"
]

# The most Garnet reads from one lockfile. Real ones are a few MB; the largest
# monorepo package-lock.json files are tens of MB.
MAX_LOCKFILE_BYTES = 64 * 1024 * 1024


class LockfileError(Exception):
    """The lockfile can't be read or its format isn't supported."""


_TOML_POSITION = re.compile(r"\(at line (\d+), column (\d+)\)")


def toml_error(err: ValueError) -> LockfileError:
    """A TOML error that names only the position.

    tomllib messages can quote keys from the file, and the report may be
    posted publicly, so the file's own text is left out.
    """
    m = _TOML_POSITION.search(str(err))
    where = f" at line {m[1]}, column {m[2]}" if m else ""
    return LockfileError(f"invalid TOML{where}")


@dataclass(frozen=True)
class Pin:
    """One package entry in a lockfile.

    ``source`` is "registry" for a release on the ecosystem's public registry,
    which Garnet can check; "unpinned" for a requirements line without ``==``
    (GRN-E004); and "unsupported" for git, path, URL, private-index or bundled
    sources (GRN-E005), with ``detail`` saying why. ``origin`` records where
    an unsupported entry installs from, so a git dependency that moves to a
    new commit counts as changed; it is compared, never shown.
    """

    package: str  # PEP 503 normalized on PyPI; as written on npm
    version: str | None
    line: int
    source: Literal["registry", "unpinned", "unsupported"] = "registry"
    detail: str | None = None
    ecosystem: str = "pypi"
    origin: str | None = None


_REQ_NAME = re.compile(r"requirements[^/\\]*\.(txt|in)$", re.IGNORECASE)
_PYLOCK_NAME = re.compile(r"^pylock(\.[^./\\]+)?\.toml$", re.IGNORECASE)


def normalize(name: str) -> str:
    """PEP 503 name normalization (``Foo_Bar`` becomes ``foo-bar``)."""
    return re.sub(r"[-_.]+", "-", name).lower()


_PNPM = "which Garnet doesn't read yet; pnpm support is planned"


def detect(name: str, data: bytes) -> Format:
    """The lockfile's format, from its file name, else from its first bytes.

    pnpm-lock.yaml is recognized and refused, as is a Yarn 2+ yarn.lock when
    it is read: both need a YAML parser.
    """
    from .yarn import BERRY, V1_HEADER, is_berry

    base = PurePath(name).name
    if base == "uv.lock":
        return "uv.lock"
    if base == "poetry.lock":
        return "poetry.lock"
    if _PYLOCK_NAME.match(base):
        return "pylock.toml"
    if _REQ_NAME.search(base) or base.endswith(".txt"):
        return "requirements.txt"
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        return "package-lock.json"
    if base == "yarn.lock":
        return "yarn.lock"
    if base == "pnpm-lock.yaml":
        raise LockfileError(f"{base} is a pnpm lockfile, {_PNPM}")
    head = data[:4096]
    if b"lock-version" in head and b"[[packages]]" in data:
        return "pylock.toml"
    if b"[[package]]" in head and b"source = {" in data:
        return "uv.lock"
    if b"[[package]]" in head:
        return "poetry.lock"
    if head.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"{") and b'"lockfileVersion"' in head:
        return "package-lock.json"
    if V1_HEADER.encode() in head:
        return "yarn.lock"
    if is_berry(head):
        raise LockfileError(f"{base} is {BERRY}")
    if re.match(rb"lockfileVersion: ", head):
        raise LockfileError(f"{base} looks like a pnpm lockfile, {_PNPM}")
    raise LockfileError(f"unsupported lockfile: {base}")


def parse(name: str, data: bytes, *, format: Format | None = None) -> list[Pin]:
    """Every package entry in a lockfile. Raises ``LockfileError``."""
    from . import package_lock, pylock, requirements, toml_locks, yarn

    if len(data) > MAX_LOCKFILE_BYTES:
        raise LockfileError(f"{name} is larger than 64 MiB, the most Garnet reads")
    fmt = format or detect(name, data)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as err:
        raise LockfileError(f"{name} is not UTF-8") from err
    parsers: dict[Format, Callable[[str], list[Pin]]] = {
        "uv.lock": toml_locks.parse_uv,
        "poetry.lock": toml_locks.parse_poetry,
        "pylock.toml": pylock.parse,
        "requirements.txt": requirements.parse,
        "package-lock.json": package_lock.parse,
        "yarn.lock": yarn.parse,
    }
    try:
        return parsers[fmt](text)
    except LockfileError as err:
        raise LockfileError(f"{name}: {err}") from err
