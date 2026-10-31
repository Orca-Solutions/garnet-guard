"""Shared lockfile types, format detection and dispatch."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePath
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from .registries import Registries
    from .requirements import Included

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
    "uv.lock",
    "poetry.lock",
    "pylock.toml",
    "requirements.txt",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
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


def detect(name: str, data: bytes) -> Format:
    """The lockfile's format, from its file name, else from its first bytes.

    "yarn.lock" covers Yarn 1 and Yarn 2+ (Berry); ``yarn.parse`` tells
    them apart.
    """
    from .yarn import V1_HEADER, is_berry

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
        return "pnpm-lock.yaml"
    head = data[:4096]
    if b"lock-version" in head and b"[[packages]]" in data:
        return "pylock.toml"
    if b"[[package]]" in head and b"source = {" in data:
        return "uv.lock"
    if b"[[package]]" in head:
        return "poetry.lock"
    if head.lstrip(b"\xef\xbb\xbf \t\r\n").startswith(b"{") and b'"lockfileVersion"' in head:
        return "package-lock.json"
    if V1_HEADER.encode() in head or is_berry(head):
        return "yarn.lock"
    if re.match(rb"(?:\xef\xbb\xbf)?lockfileVersion: ", head):
        return "pnpm-lock.yaml"
    raise LockfileError(f"unsupported lockfile: {base}")


def parse(
    name: str,
    data: bytes,
    *,
    format: Format | None = None,
    registries: Registries | None = None,
    included: Included | None = None,
) -> list[Pin]:
    """Every package entry in a lockfile. Raises ``LockfileError``.

    ``registries`` is what the repository's .npmrc and pnpm-workspace.yaml
    (for pnpm-lock.yaml) or .yarnrc.yml (for a Yarn 2+ yarn.lock) say about
    registries; the other formats record the registry in the lockfile.
    ``included`` is what the files a requirements file is read with say
    about its index (``workspace.requirement_includes``).
    """
    from . import package_lock, pnpm, pylock, requirements, toml_locks, yarn
    from .registries import NONE

    if len(data) > MAX_LOCKFILE_BYTES:
        raise LockfileError(f"{name} is larger than 64 MiB, the most Garnet reads")
    fmt = format or detect(name, data)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as err:
        raise LockfileError(f"{name} is not UTF-8") from err
    settings = registries or NONE
    parsers: dict[Format, Callable[[str], list[Pin]]] = {
        "uv.lock": toml_locks.parse_uv,
        "poetry.lock": toml_locks.parse_poetry,
        "pylock.toml": pylock.parse,
        "requirements.txt": lambda t: requirements.parse(t, included),
        "package-lock.json": package_lock.parse,
        "pnpm-lock.yaml": lambda t: pnpm.parse(t, settings),
        "yarn.lock": lambda t: yarn.parse(t, settings),
    }
    try:
        return parsers[fmt](text)
    except LockfileError as err:
        raise LockfileError(f"{name}: {err}") from err
