"""Shared lockfile types, format detection and dispatch."""

from __future__ import annotations

import re
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

Format = Literal["uv.lock", "poetry.lock", "pylock.toml", "requirements.txt"]


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

    ``source`` is "pypi" for packages Garnet can check, "unpinned" for a
    requirements line without ``==`` (GRN-E004), and "unsupported" for git,
    path, URL or private-index sources (GRN-E005), with ``detail`` saying why.
    """

    package: str  # PEP 503 normalized
    version: str | None
    line: int
    source: Literal["pypi", "unpinned", "unsupported"] = "pypi"
    detail: str | None = None
    # The entry applies only under an environment marker (a requirements
    # line with "; marker", uv's resolution-markers, pylock's marker).
    marker: bool = False


_REQ_NAME = re.compile(r"requirements[^/\\]*\.(txt|in)$", re.IGNORECASE)
_PYLOCK_NAME = re.compile(r"^pylock(\.[^./\\]+)?\.toml$", re.IGNORECASE)


def normalize(name: str) -> str:
    """PEP 503 name normalization (``Foo_Bar`` becomes ``foo-bar``)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def detect(name: str, data: bytes) -> Format:
    """The lockfile's format, from its file name, else from its first bytes."""
    base = PurePath(name).name
    if base == "uv.lock":
        return "uv.lock"
    if base == "poetry.lock":
        return "poetry.lock"
    if _PYLOCK_NAME.match(base):
        return "pylock.toml"
    if _REQ_NAME.search(base) or base.endswith(".txt"):
        return "requirements.txt"
    head = data[:4096]
    if b"lock-version" in head and b"[[packages]]" in data:
        return "pylock.toml"
    if b"[[package]]" in head and b"source = {" in data:
        return "uv.lock"
    if b"[[package]]" in head:
        return "poetry.lock"
    raise LockfileError(f"unsupported lockfile: {base}")


def parse(name: str, data: bytes, *, format: Format | None = None) -> list[Pin]:
    """Every package entry in a lockfile. Raises ``LockfileError``."""
    from . import pylock, requirements, toml_locks

    fmt = format or detect(name, data)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as err:
        raise LockfileError(f"{name} is not UTF-8") from err
    if fmt == "uv.lock":
        return toml_locks.parse_uv(text)
    if fmt == "poetry.lock":
        return toml_locks.parse_poetry(text)
    if fmt == "pylock.toml":
        return pylock.parse(text)
    return requirements.parse(text)
