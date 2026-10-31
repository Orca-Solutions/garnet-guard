"""yarn.lock from Yarn 1 (``# yarn lockfile v1``).

Yarn 2 and later (Berry) write a YAML lockfile that starts with ``__metadata:``.
Reading it needs a YAML parser, so it is refused here, and
``workspace.discover`` leaves it out.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .base import LockfileError, Pin
from .npm import (
    INVALID_NAME,
    alias_target,
    is_semver,
    looks_like_git,
    source_problem,
    split_spec,
    valid_name,
)

V1_HEADER = "# yarn lockfile v1"
BERRY = (
    "a Yarn 2 or later (Berry) lockfile, which Garnet doesn't read yet; it reads Yarn 1 lockfiles"
)

_BERRY_LINE = re.compile(rb"^__metadata:", re.MULTILINE)
_STRING = r'"[^"\\]*(?:\\.[^"\\]*)*"'
# One pattern of an entry's key, with the comma or end that follows it.
_PATTERN = re.compile(rf"\s*({_STRING}|[^\s\",]+)\s*(,|$)")
_FIELD = re.compile(rf"({_STRING}|[^\s\":]+)(?:\s+({_STRING}|\S+)|:)")


def is_berry(head: bytes) -> bool:
    """True if these first bytes of a yarn.lock are a Berry lockfile's."""
    return V1_HEADER.encode() not in head and bool(_BERRY_LINE.search(head))


@dataclass
class _Entry:
    line: int
    patterns: list[str]
    fields: dict[str, tuple[str, int]] = field(default_factory=dict)


def _unquote(token: str, line: int) -> str:
    if not token.startswith('"'):
        return token
    try:
        value = json.loads(token)
    except ValueError as err:
        raise LockfileError(f"line {line}: a quoted string Garnet can't read") from err
    if not isinstance(value, str):
        raise LockfileError(f"line {line}: a quoted string Garnet can't read")
    return value


def _patterns(key: str, line: int) -> list[str]:
    """The ``name@range`` patterns of an entry's key line (without its colon)."""
    out: list[str] = []
    pos = 0
    while pos < len(key):
        m = _PATTERN.match(key, pos)
        if m is None or m.end() == pos:
            raise LockfileError(f"line {line}: an entry key Garnet can't read")
        out.append(_unquote(m[1], line))
        pos = m.end()
        if m[2] == "" and pos < len(key):
            raise LockfileError(f"line {line}: an entry key Garnet can't read")
    if not out:
        raise LockfileError(f"line {line}: an entry with no name")
    return out


def _entries(text: str) -> list[_Entry]:
    entries: list[_Entry] = []
    seen: set[str] = set()
    current: _Entry | None = None
    for no, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw[0].isspace():
            if not raw.rstrip().endswith(":"):
                raise LockfileError(f"line {no}: expected an entry such as 'name@range:'")
            current = _Entry(no, _patterns(raw.rstrip()[:-1], no))
            for p in current.patterns:
                if p in seen:
                    raise LockfileError(f"line {no}: a dependency listed in two entries")
                seen.add(p)
            entries.append(current)
            continue
        if current is None:
            raise LockfileError(f"line {no}: an indented line before the first entry")
        if raw.startswith("    "):
            continue  # inside dependencies or optionalDependencies
        if not raw.startswith("  ") or raw[2].isspace():
            raise LockfileError(f"line {no}: indentation Garnet can't read")
        m = _FIELD.fullmatch(stripped)
        if m is None:
            raise LockfileError(f"line {no}: a field Garnet can't read")
        if m[2] is None:
            continue  # the start of a nested table such as dependencies:
        key = _unquote(m[1], no)
        if key in current.fields:
            what = key if key in ("version", "resolved", "integrity") else "a field"
            raise LockfileError(f"line {no}: the entry repeats {what}")
        current.fields[key] = (_unquote(m[2], no), no)
    return entries


def _pin(entry: _Entry) -> Pin | None:
    """The pin for one entry, or None for a ``link:`` to a folder of the project."""
    names: set[str] = set()
    reals: set[str] = set()
    ranges: list[str] = []
    for pattern in entry.patterns:
        name, spec_range = split_spec(pattern)
        target = alias_target(spec_range)
        names.add(name)
        reals.add(target[0] if target else name)
        ranges.append(target[1] if target else spec_range)
    version, version_line = entry.fields.get("version", (None, entry.line))
    resolved = entry.fields.get("resolved", (None, 0))[0]
    origin = resolved or ",".join(entry.patterns)
    line = version_line
    if any(r.startswith("link:") for r in ranges):
        return None
    if not all(valid_name(n) for n in names | reals):
        shown = version if version and is_semver(version) else None
        return Pin(
            INVALID_NAME, shown, line, "unsupported", "not a valid npm package name", "npm", origin
        )
    if len(reals) != 1:
        name = sorted(reals)[0]
        return Pin(
            name, version, line, "unsupported", "entry names more than one package", "npm", origin
        )
    (real,) = reals
    if any(r.startswith("file:") for r in ranges):
        return Pin(real, version, line, "unsupported", "file: source", "npm", origin)
    if version is None:
        return Pin(real, None, line, "unsupported", "no version", "npm", origin)
    if resolved is None:
        return Pin(real, version, line, "unsupported", "no resolved URL", "npm", origin)
    why = source_problem(resolved, real, version)
    if why is None:
        return Pin(real, version, line, ecosystem="npm")
    if any(looks_like_git(r) for r in ranges):
        why = "git source"
    return Pin(real, version, line, "unsupported", why, "npm", origin)


def parse(text: str) -> list[Pin]:
    """Pins from a Yarn 1 yarn.lock, one per entry, at its ``version`` line.

    An alias (``alias@npm:real@range``) is the package it installs. Every
    entry counts, dev and optional dependencies too; yarn doesn't list
    workspace members, and ``link:`` entries are skipped.
    """
    text = text.removeprefix("﻿")
    head = text[:65536].encode()
    if is_berry(head):
        raise LockfileError(f"this is {BERRY}")
    leading = []
    for raw in text.splitlines():
        if raw.strip() and not raw.startswith("#"):
            break
        leading.append(raw.strip())
    if V1_HEADER not in leading:
        raise LockfileError(f"no '{V1_HEADER}' header, so it isn't a Yarn 1 lockfile")
    return [p for e in _entries(text) if (p := _pin(e)) is not None]
