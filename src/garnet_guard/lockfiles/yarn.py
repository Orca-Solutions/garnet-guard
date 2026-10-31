"""yarn.lock from Yarn 1 (``# yarn lockfile v1``).

Yarn 2 and later (Berry) write a YAML lockfile that starts with
``__metadata:``; :func:`parse` hands one to ``berry.parse``. Only the shape
Yarn 1 ignores counts as Berry (:func:`is_berry`), so a file Yarn 1 would
install from is always read as Yarn 1's.

The file is read with a port of Yarn 1's own tokenizer and parser
(``src/lockfile/parse.js`` in yarn 1.22), so Garnet sees the entries yarn
sees. Yarn reads a file its parser rejects as YAML instead, ignores the rest
of a file after a line indented deeper than it expects, and merges the two
sides of a merge conflict; Garnet refuses all three.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import NamedTuple

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
from .registries import NONE, Registries

V1_HEADER = "# yarn lockfile v1"

_BERRY_VERSION = re.compile(rb"  version: \S")


def is_berry(head: bytes) -> bool:
    """True if these first bytes of a yarn.lock are a Berry lockfile's.

    That is a file with no Yarn 1 header whose first entry is ``__metadata:``
    with a ``version`` under it, the only shape Yarn 1 ignores. A
    ``__metadata`` entry with nothing under it, or one further down, doesn't
    count: Yarn 1 may still install from such a file.
    """
    if V1_HEADER.encode() in head:
        return False
    lines = head.removeprefix(b"\xef\xbb\xbf").split(b"\n")
    for i, raw in enumerate(lines):
        stripped = raw.strip()
        if not stripped or stripped.startswith(b"#"):
            continue
        following = lines[i + 1] if i + 1 < len(lines) else b""
        return raw.rstrip(b"\r") == b"__metadata:" and bool(_BERRY_VERSION.match(following))
    return False


# --- Yarn 1's tokenizer and parser --------------------------------------------------

_NEWLINE, _COMMENT, _INDENT, _STRING, _NUMBER, _BOOLEAN = "nl", "#", "indent", "str", "num", "bool"
_COLON, _COMMA, _INVALID, _EOF = ":", ",", "invalid", "eof"
_VALUES = (_STRING, _NUMBER, _BOOLEAN)

_SPACES = re.compile(" +")
_DIGITS = re.compile("[0-9]+")
_WORD_START = re.compile("[a-zA-Z/.-]")
_WORD = re.compile("[^: \n\r,]*")  # an unquoted string runs to one of these
_LOCKFILE_VERSION = re.compile("yarn lockfile v([0-9]+)")
_CONFLICT = ("<<<<<<<", "=======", ">>>>>>>")
_MAX_DEPTH = 8  # yarn writes three levels: entries, their fields, dependency tables


class _Number:
    """A number token. Garnet never needs its value, so it isn't converted."""


class _Token(NamedTuple):
    kind: str
    value: object
    line: int
    why: str = ""  # for an invalid token, what Garnet can't read


@dataclass
class _Table:
    """A parsed level: each item's keys, value and line, in file order."""

    items: list[tuple[list[str], object, int]] = field(default_factory=list)


def _tokens(text: str) -> Iterator[_Token]:
    """Yarn 1's ``tokenise``, with real line numbers (yarn counts ``\\n\\n`` as one)."""
    pos, end, line = 0, len(text), 1
    last_newline = False
    while pos < end:
        c = text[pos]
        if c in "\n\r":
            # yarn takes a second character only when it is \n, after \r or \n alike.
            chop = 2 if text.startswith("\n", pos + 1) else 1
            yield _Token(_NEWLINE, None, line)
            line += text.count("\n", pos, pos + chop)
        elif c == "#":
            stop = text.find("\n", pos + 1)
            stop = end if stop < 0 else stop
            yield _Token(_COMMENT, text[pos + 1 : stop], line)
            chop = stop - pos
        elif c == " ":
            chop = 1
            if last_newline:
                spaces = _SPACES.match(text, pos)
                chop = (spaces.end() if spaces else pos + 1) - pos
                if chop % 2:
                    raise LockfileError(f"line {line}: indentation Garnet can't read")
                yield _Token(_INDENT, chop // 2, line)
        elif c == '"':
            stop = pos + 1
            while True:
                stop = text.find('"', stop)
                if stop < 0:
                    stop = end
                    break
                stop += 1
                if not (text[stop - 2] == "\\" and text[stop - 3] != "\\"):
                    break
            chop = stop - pos
            yield _quoted(text[pos:stop], line)
            line += text.count("\n", pos, stop)  # never valid, but counted for what follows
        elif "0" <= c <= "9":
            digits = _DIGITS.match(text, pos)
            chop = (digits.end() if digits else pos + 1) - pos
            yield _Token(_NUMBER, _Number(), line)
        elif text.startswith("true", pos):
            chop = 4
            yield _Token(_BOOLEAN, True, line)
        elif text.startswith("false", pos):
            chop = 5
            yield _Token(_BOOLEAN, False, line)
        elif c == ":":
            chop = 1
            yield _Token(_COLON, None, line)
        elif c == ",":
            chop = 1
            yield _Token(_COMMA, None, line)
        elif _WORD_START.match(c):
            word = _WORD.match(text, pos)
            chop = (word.end() if word else pos + 1) - pos
            yield _Token(_STRING, text[pos : pos + chop], line)
        else:
            chop = 1
            at_start = pos == 0 or last_newline
            why = "indentation" if at_start and c.isspace() else "a character"
            yield _Token(_INVALID, None, line, f"{why} Garnet can't read")
        last_newline = c == "\n" or (c == "\r" and text.startswith("\n", pos + 1))
        pos += chop
    yield _Token(_EOF, None, line)


def _quoted(raw: str, line: int) -> _Token:
    """A quoted string token, read with JSON's rules as yarn does."""
    try:
        value = json.loads(raw)
    except ValueError:
        value = None
    if not isinstance(value, str):
        return _Token(_INVALID, None, line, "a quoted string Garnet can't read")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:  # a lone surrogate from a \u escape
        return _Token(_INVALID, None, line, "a quoted string that isn't valid text")
    return _Token(_STRING, value, line)


class _Parser:
    """Yarn 1's ``Parser``. Where yarn would throw, this raises LockfileError."""

    def __init__(self, text: str) -> None:
        self._tokens = _tokens(text)
        self.token = self.next()

    def next(self) -> _Token:
        for token in self._tokens:
            if token.kind != _COMMENT:
                self.token = token
                return token
            m = _LOCKFILE_VERSION.search(str(token.value))
            if m and m[1].lstrip("0") not in ("", "1"):
                raise LockfileError(f"line {token.line}: a lockfile version Garnet doesn't read")
        raise LockfileError("the lockfile ends unexpectedly")

    def fail(self, indent: int, what: str) -> LockfileError:
        token = self.token
        if token.kind == _INVALID:
            why = token.why
        elif indent:
            why = "a field Garnet can't read"
        elif what == "value":
            why = "expected an entry such as 'name@range:'"
        else:
            why = "an entry key Garnet can't read"
        return LockfileError(f"line {token.line}: {why}")

    def key(self, indent: int) -> str:
        value = self.token.value
        if not (isinstance(value, str) and value):
            raise self.fail(indent, "key")
        return value

    def parse(self, indent: int = 0) -> _Table:
        if indent > _MAX_DEPTH:
            raise LockfileError(f"line {self.token.line}: nested deeper than Garnet reads")
        table = _Table()
        while True:
            token = self.token
            if token.kind == _NEWLINE:
                following = self.next()
                if not indent:
                    continue
                if following.kind != _INDENT or following.value != indent:
                    break  # back up a level
                self.next()
            elif token.kind == _INDENT:
                if token.value != indent:
                    break
                self.next()
            elif token.kind == _EOF:
                break
            elif token.kind == _STRING:
                keys = [self.key(indent)]
                self.next()
                while self.token.kind == _COMMA:
                    self.next()
                    if self.token.kind != _STRING:
                        raise self.fail(indent, "key")
                    keys.append(self.key(indent))
                    self.next()
                was_colon = self.token.kind == _COLON
                if was_colon:
                    self.next()
                if self.token.kind in _VALUES:
                    table.items.append((keys, self.token.value, token.line))
                    self.next()
                elif was_colon:
                    table.items.append((keys, self.parse(indent + 1), token.line))
                    if indent and self.token.kind != _INDENT:
                        break
                else:
                    raise self.fail(indent, "value")
            else:
                raise self.fail(indent, "token")
        return table


# --- Entries ----------------------------------------------------------------------


@dataclass
class _Entry:
    line: int
    patterns: list[str]
    fields: dict[str, tuple[object, int]] = field(default_factory=dict)

    def text(self, name: str) -> tuple[str | None, int]:
        """A field that must be a string, if present, and its line."""
        value, line = self.fields.get(name, (None, self.line))
        if value is None or isinstance(value, str):
            return value, line
        raise LockfileError(f"line {line}: a {name} that isn't a string")


def _entries(text: str) -> list[_Entry]:
    if all(marker in text for marker in _CONFLICT):
        raise LockfileError(
            "it has merge conflict markers, and yarn would merge both sides itself; resolve "
            "the conflict and regenerate the lockfile"
        )
    parser = _Parser(text)
    top = parser.parse()
    if parser.token.kind != _EOF:
        # yarn stops reading here and ignores the rest of the file.
        where = (
            "indentation Garnet can't read"
            if top.items
            else "an indented line before the first entry"
        )
        raise LockfileError(f"line {parser.token.line}: {where}")
    entries: list[_Entry] = []
    seen: set[str] = set()
    for patterns, value, line in top.items:
        if not isinstance(value, _Table):
            raise LockfileError(f"line {line}: expected an entry such as 'name@range:'")
        entry = _Entry(line, patterns)
        for p in patterns:
            if p == "__metadata":
                raise LockfileError(
                    f"line {line}: a __metadata entry, which makes Yarn 1 ignore the lockfile"
                )
            if p in seen:
                raise LockfileError(f"line {line}: a dependency listed in two entries")
            seen.add(p)
        for keys, field_value, field_line in value.items:
            for key in keys:
                if key in entry.fields:
                    what = key if key in ("version", "resolved", "integrity") else "a field"
                    raise LockfileError(f"line {field_line}: the entry repeats {what}")
                entry.fields[key] = (field_value, field_line)
        entries.append(entry)
    return entries


def _pin(entry: _Entry) -> Pin | None:
    """The pin for one entry, or None when every pattern is a ``link:`` to a folder."""
    version, line = entry.text("version")
    resolved, _ = entry.text("resolved")
    integrity, _ = entry.text("integrity")
    names: set[str] = set()
    reals: set[str] = set()
    ranges: list[str] = []
    for pattern in entry.patterns:
        name, spec_range = split_spec(pattern)
        real, real_range = alias_target(spec_range) or (name, spec_range)
        if real_range.startswith("link:"):
            # yarn links that folder, whatever the entry says, and installs
            # the entry's other patterns from its resolved URL.
            continue
        names.add(name)
        reals.add(real)
        ranges.append(real_range)
    if not ranges:
        return None
    origin = " ".join(v for v in (resolved, integrity) if v) or ",".join(entry.patterns)
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


def parse(text: str, registries: Registries = NONE) -> list[Pin]:
    """Pins from a yarn.lock. A Yarn 2+ one goes to ``berry.parse`` with
    ``registries``, what the project's .yarnrc.yml says.

    From Yarn 1, one pin per entry, at its ``version`` line. An alias
    (``alias@npm:real@range``) is the package it installs. Every entry
    counts, dev and optional dependencies too; yarn doesn't list workspace
    members, and an entry whose patterns are all ``link:`` is skipped.
    """
    text = text.removeprefix("﻿")
    head = text[:65536].encode()
    if is_berry(head):
        from . import berry

        return berry.parse(text, registries)
    leading = []
    for raw in text.splitlines():
        if raw.strip() and not raw.startswith("#"):
            break
        leading.append(raw.strip())
    if V1_HEADER not in leading:
        raise LockfileError(f"no '{V1_HEADER}' header, so it isn't a Yarn 1 lockfile")
    return [p for e in _entries(text) if (p := _pin(e)) is not None]
