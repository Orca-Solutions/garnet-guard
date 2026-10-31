"""requirements*.txt: only ``==`` pins are checked (SPEC §3.1)."""

from __future__ import annotations

import re
import shlex

from .base import PYPI_INDEXES, Pin, normalize

_NAME = r"[A-Za-z0-9][A-Za-z0-9._-]*"
_PINNED = re.compile(rf"^({_NAME})\s*(\[[^\]]*\])?\s*===?\s*([^\s;,]+)\s*(;.*)?$")
_NAMED = re.compile(rf"^({_NAME})\s*(\[[^\]]*\])?\s*(.*)$")


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash continuations; strip comments. Returns (first line, text)."""
    out: list[tuple[int, str]] = []
    buf = ""
    start = 0
    for i, raw in enumerate(text.splitlines(), start=1):
        if not buf:
            start = i
        line = re.sub(r"(^|\s)#.*$", "", raw)
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        buf += line
        if buf.strip():
            out.append((start, buf.strip()))
        buf = ""
    if buf.strip():
        out.append((start, buf.strip()))
    return out


# The options pip accepts in a requirements file (``req_file.py``, pip 24.0;
# 26.2's additions are listed too so an abbreviation that is ambiguous there
# isn't read as one option), and whether each takes a value. Like optparse,
# pip takes any unambiguous prefix of a long option (``--extra-ind``) and a
# short option's value attached (``-ihttps://…``, ``-f/dir``).
_FILE_OPTIONS: dict[str, bool] = {
    "--index-url": True,
    "--pypi-url": True,
    "--extra-index-url": True,
    "--no-index": False,
    "--constraint": True,
    "--requirement": True,
    "--editable": True,
    "--find-links": True,
    "--no-binary": True,
    "--only-binary": True,
    "--prefer-binary": False,
    "--require-hashes": False,
    "--no-require-hashes": False,
    "--pre": False,
    "--all-releases": True,
    "--only-final": True,
    "--trusted-host": True,
    "--use-feature": True,
    "--global-option": True,
    "--hash": True,
    "--config-settings": True,
}
_SHORT_OPTIONS = {
    "-i": "--index-url",
    "-c": "--constraint",
    "-r": "--requirement",
    "-e": "--editable",
    "-f": "--find-links",
    "-C": "--config-settings",
}
_PYPI = {s.rstrip("/") + "/" for s in PYPI_INDEXES}


class _UnreadableOption(Exception):
    """pip would refuse the option; ``name`` is as written, without its value."""

    def __init__(self, name: str) -> None:
        self.name = name[:40]


def _long(name: str) -> str | None:
    """The long option ``name`` stands for: itself, or the one it's a prefix of."""
    if name in _FILE_OPTIONS:
        return name
    hits = [k for k in _FILE_OPTIONS if k.startswith(name)]
    return hits[0] if len(hits) == 1 else None


def _options(text: str) -> list[tuple[str, str | None]]:
    """(option, value) pairs from a line's options, read as pip's optparse
    reads them. Positional words among them are dropped, as pip drops them.
    Raises ``_UnreadableOption`` for anything pip would refuse."""
    try:
        words = shlex.split(text)
    except ValueError:
        raise _UnreadableOption("an option line") from None
    out: list[tuple[str, str | None]] = []
    j = 0
    while j < len(words):
        w = words[j]
        j += 1
        if w == "--":
            break  # optparse: the rest are positional
        if w.startswith("--"):
            name, eq, value = w.partition("=")
            opt = _long(name)
            if opt is None or (eq and not _FILE_OPTIONS[opt]):
                raise _UnreadableOption(name)
        elif w.startswith("-") and len(w) > 1:
            name, value, eq = w[:2], w[2:], "=" if len(w) > 2 else ""
            got = _SHORT_OPTIONS.get(name)
            if got is None:
                raise _UnreadableOption(name)
            opt = got
        else:
            continue
        if _FILE_OPTIONS[opt]:
            if not eq:
                if j >= len(words):
                    raise _UnreadableOption(opt)
                value = words[j]
                j += 1
            out.append((opt, value))
        else:
            out.append((opt, None))
    return out


def _split(line: str) -> tuple[str, str]:
    """pip's ``break_args_options``: the requirement, then its options from
    the first space-separated word that starts with "-"."""
    words = line.split(" ")
    k = next((i for i, w in enumerate(words) if w.startswith("-")), len(words))
    return " ".join(words[:k]).strip(), " ".join(words[k:])


def _elsewhere(opt: str, value: str | None) -> str | None:
    """Why ``opt`` means pip may not install this file's requirements from
    PyPI, naming the option, never its value (it can hold credentials)."""
    if opt in ("--index-url", "--pypi-url"):
        if value is not None and value.strip().rstrip("/") + "/" in _PYPI:
            return None
        return f"private index, set with {opt} in this file"
    if opt == "--extra-index-url":
        if value is not None and value.strip().rstrip("/") + "/" in _PYPI:
            return None
        return "extra index, set with --extra-index-url in this file"
    if opt == "--find-links":
        return "--find-links in this file, so pip can install it from elsewhere"
    if opt == "--no-index":
        return "--no-index in this file, so pip doesn't install it from PyPI"
    if opt in ("--requirement", "--constraint"):
        short = "-r" if opt == "--requirement" else "-c"
        return f"{short} in this file brings in a file Garnet doesn't follow, which can set another index"
    return None


def parse(text: str) -> list[Pin]:
    """Pins from a requirements file.

    ``==`` pins from PyPI are checked. Ranges are ``unpinned``; URLs, paths
    and editable installs are ``unsupported``. pip applies index options to
    the whole file, wherever they are, so when the file sets an index other
    than PyPI, an extra index, ``--find-links`` or ``--no-index``, includes
    another file with ``-r`` or ``-c`` (which can set one), or holds an
    option pip would refuse, every ``==`` pin in it is ``unsupported``.
    """
    lines: list[tuple[int, str, list[tuple[str, str | None]]]] = []
    why: str | None = None
    origin: list[str] = []
    for line_no, line in logical_lines(text):
        req, opts_text = _split(line)
        try:
            opts = _options(opts_text) if opts_text else []
        except _UnreadableOption as err:
            opts = []
            why = why or f"an option Garnet can't read ({err.name}), so the index is unknown"
            origin.append(f"unreadable {err.name}")
        for opt, value in opts:
            reason = _elsewhere(opt, value)
            if reason:
                why = why or reason
                origin.append(f"{opt} {value or ''}")
        lines.append((line_no, req, opts))

    pins: list[Pin] = []
    for line_no, line, opts in lines:
        editables = [v for o, v in opts if o == "--editable"]
        if not line:
            pins.extend(
                Pin("(editable)", None, line_no, "unsupported", "editable install")
                for _ in editables
            )
            continue  # an option line
        if "://" in line or line.startswith((".", "/")) or " @ " in line:
            m = _NAMED.match(line)
            name = normalize(m.group(1)) if m and " @ " in line else "(url)"
            pins.append(Pin(name, None, line_no, "unsupported", "direct URL or path"))
            continue
        m = _PINNED.match(line)
        if m:
            name, version = normalize(m.group(1)), m.group(3)
            if why:
                pins.append(
                    Pin(name, version, line_no, "unsupported", why, origin="\n".join(origin))
                )
            else:
                pins.append(Pin(name, version, line_no))
            continue
        m = _NAMED.match(line)
        if m:
            pins.append(Pin(normalize(m.group(1)), None, line_no, "unpinned", m.group(3) or None))
    return pins
