"""requirements*.txt: only ``==`` pins are checked (SPEC §3.1)."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

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


# The option name ``FileOptions.moves`` gives an option pip would refuse; its
# value is the option as written, without its value.
UNREADABLE = "?"


def _moves(opt: str, value: str | None) -> bool:
    """Whether ``opt`` means pip may not install the file's requirements
    from PyPI. Includes (``-r``, ``-c``) are listed apart."""
    if opt in ("--index-url", "--pypi-url", "--extra-index-url"):
        return value is None or value.strip().rstrip("/") + "/" not in _PYPI
    return opt in ("--find-links", "--no-index", UNREADABLE)


def describe(opt: str, value: str | None, where: str) -> str:
    """The reason a pin isn't checked, for an option in ``moves`` found in
    ``where`` ("this file", or another file's path). It names the option,
    never its value, which can hold credentials."""
    if opt in ("--index-url", "--pypi-url"):
        return f"private index, set with {opt} in {where}"
    if opt == "--extra-index-url":
        return f"extra index, set with --extra-index-url in {where}"
    if opt == "--find-links":
        return f"--find-links in {where}, so pip can install it from elsewhere"
    if opt == "--no-index":
        return f"--no-index in {where}, so pip doesn't install it from PyPI"
    at = "" if where == "this file" else f" in {where}"
    return f"an option Garnet can't read ({value}){at}, so the index is unknown"


@dataclass(frozen=True)
class FileOptions:
    """What a requirements file's options say about where pip installs from.

    ``moves`` are the (option, value) pairs, in file order, that can move its
    requirements off PyPI; ``includes`` are its ``-r`` and ``-c`` files, as
    ("-r" or "-c", path as written). Values are compared, never shown.
    """

    moves: tuple[tuple[str, str | None], ...] = ()
    includes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Included:
    """What the other files pip reads with this one (its ``-r`` and ``-c``
    files, and the files that bring it in) say about where pip installs
    from, worked out by the caller (``workspace.requirement_includes``),
    which reads them. ``why`` is the first reason a pin isn't checked, or
    None when every include was followed and none moves pins off PyPI;
    ``origin`` is compared, never shown."""

    why: str | None = None
    origin: tuple[str, ...] = ()


def _scan(
    text: str,
) -> tuple[list[tuple[int, str, list[tuple[str, str | None]]]], FileOptions]:
    lines: list[tuple[int, str, list[tuple[str, str | None]]]] = []
    moves: list[tuple[str, str | None]] = []
    includes: list[tuple[str, str]] = []
    for line_no, line in logical_lines(text):
        req, opts_text = _split(line)
        try:
            opts = _options(opts_text) if opts_text else []
        except _UnreadableOption as err:
            opts = []
            moves.append((UNREADABLE, err.name))
        for opt, value in opts:
            if opt in ("--requirement", "--constraint"):
                includes.append(("-r" if opt == "--requirement" else "-c", value or ""))
            elif _moves(opt, value):
                moves.append((opt, value))
        lines.append((line_no, req, opts))
    return lines, FileOptions(tuple(moves), tuple(includes))


def file_options(text: str) -> FileOptions:
    """The options of a requirements file that decide where pip installs from."""
    return _scan(text)[1]


def parse(text: str, included: Included | None = None) -> list[Pin]:
    """Pins from a requirements file.

    ``==`` pins from PyPI are checked. Ranges are ``unpinned``; URLs, paths
    and editable installs are ``unsupported``. pip applies index options to
    the whole file, wherever they are, and an included file's options to
    every file it reads with it. So when the file sets an index other than
    PyPI, an extra index, ``--find-links`` or ``--no-index``, holds an option
    pip would refuse, or ``included`` gives a reason from the files read with
    it, every ``==`` pin in it is ``unsupported``. Without ``included`` (the
    caller didn't read the includes), a file with ``-r`` or ``-c`` is treated
    the same way.
    """
    lines, opts = _scan(text)
    why = describe(*opts.moves[0], "this file") if opts.moves else None
    origin = [f"{o} {v or ''}" for o, v in opts.moves]
    if included is not None:
        why = why or included.why
        origin += included.origin
    elif opts.includes:
        short = opts.includes[0][0]
        why = why or (
            f"{short} in this file brings in a file Garnet doesn't follow, which can set another index"
        )
        origin += [f"{o} {v}" for o, v in opts.includes]

    pins: list[Pin] = []
    for line_no, line, line_opts in lines:
        editables = [v for o, v in line_opts if o == "--editable"]
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
