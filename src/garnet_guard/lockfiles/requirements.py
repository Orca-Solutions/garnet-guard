"""requirements*.txt: only ``==`` pins are checked (SPEC §3.1)."""

from __future__ import annotations

import re

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


_FIND_ELSEWHERE = re.compile(r"^(--extra-index-url|--find-links|-f|--no-index)(?=$|[\s=])")
_INDEX_URL = re.compile(r"^(--index-url|-i)(?:\s*=\s*|\s+)(\S+)")


def other_index(text: str) -> str | None:
    """The first option, anywhere in the file, that makes pip look for
    packages somewhere other than PyPI (``--index-url`` naming another index,
    ``--extra-index-url``, ``--find-links``, ``--no-index``), or None."""
    for _, line in logical_lines(text):
        m = _FIND_ELSEWHERE.match(line)
        if m is not None:
            return m.group(1)
        m2 = _INDEX_URL.match(line)
        if m2 is not None and m2.group(2).rstrip("/") + "/" not in {
            s.rstrip("/") + "/" for s in PYPI_INDEXES
        }:
            return m2.group(1)
    return None


def parse(text: str) -> list[Pin]:
    """Pins from a requirements file.

    ``==`` pins from PyPI are checked. Ranges are ``unpinned``; URLs, paths,
    editable installs and pins under a private ``--index-url`` are
    ``unsupported``. Other options (``-r``, ``-c``) are skipped.
    """
    pins: list[Pin] = []
    private_index: str | None = None
    for line_no, line in logical_lines(text):
        # drop per-requirement options such as --hash
        line = re.sub(r"\s--hash[=\s]\S+", "", line).strip()
        if line.startswith(("-i ", "--index-url")):
            url = line.split("=", 1)[1] if "=" in line else line.split(None, 1)[1]
            if url.strip().rstrip("/") + "/" not in {s.rstrip("/") + "/" for s in PYPI_INDEXES}:
                private_index = url.strip()
            continue
        if line.startswith("-e ") or line.startswith("--editable"):
            pins.append(Pin("(editable)", None, line_no, "unsupported", "editable install"))
            continue
        if line.startswith("-"):
            continue  # -r, -c, --extra-index-url and other options aren't pins
        if "://" in line or line.startswith((".", "/")) or " @ " in line:
            m = _NAMED.match(line)
            name = normalize(m.group(1)) if m and " @ " in line else "(url)"
            pins.append(Pin(name, None, line_no, "unsupported", "direct URL or path"))
            continue
        m = _PINNED.match(line)
        if m:
            name, version = normalize(m.group(1)), m.group(3)
            if private_index:
                pins.append(Pin(name, version, line_no, "unsupported", "private index"))
            else:
                pins.append(Pin(name, version, line_no, marker=bool(m.group(4))))
            continue
        m = _NAMED.match(line)
        if m:
            pins.append(Pin(normalize(m.group(1)), None, line_no, "unpinned", m.group(3) or None))
    return pins
