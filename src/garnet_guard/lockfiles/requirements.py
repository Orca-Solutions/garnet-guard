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


_OPTION = re.compile(r"^(--[A-Za-z][A-Za-z-]*|-[A-Za-z])")


def unsure_source(text: str) -> str | None:
    """The first line, anywhere in the file, after which Garnet can't tell
    where pip installs a package from, said without its value (which can
    hold credentials), or None. That is any option line but ``--hash``
    (pip accepts abbreviated options and attached values, ``-ihttps://…``,
    ``--extra-ind``, and ``-r``/``-c`` bring in files Garnet doesn't read
    here), and any URL, path or editable requirement."""
    for _, line in logical_lines(text):
        if line.startswith("-"):
            if line.startswith("--hash"):
                continue
            m = _OPTION.match(line)
            return m.group(1) if m else "an option"
        if "://" in line or line.startswith((".", "/", "~")) or " @ " in line:
            return "a URL or path requirement"
        if _NAMED.match(line) is None:
            return "a line Garnet can't read"
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
