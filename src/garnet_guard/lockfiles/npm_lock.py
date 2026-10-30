"""package-lock.json and npm-shrinkwrap.json, lockfileVersion 2 and 3 (SPEC §3.1)."""

from __future__ import annotations

import json
import re
from typing import Any

from .base import NPM_REGISTRIES, LockfileError, Pin, npm_pin

_KEY_LINE = re.compile(r'^    "([^"]*)": \{\s*$')  # one entry of the "packages" map
_VERSION_LINE = re.compile(r'^\s*"version":')


def _entry_lines(text: str) -> dict[str, int]:
    """1-based line of each entry's ``"version"`` key (else its own key line).

    npm writes the file with two-space indentation, so an entry of the
    ``packages`` map starts at four spaces. A hand-edited file that doesn't
    gets line 0, which the report shows as no line.
    """
    out: dict[str, int] = {}
    current: str | None = None
    for i, raw in enumerate(text.splitlines(), start=1):
        m = _KEY_LINE.match(raw)
        if m:
            current = m.group(1)
            out.setdefault(current, i)
        elif current is not None and _VERSION_LINE.match(raw) and out.get(current) is not None:
            if raw.startswith("      "):  # the entry's own version, not a nested object's
                out[current] = i
                current = None
    return out


def _source(entry: dict[str, Any]) -> str | None:
    """None for a registry package, else why it isn't one."""
    resolved = entry.get("resolved")
    if entry.get("inBundle"):
        return "bundled with another package"
    if not isinstance(resolved, str):
        return "no resolved URL"
    if resolved.startswith(("git+", "git:")):
        return "git source"
    if resolved.startswith("file:"):
        return "local path"
    if any(resolved.startswith(r) for r in NPM_REGISTRIES):
        return None
    if "://" in resolved:
        return "URL outside the registry"
    return "unrecognized resolved field"


def parse(text: str) -> list[Pin]:
    """Pins from a package-lock.json.

    Entries under ``node_modules/`` are dependencies; the root and workspace
    packages are the project's own code and are skipped. Packages resolved
    from git, a path, a bundle or a URL outside the registry are
    ``unsupported``.
    """
    try:
        doc = json.loads(text)
    except ValueError as err:
        raise LockfileError(f"invalid JSON: {_position(err)}") from err
    if not isinstance(doc, dict):
        raise LockfileError("package-lock.json is not a JSON object")
    packages = doc.get("packages")
    if not isinstance(packages, dict):
        version = doc.get("lockfileVersion", "1")
        raise LockfileError(
            f"package-lock.json lockfileVersion {version} isn't supported; "
            "npm 7 or later writes lockfileVersion 2 or 3"
        )
    lines = _entry_lines(text)
    pins: list[Pin] = []
    for key, entry in packages.items():
        if not isinstance(key, str) or not isinstance(entry, dict):
            continue
        if "node_modules/" not in key or entry.get("link"):
            continue  # the root, a workspace package, or a link to one
        name = entry.get("name") if isinstance(entry.get("name"), str) else None
        name = name or key.rsplit("node_modules/", 1)[1]
        version = entry.get("version")
        pins.append(
            npm_pin(
                name,
                version if isinstance(version, str) else None,
                lines.get(key, 0),
                why=_source(entry),
            )
        )
    return pins


def _position(err: ValueError) -> str:
    """The position from a JSON error, without the file's own text."""
    m = re.search(r"line (\d+) column (\d+)", str(err))
    return f"line {m[1]}, column {m[2]}" if m else "unknown position"
