"""uv.lock and poetry.lock."""

from __future__ import annotations

import re
import tomllib
from typing import Any

from .base import PYPI_INDEXES, Pin, normalize, toml_error


def block_lines(text: str, header: str) -> list[int]:
    """1-based line of each block's ``version =`` key (else its header line)."""
    out: list[int] = []
    current: int | None = None
    found = False
    for i, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if stripped == header:
            if current is not None:
                out.append(current)
            current, found = i, False
        elif (
            current is not None
            and not found
            and not raw[:1].isspace()
            and re.match(r"version\s*=", stripped)
        ):
            current, found = i, True
    if current is not None:
        out.append(current)
    return out


def _load(text: str) -> dict[str, Any]:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as err:
        raise toml_error(err) from err


def parse_uv(text: str) -> list[Pin]:
    """Pins from a uv.lock. The project itself and workspace members are skipped."""
    doc = _load(text)
    packages = doc.get("package", [])
    lines = block_lines(text, "[[package]]")
    pins = []
    for i, pkg in enumerate(packages):
        name = normalize(str(pkg.get("name", "")))
        version = pkg.get("version")
        line = lines[i] if i < len(lines) else 0
        source = pkg.get("source", {})
        if not isinstance(source, dict):
            source = {}
        registry = source.get("registry")
        if registry is not None and str(registry).rstrip("/") + "/" in {
            s.rstrip("/") + "/" for s in PYPI_INDEXES
        }:
            pins.append(Pin(name, str(version) if version else None, line))
        elif "virtual" in source or "editable" in source:
            continue  # the project itself or a workspace member, not a dependency
        else:
            kind = next(iter(source), "unknown")
            pins.append(
                Pin(name, str(version) if version else None, line, "unsupported", f"{kind} source")
            )
    return pins


def parse_poetry(text: str) -> list[Pin]:
    """Pins from a poetry.lock. An entry with no ``source`` comes from PyPI."""
    doc = _load(text)
    packages = doc.get("package", [])
    lines = block_lines(text, "[[package]]")
    pins = []
    for i, pkg in enumerate(packages):
        name = normalize(str(pkg.get("name", "")))
        version = pkg.get("version")
        line = lines[i] if i < len(lines) else 0
        source = pkg.get("source")
        if not source:
            pins.append(Pin(name, str(version) if version else None, line))
            continue
        kind = str(source.get("type", "unknown"))
        url = str(source.get("url", ""))
        if kind == "legacy" and url.rstrip("/") + "/" in {
            s.rstrip("/") + "/" for s in PYPI_INDEXES
        }:
            pins.append(Pin(name, str(version) if version else None, line))
        else:
            detail = f"{kind} source" if kind != "legacy" else "private index"
            pins.append(Pin(name, str(version) if version else None, line, "unsupported", detail))
    return pins
