"""pylock.toml (PEP 751)."""

from __future__ import annotations

import tomllib
from typing import Any

from .base import PYPI_FILE_HOST, PYPI_INDEXES, Pin, normalize, toml_error
from .toml_locks import block_lines


def _on_pypi(pkg: dict[str, Any]) -> tuple[bool, str]:
    """(True, "") for a package from PyPI, else (False, why not)."""
    if "vcs" in pkg:
        return False, "vcs source"
    if "directory" in pkg:
        return False, "directory source"
    index = pkg.get("index")
    if index is not None:
        if str(index).rstrip("/") + "/" not in {s.rstrip("/") + "/" for s in PYPI_INDEXES}:
            return False, "private index"
        return True, ""
    urls: list[str] = []
    archive = pkg.get("archive")
    if isinstance(archive, dict):
        urls.append(str(archive.get("url", "")))
    sdist = pkg.get("sdist")
    if isinstance(sdist, dict):
        urls.append(str(sdist.get("url", "")))
    for w in pkg.get("wheels", []) or []:
        if isinstance(w, dict):
            urls.append(str(w.get("url", "")))
    if urls and all(u.startswith(PYPI_FILE_HOST) for u in urls):
        return True, ""
    return False, "archive outside PyPI" if urls else "no source"


def parse(text: str) -> list[Pin]:
    """Pins from a pylock.toml. Packages from anywhere but PyPI are ``unsupported``."""
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as err:
        raise toml_error(err) from err
    lines = block_lines(text, "[[packages]]")
    pins = []
    for i, pkg in enumerate(doc.get("packages", [])):
        name = normalize(str(pkg.get("name", "")))
        version = pkg.get("version")
        line = lines[i] if i < len(lines) else 0
        ok, why = _on_pypi(pkg)
        if ok and version:
            pins.append(Pin(name, str(version), line))
        else:
            pins.append(
                Pin(
                    name,
                    str(version) if version else None,
                    line,
                    "unsupported",
                    why or "no version",
                )
            )
    return pins
