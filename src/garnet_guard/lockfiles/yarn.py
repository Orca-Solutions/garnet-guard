"""yarn.lock, classic (v1) and Berry (SPEC §3.1).

Both formats are a list of entries: an unindented header naming one or more
descriptors (``"@babel/core@^7.0.0", "@babel/core@^7.10.4":``), then
indented ``key value`` (classic) or ``key: value`` (Berry) lines. Neither is
YAML in the strict sense, so the file is read line by line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .base import NPM_REGISTRIES, Pin, npm_pin

_FIELD = re.compile(r'^  ([A-Za-z_][\w-]*):?\s+"?(.*?)"?\s*$')
_REGISTRY_HOSTS = frozenset(urlsplit(r).hostname or "" for r in NPM_REGISTRIES)


@dataclass
class _Entry:
    descriptors: list[str]
    line: int
    fields: dict[str, str] = field(default_factory=dict)
    version_line: int = 0


def _descriptor_name(descriptor: str) -> tuple[str, str]:
    """``("@babel/core", "^7.0.0")`` from ``@babel/core@^7.0.0``.

    The first ``@`` after the scope separates name from range, so a range
    that holds an ``@`` of its own (``git+ssh://git@...``) stays whole.
    """
    at = descriptor.find("@", 1)
    if at < 0:
        return descriptor, ""
    return descriptor[:at], descriptor[at + 1 :]


def _entries(text: str) -> list[_Entry]:
    out: list[_Entry] = []
    current: _Entry | None = None
    for i, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[:1].isspace():
            header = raw.rstrip()
            if not header.endswith(":"):
                current = None
                continue
            descriptors = [d.strip().strip('"') for d in header[:-1].split(",")]
            current = _Entry([d for d in descriptors if d], i)
            out.append(current)
            continue
        if current is None:
            continue
        m = _FIELD.match(raw)
        if m and m.group(1) not in current.fields:
            current.fields[m.group(1)] = m.group(2)
            if m.group(1) == "version":
                current.version_line = i
    return out


def _registry_name(url: str) -> str | None:
    """The package name from a registry tarball URL (``/@scope/name/-/name-1.0.0.tgz``)."""
    parts = urlsplit(url)
    if (parts.hostname or "").lower() not in _REGISTRY_HOSTS:
        return None
    path = parts.path
    if "/-/" not in path:
        return None
    return path[: path.index("/-/")].strip("/") or None


def _classic(entry: _Entry, name: str) -> Pin:
    version = entry.fields.get("version") or None
    line = entry.version_line or entry.line
    resolved = entry.fields.get("resolved", "")
    if resolved:
        real = _registry_name(resolved)
        if real:
            return npm_pin(real, version, line)
        why = "git source" if resolved.startswith(("git", "ssh")) else "URL outside the registry"
        return npm_pin(name, version, line, why=why)
    ranges = {_descriptor_name(d)[1] for d in entry.descriptors}
    if any(r.startswith(("file:", "link:", "portal:")) for r in ranges):
        return npm_pin(name, version, line, why="local path")
    if any(r.startswith(("git", "github:", "ssh:")) or "://" in r for r in ranges):
        return npm_pin(name, version, line, why="git source")
    return npm_pin(name, version, line, why="no resolved URL")


def _berry(entry: _Entry, name: str) -> Pin | None:
    version = entry.fields.get("version") or None
    line = entry.version_line or entry.line
    resolution = entry.fields.get("resolution", "")
    real, locator = _descriptor_name(resolution) if resolution else (name, "")
    if locator.startswith("workspace:"):
        return None  # the project's own package
    if locator.startswith("npm:"):
        return npm_pin(real, version, line)
    if locator.startswith("patch:"):
        return npm_pin(real, version, line, why="patched package")
    if locator.startswith(("file:", "link:", "portal:")):
        return npm_pin(real, version, line, why="local path")
    if locator.startswith(("git", "ssh:", "github:")) or "://" in locator:
        return npm_pin(real, version, line, why="git source or URL")
    return npm_pin(name, version, line, why="unrecognized resolution")


def parse(text: str) -> list[Pin]:
    """Pins from a yarn.lock of either generation."""
    berry = "__metadata:" in text
    pins: list[Pin] = []
    for entry in _entries(text):
        if not entry.descriptors or entry.descriptors[0] == "__metadata":
            continue
        name, _ = _descriptor_name(entry.descriptors[0])
        pin = _berry(entry, name) if berry else _classic(entry, name)
        if pin is not None:
            pins.append(pin)
    return pins
