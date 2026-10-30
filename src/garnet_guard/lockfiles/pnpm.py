"""pnpm-lock.yaml, lockfile versions 6 and 9 (SPEC §3.1 names v9).

Read with PyYAML's safe loader, aliases refused (ADR-0016). pnpm records a
package's integrity but not which registry served it, so a package from a
private registry configured in ``.npmrc`` is checked against npmjs.org and,
when it isn't there, reported as GRN-E001 rather than passed.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

import yaml

from .base import NPM_REGISTRIES, LockfileError, Pin, npm_pin

_SUPPORTED = ("6", "9")
_KEY_LINE = re.compile(r"""^  ['"]?([^'"\s][^'"]*?)['"]?:\s*$""")
_REGISTRY_HOSTS = frozenset(urlsplit(r).hostname or "" for r in NPM_REGISTRIES)


class _Loader(yaml.SafeLoader):
    """The safe loader without aliases.

    The safe loader builds only plain values. Refusing aliases as well keeps
    a lockfile from a pull request from expanding into memory (``&a`` and
    ``*a`` references); pnpm never writes them.
    """

    def compose_node(self, parent: yaml.Node | None, index: Any) -> yaml.Node | None:
        if self.check_event(yaml.AliasEvent):
            raise LockfileError("pnpm-lock.yaml uses a YAML alias, which pnpm doesn't write")
        return super().compose_node(parent, index)


def _package_lines(text: str) -> dict[str, int]:
    """1-based line of each key under the top-level ``packages:`` map."""
    out: dict[str, int] = {}
    inside = False
    for i, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        if not raw[:1].isspace():
            inside = raw.rstrip() == "packages:"
            continue
        if inside:
            m = _KEY_LINE.match(raw)
            if m:
                out.setdefault(m.group(1), i)
    return out


def split_key(key: str) -> tuple[str, str]:
    """``("@scope/name", "1.0.0")`` from ``@scope/name@1.0.0``, ``/name@1.0.0``
    (v6) or ``name@1.0.0(peer@2.0.0)``.

    The first ``@`` after the scope separates name from version, so a git
    locator with an ``@`` of its own stays whole.
    """
    k = key.lstrip("/").split("(", 1)[0]
    at = k.find("@", 1)
    if at < 0:
        return k, ""
    return k[:at], k[at + 1 :]


def _source(resolution: Any) -> str | None:
    """None for a registry package, else why it isn't one."""
    if not isinstance(resolution, dict):
        return "no resolution"
    if resolution.get("type") == "git" or "repo" in resolution:
        return "git source"
    if "directory" in resolution:
        return "local path"
    tarball = resolution.get("tarball")
    if isinstance(tarball, str):
        host = (urlsplit(tarball).hostname or "").lower()
        return None if host in _REGISTRY_HOSTS else "URL outside the registry"
    if "integrity" in resolution:
        return None
    return "unrecognized resolution"


def parse(text: str) -> list[Pin]:
    """Pins from a pnpm-lock.yaml."""
    try:
        doc = yaml.load(text, Loader=_Loader)  # noqa: S506  (a SafeLoader subclass)
    except yaml.YAMLError as err:
        mark = getattr(err, "problem_mark", None)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise LockfileError(f"invalid YAML{where}") from err
    if not isinstance(doc, dict):
        raise LockfileError("pnpm-lock.yaml is not a mapping")
    version = str(doc.get("lockfileVersion", "")).strip("'\"")
    if version.split(".", 1)[0] not in _SUPPORTED:
        raise LockfileError(
            f"pnpm-lock.yaml lockfileVersion {version or 'unknown'} isn't supported; "
            "pnpm 8 writes 6.x and pnpm 9 writes 9.x"
        )
    packages = doc.get("packages") or {}
    if not isinstance(packages, dict):
        raise LockfileError("pnpm-lock.yaml has no packages map")
    lines = _package_lines(text)
    pins: list[Pin] = []
    for key, entry in packages.items():
        if not isinstance(key, str):
            continue
        name, ver = split_key(key)
        if isinstance(entry, dict) and isinstance(entry.get("version"), str):
            ver = entry["version"]  # written for git, tarball and directory sources
        why = _source(entry.get("resolution") if isinstance(entry, dict) else None)
        pins.append(npm_pin(name, ver or None, lines.get(key, 0), why=why))
    return pins
