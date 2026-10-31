"""Turn base and head pins into changes (SPEC §3.2)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from packaging.version import InvalidVersion, Version

from .base import Pin
from .npm import semver_key


@dataclass(frozen=True)
class PinChange:
    """A package version in head that base didn't have, and what to compare it with."""

    package: str
    baseline: str | None
    candidate: str
    line: int
    ecosystem: str = "pypi"


def _pep440_key(v: str) -> tuple[int, Any]:
    """Sort by PEP 440 version, with versions that don't parse first."""
    try:
        return (1, Version(v))
    except (InvalidVersion, ValueError):  # ValueError: a number too long to convert
        return (0, v)


def version_key(ecosystem: str, v: str) -> tuple[int, Any]:
    """The ecosystem's version order: SemVer 2.0 on npm, PEP 440 on PyPI."""
    return semver_key(v) if ecosystem == "npm" else _pep440_key(v)


def diff_pins(base: list[Pin], head: list[Pin]) -> list[PinChange]:
    """Checkable changes: head versions not in base, each against its baseline.

    Packages are matched by (ecosystem, name). A head version is compared with
    the highest base version below it, else the highest base version. Removed
    packages produce nothing.
    """
    base_versions: dict[tuple[str, str], set[str]] = {}
    for p in base:
        if p.source == "registry" and p.version:
            base_versions.setdefault((p.ecosystem, p.package), set()).add(p.version)
    changes: dict[tuple[str, str, str], PinChange] = {}
    for p in head:
        if p.source != "registry" or not p.version:
            continue
        olds = base_versions.get((p.ecosystem, p.package), set())
        if p.version in olds:
            continue
        baseline = None
        if olds:
            eco = p.ecosystem
            # The string breaks ties between versions that sort equal, so the
            # baseline doesn't depend on set order.
            ordered = sorted(olds, key=lambda v: (version_key(eco, v), v))
            cand = version_key(eco, p.version)
            lower = [v for v in ordered if version_key(eco, v) < cand]
            baseline = lower[-1] if lower else ordered[-1]
        changes.setdefault(
            (p.ecosystem, p.package, p.version),
            PinChange(p.package, baseline, p.version, p.line, p.ecosystem),
        )
    return sorted(
        changes.values(),
        key=lambda c: (c.ecosystem, c.package, version_key(c.ecosystem, c.candidate), c.candidate),
    )


def new_unchecked(base: list[Pin], head: list[Pin]) -> list[Pin]:
    """Unpinned or unsupported head entries that are new or changed since base."""

    def key(p: Pin) -> tuple[str, str, str | None, str, str | None, str | None]:
        return (p.ecosystem, p.package, p.version, p.source, p.detail, p.origin)

    seen = {key(p) for p in base}
    out = [p for p in head if p.source != "registry" and key(p) not in seen]
    return sorted(out, key=lambda p: (p.line, p.package))
