"""Turn base and head pins into changes (SPEC §3.2)."""

from __future__ import annotations

from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

from .base import Pin


@dataclass(frozen=True)
class PinChange:
    package: str
    baseline: str | None
    candidate: str
    line: int


def _key(v: str) -> tuple[int, Version | str]:
    try:
        return (1, Version(v))
    except InvalidVersion:
        return (0, v)


def diff_pins(base: list[Pin], head: list[Pin]) -> list[PinChange]:
    """Checkable changes: head versions not in base, each against its baseline.

    A head version is compared with the highest base version below it, else
    the highest base version. Removed packages produce nothing.
    """
    base_versions: dict[str, set[str]] = {}
    for p in base:
        if p.source == "pypi" and p.version:
            base_versions.setdefault(p.package, set()).add(p.version)
    changes: dict[tuple[str, str], PinChange] = {}
    for p in head:
        if p.source != "pypi" or not p.version:
            continue
        olds = base_versions.get(p.package, set())
        if p.version in olds:
            continue
        baseline = None
        if olds:
            ordered = sorted(olds, key=_key)
            lower = [v for v in ordered if _key(v) < _key(p.version)]
            baseline = lower[-1] if lower else ordered[-1]
        changes.setdefault(
            (p.package, p.version), PinChange(p.package, baseline, p.version, p.line)
        )
    return sorted(changes.values(), key=lambda c: (c.package, _key(c.candidate)))


def new_unchecked(base: list[Pin], head: list[Pin]) -> list[Pin]:
    """Unpinned or unsupported head entries that are new or changed since base."""
    seen = {(p.package, p.version, p.source, p.detail) for p in base}
    out = [
        p
        for p in head
        if p.source != "pypi" and (p.package, p.version, p.source, p.detail) not in seen
    ]
    return sorted(out, key=lambda p: (p.line, p.package))
