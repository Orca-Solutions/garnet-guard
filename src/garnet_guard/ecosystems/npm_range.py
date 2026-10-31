"""npm version ranges, enough to pick the version a dependency range installs.

GRN-C008 reads the release of a new dependency that the candidate would have
installed when it was published: the newest version that satisfies the range
and was on the registry by then. This follows node-semver's rules for the
range forms package.json uses (``^``, ``~``, x-ranges, hyphen ranges,
comparators and ``||``) and its prerelease rule: a prerelease version matches
only a comparator set that names a prerelease of the same major.minor.patch.
It never runs npm. A range it can't read raises ``ValueError``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

_VERSION = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$"
)
_PARTIAL = re.compile(
    r"^v?(\d+|[xX*])(?:\.(\d+|[xX*])(?:\.(\d+|[xX*])"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?)?)?$"
)
_COMPARATOR = re.compile(r"^(<=|>=|<|>|=|\^|~>|~)?(.*)$")
_HYPHEN = re.compile(r"^(\S+)\s+-\s+(\S+)$")

Pre = tuple[tuple[int, int | str], ...]


@dataclass(frozen=True, order=True)
class SemVer:
    """A version in semver precedence order (build metadata ignored)."""

    major: int
    minor: int
    patch: int
    release: int  # 1 for a release, 0 for a prerelease, which sorts before it
    pre: Pre = ()

    @property
    def core(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)


def _pre(text: str | None) -> Pre:
    if not text:
        return ()
    return tuple((0, int(p)) if p.isdigit() else (1, p) for p in text.split("."))


def parse(version: str) -> SemVer | None:
    """A strict semver version, or None."""
    m = _VERSION.match(version.strip())
    if m is None:
        return None
    pre = _pre(m.group(4))
    return SemVer(int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre else 1, pre)


def _at(major: int, minor: int, patch: int, pre: Pre = ()) -> SemVer:
    return SemVer(major, minor, patch, 0 if pre else 1, pre)


@dataclass(frozen=True)
class _Cmp:
    op: str  # ">=", ">", "<", "<=", "="
    v: SemVer

    def test(self, v: SemVer) -> bool:
        if self.op == ">=":
            return v >= self.v
        if self.op == ">":
            return v > self.v
        if self.op == "<":
            return v < self.v
        if self.op == "<=":
            return v <= self.v
        return v == self.v


def _partial(text: str) -> tuple[int | None, int | None, int | None, Pre]:
    m = _PARTIAL.match(text)
    if m is None:
        raise ValueError(f"not a version: {text!r}")
    parts: list[int | None] = []
    for g in m.group(1, 2, 3):
        parts.append(None if g is None or g in "xX*" else int(g))
    # Anything after a wildcard is a wildcard too (1.x.3 is 1.x).
    for i in range(1, 3):
        if parts[i - 1] is None:
            parts[i] = None
    return parts[0], parts[1], parts[2], _pre(m.group(4)) if parts[2] is not None else ()


def _desugar(op: str, text: str) -> list[_Cmp]:
    """One written comparator as the plain ones it means."""
    if text in ("", "*", "x", "X"):
        return [] if op in ("", "=", ">=", "^", "~", "~>", "<=") else [_Cmp("<", _at(0, 0, 0))]
    major, minor, patch, pre = _partial(text)
    if major is None:
        return []
    if op == "^":
        lo = _at(major, minor or 0, patch or 0, pre)
        if major > 0 or minor is None:
            hi = _at(major + 1, 0, 0)
        elif minor > 0 or patch is None:
            hi = _at(0, minor + 1, 0)
        else:
            hi = _at(0, 0, patch + 1)
        return [_Cmp(">=", lo), _Cmp("<", hi)]
    if op in ("~", "~>"):
        lo = _at(major, minor or 0, patch or 0, pre)
        hi = _at(major + 1, 0, 0) if minor is None else _at(major, minor + 1, 0)
        return [_Cmp(">=", lo), _Cmp("<", hi)]
    if minor is None or patch is None:
        # A partial version: the range of versions it stands for.
        lo = _at(major, minor or 0, 0)
        hi = _at(major + 1, 0, 0) if minor is None else _at(major, minor + 1, 0)
        if op in ("", "="):
            return [_Cmp(">=", lo), _Cmp("<", hi)]
        if op == ">":
            return [_Cmp(">=", hi)]
        if op == ">=":
            return [_Cmp(">=", lo)]
        if op == "<":
            return [_Cmp("<", lo)]
        return [_Cmp("<", hi)]  # "<="
    return [_Cmp(op or "=", _at(major, minor, patch, pre))]


def _hyphen(lo_text: str, hi_text: str) -> list[_Cmp]:
    out: list[_Cmp] = []
    major, minor, patch, pre = _partial(lo_text)
    if major is not None:
        out.append(_Cmp(">=", _at(major, minor or 0, patch or 0, pre)))
    major, minor, patch, pre = _partial(hi_text)
    if major is None:
        return out
    if minor is None:
        out.append(_Cmp("<", _at(major + 1, 0, 0)))
    elif patch is None:
        out.append(_Cmp("<", _at(major, minor + 1, 0)))
    else:
        out.append(_Cmp("<=", _at(major, minor, patch, pre)))
    return out


def _sets(rng: str) -> list[list[_Cmp]]:
    out: list[list[_Cmp]] = []
    for part in rng.split("||"):
        text = " ".join(part.split())
        m = _HYPHEN.match(text)
        if m is not None:
            out.append(_hyphen(m.group(1), m.group(2)))
            continue
        # ">= 1.2.3" means ">=1.2.3".
        text = re.sub(r"(<=|>=|<|>|=|\^|~>|~)\s+", r"\1", text)
        cmps: list[_Cmp] = []
        for token in text.split(" ") if text else [""]:
            m2 = _COMPARATOR.match(token)
            assert m2 is not None  # the pattern matches any string
            cmps.extend(_desugar(m2.group(1) or "", m2.group(2)))
        out.append(cmps)
    return out


def _satisfies(v: SemVer, cmps: list[_Cmp]) -> bool:
    if not all(c.test(v) for c in cmps):
        return False
    if not v.pre:
        return True
    return any(c.v.pre and c.v.core == v.core for c in cmps)


def matching(rng: str, versions: Iterable[str]) -> list[str]:
    """The ``versions`` that satisfy ``rng``, lowest first.

    ``latest`` counts as ``*``. Versions that aren't semver are skipped.
    Raises ``ValueError`` for a range it can't read (another dist-tag, for one).
    """
    text = rng.strip()
    sets = _sets("*" if text == "latest" else text)
    found = [(v, raw) for raw in versions if (v := parse(raw)) is not None]
    return [raw for v, raw in sorted(found) if any(_satisfies(v, s) for s in sets)]


# A spec that admits any version: npm then installs the ``latest`` dist-tag,
# even when that is a prerelease, which node-semver's rule leaves out.
_ANY = re.compile(r"^(?:|latest|[xX*](?:\.[xX*]){0,2})$")


def admits_any(rng: str) -> bool:
    """Whether ``rng`` is ``*``, ``x``, ``latest`` or empty, which npm installs as
    the ``latest`` dist-tag."""
    return _ANY.match(rng.strip()) is not None


def readable(rng: str, versions: Iterable[str]) -> list[str]:
    """The ``versions`` GRN-C008 reads for ``rng``, lowest first: those that
    satisfy it, and every version, prereleases included, when it admits any
    (whatever ``latest`` points to installs then). Raises ``ValueError`` as
    ``matching`` does."""
    if admits_any(rng):
        found = [(v, raw) for raw in versions if (v := parse(raw)) is not None]
        return [raw for _, raw in sorted(found)]
    return matching(rng, versions)


def best_match(rng: str, versions: Iterable[str]) -> str | None:
    """The highest of ``versions`` that satisfies ``rng``, or None (see ``matching``)."""
    found = matching(rng, versions)
    return found[-1] if found else None
