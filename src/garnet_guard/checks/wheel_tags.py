"""Which of a release's wheels pip installs, machine by machine. Pure.

GRN-T006 uses this to tell a late wheel that fills a gap (pip had no wheel to
install there, so it built the sdist or failed) from one that takes the place
of a wheel people were already installing. The machines are built from the
tags the release's own wheels carry and ranked with packaging's tag lists, the
order pip uses. The machine Garnet runs on plays no part.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from packaging.tags import Tag, compatible_tags, cpython_tags, generic_tags, mac_platforms
from packaging.utils import InvalidWheelFilename, parse_wheel_filename

# The PEP 600 names of the older manylinux tags.
_LEGACY = {"manylinux1": 5, "manylinux2010": 12, "manylinux2014": 17}
_LINUX = re.compile(r"(manylinux|musllinux)_(\d+)_(\d+)_(\w+)")
_MAC = re.compile(r"macosx_(\d+)_(\d+)_(\w+)")
_PYTHON = re.compile(r"(cp|pp|py)(\d)(\d*)")
# The machines a macOS wheel's architecture runs on.
_MAC_ARCHES = {
    "x86_64": ("x86_64",),
    "arm64": ("arm64",),
    "universal2": ("arm64", "x86_64"),
    "intel": ("x86_64",),
    "fat64": ("x86_64",),
    "universal": ("x86_64",),
}
_NAMES = {"win32": "32-bit Windows", "win_amd64": "64-bit Windows", "win_arm64": "Windows on Arm"}

Group = tuple[str, ...]  # a platform family and architecture
Level = tuple[int, int]  # glibc, musl or macOS version; (0, 0) when there is none


@dataclass(frozen=True)
class Wheel:
    filename: str
    tags: frozenset[Tag]
    build: tuple[()] | tuple[int, str]


@dataclass(frozen=True)
class Displacement:
    """A late wheel pip installs on ``machine`` instead of ``replaced``."""

    machine: str
    replaced: str
    tie: bool  # same tag rank as ``replaced``: a build number or pip's file order decides
    build: bool  # the late wheel has a build number and ``replaced`` a lower one or none


def parse(filename: str) -> Wheel | None:
    """A wheel's tags and build number, or None for an sdist or a name pip rejects."""
    if not filename.endswith(".whl"):
        return None
    try:
        _, _, build, tags = parse_wheel_filename(filename)
    except InvalidWheelFilename:
        return None
    return Wheel(
        filename, frozenset(Tag(t.interpreter, t.abi, _pep600(t.platform)) for t in tags), build
    )


def _pep600(platform: str) -> str:
    for old, minor in _LEGACY.items():
        if platform.startswith(old + "_"):
            return f"manylinux_2_{minor}_{platform[len(old) + 1 :]}"
    return platform


def _platform_groups(platform: str) -> list[tuple[Group, Level]]:
    """The machines families a platform tag fits, with the oldest version it needs."""
    if platform == "any":
        return []
    if m := _LINUX.fullmatch(platform):
        return [((m[1], m[2], m[4]), (int(m[2]), int(m[3])))]
    if m := _MAC.fullmatch(platform):
        level = (int(m[1]), int(m[2]))
        return [
            (("macosx", arch), max(level, (11, 0)) if arch == "arm64" else level)
            for arch in _MAC_ARCHES.get(m[3], ())
        ]
    return [(("exact", platform), (0, 0))]


def _platforms(group: Group, level: Level) -> tuple[tuple[str, ...], str]:
    """A machine's platform tags, most preferred first, and how to name it."""
    if group[0] in ("manylinux", "musllinux"):
        family, major, arch = group
        libc = "glibc" if family == "manylinux" else "musl"
        tags = tuple(f"{family}_{major}_{k}_{arch}" for k in range(level[1], -1, -1))
        return (*tags, f"linux_{arch}"), f"Linux {arch} with {libc} {level[0]}.{level[1]}"
    if group[0] == "macosx":
        arch = group[1]
        return tuple(mac_platforms(level, arch)), f"macOS {level[0]}.{level[1]} {arch}"
    return (group[1],), _NAMES.get(group[1], group[1])


def _pythons(tags: Iterable[Tag]) -> set[tuple[str, Level, str]]:
    """(implementation, version, ABI) of the interpreters these tags name."""
    out: set[tuple[str, Level, str]] = set()
    for t in tags:
        m = _PYTHON.fullmatch(t.interpreter)
        if not m or not m[3]:
            continue  # py3, py2: no version to build a machine for
        impl = "pp" if m[1] == "pp" else "cp"
        version = (int(m[2]), int(m[3]))
        own_abi = t.abi not in ("none", "abi3", "abi3t") and impl == m[1]
        out.add((impl, version, t.abi if own_abi else f"{impl}{m[2]}{m[3]}"))
    return out


def _python_name(impl: str, version: Level, abi: str) -> str:
    if version == (3, 0):
        return "Python 3"
    name = f"{'PyPy' if impl == 'pp' else 'CPython'} {version[0]}.{version[1]}"
    return f"{name} free-threaded" if impl == "cp" and abi.endswith("t") else name


def _supported(impl: str, version: Level, abi: str, platforms: Sequence[str]) -> dict[Tag, int]:
    """The tags this interpreter installs, by pip's preference (0 is best)."""
    nodot = f"{version[0]}{version[1]}"
    if impl == "cp":
        ranked = [*cpython_tags(version, [abi], platforms)]
    else:
        ranked = [*generic_tags(f"pp{nodot}", [abi], platforms)]
    ranked += compatible_tags(version, f"{impl}{nodot}", platforms)
    rank: dict[Tag, int] = {}
    for i, t in enumerate(ranked):
        rank.setdefault(t, i)
    return rank


def _machines(late: list[Wheel], every: list[Wheel]) -> list[tuple[str, dict[Tag, int]]]:
    """The machines a late wheel fits, each with its ranked tags, in a stable order.

    A late wheel can only change what pip installs where it fits, so the
    machines come from its tags. Versions of the same platform family come
    from every wheel: a late glibc 2.17 wheel is only compared with a glibc
    2.28 one on a machine new enough for both.
    """
    late_tags = {t for w in late for t in w.tags}
    all_tags = {t for w in every for t in w.tags}

    pythons = _pythons(late_tags)
    if any(
        t.abi in ("none", "abi3", "abi3t") or not _PYTHON.fullmatch(t.interpreter)
        for t in late_tags
    ):
        pythons |= _pythons(all_tags)  # a wheel for many Pythons meets the others on theirs
    if not pythons:
        pythons = {("cp", (3, 0), "cp30")}

    groups = {g for t in late_tags for g, _ in _platform_groups(t.platform)}
    if any(t.platform == "any" for t in late_tags):
        groups |= {g for t in all_tags for g, _ in _platform_groups(t.platform)}
    levels = sorted(
        {(g, lv) for t in all_tags for g, lv in _platform_groups(t.platform) if g in groups},
        key=lambda gl: (gl[0], tuple(-x for x in gl[1])),
    )
    platforms = [_platforms(g, lv) for g, lv in levels] or [((), "")]

    out = []
    for impl, version, abi in sorted(pythons, key=lambda p: (-p[1][0], -p[1][1], p[0], p[2])):
        for tags, where in platforms:
            name = _python_name(impl, version, abi) + (f" on {where}" if where else "")
            out.append((name, _supported(impl, version, abi, tags)))
    return out


def displacements(on_time: Sequence[str], late: Sequence[str]) -> dict[str, Displacement]:
    """For each late wheel pip would now install where an on-time wheel fitted,
    the first such machine and the file it takes the place of.

    pip picks the wheel whose best tag ranks highest, then the higher build
    number. A late wheel that ties with an on-time one is listed too, since
    pip's file order then decides. A late wheel that fits only machines no
    on-time wheel fitted is a backfill and is left out.
    """
    before = [w for n in on_time if (w := parse(n)) is not None]
    after = [w for n in late if (w := parse(n)) is not None]
    if not before or not after:
        return {}
    found: dict[str, Displacement] = {}
    for machine, rank in _machines(after, before + after):

        def score(
            w: Wheel, rank: dict[Tag, int] = rank
        ) -> tuple[int, tuple[()] | tuple[int, str]] | None:
            fits = [rank[t] for t in w.tags if t in rank]
            return (-min(fits), w.build) if fits else None

        scored_before = [(s, w.filename) for w in before if (s := score(w)) is not None]
        if not scored_before:
            continue  # nothing installed here before: a late wheel fills a gap
        best = max(s for s, _ in scored_before)
        replaced = min(n for s, n in scored_before if s == best)
        scored_after = [(s, w.filename) for w in after if (s := score(w)) is not None]
        if not scored_after:
            continue
        top = max(s for s, _ in scored_after)
        if top < best:
            continue
        for s, name in sorted(scored_after, key=lambda sn: sn[1]):
            if s == top and name not in found:
                found[name] = Displacement(
                    machine, replaced, tie=s[0] == best[0], build=s[1] > best[1]
                )
    return found
