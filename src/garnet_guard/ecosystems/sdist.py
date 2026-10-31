"""Compare the wheel the content rules read with the release's sdist (GRN-C006).

A wheel is built from its sdist, or from the same tagged source, so each of its
Python files should be byte for byte a file in the sdist. A file that isn't is
read back and asked what GRN-C007 asks of a file that isn't at the tag: does it
make a sensitive call that the sdist's copy doesn't? A ``.pth`` file is asked
whether the sdist has a copy, and whether it has executable lines that copy
lacks. The answers are recorded; the rule in ``checks.content`` decides what to
report.

An sdist keeps the repository's layout, so a wheel file is looked for where its
package lives there: under the folder most of the wheel's files are found in
(``src/``, ``python/``), under a folder of another name for a package published
under a new one (pycryptodomex's ``Cryptodome/`` from ``lib/Crypto/``), as
GRN-C007 looks in the source tree, then at the sdist's top and under ``src/``.
A file whose bytes are anywhere in the sdist matches, wherever the build put it,
and so does one that differs only in CRLF line endings.

Nothing is fetched or run: both archives are already downloaded and checked
against PyPI's hashes, and files are read back through ``safe_archive``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping

from ..facts.inventory import project_name, site_path
from ..facts.pyindex import sensitive_calls
from ..models import ArtifactFacts, FileEntry, Limits, PthFile, SdistMatch, WheelOnlyCode
from .source import find_prefix, find_renames

# Folders of a wheel that don't install as importable code in site-packages.
_NOT_SITE = (".data", ".dist-info", ".egg-info")


def _in_site(site: str) -> bool:
    """Whether a wheel file, by where it installs, lands in site-packages as
    code Python can import: not under ``<name>.data/scripts/`` and the other
    non-library schemes, and not in a metadata folder."""
    top, sep, _ = site.partition("/")
    return not (sep and top.endswith(_NOT_SITE))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _lf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def _counterpart(
    site: str, prefix: str, renames: Mapping[str, str], files: Mapping[str, object]
) -> str | None:
    """The sdist file at a wheel file's install path: under the renamed folder
    for a package published under another name, under the folder most files
    share, then at the sdist's top and under ``src/``."""
    top, _, rest = site.partition("/")
    tried = [renames[top] + rest] if top in renames and rest else []
    tried += [prefix + site, site, "src/" + site]
    return next((p for p in tried if p in files), None)


def _sdist_calls(
    data: bytes, path: str, own: frozenset[str], project: str, limits: Limits
) -> tuple[set[str], bool]:
    """The names of the sensitive calls in the sdist's copy, and whether it
    could be parsed. A copy over the parse limit, or one ast can't read,
    explains nothing: every call in the wheel's copy counts."""
    if len(data) > limits.max_py_file_bytes:
        return set(), False
    try:
        calls = sensitive_calls(data, path=path, own=own, project=project)
    except (SyntaxError, ValueError, RecursionError):
        return set(), False
    return {c.name for c in calls}, True


def match_sdist(
    wheel: ArtifactFacts,
    read_wheel: Callable[[str], bytes],
    sdist: ArtifactFacts,
    read_sdist: Callable[[str], bytes],
    limits: Limits,
) -> SdistMatch:
    """Compare the wheel's parsed Python files and its ``.pth`` files with the sdist.

    ``read_wheel`` and ``read_sdist`` read single files back by the paths
    ``inspect_artifact`` recorded (``facts.inventory.file_reader``); only wheel
    files whose bytes aren't in the sdist are read, with their sdist copies,
    and a copy is parsed only when the wheel's file has a sensitive call.
    Raises ``ArchiveError`` when a file can't be read back.
    """
    files = {f.path: f for f in sdist.files}
    shas = {f.sha256 for f in sdist.files}
    entries = {f.path: f for f in wheel.files}
    modules = sorted(
        (m for m in wheel.modules if _in_site(site_path(m.path))), key=lambda m: m.path
    )
    sites = [site_path(m.path) for m in modules]
    prefix = find_prefix(sites, files)
    renames = find_renames(sites, files, prefix)
    own = frozenset(m.module.split(".")[0] for m in modules)
    # The sdist's own packages go by their folder names there.
    own_there = own | {d.rstrip("/").rpartition("/")[2] for d in renames.values()}
    project = project_name(wheel.filename)
    matched = differ = absent = 0
    code: list[WheelOnlyCode] = []
    for m, site in zip(modules, sites, strict=True):
        if entries[m.path].sha256 in shas:
            matched += 1
            continue
        data = read_wheel(m.path)
        if b"\r\n" in data and _sha256(_lf(data)) in shas:
            matched += 1  # built on Windows: the same file with CRLF line endings
            continue
        at = _counterpart(site, prefix, renames, files)
        theirs = read_sdist(at) if at is not None else None
        if theirs is not None and _lf(theirs) == _lf(data):
            matched += 1
            continue
        if at is None:
            absent += 1
        else:
            differ += 1
        try:
            calls = sensitive_calls(data, path=m.path, own=own, project=project)
        except (SyntaxError, ValueError, RecursionError):
            continue  # inventory parsed it once; nothing more can be said
        parsed = True
        if calls and theirs is not None and at is not None:
            known, parsed = _sdist_calls(theirs, at, own_there, project, limits)
            calls = tuple(c for c in calls if c.name not in known)
        if calls:
            code.append(WheelOnlyCode(site, at, calls, sdist_parsed=parsed))
    code += _pth_code(wheel.pth_files, entries, sdist.pth_files, shas, prefix)
    return SdistMatch(
        wheel=wheel.filename,
        sdist=sdist.filename,
        matched=matched,
        differ=differ,
        absent=absent,
        code=tuple(sorted(code, key=lambda w: w.path)),
    )


def _pth_code(
    pths: tuple[PthFile, ...],
    entries: Mapping[str, FileEntry],
    theirs: tuple[PthFile, ...],
    shas: set[str],
    prefix: str,
) -> list[WheelOnlyCode]:
    """The wheel's ``.pth`` files with no copy in the sdist, and those whose
    executable lines the sdist's copy lacks. A build often copies a ``.pth``
    to the top of the wheel from elsewhere, so a copy is looked for at the
    install path, then by name anywhere in the sdist."""
    at_path = {p.path: p for p in theirs}
    by_name: dict[str, list[PthFile]] = {}
    for p in sorted(theirs, key=lambda p: p.path):
        by_name.setdefault(p.path.rsplit("/", 1)[-1], []).append(p)
    out: list[WheelOnlyCode] = []
    for p in pths:
        if entries[p.path].sha256 in shas:
            continue
        site = site_path(p.path)
        copy = next(
            (at_path[c] for c in (prefix + site, site, "src/" + site) if c in at_path),
            None,
        ) or next(iter(by_name.get(site, ())), None)
        if copy is None:
            out.append(WheelOnlyCode(site, None, lines=p.exec_lines))
            continue
        lines = tuple(x for x in p.exec_lines if x not in copy.exec_lines)
        if lines:
            out.append(WheelOnlyCode(site, copy.path, lines=lines))
    return out
