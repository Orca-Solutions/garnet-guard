"""PyPI adapter: JSON API, Integrity API, artifacts, tags and OSV."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from packaging.requirements import InvalidRequirement
from packaging.requirements import Requirement as PackagingRequirement
from packaging.tags import sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from ..facts.inventory import file_reader, inspect_artifact, site_path, wheel_files, wheel_own
from ..facts.pyindex import sensitive_calls
from ..models import (
    MAX_DEPENDENCY_VERSIONS,
    ArtifactFacts,
    CallSite,
    DependencyInstalls,
    DependencyProfile,
    DependencyRelease,
    FactError,
    FileProvenance,
    IndexFile,
    Limits,
    ProjectReleases,
    ReleaseFacts,
    Requirement,
    TagInfo,
    UnparsedWheelFile,
    WheelCalls,
    WheelDifference,
)
from ..net import Http, NetError
from ..safe_archive import ArchiveError
from . import github, gittree, osv, source
from .provenance import verify_provenance

TRUST_RULES = ("GRN-T001", "GRN-T002", "GRN-T003", "GRN-T005", "GRN-T007")
CONTENT_RULES = ("GRN-C001", "GRN-C002", "GRN-C003", "GRN-C004", "GRN-C007")
# GRN-C009 reads only wheels, and a wheel the content rules can't read leaves
# GRN-C012 nothing to compare with.
WHEEL_RULES = (*CONTENT_RULES, "GRN-C009", "GRN-C012")


@dataclass(frozen=True)
class RegistryFile:
    """One file of a release as PyPI's JSON API lists it."""

    filename: str
    url: str
    sha256: str
    packagetype: str
    uploaded_at: datetime | None
    size: int | None = None


@dataclass(frozen=True)
class ReplayRelease:
    """Registry data for a release that is no longer listed (incident replay)."""

    files: tuple[RegistryFile, ...]
    source_repo: str | None
    note: str
    # PyPI no longer serves provenance for a removed release. False records
    # that published sources confirm no file was attested; None means unknown.
    attested: bool | None = None


@dataclass
class FetchContext:
    """What every fetch shares: the HTTP client, the limits, and the tag and
    source-tree caches."""

    http: Http
    limits: Limits
    tags: github.TagLookup
    trees: gittree.TreeLookup


def normalize(package: str) -> str:
    """PEP 503 name normalization (``Foo_Bar`` becomes ``foo-bar``)."""
    return canonicalize_name(package)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


_REPO_KEYS = ("source", "source code", "repository", "code", "github", "homepage")


def _source_repo_from_urls(info: dict[str, Any]) -> str | None:
    """The GitHub repository named in the project URLs, best-labelled key first."""
    urls = info.get("project_urls") or {}
    if not isinstance(urls, dict):
        urls = {}
    ranked = sorted(
        ((k.lower().strip(), v) for k, v in urls.items() if isinstance(v, str)),
        key=lambda kv: _REPO_KEYS.index(kv[0]) if kv[0] in _REPO_KEYS else len(_REPO_KEYS),
    )
    for _, url in ranked:
        repo = github.parse_repo(url)
        if repo:
            return repo
    home = info.get("home_page")
    return github.parse_repo(home) if isinstance(home, str) else None


def owners(data: Any) -> tuple[str, ...]:
    """The PyPI accounts with a role on the project, and its organization, from
    the JSON API's ``ownership`` (as they are today, not on the release day)."""
    own = data.get("ownership") if isinstance(data, dict) else None
    if not isinstance(own, dict):
        return ()
    out = {
        str(r["user"])
        for r in own.get("roles") or []
        if isinstance(r, dict) and isinstance(r.get("user"), str)
    }
    org = own.get("organization")
    if isinstance(org, str) and org:
        out.add(f"org:{org}")
    return tuple(sorted(out))


def select_wheel(filenames: list[str]) -> str | None:
    """SPEC §4.2: the wheel pip would install on this machine.

    pip ranks a wheel by its most specific tag this interpreter supports, so a
    platform wheel beats a pure-Python one. Content rules read the same file
    pip would install: a platform wheel added to a pure-Python project is the
    one read, not the pure wheel beside it.

    When no wheel fits this interpreter, as for a release older than it, the
    pick is a wheel for this machine's platform family, then the newest
    CPython, then x86-64, then the name (``_preference``). Two releases of a
    project are then read for the same Python where they can be: pendulum
    2.0.4's first wheel by name is a Python 2 build with no compiled code,
    while its Python 3 wheels have the extension modules 2.0.5's have.
    """
    wheels = sorted(f for f in filenames if f.endswith(".whl"))
    if not wheels:
        return None
    rank = {t: i for i, t in enumerate(sys_tags())}
    best: tuple[int, str] | None = None
    for w in wheels:
        try:
            _, _, _, wtags = parse_wheel_filename(w)
        except ValueError:
            continue
        scores = [rank[t] for t in wtags if t in rank]
        if scores and (best is None or min(scores) < best[0]):
            best = (min(scores), w)
    if best:
        return best[1]
    here = _platform_family(next(iter(sys_tags())).platform)
    return min(wheels, key=lambda w: (wheel_family(w) != here, _preference(w)))


# GRN-C012 compares the wheel Garnet read with one wheel per other platform
# family and with each wheel uploaded late, up to this many late ones.
LATE_UPLOAD = timedelta(hours=24)  # the same threshold as GRN-T006
MAX_LATE_WHEELS = 30


def wheel_family(filename: str) -> str:
    """The platform family a wheel is for: Windows, macOS, Linux, any, or the
    first part of another platform tag (android, ios, pyodide)."""
    try:
        _, _, _, tags = parse_wheel_filename(filename)
    except ValueError:
        return "unknown"
    platforms = sorted({t.platform for t in tags})
    return _platform_family(next((p for p in platforms if p != "any"), platforms[0]))


def _platform_family(platform: str) -> str:
    """The family of one platform tag, as ``wheel_family`` names it."""
    if platform == "any":
        return "any"
    if platform.startswith("win"):
        return "Windows"
    if platform.startswith("macosx"):
        return "macOS"
    if platform.startswith(("manylinux", "musllinux", "linux")):
        return "Linux"
    return platform.split("_")[0]


# A CPython or generic Python tag with a version: cp313, py3, py310. The
# uploader names the file, so ``py3x`` or ``cp3k`` can turn up; they rank last.
_PYTHON_TAG = re.compile(r"(?:cp|py)(\d)(\d*)")


def _preference(filename: str) -> tuple[int, int, int, str]:
    """Which wheel of a family stands for it: the newest CPython, then x86-64,
    then the name, so the same release always gives the same pick."""
    try:
        _, _, _, tags = parse_wheel_filename(filename)
    except ValueError:
        return (0, 0, 9, filename)
    versions = [
        (int(m[1]), int(m[2] or 0))
        for t in tags
        if (m := _PYTHON_TAG.fullmatch(t.interpreter)) is not None
    ]
    major, minor = max(versions, default=(0, 0))
    arch = 0 if any(a in t.platform for t in tags for a in ("x86_64", "amd64")) else 1
    return (-major, -minor, arch, filename)


def wheels_to_compare(
    files: tuple[RegistryFile, ...], read: str | None
) -> tuple[list[RegistryFile], list[str]]:
    """The other wheels GRN-C012 compares with the one Garnet read: one per
    platform family other than the read wheel's own, and every wheel uploaded
    more than a day after the release's first file, up to ``MAX_LATE_WHEELS``.
    Returns them in a stable order, and the late wheels left out."""
    if read is None:
        return [], []
    wheels = [f for f in files if f.filename.endswith(".whl") and f.filename != read]
    times = [f.uploaded_at for f in files if f.uploaded_at is not None]
    first = min(times, default=None)
    late = sorted(
        (
            f
            for f in wheels
            if first is not None
            and f.uploaded_at is not None
            and f.uploaded_at - first > LATE_UPLOAD
        ),
        key=lambda f: f.filename,
    )
    own = wheel_family(read)
    picks: dict[str, RegistryFile] = {}
    for f in sorted(wheels, key=lambda f: _preference(f.filename)):
        family = wheel_family(f.filename)
        if family != own and family not in picks:
            picks[family] = f
    chosen = {f.filename: f for f in [*picks.values(), *late[:MAX_LATE_WHEELS]]}
    left = [f.filename for f in late[MAX_LATE_WHEELS:] if f.filename not in chosen]
    return sorted(chosen.values(), key=lambda f: f.filename), left


def _calls(
    read: Callable[[str], bytes], rel: str, own: frozenset[str]
) -> tuple[CallSite, ...] | None:
    """The sensitive calls in one file of a wheel, or None if Garnet couldn't
    parse it: a syntax error under the Python Garnet runs on, which may be
    older than the one the wheel is for, or a file nested too deep to walk."""
    try:
        return sensitive_calls(read(rel), path=rel, own=own)
    except (SyntaxError, ValueError, RecursionError, ArchiveError):
        return None


def _read_calls(read_art: ArtifactFacts) -> dict[str, tuple[str, ...] | None]:
    """The names of the sensitive calls in each Python file of the wheel the
    content rules read, by install path; None for a file that didn't parse or
    is over the parse limit (``inspect_artifact`` reported it)."""
    known: dict[str, tuple[str, ...] | None] = {
        site_path(f.path): None for f in read_art.files if f.kind == "py"
    }
    for m in read_art.modules:
        known[site_path(m.path)] = m.sensitive
    return known


def _compare_wheels(
    ctx: FetchContext,
    others: list[RegistryFile],
    read_art: ArtifactFacts,
    read_known: dict[str, tuple[str, ...] | None],
) -> tuple[
    list[WheelDifference],
    list[WheelCalls],
    list[UnparsedWheelFile],
    dict[str, str],
    list[tuple[str, str]],
    list[FactError],
]:
    """Download each wheel in ``others`` and find its Python files that differ
    from the read wheel's, keeping those with sensitive calls the read copy
    lacks (``read_known``, from ``_read_calls``). Returns the differences, the
    calls each Python file of the compared wheels makes (the next version
    compares with them), the differing files Garnet couldn't parse, the
    downloaded hash of each other wheel (for GRN-T008), the (filename, family)
    of each wheel compared, and errors.

    A differing file that is over the parse limit is GRN-E003 naming GRN-C012.
    One Garnet couldn't parse is GRN-E002 when it is new or changed since the
    trusted version's wheels of the family, which the check decides."""
    reference = {site_path(f.path): f for f in read_art.files if f.kind == "py"}
    # The read wheel says which packages are the release's own: an extra
    # top-level module in another wheel doesn't make calls into it the package's.
    own = wheel_own([f.path for f in read_art.files])
    diffs: list[WheelDifference] = []
    seen: list[WheelCalls] = []
    unparsed: list[UnparsedWheelFile] = []
    digests: dict[str, str] = {}
    compared: list[tuple[str, str]] = []
    errors: list[FactError] = []
    for f in others:
        try:
            resp = ctx.http.get(f.url, max_bytes=ctx.limits.max_artifact_bytes)
        except NetError as err:
            errors.append(FactError("GRN-E001", f"download {f.filename}: {err}", ("GRN-C012",)))
            continue
        if resp.status != 200:
            msg = f"download {f.filename}: HTTP {resp.status}"
            errors.append(FactError("GRN-E001", msg, ("GRN-C012",)))
            continue
        digest = hashlib.sha256(resp.content).hexdigest()
        digests[f.filename] = digest
        if digest != f.sha256.lower():
            continue  # GRN-T008 reports it
        listed, _, errs = wheel_files(f.filename, resp.content, ctx.limits)
        errors.extend(errs)
        if errs:
            continue
        family = wheel_family(f.filename)
        compared.append((f.filename, family))
        read_other = file_reader(f.filename, resp.content, ctx.limits, sdist=False)
        for entry in listed:
            if entry.kind != "py":
                continue
            site = site_path(entry.path)
            ref = reference.get(site)
            if ref is not None and ref.sha256 == entry.sha256:
                if read_known.get(site) != ():
                    seen.append(WheelCalls(family, site, read_known.get(site), entry.sha256))
                continue
            if entry.size > ctx.limits.max_py_file_bytes:
                msg = f"{f.filename}: {entry.path} is larger than the parse limit"
                errors.append(FactError("GRN-E003", msg, ("GRN-C012",), entry.path))
                seen.append(WheelCalls(family, site, None, entry.sha256))
                continue
            calls = _calls(read_other, entry.path, own)
            if calls is None:
                unparsed.append(UnparsedWheelFile(f.filename, family, entry.path, entry.sha256))
                seen.append(WheelCalls(family, site, None, entry.sha256))
                continue
            if calls:
                names = tuple(sorted({c.name for c in calls}))
                seen.append(WheelCalls(family, site, names, entry.sha256))
            known = read_known.get(site) if ref is not None else ()
            new = tuple(c for c in calls if known is None or c.name not in known)
            if new:
                diffs.append(
                    WheelDifference(
                        f.filename, family, site, ref is not None, new, known is not None
                    )
                )
    return diffs, seen, unparsed, digests, compared, errors


def _fetch_provenance(
    ctx: FetchContext, package: str, version: str, f: RegistryFile
) -> FileProvenance:
    url = f"https://pypi.org/integrity/{package}/{version}/{f.filename}/provenance"
    resp = ctx.http.get(url, headers={"Accept": "application/vnd.pypi.integrity.v1+json"})
    if resp.status == 404:
        return FileProvenance(filename=f.filename, present=False, verified=False)
    if resp.status != 200:
        raise NetError(f"Integrity API returned HTTP {resp.status} for {f.filename}")
    return verify_provenance(f.filename, f.sha256, resp.content)


def release_facts(
    package: str,
    version: str,
    ctx: FetchContext,
    *,
    replay: ReplayRelease | None = None,
    advisories: bool = True,
) -> ReleaseFacts:
    """Fetch and inspect one PyPI release.

    In order: registry metadata (JSON API), provenance for every file
    (Integrity API), the contents of the sdist and one wheel, the git tag, and
    OSV advisories when ``advisories`` is true. A network failure in any step
    becomes a ``FactError`` naming the rules it kept from running. ``replay``
    supplies registry data for a release PyPI no longer lists.
    """
    name = normalize(package)
    errors: list[FactError] = []
    notes: list[str] = []
    yanked = False
    owned_by: tuple[str, ...] = ()

    if replay is None:
        try:
            resp = ctx.http.get(f"https://pypi.org/pypi/{name}/{version}/json")
        except NetError as err:
            return _unfetchable(name, version, str(err))
        if resp.status == 404:
            return _unfetchable(name, version, f"PyPI has no release {name} {version}")
        if resp.status != 200:
            return _unfetchable(name, version, f"PyPI JSON API returned HTTP {resp.status}")
        data = resp.json()
        info = data.get("info", {})
        yanked = bool(info.get("yanked"))
        owned_by = owners(data)
        files = tuple(
            RegistryFile(
                filename=u["filename"],
                url=u["url"],
                sha256=u["digests"]["sha256"],
                packagetype=u.get("packagetype", ""),
                uploaded_at=_parse_time(u.get("upload_time_iso_8601")),
                size=u.get("size") if isinstance(u.get("size"), int) else None,
            )
            for u in data.get("urls", [])
        )
        source_repo = _source_repo_from_urls(info)
    else:
        files = replay.files
        source_repo = replay.source_repo
        notes.append(replay.note)

    if not files:
        errors.append(FactError("GRN-E001", "release has no files", (*TRUST_RULES, *WHEEL_RULES)))

    # Trust facts for every artifact.
    provenance: dict[str, FileProvenance | None] = {}
    for f in files:
        if replay is not None:
            provenance[f.filename] = (
                FileProvenance(filename=f.filename, present=False, verified=False)
                if replay.attested is False
                else None
            )
            continue
        try:
            provenance[f.filename] = _fetch_provenance(ctx, name, version, f)
        except NetError as err:
            provenance[f.filename] = None
            errors.append(FactError("GRN-E001", f"provenance for {f.filename}: {err}", TRUST_RULES))

    # Content facts for the sdist and one wheel.
    sdists = sorted(f.filename for f in files if f.packagetype == "sdist")
    wheel = select_wheel([f.filename for f in files])
    selected = {s for s in sdists[:1]} | ({wheel} if wheel else set())

    artifacts: list[ArtifactFacts] = []
    payloads: dict[str, tuple[bytes, bool]] = {}  # inspected bytes, kept for GRN-C007
    read_whole = False  # every file of the read wheel was read
    for f in sorted(files, key=lambda x: x.filename):
        art = ArtifactFacts(
            filename=f.filename,
            sha256=f.sha256,
            packagetype=f.packagetype,
            uploaded_at=f.uploaded_at,
            provenance=provenance.get(f.filename),
        )
        if f.filename in selected:
            art, errs, payload, whole = _inspect(ctx, f, art)
            errors.extend(errs)
            if payload is not None:
                payloads[f.filename] = (payload, f.packagetype == "sdist")
            if f.filename == wheel:
                read_whole = payload is not None and whole
        artifacts.append(art)

    # The attested repository beats project URLs, which anyone can edit.
    url_repo = source_repo
    for p in provenance.values():
        if p is not None and p.verified and (p.repository or "").startswith("github.com/"):
            source_repo = (p.repository or "")[len("github.com/") :]
            break

    # Look for the tag in the attested repository, then the project URL's:
    # projects that publish from a separate release repository (scipy) tag
    # the main one.
    tag_repos = tuple(dict.fromkeys(r for r in (source_repo, url_repo) if r))
    tag = None
    version_tags: list[TagInfo] = []  # every tag naming the version, ``tag`` first
    tag_checked = False
    tag_errors: list[FactError] = []
    for repo in tag_repos:
        try:
            version_tags = github.matching_tags(ctx.tags.tags(repo), name, version, repo)
        except NetError as err:
            tag_errors.append(FactError("GRN-E001", f"tag lookup: {err}", ("GRN-T004",)))
            continue
        if version_tags:
            tag = version_tags[0]
            break
    if tag is not None:
        tag_checked = True
    elif tag_repos and not tag_errors:
        tag_checked = True
    else:
        errors.extend(tag_errors)

    # GRN-C007: are the release's Python files the ones at the tag? The wheel
    # is what gets installed; the sdist stands in when there is no wheel.
    if tag is not None and tag.sha and tag.repo:
        for i, art in enumerate(artifacts):
            if not art.inspected or art.downloaded_sha256 != art.sha256.lower():
                continue
            if not (
                art.filename.endswith(".whl") or (wheel is None and art.packagetype == "sdist")
            ):
                continue
            data, is_sdist = payloads[art.filename]
            source_of = file_reader(art.filename, data, ctx.limits, sdist=is_sdist)
            try:
                match = source.match_tags(ctx.trees, version_tags, art, source_of)
            except NetError as err:
                errors.append(
                    FactError("GRN-E001", f"source at tag {tag.name}: {err}", ("GRN-C007",))
                )
                break
            except ArchiveError as err:
                errors.append(FactError("GRN-E001", f"{art.filename}: {err}", ("GRN-C007",)))
                break
            if match.unchecked:
                errors.append(
                    FactError(
                        "GRN-E001",
                        f"{len(match.unchecked)} file(s) in {art.filename} come from a submodule "
                        f"Garnet couldn't read: {', '.join(match.unchecked[:5])}",
                        ("GRN-C007",),
                    )
                )
            artifacts[i] = replace(art, source_match=match)
            break

    # GRN-C012: the release's other wheels, one per platform family and each
    # late one, compared file by file with the wheel the content rules read.
    # The read wheel's calls are kept even with nothing to compare, for the
    # next version: its wheel for this platform may not be the one read.
    differences: list[WheelDifference] = []
    compared: list[tuple[str, str]] = []
    seen: list[WheelCalls] = []
    unparsed: list[UnparsedWheelFile] = []
    read_family = None
    others, not_compared = wheels_to_compare(files, wheel)
    read_art = next((a for a in artifacts if a.filename == wheel), None)
    if (
        read_art is not None
        and read_whole
        and read_art.downloaded_sha256 == read_art.sha256.lower()
    ):
        read_family = wheel_family(read_art.filename)
        read_known = _read_calls(read_art)
        shas = {site_path(f.path): f.sha256 for f in read_art.files}
        seen = [WheelCalls(read_family, p, n, shas[p]) for p, n in read_known.items() if n != ()]
        if others:
            differences, more, unparsed, digests, compared, errs = _compare_wheels(
                ctx, others, read_art, read_known
            )
            seen += more
            errors.extend(errs)
            artifacts = [
                replace(a, downloaded_sha256=digests[a.filename]) if a.filename in digests else a
                for a in artifacts
            ]
    else:
        not_compared = []
    payloads.clear()

    mal: tuple[str, ...] = ()
    advisories_checked = False
    if advisories:
        try:
            mal = osv.malicious_advisories(ctx.http, "pypi", name, version)
            advisories_checked = True
        except NetError as err:
            errors.append(FactError("GRN-E001", f"OSV lookup: {err}", ("GRN-K001",)))

    return ReleaseFacts(
        ecosystem="pypi",
        package=name,
        version=version,
        yanked=yanked,
        artifacts=tuple(artifacts),
        source_repo=source_repo,
        tag=tag,
        tag_checked=tag_checked,
        tag_repos=tag_repos,
        advisories=mal,
        advisories_checked=advisories_checked,
        errors=tuple(errors),
        notes=tuple(notes),
        owners=owned_by,
        wheel_differences=tuple(differences),
        wheels_compared=tuple(compared),
        wheels_not_compared=tuple(not_compared),
        wheel_families=tuple(
            sorted({wheel_family(f.filename) for f in files if f.filename.endswith(".whl")})
        ),
        wheel_calls=tuple(
            sorted(seen, key=lambda w: (w.family, w.path, w.names is None, w.names or (), w.sha256))
        ),
        read_wheel_family=read_family,
        wheel_unparsed=tuple(sorted(unparsed, key=lambda u: (u.wheel, u.path))),
    )


def _inspect(
    ctx: FetchContext, f: RegistryFile, art: ArtifactFacts
) -> tuple[ArtifactFacts, list[FactError], bytes | None, bool]:
    """Download one artifact, check its hash, then read its contents.

    A file whose hash doesn't match the registry's is not read; GRN-T008
    reports it. The bytes come back with the facts when they were read, so
    GRN-C007 can look at single files again after the tag lookup, and with
    whether every file in the archive was read.
    """
    rules = CONTENT_RULES if f.packagetype == "sdist" else WHEEL_RULES
    try:
        resp = ctx.http.get(f.url, max_bytes=ctx.limits.max_artifact_bytes)
    except NetError as err:
        return art, [FactError("GRN-E001", f"download {f.filename}: {err}", rules)], None, False
    if resp.status != 200:
        msg = f"download {f.filename}: HTTP {resp.status}"
        return art, [FactError("GRN-E001", msg, rules)], None, False
    digest = hashlib.sha256(resp.content).hexdigest()
    if digest != f.sha256.lower():
        return replace(art, inspected=True, downloaded_sha256=digest), [], None, False
    ins = inspect_artifact(f.filename, resp.content, ctx.limits, sdist=f.packagetype == "sdist")
    wheel_tag = None
    if f.filename.endswith(".whl"):
        try:
            _, _, _, wtags = parse_wheel_filename(f.filename)
            wheel_tag = ".".join(sorted(str(t) for t in wtags))
        except ValueError:
            pass
    return (
        replace(
            art,
            inspected=True,
            downloaded_sha256=digest,
            files=tuple(ins.files),
            modules=tuple(ins.modules),
            pth_files=tuple(ins.pth_files),
            build_backend=ins.build_backend,
            setup_py_calls=ins.setup_py_calls,
            entry_points=tuple(sorted(ins.entry_points)),
            entry_point_specs=ins.entry_point_specs,
            entry_points_read=ins.entry_points_read,
            unparsed=tuple(ins.unparsed),
            wheel_tag=wheel_tag,
            requirements=ins.requirements,
            requirements_read=ins.requirements_read,
        ),
        ins.errors,
        resp.content,
        ins.complete,
    )


PROFILE_MAX_BYTES = 64 * 1024 * 1024  # a project with thousands of files lists them all


def package_profile(ctx: FetchContext, package: str) -> DependencyProfile:
    """What PyPI says about a package (GRN-C008): when its first file was
    uploaded, how many releases have files, and its repository. Raises
    ``NetError``; a project PyPI doesn't know is ``on_registry=False``.
    """
    name = normalize(package)
    resp = ctx.http.get(f"https://pypi.org/pypi/{name}/json", max_bytes=PROFILE_MAX_BYTES)
    if resp.status == 404:
        return DependencyProfile(name, on_registry=False)
    if resp.status != 200:
        raise NetError(f"PyPI JSON API returned HTTP {resp.status} for {name}")
    data = resp.json()
    info = data.get("info") if isinstance(data, dict) else None
    releases = data.get("releases") if isinstance(data, dict) else None
    if not isinstance(info, dict):
        info = {}
    if not isinstance(releases, dict):
        releases = {}
    times = [
        t
        for files in releases.values()
        if isinstance(files, list)
        for f in files
        if isinstance(f, dict) and (t := _parse_time(f.get("upload_time_iso_8601")))
    ]
    latest = info.get("version")
    return DependencyProfile(
        name,
        on_registry=True,
        first_release_at=min(times) if times else None,
        releases=sum(1 for files in releases.values() if isinstance(files, list) and files),
        source_repo=_source_repo_from_urls(info),
        latest_version=latest if isinstance(latest, str) else None,
        owners=owners(data),
    )


# A young dependency's release is read only when it ships at most this many
# wheels; one with more stays at the rule's severity, with a note.
MAX_DEPENDENCY_WHEELS = 10


def _registry_files(entries: Any) -> list[RegistryFile]:
    """The files of one release as the JSON API's ``releases`` table lists them."""
    out = []
    for u in entries if isinstance(entries, list) else []:
        if not isinstance(u, dict):
            continue
        digests = u.get("digests")
        sha = digests.get("sha256") if isinstance(digests, dict) else None
        if not (isinstance(u.get("filename"), str) and isinstance(u.get("url"), str) and sha):
            continue
        out.append(
            RegistryFile(
                filename=u["filename"],
                url=u["url"],
                sha256=str(sha),
                packagetype=str(u.get("packagetype", "")),
                uploaded_at=_parse_time(u.get("upload_time_iso_8601")),
                size=u.get("size") if isinstance(u.get("size"), int) else None,
            )
        )
    return sorted(out, key=lambda f: f.filename)


def _requires_python(entries: Any) -> tuple[str, ...]:
    """The distinct Requires-Python values of a release's files."""
    found = {
        u["requires_python"].strip()
        for u in (entries if isinstance(entries, list) else [])
        if isinstance(u, dict) and isinstance(u.get("requires_python"), str)
    }
    return tuple(sorted(v for v in found if v))


# Modules Python imports at every start when they are on the path, in any
# form: sitecustomize.py, a sitecustomize/ package, a .pyc, an extension
# module (.so, .pyd, abi3). Matched by top-level module name, any case.
_STARTUP_MODULES = frozenset({"sitecustomize", "usercustomize"})
_DATA_DATA = re.compile(r"^[^/]+\.data/data/", re.IGNORECASE)


def _module_name(part: str) -> str:
    """The module a top-level file or folder name imports as: the text
    before the first dot, lowercased."""
    return part.split(".", 1)[0].lower()


def _startup_file(path: str) -> bool:
    """A wheel file that Python reads or runs at every start once installed:
    a .pth file in site-packages itself, or anything that imports as
    sitecustomize or usercustomize from there (a module, a package, a .pyc,
    an extension module), including under ``.data/purelib/`` and
    ``platlib/``, and any of those anywhere under ``.data/data/``, which
    installs relative to the environment and can land in site-packages
    (``lib/python3.12/site-packages/x.pth``)."""
    if _DATA_DATA.match(path):
        parts = path.split("/")[2:]
        return parts[-1].lower().endswith(".pth") or any(
            _module_name(p) in _STARTUP_MODULES for p in parts
        )
    site = site_path(path)
    parts = site.split("/")
    if len(parts) == 1 and parts[0].lower().endswith(".pth"):
        return True
    if _module_name(parts[0]) in _STARTUP_MODULES:
        return True
    # a sourceless __pycache__/sitecustomize.cpython-312.pyc at the top
    return (
        len(parts) == 2 and parts[0] == "__pycache__" and _module_name(parts[1]) in _STARTUP_MODULES
    )


def dependency_installs(
    ctx: FetchContext, req: Requirement, pinned: tuple[str, ...] = ()
) -> DependencyInstalls:
    """The releases of a new dependency that GRN-C008 reads, each with
    ``_dependency_release``: the versions a lockfile pins (``pinned``), else
    every version with a file on PyPI that the requirement's specifier
    admits, prereleases included, whenever it was uploaded. More than
    ``MAX_DEPENDENCY_VERSIONS`` aren't read. Raises ``NetError`` when a
    request fails; anything else that stops the read is in ``problem``.
    """
    name = normalize(req.package)
    out = DependencyInstalls(name, req.spec, pinned=bool(pinned))
    try:
        specifier = PackagingRequirement(req.spec).specifier
    except InvalidRequirement:
        return replace(out, problem=f"Garnet can't read the requirement {req.spec!r}")
    resp = ctx.http.get(f"https://pypi.org/pypi/{name}/json", max_bytes=PROFILE_MAX_BYTES)
    if resp.status == 404:
        return replace(out, problem=f"PyPI has no project {name}")
    if resp.status != 200:
        raise NetError(f"PyPI JSON API returned HTTP {resp.status} for {name}")
    data = resp.json()
    releases = data.get("releases") if isinstance(data, dict) else None
    if not isinstance(releases, dict):
        releases = {}
    # Every version with a file, by PEP 440 version: a lockfile may spell one
    # differently (1.0 and 1.0.0 are one release).
    listed: dict[Version, str] = {}
    for raw, entries in releases.items():
        if not _registry_files(entries):
            continue
        try:
            listed[Version(raw)] = raw
        except InvalidVersion:
            continue
    if pinned:
        wanted = []
        for pin in sorted(set(pinned)):
            try:
                raw = listed.get(Version(pin))
            except InvalidVersion:
                raw = None
            if raw is None:
                return replace(
                    out, problem=f"the lockfile pins {name} {pin}, which PyPI doesn't list"
                )
            wanted.append(raw)
    else:
        # Every release the specifier admits, prereleases and yanked ones too
        # and whenever uploaded: what installs depends on the installer and
        # its options (pip's yanked fallback, uv's lowest resolution).
        matching = sorted(specifier.filter(listed, prereleases=True))
        if not matching:
            return replace(out, problem=f"no version of {name} matches {specifier or 'any'}")
        wanted = [listed[v] for v in matching]
    if len(wanted) > MAX_DEPENDENCY_VERSIONS:
        return replace(
            out,
            problem=f"{len(wanted)} versions of {name} could install ({wanted[0]} to "
            f"{wanted[-1]}); Garnet reads a young dependency's releases only up to "
            f"{MAX_DEPENDENCY_VERSIONS}",
        )
    return replace(
        out,
        releases=tuple(_dependency_release(ctx, name, v, releases.get(v)) for v in wanted),
    )


def _dependency_release(
    ctx: FetchContext, name: str, version: str, entries: Any
) -> DependencyRelease:
    """One release of a new dependency: its files and their Requires-Python,
    each wheel's file list (never its code) for files Python reads at every
    start, and each file's PEP 740 provenance. Raises ``NetError``."""
    files = _registry_files(entries)
    out = DependencyRelease(
        name,
        version,
        files=tuple(f.filename for f in files),
        requires_python=_requires_python(entries),
    )
    out = replace(out, provenance=tuple(_fetch_provenance(ctx, name, version, f) for f in files))
    wheels = [f for f in files if f.filename.lower().endswith(".whl")]
    if len(wheels) > MAX_DEPENDENCY_WHEELS:
        return replace(
            out,
            problem=f"{name} {version} has {len(wheels)} wheels; Garnet reads a young "
            f"dependency's wheels only up to {MAX_DEPENDENCY_WHEELS}",
        )
    startup: list[str] = []
    for f in wheels:
        got = ctx.http.get(f.url, max_bytes=ctx.limits.max_artifact_bytes)
        if got.status != 200:
            raise NetError(f"download {f.filename}: HTTP {got.status}")
        if hashlib.sha256(got.content).hexdigest() != f.sha256.lower():
            return replace(out, problem=f"{f.filename} doesn't match PyPI's sha256")
        listed, _, errs = wheel_files(f.filename, got.content, ctx.limits)
        if errs:
            return replace(out, problem=errs[0].summary)
        startup += [f"{f.filename}: {e.path}" for e in listed if _startup_file(e.path)]
    return replace(out, wheels_read=tuple(f.filename for f in wheels), startup_files=tuple(startup))


def project_releases(ctx: FetchContext, package: str) -> ProjectReleases:
    """Every release PyPI lists for a project, with each file's type,
    Requires-Python and yanked flag (the install wrapper's newest-release
    check). Raises ``NetError``; a project PyPI doesn't know is
    ``on_registry=False``.
    """
    name = normalize(package)
    resp = ctx.http.get(f"https://pypi.org/pypi/{name}/json", max_bytes=PROFILE_MAX_BYTES)
    if resp.status == 404:
        return ProjectReleases(name, on_registry=False)
    if resp.status != 200:
        raise NetError(f"PyPI JSON API returned HTTP {resp.status} for {name}")
    data = resp.json()
    releases = data.get("releases") if isinstance(data, dict) else None
    if not isinstance(releases, dict):
        releases = {}
    out: list[tuple[str, tuple[IndexFile, ...]]] = []
    for version, files in sorted(releases.items()):
        if not isinstance(files, list):
            continue
        listed = tuple(
            IndexFile(
                str(f.get("filename", "")),
                str(f.get("packagetype", "")),
                f["requires_python"] if isinstance(f.get("requires_python"), str) else None,
                bool(f.get("yanked")),
            )
            for f in files
            if isinstance(f, dict)
        )
        out.append((str(version), listed))
    return ProjectReleases(name, on_registry=True, releases=tuple(out))


def _unfetchable(name: str, version: str, why: str) -> ReleaseFacts:
    """Facts for a release Garnet couldn't fetch at all: one GRN-E001 naming every rule."""
    return ReleaseFacts(
        ecosystem="pypi",
        package=name,
        version=version,
        yanked=False,
        artifacts=(),
        errors=(
            FactError(
                "GRN-E001",
                why,
                (*TRUST_RULES, "GRN-T004", *WHEEL_RULES, "GRN-K001"),
            ),
        ),
    )
