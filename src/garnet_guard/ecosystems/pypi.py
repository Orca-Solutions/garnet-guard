"""PyPI adapter: JSON API, Integrity API, artifacts, tags and OSV."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from packaging.tags import sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename

from ..facts.inventory import file_reader, inspect_artifact, site_path, wheel_files
from ..facts.pyindex import sensitive_calls
from ..models import (
    ArtifactFacts,
    CallSite,
    DependencyProfile,
    FactError,
    FileProvenance,
    Limits,
    ReleaseFacts,
    WheelDifference,
)
from ..net import Http, NetError
from ..safe_archive import ArchiveError
from . import github, gittree, osv, source
from .provenance import verify_provenance

TRUST_RULES = ("GRN-T001", "GRN-T002", "GRN-T003", "GRN-T005", "GRN-T007")
CONTENT_RULES = ("GRN-C001", "GRN-C002", "GRN-C003", "GRN-C004", "GRN-C007")


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
    """SPEC §4.2: the wheel pip would install on this machine, else the first sorted.

    pip ranks a wheel by its most specific tag this interpreter supports, so a
    platform wheel beats a pure-Python one. Content rules read the same file
    pip would install: a platform wheel added to a pure-Python project is the
    one read, not the pure wheel beside it.
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
    return best[1] if best else wheels[0]


# GRN-C012 compares the wheel Garnet read with one wheel per other platform
# family and with each wheel uploaded late, up to this many late ones.
LATE_UPLOAD = timedelta(hours=24)  # the same threshold as GRN-T006
MAX_LATE_WHEELS = 10


def wheel_family(filename: str) -> str:
    """The platform family a wheel is for: Windows, macOS, Linux, any, or the
    first part of another platform tag (android, ios, pyodide)."""
    try:
        _, _, _, tags = parse_wheel_filename(filename)
    except ValueError:
        return "unknown"
    platforms = sorted({t.platform for t in tags})
    if platforms == ["any"]:
        return "any"
    first = next((p for p in platforms if p != "any"), platforms[0])
    if first.startswith("win"):
        return "Windows"
    if first.startswith("macosx"):
        return "macOS"
    if first.startswith(("manylinux", "musllinux", "linux")):
        return "Linux"
    return first.split("_")[0]


def _preference(filename: str) -> tuple[int, int, int, str]:
    """Which wheel of a family stands for it: the newest CPython, then x86-64,
    then the name, so the same release always gives the same pick."""
    try:
        _, _, _, tags = parse_wheel_filename(filename)
    except ValueError:
        return (0, 0, 9, filename)
    versions = [
        (int(t.interpreter[2]), int(t.interpreter[3:] or 0))
        for t in tags
        if t.interpreter[:2] in ("cp", "py") and t.interpreter[2:3].isdigit()
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
    """The sensitive calls in one file of a wheel, or None if it doesn't parse."""
    try:
        return sensitive_calls(read(rel), path=rel, own=own)
    except (SyntaxError, ValueError, RecursionError, ArchiveError):
        return None


def _compare_wheels(
    ctx: FetchContext,
    others: list[RegistryFile],
    read_art: ArtifactFacts,
    read_bytes: bytes,
) -> tuple[list[WheelDifference], dict[str, str], list[tuple[str, str]], list[FactError]]:
    """Download each wheel in ``others`` and find its Python files that differ
    from the read wheel's, keeping those with sensitive calls the read copy
    lacks. Returns the differences, the downloaded hash of each other wheel
    (for GRN-T008), the (filename, family) of each wheel compared, and errors."""
    reference = {site_path(f.path): f for f in read_art.files if f.kind == "py"}
    read_ref = file_reader(read_art.filename, read_bytes, ctx.limits, sdist=False)
    ref_own = frozenset(m.module.split(".")[0] for m in read_art.modules)
    ref_names: dict[str, set[str] | None] = {}  # None: the read copy doesn't parse
    diffs: list[WheelDifference] = []
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
        listed, own, errs = wheel_files(f.filename, resp.content, ctx.limits)
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
                continue
            calls = _calls(read_other, entry.path, own)
            if not calls:
                continue  # none, or Python can't compile it, so it can't run either
            if ref is not None and site not in ref_names:
                ref_calls = _calls(read_ref, ref.path, ref_own)
                ref_names[site] = None if ref_calls is None else {c.name for c in ref_calls}
            known = ref_names.get(site, set())
            new = tuple(c for c in calls if known is None or c.name not in known)
            if new:
                diffs.append(
                    WheelDifference(
                        f.filename, family, site, ref is not None, new, known is not None
                    )
                )
    return diffs, digests, compared, errors


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
        errors.append(FactError("GRN-E001", "release has no files", (*TRUST_RULES, *CONTENT_RULES)))

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
    for f in sorted(files, key=lambda x: x.filename):
        art = ArtifactFacts(
            filename=f.filename,
            sha256=f.sha256,
            packagetype=f.packagetype,
            uploaded_at=f.uploaded_at,
            provenance=provenance.get(f.filename),
        )
        if f.filename in selected:
            art, errs, payload = _inspect(ctx, f, art)
            errors.extend(errs)
            if payload is not None:
                payloads[f.filename] = (payload, f.packagetype == "sdist")
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
    tag_checked = False
    tag_errors: list[FactError] = []
    for repo in tag_repos:
        try:
            tag = github.match_tag(ctx.tags.tags(repo), name, version, repo)
        except NetError as err:
            tag_errors.append(FactError("GRN-E001", f"tag lookup: {err}", ("GRN-T004",)))
            continue
        if tag is not None:
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
                match = source.match_artifact(ctx.trees, tag, art, source_of)
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
    differences: list[WheelDifference] = []
    compared: list[tuple[str, str]] = []
    others, not_compared = wheels_to_compare(files, wheel)
    read_art = next((a for a in artifacts if a.filename == wheel), None)
    if (
        others
        and read_art is not None
        and wheel in payloads
        and read_art.downloaded_sha256 == read_art.sha256.lower()
    ):
        differences, digests, compared, errs = _compare_wheels(
            ctx, others, read_art, payloads[wheel][0]
        )
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
    )


def _inspect(
    ctx: FetchContext, f: RegistryFile, art: ArtifactFacts
) -> tuple[ArtifactFacts, list[FactError], bytes | None]:
    """Download one artifact, check its hash, then read its contents.

    A file whose hash doesn't match the registry's is not read; GRN-T008
    reports it. The bytes come back with the facts when they were read, so
    GRN-C007 can look at single files again after the tag lookup.
    """
    try:
        resp = ctx.http.get(f.url, max_bytes=ctx.limits.max_artifact_bytes)
    except NetError as err:
        return art, [FactError("GRN-E001", f"download {f.filename}: {err}", CONTENT_RULES)], None
    if resp.status != 200:
        msg = f"download {f.filename}: HTTP {resp.status}"
        return art, [FactError("GRN-E001", msg, CONTENT_RULES)], None
    digest = hashlib.sha256(resp.content).hexdigest()
    if digest != f.sha256.lower():
        return replace(art, inspected=True, downloaded_sha256=digest), [], None
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
            unparsed=tuple(ins.unparsed),
            wheel_tag=wheel_tag,
            requirements=ins.requirements,
            requirements_read=ins.requirements_read,
        ),
        ins.errors,
        resp.content,
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
                (*TRUST_RULES, "GRN-T004", *CONTENT_RULES, "GRN-K001"),
            ),
        ),
    )
