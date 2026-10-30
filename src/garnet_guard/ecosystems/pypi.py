"""PyPI adapter: JSON API, Integrity API, artifacts, tags and OSV."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from packaging.tags import sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename

from ..facts.inventory import file_reader, inspect_artifact
from ..models import (
    ArtifactFacts,
    DependencyProfile,
    FactError,
    FileProvenance,
    Limits,
    ReleaseFacts,
)
from ..net import Http, NetError
from ..safe_archive import ArchiveError
from . import github, gittree, osv, source
from .provenance import verify_provenance

TRUST_RULES = ("GRN-T001", "GRN-T002", "GRN-T003", "GRN-T005", "GRN-T007")
CONTENT_RULES = ("GRN-C001", "GRN-C002", "GRN-C003", "GRN-C007")


@dataclass(frozen=True)
class RegistryFile:
    """One file of a release as PyPI's JSON API lists it."""

    filename: str
    url: str
    sha256: str
    packagetype: str
    uploaded_at: datetime | None


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
