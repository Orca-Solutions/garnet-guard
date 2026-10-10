"""PyPI adapter: JSON API, Integrity API, artifacts, tags and OSV."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from packaging.tags import sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename

from ..facts.inventory import inspect_artifact
from ..models import ArtifactFacts, FactError, FileProvenance, Limits, ReleaseFacts
from ..net import Http, NetError
from . import github, osv
from .provenance import verify_provenance

TRUST_RULES = ("GRN-T001", "GRN-T002", "GRN-T003", "GRN-T005", "GRN-T007")
CONTENT_RULES = ("GRN-C001", "GRN-C002", "GRN-C003")


@dataclass(frozen=True)
class RegistryFile:
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


@dataclass
class FetchContext:
    http: Http
    limits: Limits
    tags: github.TagLookup


def normalize(package: str) -> str:
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


def select_wheel(filenames: list[str]) -> str | None:
    """SPEC §4.2: pure-Python wheel, else one for this platform, else first sorted."""
    wheels = sorted(f for f in filenames if f.endswith(".whl"))
    if not wheels:
        return None
    for w in wheels:
        if w.endswith("-py3-none-any.whl") or w.endswith("-py2.py3-none-any.whl"):
            return w
    supported = list(sys_tags())
    rank = {t: i for i, t in enumerate(supported)}
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
    name = normalize(package)
    errors: list[FactError] = []
    notes: list[str] = []
    yanked = False

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
            provenance[f.filename] = None
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
    for f in sorted(files, key=lambda x: x.filename):
        art = ArtifactFacts(
            filename=f.filename,
            sha256=f.sha256,
            packagetype=f.packagetype,
            uploaded_at=f.uploaded_at,
            provenance=provenance.get(f.filename),
        )
        if f.filename in selected:
            art, errs = _inspect(ctx, f, art)
            errors.extend(errs)
        artifacts.append(art)

    # The attested repository beats project URLs, which anyone can edit.
    for p in provenance.values():
        if p is not None and p.verified and (p.repository or "").startswith("github.com/"):
            source_repo = (p.repository or "")[len("github.com/") :]
            break

    tag = None
    tag_checked = False
    if source_repo:
        try:
            tag = github.match_tag(ctx.tags.tags(source_repo), name, version)
            tag_checked = True
        except NetError as err:
            errors.append(FactError("GRN-E001", f"tag lookup: {err}", ("GRN-T004",)))

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
        advisories=mal,
        advisories_checked=advisories_checked,
        errors=tuple(errors),
        notes=tuple(notes),
    )


def _inspect(
    ctx: FetchContext, f: RegistryFile, art: ArtifactFacts
) -> tuple[ArtifactFacts, list[FactError]]:
    try:
        resp = ctx.http.get(f.url, max_bytes=ctx.limits.max_artifact_bytes)
    except NetError as err:
        return art, [FactError("GRN-E001", f"download {f.filename}: {err}", CONTENT_RULES)]
    if resp.status != 200:
        msg = f"download {f.filename}: HTTP {resp.status}"
        return art, [FactError("GRN-E001", msg, CONTENT_RULES)]
    digest = hashlib.sha256(resp.content).hexdigest()
    if digest != f.sha256.lower():
        return replace(art, inspected=True, downloaded_sha256=digest), []
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
            unparsed=tuple(ins.unparsed),
            wheel_tag=wheel_tag,
        ),
        ins.errors,
    )


def _unfetchable(name: str, version: str, why: str) -> ReleaseFacts:
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
