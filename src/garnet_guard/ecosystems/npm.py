"""npm adapter: registry packument, attestations, the tarball, tags and OSV."""

from __future__ import annotations

import base64
import hashlib
import json
import posixpath
import re
import threading
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlsplit

from ..facts.npmmeta import INSTALL_SCRIPTS, inspect_tarball, install_hooks, install_scripts
from ..models import (
    MAX_DEPENDENCY_VERSIONS,
    ArtifactFacts,
    DependencyInstalls,
    DependencyProfile,
    DependencyRelease,
    FactError,
    FileProvenance,
    Limits,
    ReleaseFacts,
    Requirement,
)
from ..net import Http, NetError
from . import github, npm_range, osv
from .npm_provenance import verify_provenance

REGISTRY = "https://registry.npmjs.org"
TRUST_RULES = ("GRN-T001", "GRN-T002", "GRN-T003", "GRN-T005", "GRN-T007")
CONTENT_RULES = ("GRN-C002", "GRN-C011")
PACKUMENT_MAX_BYTES = 64 * 1024 * 1024  # the largest packuments are tens of MB


@dataclass(frozen=True)
class ReplayRelease:
    """Recorded registry facts for a release npm has removed (incident replay).

    npm deletes the tarball of a removed version, so the content can't be
    fetched; ``scripts`` records the package.json scripts public write-ups
    reported, and ``attestation`` whether the registry record had provenance.
    """

    uploaded_at: datetime | None
    attestation: bool
    trusted_publisher: bool | None
    scripts: tuple[tuple[str, str], ...]
    source_repo: str | None
    note: str
    # The package.json dependencies the write-ups reported, and what the
    # registry showed about the new ones on the day (GRN-C008). ``None``
    # requirements means the write-ups didn't say, so nothing is compared.
    requirements: tuple[Requirement, ...] | None = None
    dependency_profiles: tuple[DependencyProfile, ...] = ()


@dataclass
class FetchContext:
    """What every fetch shares: the HTTP client, limits, tags and packuments."""

    http: Http
    limits: Limits
    tags: github.TagLookup
    packuments: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


_NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$", re.IGNORECASE)


def normalize(package: str) -> str:
    """npm names are used as written: the registry is case-sensitive and scoped
    names keep their ``@scope/`` prefix. Anything else is refused."""
    name = package.strip()
    if not _NAME_RE.match(name) or len(name) > 214:
        raise ValueError(f"not an npm package name: {package!r}")
    return name


def registry_url(package: str) -> str:
    """The packument URL; a scoped name's slash is percent-encoded."""
    return f"{REGISTRY}/{quote(package, safe='@')}"


def tarball_name(package: str, version: str) -> str:
    """The registry's tarball filename: ``<name>-<version>.tgz`` without the scope."""
    return f"{package.rpartition('/')[2]}-{version}.tgz"


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


_SHORTHAND = re.compile(r"^(?:github:)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:#.*)?$")


def parse_repo_url(url: str) -> str | None:
    """``owner/repo`` from the forms package.json uses for a GitHub repository.

    Accepts ``https://github.com/o/r``, ``git+https://…``, ``git://…``,
    ``git+ssh://git@github.com/o/r.git``, ``git@github.com:o/r.git``,
    ``github:o/r`` and the bare ``o/r`` shorthand.
    """
    text = url.strip()
    if text.startswith("git+"):
        text = text[4:]
    text = re.sub(
        r"^(?:(?:git|ssh|https?)://)?(?:git@)?(?:www\.)?github\.com[:/]",
        "https://github.com/",
        text,
    )
    if "://" in text:
        return github.parse_repo(text) if text.startswith("https://github.com/") else None
    m = _SHORTHAND.match(text)
    return f"{m.group(1)}/{m.group(2)}" if m else None


def source_repo(doc: dict[str, Any]) -> str | None:
    """The GitHub repository a version document names, ``repository`` first."""
    repo = doc.get("repository")
    candidates: list[str] = []
    if isinstance(repo, dict) and isinstance(repo.get("url"), str):
        candidates.append(repo["url"])
    elif isinstance(repo, str):
        candidates.append(repo)
    for key in ("homepage",):
        if isinstance(doc.get(key), str):
            candidates.append(doc[key])
    bugs = doc.get("bugs")
    if isinstance(bugs, dict) and isinstance(bugs.get("url"), str):
        candidates.append(bugs["url"])
    for c in candidates:
        found = parse_repo_url(c)
        if found:
            return found
    return None


def packument(ctx: FetchContext, package: str) -> dict[str, Any] | None:
    """The package's registry document, fetched once per run. None when unknown."""
    with ctx.lock:
        if package in ctx.packuments:
            return ctx.packuments[package]
    resp = ctx.http.get(registry_url(package), max_bytes=PACKUMENT_MAX_BYTES)
    doc: dict[str, Any] | None
    if resp.status == 404:
        doc = None
    elif resp.status != 200:
        raise NetError(f"npm registry returned HTTP {resp.status} for {package}")
    else:
        doc = resp.json()
        if not isinstance(doc, dict):
            raise NetError(f"npm registry sent an unexpected document for {package}")
    with ctx.lock:
        ctx.packuments[package] = doc
    return doc


def _compute_sri(integrity: str, data: bytes) -> str | None:
    """The SRI string of ``data`` with the algorithm the registry used."""
    algo = integrity.partition("-")[0]
    if algo not in ("sha512", "sha384", "sha256", "sha1"):
        return None
    # sha1 appears on old releases only; the registry chose it, not Garnet.
    digest = hashlib.new(algo, data, usedforsecurity=algo != "sha1").digest()
    return f"{algo}-{base64.b64encode(digest).decode()}"


def _fetch_provenance(
    ctx: FetchContext, package: str, version: str, filename: str, integrity: str, tp: bool | None
) -> FileProvenance:
    url = f"{REGISTRY}/-/npm/v1/attestations/{quote(package, safe='@')}@{version}"
    resp = ctx.http.get(url, max_bytes=16 * 1024 * 1024)
    if resp.status == 404:
        # Only called when the version document lists attestations, so this
        # is a listed attestation the registry doesn't serve (whatwg-url 17.1.1).
        return FileProvenance(
            filename=filename,
            present=False,
            verified=False,
            error="the registry lists an attestation, but its attestations endpoint returns HTTP 404",
        )
    if resp.status != 200:
        raise NetError(f"attestations endpoint returned HTTP {resp.status} for {filename}")
    return verify_provenance(
        package, version, filename, integrity, resp.content, trusted_publishing=tp
    )


def release_facts(
    package: str,
    version: str,
    ctx: FetchContext,
    *,
    replay: ReplayRelease | None = None,
    advisories: bool = True,
) -> ReleaseFacts:
    """Fetch and inspect one npm release.

    In order: the packument, the release's provenance (attestations endpoint,
    verified with Sigstore), the tarball's contents, the git tag, and OSV
    advisories when ``advisories`` is true. A network failure in any step
    becomes a ``FactError`` naming the rules it kept from running. ``replay``
    supplies recorded facts for a release the registry has removed.
    """
    name = normalize(package)
    filename = tarball_name(name, version)
    errors: list[FactError] = []
    notes: list[str] = []
    yanked = False
    uploaded_at: datetime | None = None
    doc: dict[str, Any] = {}

    if replay is None:
        try:
            pack = packument(ctx, name)
        except NetError as err:
            return _unfetchable(name, version, str(err))
        if pack is None:
            return _unfetchable(name, version, f"npm has no package {name}")
        versions = pack.get("versions") or {}
        if version not in versions:
            return _unfetchable(name, version, f"npm has no release {name} {version}")
        doc = versions[version]
        uploaded_at = _parse_time((pack.get("time") or {}).get(version))
        yanked = bool(doc.get("deprecated"))
        repo = source_repo(doc)
    else:
        uploaded_at = replay.uploaded_at
        repo = replay.source_repo
        notes.append(replay.note)

    dist = doc.get("dist") or {}
    integrity = dist.get("integrity")
    if not isinstance(integrity, str) and isinstance(dist.get("shasum"), str):
        integrity = "sha1-" + base64.b64encode(bytes.fromhex(dist["shasum"])).decode()
    user = doc.get("_npmUser") or {}
    trusted = bool(user.get("trustedPublisher")) if isinstance(user, dict) and user else None

    # Trust facts.
    provenance: FileProvenance | None
    if replay is not None:
        provenance = FileProvenance(filename=filename, present=replay.attestation, verified=False)
        if replay.attestation:
            provenance = replace(provenance, verification_ran=False, error="not replayed")
        provenance = replace(provenance, trusted_publishing=replay.trusted_publisher)
    elif not dist.get("attestations"):
        provenance = FileProvenance(filename=filename, present=False, verified=False)
    elif not isinstance(integrity, str):
        provenance = None
        errors.append(FactError("GRN-E001", "release has no integrity hash", TRUST_RULES))
    else:
        try:
            provenance = _fetch_provenance(ctx, name, version, filename, integrity, trusted)
        except NetError as err:
            provenance = None
            errors.append(FactError("GRN-E001", f"provenance for {filename}: {err}", TRUST_RULES))

    art = ArtifactFacts(
        filename=filename,
        sha256="",
        packagetype="tarball",
        uploaded_at=uploaded_at,
        provenance=provenance,
        integrity=integrity if isinstance(integrity, str) else None,
    )

    # Content facts.
    if replay is not None:
        art = replace(
            art,
            inspected=True,
            install_scripts=replay.scripts,
            requirements=replay.requirements or (),
            requirements_read=replay.requirements is not None,
        )
    else:
        art, errs = _inspect(ctx, dist, art)
        errors.extend(errs)

    # The attested repository beats package.json, which anyone can edit.
    url_repo = repo
    if provenance is not None and provenance.verified:
        attested = provenance.repository or ""
        if attested.startswith("github.com/"):
            repo = attested[len("github.com/") :]

    tag_repos = tuple(dict.fromkeys(r for r in (repo, url_repo) if r))
    tag = None
    tag_checked = False
    tag_errors: list[FactError] = []
    for r in tag_repos:
        try:
            tag = github.match_tag(ctx.tags.tags(r), name, version, r, npm=True)
        except NetError as err:
            tag_errors.append(FactError("GRN-E001", f"tag lookup: {err}", ("GRN-T004",)))
            continue
        if tag is not None:
            break
    if tag is not None or (tag_repos and not tag_errors):
        tag_checked = True
    else:
        errors.extend(tag_errors)

    mal: tuple[str, ...] = ()
    advisories_checked = False
    if advisories:
        try:
            mal = osv.malicious_advisories(ctx.http, "npm", name, version)
            advisories_checked = True
        except NetError as err:
            errors.append(FactError("GRN-E001", f"OSV lookup: {err}", ("GRN-K001",)))

    return ReleaseFacts(
        ecosystem="npm",
        package=name,
        version=version,
        yanked=yanked,
        artifacts=(art,),
        source_repo=repo,
        tag=tag,
        tag_checked=tag_checked,
        tag_repos=tag_repos,
        advisories=mal,
        advisories_checked=advisories_checked,
        errors=tuple(errors),
        notes=tuple(notes),
        dependencies=replay.dependency_profiles if replay is not None else (),
        owners=maintainers(doc),
    )


def _inspect(
    ctx: FetchContext, dist: dict[str, Any], art: ArtifactFacts
) -> tuple[ArtifactFacts, list[FactError]]:
    """Download the tarball, check its integrity, then read its contents.

    A tarball whose integrity doesn't match the registry's is not read;
    GRN-T008 reports it.
    """
    url = dist.get("tarball")
    if not isinstance(url, str) or urlsplit(url).scheme != "https":
        return art, [FactError("GRN-E001", "release has no tarball URL", CONTENT_RULES)]
    try:
        resp = ctx.http.get(url, max_bytes=ctx.limits.max_artifact_bytes)
    except NetError as err:
        return art, [FactError("GRN-E001", f"download {art.filename}: {err}", CONTENT_RULES)]
    if resp.status != 200:
        msg = f"download {art.filename}: HTTP {resp.status}"
        return art, [FactError("GRN-E001", msg, CONTENT_RULES)]
    data = resp.content
    sha256 = hashlib.sha256(data).hexdigest()
    if art.integrity is None:
        return art, [FactError("GRN-E001", "release has no integrity hash", CONTENT_RULES)]
    got = _compute_sri(art.integrity, data)
    if got is None:
        msg = f"{art.filename}: unsupported integrity algorithm"
        return art, [FactError("GRN-E001", msg, CONTENT_RULES)]
    art = replace(art, sha256=sha256, downloaded_sha256=sha256, downloaded_integrity=got)
    if got != art.integrity:
        return replace(art, inspected=True), []
    name = posixpath.basename(urlsplit(url).path) or art.filename
    ins = inspect_tarball(name, data, ctx.limits)
    return (
        replace(
            art,
            inspected=True,
            files=tuple(ins.files),
            install_scripts=ins.scripts,
            requirements=ins.requirements,
            requirements_read=ins.requirements_read,
            js_uses=ins.js_uses,
            js_scanned=ins.js_scanned,
        ),
        ins.errors,
    )


def _table(doc: dict[str, Any], key: str) -> dict[str, Any]:
    """A packument table, or an empty one when the key is missing or malformed."""
    value = doc.get(key)
    return value if isinstance(value, dict) else {}


def maintainers(doc: Any) -> tuple[str, ...]:
    """The npm accounts a packument or version document lists as maintainers."""
    people = doc.get("maintainers") if isinstance(doc, dict) else None
    if not isinstance(people, list):
        return ()
    return tuple(
        sorted(
            {
                str(m["name"])
                for m in people
                if isinstance(m, dict) and isinstance(m.get("name"), str)
            }
        )
    )


def package_profile(ctx: FetchContext, package: str) -> DependencyProfile:
    """What the registry says about a package (GRN-C008): when it was created,
    how many versions it has, and the repository its latest version names.
    Raises ``NetError``; a name the registry doesn't know is ``on_registry=False``,
    and so is one it couldn't hold (a ``package.json`` key that isn't an npm name),
    which is never sent to the registry.
    """
    try:
        name = normalize(package)
    except ValueError:
        name = ""
    if name != package:
        return DependencyProfile(package, on_registry=False)
    pack = packument(ctx, name)
    if pack is None:
        return DependencyProfile(name, on_registry=False)
    times, versions = _table(pack, "time"), _table(pack, "versions")
    created = _parse_time(times.get("created"))
    if created is None:
        stamps = [t for v in versions if (t := _parse_time(times.get(v)))]
        created = min(stamps) if stamps else None
    # The time table keeps the dates of versions that were unpublished; when a
    # name was unpublished and created again, they predate ``created``.
    gone = sorted(
        (t, v)
        for v, raw in times.items()
        if v not in ("created", "modified")
        and v not in versions
        and (t := _parse_time(raw)) is not None
        and (created is None or t < created)
    )
    latest = _table(pack, "dist-tags").get("latest")
    doc = versions.get(latest) if isinstance(latest, str) else None
    return DependencyProfile(
        name,
        on_registry=True,
        first_release_at=created,
        releases=len(versions),
        source_repo=source_repo(doc) if isinstance(doc, dict) else None,
        latest_version=latest if isinstance(latest, str) else None,
        owners=maintainers(pack),
        unpublished_versions=tuple(v for _, v in gone),
        earliest_unpublished_at=gone[0][0] if gone else None,
    )


def requirement_range(r: Requirement) -> str:
    """The version range of an npm requirement as package.json writes it,
    the part after ``npm:name@`` for an alias."""
    spec = r.spec
    for label in (" (optional)", " (peer)"):
        if spec.endswith(label):
            spec = spec[: -len(label)]
            break
    rng = spec[len(r.name) + 1 :] if spec.startswith(f"{r.name}@") else spec
    if rng.startswith("npm:"):
        target = rng[4:]
        at = target.rfind("@")
        rng = target[at + 1 :] if at > 0 else ""
    return rng.strip()


def _integrity(dist: dict[str, Any]) -> str | None:
    """The tarball's SRI string, from ``integrity`` or the old ``shasum``."""
    integrity = dist.get("integrity")
    if isinstance(integrity, str):
        return integrity
    shasum = dist.get("shasum")
    if isinstance(shasum, str):
        try:
            return "sha1-" + base64.b64encode(bytes.fromhex(shasum)).decode()
        except ValueError:
            return None
    return None


def _script_order(script: tuple[str, str]) -> tuple[int, str]:
    return (INSTALL_SCRIPTS.index(script[0]), script[1])


def dependency_installs(
    ctx: FetchContext, req: Requirement, pinned: tuple[str, ...] = ()
) -> DependencyInstalls:
    """The releases of a new dependency that GRN-C008 reads, each with
    ``_dependency_release``: the versions a lockfile pins (``pinned``), else
    every version npm lists that satisfies the range, whenever it was
    published (npm can pick any of them: the ``latest`` tag, a deprecated
    version skipped, an ``engines`` preference, a tree reused), and every
    version, prereleases too, for ``*``, ``x``, ``latest`` or an empty range,
    where npm installs whatever ``latest`` points to. More than
    ``MAX_DEPENDENCY_VERSIONS`` aren't read. Raises ``NetError`` when a
    request fails; anything else that stops the read is in ``problem``.
    """
    name = req.package
    rng = requirement_range(req)
    out = DependencyInstalls(name, req.spec, pinned=bool(pinned))
    pack = packument(ctx, name)
    if pack is None:
        return replace(out, problem=f"npm has no package {name}")
    versions = _table(pack, "versions")
    if pinned:
        wanted = sorted(set(pinned))
        gone = [v for v in wanted if v not in versions]
        if gone:
            return replace(
                out, problem=f"the lockfile pins {name} {gone[0]}, which npm doesn't list"
            )
    else:
        try:
            wanted = npm_range.readable(rng, versions)
        except ValueError:
            return replace(out, problem=f"Garnet can't read the range {rng!r}")
        if not wanted:
            return replace(out, problem=f"no version of {name} matches {rng or '*'}")
    if len(wanted) > MAX_DEPENDENCY_VERSIONS:
        return replace(
            out,
            problem=f"{len(wanted)} versions of {name} could install ({wanted[0]} to "
            f"{wanted[-1]}); Garnet reads a young dependency's releases only up to "
            f"{MAX_DEPENDENCY_VERSIONS}",
        )
    return replace(
        out, releases=tuple(_dependency_release(ctx, name, v, versions[v]) for v in wanted)
    )


def _dependency_release(ctx: FetchContext, name: str, version: str, doc: Any) -> DependencyRelease:
    """One release of a new dependency: its provenance (verified with
    Sigstore), and the install scripts and ``binding.gyp`` of its tarball and
    of the registry's copy of package.json. Raises ``NetError``."""
    filename = tarball_name(name, version)
    out = DependencyRelease(name, version, files=(filename,))
    if not isinstance(doc, dict):
        return replace(out, problem=f"npm's record of {name} {version} is malformed")
    dist = _table(doc, "dist")
    integrity = _integrity(dist)
    if integrity is None:
        return replace(out, problem=f"{name} {version} has no integrity hash")
    user = doc.get("_npmUser") or {}
    trusted = bool(user.get("trustedPublisher")) if isinstance(user, dict) and user else None
    if dist.get("attestations"):
        prov = _fetch_provenance(ctx, name, version, filename, integrity, trusted)
    else:
        prov = FileProvenance(filename=filename, present=False, verified=False)
    out = replace(out, provenance=(prov,))

    url = dist.get("tarball")
    if not isinstance(url, str) or urlsplit(url).scheme != "https":
        return replace(out, problem=f"{name} {version} has no tarball URL")
    resp = ctx.http.get(url, max_bytes=ctx.limits.max_artifact_bytes)
    if resp.status != 200:
        raise NetError(f"download {filename}: HTTP {resp.status}")
    if _compute_sri(integrity, resp.content) != integrity:
        return replace(out, problem=f"{filename} doesn't match the registry's integrity hash")
    hooks = install_hooks(filename, resp.content, ctx.limits)
    if hooks.problem is not None:
        return replace(out, problem=hooks.problem)
    # npm runs what the package.json on disk says; the registry's copy can
    # differ (manifest confusion), so a script in either counts.
    listed = install_scripts(json.dumps(doc).encode())
    scripts = tuple(sorted(set(hooks.scripts) | set(listed), key=_script_order))
    return replace(
        out,
        install_scripts=scripts,
        binding_gyp=hooks.binding_gyp,
        gypfile_off=hooks.gypfile_off and doc.get("gypfile") is not True,
    )


def _unfetchable(name: str, version: str, why: str) -> ReleaseFacts:
    """Facts for a release Garnet couldn't fetch at all: one GRN-E001 naming every rule."""
    return ReleaseFacts(
        ecosystem="npm",
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
