"""Trust rules: how a release was published. Pure functions of facts."""

from __future__ import annotations

from collections.abc import Iterator

from ..models import ArtifactFacts, Change, Evidence, FileProvenance, RawFinding, ReleaseFacts


def _provs(rel: ReleaseFacts) -> list[tuple[ArtifactFacts, FileProvenance | None]]:
    return [(a, a.provenance) for a in rel.artifacts]


def _all_verified(rel: ReleaseFacts) -> bool:
    """True when the release has files and every one has a verified attestation."""
    ps = _provs(rel)
    return bool(ps) and all(p is not None and p.verified for _, p in ps)


def _unknown(rel: ReleaseFacts) -> list[str]:
    """Files whose provenance couldn't be fetched or verified."""
    return [a.filename for a, p in _provs(rel) if p is None or not p.verification_ran]


def _not_checked(rule: str, rel: ReleaseFacts, files: list[str]) -> RawFinding:
    """GRN-E001 for a rule that needed provenance Garnet couldn't get."""
    return RawFinding(
        "GRN-E001",
        f"Couldn't evaluate {rule}: provenance of {rel.version} is unknown",
        tuple(Evidence("note", f"{f}: provenance not available", path=f) for f in sorted(files)),
    )


def lost_provenance(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-T001: every baseline file was attested; a candidate file isn't.

    Silent when the baseline wasn't fully attested: a project that never
    attested isn't flagged for not attesting now. If the candidate's
    provenance couldn't be fetched, says so (GRN-E001) instead of passing.
    """
    if base is None or not _all_verified(base):
        return
    missing = [(a, p) for a, p in _provs(cand) if p is not None and not p.present]
    if missing:
        # An attestation the registry lists but doesn't serve is still missing,
        # but the title says so instead of claiming there is none.
        what = (
            "no attestation"
            if any(p.error is None for _, p in missing)
            else "no attestation served"
        )
        yield RawFinding(
            "GRN-T001",
            f"{len(missing)} file(s) in {cand.version} have {what}; every file of {base.version} had one",
            tuple(
                Evidence(
                    "attestation",
                    f"{a.filename}: {p.error or 'no attestation'}",
                    path=a.filename,
                    sha256=a.sha256 or None,
                )
                for a, p in missing
            )
            + (_base_identity(base),),
        )
    elif _unknown(cand):
        yield _not_checked("GRN-T001", cand, _unknown(cand))


def _base_identity(base: ReleaseFacts) -> Evidence:
    p = next(a.provenance for a in base.artifacts if a.provenance)
    assert p is not None
    return Evidence(
        "attestation",
        f"{base.version} was attested by {p.repository} {p.workflow}",
        identity=p.identity,
    )


def _publishers(
    rel: ReleaseFacts,
) -> dict[tuple[str | None, str | None, str | None], list[FileProvenance]]:
    """Verified files grouped by (repository, workflow, environment)."""
    out: dict[tuple[str | None, str | None, str | None], list[FileProvenance]] = {}
    for _, p in _provs(rel):
        if p is not None and p.verified:
            key = ((p.repository or "").lower() or None, p.workflow, p.environment)
            out.setdefault(key, []).append(p)
    return out


def publisher_changed(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-T002: a candidate file was attested by a repository the baseline wasn't.

    Needs verified attestations on both sides. A renamed repository keeps its
    GitHub repository id, so a rename doesn't fire.
    """
    if base is None:
        return
    bp, cp = _publishers(base), _publishers(cand)
    if not bp or not cp:
        return
    base_repos = {k[0] for k in bp}
    base_ids = {p.repository_id for ps in bp.values() for p in ps if p.repository_id}
    for key, provs in sorted(cp.items(), key=lambda kv: str(kv[0])):
        repo = key[0]
        if repo in base_repos:
            continue
        if base_ids and all(p.repository_id in base_ids for p in provs):
            continue  # same GitHub repository id: a rename, not a new publisher
        yield RawFinding(
            "GRN-T002",
            f"{cand.version} was published from {provs[0].repository}, not {', '.join(sorted(r or '?' for r in base_repos))}",
            tuple(
                Evidence(
                    "attestation",
                    f"{p.filename}: {p.repository}",
                    path=p.filename,
                    identity=p.identity,
                )
                for p in provs
            ),
        )


def workflow_changed(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-T003: same repository, different workflow file or environment."""
    if base is None:
        return
    bp, cp = _publishers(base), _publishers(cand)
    for key, provs in sorted(cp.items(), key=lambda kv: str(kv[0])):
        same_repo = [k for k in bp if k[0] == key[0]]
        if not same_repo or key in bp:
            continue
        old = same_repo[0]
        what = []
        if old[1] != key[1]:
            what.append(f"workflow {old[1]} → {key[1]}")
        if old[2] != key[2]:
            what.append(f"environment {old[2] or 'none'} → {key[2] or 'none'}")
        yield RawFinding(
            "GRN-T003",
            f"{cand.version} was published by a different workflow setup: {'; '.join(what)}",
            tuple(
                Evidence(
                    "attestation",
                    f"{p.filename}: {p.workflow} env={p.environment or 'none'}",
                    path=p.filename,
                    identity=p.identity,
                )
                for p in provs
            ),
        )


def no_matching_tag(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-T004: the baseline has a git tag and the candidate has none.

    Silent unless the tag lookup for the candidate actually ran; a failed
    lookup is reported by the fetcher as GRN-E001.
    """
    if base is None or base.tag is None or not cand.tag_checked:
        return
    if cand.tag is None:
        base_repo = base.tag.repo or base.source_repo
        searched = cand.tag_repos or ((cand.source_repo,) if cand.source_repo else ())
        where = " or ".join(f"github.com/{r}" for r in searched)
        title = (
            f"github.com/{base_repo} has a tag for {base.version} but none for {cand.version}"
            if tuple(searched) == (base_repo,)
            else f"{base.version} has a tag in github.com/{base_repo}, "
            f"but {where} has none for {cand.version}"
        )
        yield RawFinding(
            "GRN-T004",
            title,
            (
                Evidence(
                    "tag",
                    f"{base.version} → tag {base.tag.name} at {base.tag.sha}",
                    url=f"https://github.com/{base_repo}/tree/{base.tag.name}",
                ),
                *(
                    Evidence(
                        "tag",
                        f"{cand.version}: no tag named {cand.version}, v{cand.version}, "
                        f"{cand.package}-{cand.version} or {cand.package}-v{cand.version} "
                        f"in github.com/{r}",
                        url=f"https://github.com/{r}/tags",
                    )
                    for r in searched
                ),
            ),
        )


def outside_trusted_publishing(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-T005: every baseline file came through Trusted Publishing; a candidate file didn't."""
    if base is None:
        return
    bps = [p for _, p in _provs(base)]
    if not bps or not all(p is not None and p.trusted_publishing for p in bps):
        return
    bad = [
        p for _, p in _provs(cand) if p is not None and p.present and p.trusted_publishing is False
    ]
    if bad:
        yield RawFinding(
            "GRN-T005",
            f"{len(bad)} file(s) in {cand.version} were attested outside Trusted Publishing",
            tuple(Evidence("attestation", p.filename, path=p.filename) for p in bad),
        )


def invalid_attestation(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-T007: a candidate attestation exists but failed verification.

    A verifier that couldn't run (``verification_ran`` False) isn't a failure;
    GRN-T001 reports that as GRN-E001.
    """
    bad = [
        p
        for _, p in _provs(cand)
        if p is not None and p.present and p.verification_ran and not p.verified
    ]
    if bad:
        yield RawFinding(
            "GRN-T007",
            f"{len(bad)} attestation(s) in {cand.version} failed verification",
            tuple(
                Evidence("attestation", f"{p.filename}: {p.error}", path=p.filename) for p in bad
            ),
        )


def hash_mismatch(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-T008: a downloaded file doesn't match the registry's hash, in either release.

    PyPI publishes a SHA-256 per file; npm publishes a Subresource Integrity
    string (``sha512-…``) per tarball. Either mismatch fires.
    """
    for rel in (cand, base):
        if rel is None:
            continue
        bad = [
            a
            for a in rel.artifacts
            if (a.downloaded_sha256 and a.sha256 and a.downloaded_sha256 != a.sha256.lower())
            or (a.downloaded_integrity and a.integrity and a.downloaded_integrity != a.integrity)
        ]
        if bad:
            yield RawFinding(
                "GRN-T008",
                f"{len(bad)} downloaded file(s) of {rel.version} don't match the registry's hash",
                tuple(
                    Evidence(
                        "file",
                        f"{a.filename}: expected {a.integrity or a.sha256}, "
                        f"got {a.downloaded_integrity or a.downloaded_sha256}",
                        path=a.filename,
                        sha256=a.downloaded_sha256,
                    )
                    for a in bad
                ),
                release=rel.version if rel is base else None,
            )
