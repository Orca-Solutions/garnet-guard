"""Trust rules: how a release was published. Pure functions of facts."""

from __future__ import annotations

from collections.abc import Iterator

from ..models import ArtifactFacts, Change, Evidence, FileProvenance, RawFinding, ReleaseFacts


def _provs(rel: ReleaseFacts) -> list[tuple[ArtifactFacts, FileProvenance | None]]:
    return [(a, a.provenance) for a in rel.artifacts]


def _all_verified(rel: ReleaseFacts) -> bool:
    ps = _provs(rel)
    return bool(ps) and all(p is not None and p.verified for _, p in ps)


def _unknown(rel: ReleaseFacts) -> list[str]:
    return [a.filename for a, p in _provs(rel) if p is None or not p.verification_ran]


def _not_checked(rule: str, rel: ReleaseFacts, files: list[str]) -> RawFinding:
    return RawFinding(
        "GRN-E001",
        f"Couldn't evaluate {rule}: provenance of {rel.version} is unknown",
        tuple(Evidence("note", f"{f}: provenance not available", path=f) for f in sorted(files)),
    )


def lost_provenance(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    if base is None or not _all_verified(base):
        return
    missing = [a for a, p in _provs(cand) if p is not None and not p.present]
    if missing:
        yield RawFinding(
            "GRN-T001",
            f"{len(missing)} file(s) in {cand.version} have no attestation; every file of {base.version} had one",
            tuple(
                Evidence(
                    "attestation", f"{a.filename}: no attestation", path=a.filename, sha256=a.sha256
                )
                for a in missing
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
    out: dict[tuple[str | None, str | None, str | None], list[FileProvenance]] = {}
    for _, p in _provs(rel):
        if p is not None and p.verified:
            key = ((p.repository or "").lower() or None, p.workflow, p.environment)
            out.setdefault(key, []).append(p)
    return out


def publisher_changed(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
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
    if base is None or base.tag is None or not cand.tag_checked:
        return
    if cand.tag is None:
        yield RawFinding(
            "GRN-T004",
            f"github.com/{cand.source_repo} has a tag for {base.version} but none for {cand.version}",
            (
                Evidence(
                    "tag",
                    f"{base.version} → tag {base.tag.name} at {base.tag.sha}",
                    url=f"https://github.com/{base.source_repo}/tree/{base.tag.name}",
                ),
                Evidence(
                    "tag",
                    f"{cand.version}: no tag named {cand.version}, v{cand.version}, {cand.package}-{cand.version} or {cand.package}-v{cand.version}",
                    url=f"https://github.com/{cand.source_repo}/tags",
                ),
            ),
        )


def outside_trusted_publishing(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
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
    for rel in (cand, base):
        if rel is None:
            continue
        bad = [
            a
            for a in rel.artifacts
            if a.downloaded_sha256 and a.downloaded_sha256 != a.sha256.lower()
        ]
        if bad:
            yield RawFinding(
                "GRN-T008",
                f"{len(bad)} downloaded file(s) of {rel.version} don't match the registry's hash",
                tuple(
                    Evidence(
                        "file",
                        f"{a.filename}: expected {a.sha256}, got {a.downloaded_sha256}",
                        path=a.filename,
                        sha256=a.downloaded_sha256,
                    )
                    for a in bad
                ),
                release=rel.version if rel is base else None,
            )
