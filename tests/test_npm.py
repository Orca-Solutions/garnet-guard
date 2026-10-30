"""npm adapter: names, repositories, tarballs, provenance and the npm rules."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from garnet_guard.ecosystems import npm, npm_provenance
from garnet_guard.ecosystems.github import match_tag
from garnet_guard.engine import run_checks
from garnet_guard.facts.npmmeta import inspect_tarball, install_scripts
from garnet_guard.models import ArtifactFacts, Change, FileProvenance, Limits, ReleaseFacts, TagInfo

FIXTURES = Path(__file__).parent / "fixtures" / "npm"
CHANGE = Change("npm", "demo", "1.0.0", "1.1.0")


def tgz(files: dict[str, str | bytes], folder: str = "package") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, body in sorted(files.items()):
            data = body.encode() if isinstance(body, str) else body
            info = tarfile.TarInfo(f"{folder}/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def release(
    version: str,
    scripts: dict[str, str] | None = None,
    *,
    provenance: FileProvenance | None | str = "none",
    tag: bool | None = True,
) -> ReleaseFacts:
    filename = f"demo-{version}.tgz"
    p: FileProvenance | None
    if provenance == "ok":
        p = FileProvenance(
            filename,
            present=True,
            verified=True,
            repository="github.com/o/r",
            repository_id="1",
            workflow=".github/workflows/publish.yml",
            trusted_publishing=True,
        )
    elif provenance == "none":
        p = FileProvenance(filename, present=False, verified=False)
    else:
        p = provenance  # type: ignore[assignment]
    art = ArtifactFacts(
        filename=filename,
        sha256="0" * 64,
        packagetype="tarball",
        uploaded_at=None,
        provenance=p,
        inspected=True,
        integrity="sha512-AAAA",
        downloaded_integrity="sha512-AAAA",
        install_scripts=tuple(sorted((scripts or {}).items())),
    )
    return ReleaseFacts(
        ecosystem="npm",
        package="demo",
        version=version,
        yanked=False,
        artifacts=(art,),
        source_repo="o/r",
        tag=TagInfo(f"v{version}", "abc") if tag else None,
        tag_checked=tag is not None,
    )


def rules(base: ReleaseFacts, cand: ReleaseFacts) -> set[str]:
    return {f.rule_id for f in run_checks(CHANGE, base, cand).findings}


# --- names and repositories -------------------------------------------------


def test_normalize_keeps_case_and_scope_and_refuses_junk() -> None:
    assert npm.normalize(" @ctrl/tinycolor ") == "@ctrl/tinycolor"
    assert npm.normalize("JSONStream") == "JSONStream"
    for bad in ("", "../x", "@/x", "a b", "a/b/c", "@scope"):
        with pytest.raises(ValueError):
            npm.normalize(bad)


def test_registry_url_encodes_the_scope_slash() -> None:
    assert npm.registry_url("@ctrl/tinycolor") == "https://registry.npmjs.org/@ctrl%2Ftinycolor"
    assert npm.registry_url("chalk") == "https://registry.npmjs.org/chalk"
    assert npm.tarball_name("@ctrl/tinycolor", "4.2.2") == "tinycolor-4.2.2.tgz"


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/chalk/chalk",
        "git+https://github.com/chalk/chalk.git",
        "git://github.com/chalk/chalk.git",
        "git+ssh://git@github.com/chalk/chalk.git",
        "git@github.com:chalk/chalk.git",
        "github:chalk/chalk",
        "chalk/chalk",
        "https://github.com/chalk/chalk/issues",
        "https://github.com/chalk/chalk#readme",
    ],
)
def test_parse_repo_url_forms(url: str) -> None:
    assert npm.parse_repo_url(url) == "chalk/chalk"


def test_parse_repo_url_rejects_other_hosts() -> None:
    assert npm.parse_repo_url("https://gitlab.com/o/r") is None
    assert npm.parse_repo_url("https://evil.example/github.com/o/r") is None
    assert npm.parse_repo_url("bitbucket:o/r") is None


def test_source_repo_prefers_repository_over_homepage() -> None:
    doc = {
        "repository": {"url": "git+https://github.com/o/r.git"},
        "homepage": "https://github.com/x/y",
    }
    assert npm.source_repo(doc) == "o/r"
    assert npm.source_repo({"homepage": "https://github.com/x/y#readme"}) == "x/y"
    assert npm.source_repo({"bugs": {"url": "https://github.com/b/c/issues"}}) == "b/c"
    assert npm.source_repo({}) is None


def test_match_tag_accepts_monorepo_forms_for_npm() -> None:
    tags = {"@ctrl/tinycolor@4.2.2": "a", "tinycolor@4.2.1": "b", "v4.2.0": "c"}
    assert match_tag(tags, "@ctrl/tinycolor", "4.2.2", npm=True).name == "@ctrl/tinycolor@4.2.2"
    assert match_tag(tags, "@ctrl/tinycolor", "4.2.1", npm=True).name == "tinycolor@4.2.1"
    assert match_tag(tags, "@ctrl/tinycolor", "4.2.0", npm=True).name == "v4.2.0"
    assert match_tag(tags, "@ctrl/tinycolor", "4.2.2") is None  # the PyPI forms only


# --- tarballs ---------------------------------------------------------------


def test_inspect_tarball_reads_scripts_and_strips_the_folder() -> None:
    manifest = {"name": "demo", "scripts": {"test": "jest", "postinstall": "node setup.js", "x": 1}}
    data = tgz({"package.json": json.dumps(manifest), "index.js": "module.exports = 1\n"})
    ins = inspect_tarball("demo-1.0.0.tgz", data, Limits())
    assert [f.path for f in ins.files] == ["index.js", "package.json"]
    assert ins.scripts == (("postinstall", "node setup.js"),)
    assert ins.errors == []


def test_inspect_tarball_with_another_top_folder() -> None:
    data = tgz({"package.json": '{"scripts": {"install": "make"}}'}, folder="demo")
    ins = inspect_tarball("demo-1.0.0.tgz", data, Limits())
    assert ins.scripts == (("install", "make"),)


def test_install_scripts_records_non_string_values() -> None:
    assert install_scripts(b'{"scripts": {"preinstall": ["a", "b"]}}') == (
        ("preinstall", '["a", "b"]'),
    )
    assert install_scripts(b"not json") == ()
    assert install_scripts(b'{"scripts": "x"}') == ()


def test_inspect_tarball_reports_bad_archive() -> None:
    ins = inspect_tarball("demo-1.0.0.tgz", b"not a tarball", Limits())
    assert [e.code for e in ins.errors] == ["GRN-E002"]


# --- rules ------------------------------------------------------------------


def test_new_install_script_fires_and_changed_script_fires() -> None:
    base = release("1.0.0", {"prepare": "npm run build"})
    added = release("1.1.0", {"prepare": "npm run build", "postinstall": "node bundle.js"})
    changed = release("1.1.0", {"prepare": "node --run build"})
    same = release("1.1.0", {"prepare": "npm run build"})
    assert rules(base, added) == {"GRN-C002"}
    assert rules(base, changed) == {"GRN-C002"}
    assert rules(base, same) == set()
    finding = run_checks(CHANGE, base, added).findings[0]
    assert "node bundle.js" in finding.evidence[0].summary


def test_removed_install_script_is_quiet() -> None:
    assert rules(release("1.0.0", {"postinstall": "x"}), release("1.1.0")) == set()


def test_lost_provenance_and_tag_on_npm() -> None:
    assert rules(release("1.0.0", provenance="ok"), release("1.1.0", tag=False)) == {
        "GRN-T001",
        "GRN-T004",
    }
    assert rules(release("1.0.0"), release("1.1.0")) == set()


def test_integrity_mismatch_blocks() -> None:
    cand = release("1.1.0")
    art = cand.artifacts[0]
    bad = ReleaseFacts(
        **{
            **cand.__dict__,
            "artifacts": (
                ArtifactFacts(**{**art.__dict__, "downloaded_integrity": "sha512-BBBB"}),
            ),
        }
    )
    result = run_checks(CHANGE, release("1.0.0"), bad)
    assert {f.rule_id for f in result.findings} == {"GRN-T008"}
    assert "sha512-AAAA" in result.findings[0].evidence[0].summary


# --- provenance (recorded registry documents, verified offline) -------------


def _verify(name: str, package: str, version: str) -> FileProvenance:
    doc = json.loads((FIXTURES / f"{name}-version.json").read_text())
    body = (FIXTURES / f"{name}-attestations.json").read_bytes()
    user = doc.get("_npmUser") or {}
    return npm_provenance.verify_provenance(
        package,
        version,
        npm.tarball_name(package, version),
        doc["dist"]["integrity"],
        body,
        trusted_publishing=bool(user.get("trustedPublisher")),
    )


def test_verifies_a_dsse_logged_bundle() -> None:
    p = _verify("tinycolor-4.2.2", "@ctrl/tinycolor", "4.2.2")
    assert p.verified and p.error is None, p.error
    assert p.repository == "github.com/scttcper/tinycolor"
    assert p.workflow == ".github/workflows/publish.yml"
    assert p.repository_id == "131563275"
    assert p.trusted_publishing is True


def test_verifies_an_intoto_logged_bundle() -> None:
    p = _verify("nx-21.4.1", "nx", "21.4.1")
    assert p.verified and p.error is None, p.error
    assert p.repository == "github.com/nrwl/nx"
    assert p.workflow == ".github/workflows/publish.yml"
    assert p.identity == "https://github.com/nrwl/nx/.github/workflows/publish.yml@refs/tags/21.4.1"
    assert p.trusted_publishing is False


def test_wrong_integrity_fails_verification() -> None:
    body = (FIXTURES / "nx-21.4.1-attestations.json").read_bytes()
    p = npm_provenance.verify_provenance(
        "nx", "21.4.1", "nx-21.4.1.tgz", "sha512-" + "A" * 86 + "==", body, trusted_publishing=False
    )
    assert p.present and not p.verified and p.verification_ran
    assert "different SHA-512" in (p.error or "")


def test_wrong_version_fails_verification() -> None:
    doc = json.loads((FIXTURES / "nx-21.4.1-version.json").read_text())
    body = (FIXTURES / "nx-21.4.1-attestations.json").read_bytes()
    p = npm_provenance.verify_provenance(
        "nx", "21.5.0", "nx-21.5.0.tgz", doc["dist"]["integrity"], body, trusted_publishing=False
    )
    assert p.present and not p.verified and "does not name" in (p.error or "")


def test_tampered_intoto_entry_fails_verification() -> None:
    doc = json.loads((FIXTURES / "nx-21.4.1-version.json").read_text())
    raw = json.loads((FIXTURES / "nx-21.4.1-attestations.json").read_text())
    for a in raw["attestations"]:
        entry = a["bundle"]["verificationMaterial"]["tlogEntries"][0]
        entry["integratedTime"] = str(int(entry["integratedTime"]) + 1)
    p = npm_provenance.verify_provenance(
        "nx",
        "21.4.1",
        "nx-21.4.1.tgz",
        doc["dist"]["integrity"],
        json.dumps(raw).encode(),
        trusted_publishing=False,
    )
    assert p.present and not p.verified and p.verification_ran
    assert "log entry timestamp" in (p.error or "")


def test_missing_or_malformed_attestations() -> None:
    p = npm_provenance.verify_provenance(
        "x", "1", "x-1.tgz", "sha512-AA==", b'{"attestations": []}', trusted_publishing=None
    )
    assert not p.present
    p = npm_provenance.verify_provenance(
        "x", "1", "x-1.tgz", "sha512-AA==", b"nope", trusted_publishing=None
    )
    assert p.present and not p.verified


def test_sri_sha512() -> None:
    assert npm_provenance.sri_sha512("sha512-" + "A" * 86 + "==") == "00" * 64
    assert npm_provenance.sri_sha512("sha1-AAE=") is None
    assert npm_provenance.sri_sha512("sha512-***") is None


def test_verifies_a_2023_bundle_without_an_inclusion_proof() -> None:
    """npm's first provenance bundles (2023) carry an inclusion promise only;
    sigstore-python can't load them, so the reduced path verifies them."""
    p = _verify("which-3.0.1", "which", "3.0.1")
    assert p.verified and p.error is None, p.error
    assert p.repository == "github.com/npm/node-which"
    assert p.workflow == ".github/workflows/release.yml"
    assert p.identity is not None and p.identity.startswith("https://github.com/npm/node-which/")
