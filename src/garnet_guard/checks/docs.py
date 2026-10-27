"""Rule documentation: the text ``garnet explain`` prints and findings carry."""

from __future__ import annotations

from ..models import RuleDoc, Severity

W, B = Severity.WARN, Severity.BLOCK

# One place for rule links, so moving to a real docs domain is a single change.
RULE_DOCS_BASE = "https://github.com/orca-solutions/garnet-guard/blob/main/docs/rules/"


def rule_url(rule_id: str) -> str:
    return f"{RULE_DOCS_BASE}{rule_id}.md"


_DOCS: tuple[RuleDoc, ...] = (
    RuleDoc(
        "GRN-T001",
        "lost-provenance",
        "diff",
        W,
        "Every file of the trusted version had a verified attestation; the new version has a file without one.",
        "The trusted version was published by CI with a Sigstore attestation proving which repository "
        "and workflow built it. A new file with no attestation was most likely uploaded some other way, "
        "for example with a stolen or leaked API token. That is how lightning 2.6.2 and 2.6.3 were published.",
        "Don't merge yet. Check the project's repository for a release workflow run and a tag for this "
        "version, and its issue tracker or security advisories. If the maintainers confirm a manual release, "
        "add a time-limited ignore.",
    ),
    RuleDoc(
        "GRN-T002",
        "publisher-changed",
        "diff",
        W,
        "The verified source repository differs between the trusted and new versions.",
        "Attestations name the repository whose CI built the release. A different repository means "
        "someone else's CI published this version: a fork, a new home, or an attacker's repository. "
        "Renames are ignored when GitHub's repository id is unchanged.",
        "Confirm the move with the project (release notes, README, an announcement from the old "
        "repository). Don't merge on the strength of the new repository's own claims.",
    ),
    RuleDoc(
        "GRN-T003",
        "workflow-changed",
        "diff",
        W,
        "Same repository, but the publishing workflow file or deployment environment changed.",
        "Moving publishing to a different workflow or dropping a protected environment is a common "
        "step in a CI takeover, and it bypasses reviewers that the environment required.",
        "Look at the commit that changed the workflow in the project's repository and who approved it.",
    ),
    RuleDoc(
        "GRN-T004",
        "no-matching-tag",
        "diff",
        W,
        "The trusted version had a matching git tag in the source repository; the new version has none.",
        "Projects that tag releases normally tag every release. A version on the registry with no tag "
        "was probably not built from the repository's history, which is typical of a token-based upload. "
        "Accepted tag forms are X, vX, <name>-X and <name>-vX, with X compared as a version "
        "(tag 2026.01.04 matches 2026.1.4). Both the attested repository and the project's "
        "source URL are searched.",
        "Check the repository's tags and releases page. A missing tag can be an oversight, so confirm "
        "with the maintainers before merging.",
    ),
    RuleDoc(
        "GRN-T005",
        "outside-trusted-publishing",
        "diff",
        W,
        "Files of the trusted version came through Trusted Publishing; a new file came with an attestation that didn't.",
        "On PyPI today an attestation implies Trusted Publishing, so a file without either is reported "
        "by GRN-T001 and this rule stays quiet. It exists for registries that separate the two.",
        "As for GRN-T001.",
    ),
    RuleDoc(
        "GRN-T007",
        "invalid-attestation",
        "absolute",
        B,
        "An attestation is present but fails Sigstore verification.",
        "A broken or forged attestation is worse than none: something tried to look trustworthy and failed.",
        "Don't install. Report it to the project and to the registry's security team.",
    ),
    RuleDoc(
        "GRN-T008",
        "hash-mismatch",
        "absolute",
        B,
        "A downloaded file doesn't match the hash the registry published.",
        "The bytes you would install are not the bytes the registry listed. That points to tampering "
        "between the registry and you, or a corrupted mirror.",
        "Don't install. Retry from a clean network and report it if it persists.",
    ),
    RuleDoc(
        "GRN-C001",
        "new-pth-file",
        "diff",
        W,
        "The new version adds a .pth file, or an existing .pth file gained executable `import` lines.",
        "Python runs `import` lines in .pth files in site-packages every time the interpreter starts, "
        "for every program, before any of your code. Almost no package needs a new one. "
        "elementary-data 0.23.3 used exactly this to steal credentials.",
        "Read the .pth file. If it is a legitimate path hook (editable installs, namespace helpers) the "
        "release notes usually say so; otherwise treat the release as compromised.",
    ),
    RuleDoc(
        "GRN-C002",
        "new-build-hook",
        "diff",
        W,
        "setup.py gained sensitive calls, or the build backend changed to an unknown or in-tree backend.",
        "Code in setup.py or a custom build backend runs on your machine when the sdist is built, "
        "before you ever import the package.",
        "Read the setup.py diff or the new backend. Prefer installing the wheel if one exists.",
    ),
    RuleDoc(
        "GRN-C003",
        "new-import-time-exec",
        "diff",
        W,
        "Code that runs at import time gained calls that run processes, load code, or use the network. "
        "In test files (tests/, test_*.py, conftest.py) it reports at info, unless a non-test module "
        "imports the file or an entry point names it.",
        "Module top-level code runs the moment anything imports the package, including your test suite "
        "and CI. lightning 2.6.2 started a credential stealer this way, from a thread launched in "
        "lightning/__init__.py.",
        "Read the flagged lines. Network or subprocess calls at import are rare in libraries; ask "
        "whether the release notes explain them.",
    ),
    RuleDoc(
        "GRN-K001",
        "known-malicious",
        "absolute",
        B,
        "OSV lists a MAL- advisory for this version.",
        "A malware feed has already confirmed this version is malicious.",
        "Don't install. If it is already installed anywhere, rotate every credential that machine could reach.",
    ),
    RuleDoc(
        "GRN-E001",
        "fetch-failed",
        "absolute",
        W,
        "Data needed for a rule couldn't be fetched.",
        "Garnet never treats a check it couldn't run as a pass. The finding names the rules that were not evaluated.",
        "Re-run with network access. If it keeps failing, check the URL in the evidence.",
    ),
    RuleDoc(
        "GRN-E002",
        "parse-failed",
        "absolute",
        W,
        "An artifact or a changed file couldn't be parsed.",
        "Content rules couldn't look inside it, so they didn't pass it either.",
        "Inspect the file by hand.",
    ),
    RuleDoc(
        "GRN-E003",
        "budget-exceeded",
        "absolute",
        W,
        "A safety limit (size, entries, compression ratio, parse size or time) was hit.",
        "Limits stop archive bombs and runaway parsing. Content past the limit was not checked.",
        "Inspect the release by hand, or raise the limit only if you trust the source.",
    ),
)

_DOCS += (
    RuleDoc(
        "GRN-E004",
        "unpinned-requirement",
        "absolute",
        Severity.INFO,
        "A requirements line isn't pinned with ==, so Garnet can't tell which release you'll get.",
        "Without an exact version there is no release to compare. The installer picks one at install "
        "time, and Garnet never sees it.",
        "Pin it (`name==version`), or use a lockfile such as uv.lock or pylock.toml.",
    ),
    RuleDoc(
        "GRN-E005",
        "unsupported-source",
        "absolute",
        Severity.INFO,
        "A dependency comes from a source Garnet doesn't check: git, a local path, a direct URL or a private index.",
        "Garnet compares releases published on PyPI. Code from other sources wasn't checked, and it "
        "isn't passed either.",
        "Review the change to that dependency by hand.",
    ),
)

DOCS: dict[str, RuleDoc] = {d.rule_id: d for d in _DOCS}
