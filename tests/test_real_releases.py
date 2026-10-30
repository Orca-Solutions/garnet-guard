"""Real, legitimate PyPI releases that each trust rule has met. Needs the network.

These are the fair test: not crafted, just what maintainers actually did.
Each row says what the rule should report and why, with the fact behind it.
Run with ``uv run pytest -m network tests/test_real_releases.py``; the facts
are fetched live, so a run takes a few minutes and needs pypi.org,
files.pythonhosted.org and github.com. The known-bad lookup is off so the
rows don't depend on api.osv.dev.

The rows were confirmed on 2026-10-30. A project can change its publishing
later (attest again, move repositories), and then a row needs updating, not
the rule.
"""

from __future__ import annotations

import pytest

from garnet_guard.engine import Options, compare

ROWS = [
    # (package, trusted, new, must fire, must stay quiet, why)
    (
        "tomli",
        "2.3.2",
        "2.4.0",
        {"GRN-T001"},
        set(),
        "every 2.3.2 file was attested; the 47 files of 2.4.0 are not",
    ),
    (
        "scikit-learn",
        "1.9.0",
        "1.9.1",
        {"GRN-T002"},
        set(),
        "1.9.1 was attested from scikit-learn/scikit-learn-release, a different repository",
    ),
    (
        "langsmith",
        "0.14.9",
        "0.14.10",
        {"GRN-T002"},
        set(),
        "0.14.10 was attested from langchain-ai/langsmith-python, not langsmith-sdk",
    ),
    (
        "msgspec",
        "0.21.1",
        "0.22.0",
        set(),
        {"GRN-T001", "GRN-T002", "GRN-T003"},
        "jcrist/msgspec was transferred to the msgspec organization: same repository id",
    ),
    (
        "authlib",
        "1.5.2",
        "1.6.0",
        set(),
        {"GRN-T001", "GRN-T002", "GRN-T003"},
        "lepture/authlib was transferred to the authlib organization: same repository id",
    ),
    (
        "pluggy",
        "1.6.0",
        "1.7.0",
        {"GRN-T003"},
        {"GRN-T002"},
        "same repository, publish workflow main.yml became deploy.yml",
    ),
    (
        "tornado",
        "6.5.10",
        "6.6",
        {"GRN-T003"},
        {"GRN-T002"},
        "same repository and workflow, a 'pypi' environment was added",
    ),
]


@pytest.mark.network
@pytest.mark.parametrize(
    ("package", "old", "new", "fires", "quiet", "why"), ROWS, ids=[f"{r[0]} {r[2]}" for r in ROWS]
)
def test_real_release(
    package: str, old: str, new: str, fires: set[str], quiet: set[str], why: str
) -> None:
    result = compare("pypi", package, old, new, options=Options(check_known_bad=False))
    ids = {f.rule_id for f in result.findings}
    assert fires <= ids, f"{package} {old} → {new}: {why}; got {sorted(ids)}"
    assert not (quiet & ids), f"{package} {old} → {new}: {why}; got {sorted(ids)}"
