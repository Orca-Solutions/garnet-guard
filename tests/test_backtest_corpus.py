from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from backtest import corpus
from garnet_guard.models import ArtifactFacts, FactError, ReleaseFacts
from tests.builders import release


def test_pick_versions_skips_prereleases_yanked_and_invalid() -> None:
    ok = [{"yanked": False}]
    releases = {
        "1.0": ok,
        "1.1": ok,
        "1.10": ok,
        "1.2": ok,
        "2.0rc1": ok,
        "2.0.dev3": ok,
        "1.3": [{"yanked": True}],
        "1.4": [],
        "not-a-version": ok,
        "1.2.post1": ok,
    }
    assert corpus.pick_versions(releases, 10) == ["1.0", "1.1", "1.2", "1.2.post1", "1.10"]
    assert corpus.pick_versions(releases, 2) == ["1.2.post1", "1.10"]


def test_cache_round_trips_release_facts(tmp_path: Path) -> None:
    rel = release("1.0", {"demo/__init__.py": "import os\nos.system('x')\n", "demo.pth": "x\n"})
    art = rel.artifacts[0]
    rel = ReleaseFacts(
        **{
            **rel.__dict__,
            "artifacts": (
                ArtifactFacts(**{**art.__dict__, "uploaded_at": datetime(2026, 1, 2, tzinfo=UTC)}),
            ),
            "errors": (FactError("GRN-E002", "x", ("GRN-C003",), path="a.py"),),
        }
    )
    cache = corpus.FactCache(tmp_path)
    assert cache.get("demo", "1.0") is None
    cache.put(rel)
    assert cache.get("demo", "1.0") == rel


def test_run_package_records_every_finding(tmp_path: Path) -> None:
    cache = corpus.FactCache(tmp_path)
    cache.put(release("1.0", {"demo/__init__.py": "x = 1\n"}))
    cache.put(release("1.1", {"demo/__init__.py": "x = 1\n"}))
    cache.put(release("1.2", {"demo/__init__.py": "x = 1\n", "demo-hook.pth": "import demo\n"}))
    rows = corpus.run_package("demo", ["1.0", "1.1", "1.2"], cache, lambda _: None)
    assert [(r["candidate"], r["warn_rules"]) for r in rows] == [("1.1", []), ("1.2", ["GRN-C001"])]
    assert rows[1]["findings"][0]["rule"] == "GRN-C001"
    summary = corpus.summarize(rows)
    assert summary["updates_warned"] == 1
    assert summary["warns_by_rule"] == {"GRN-C001": {"updates": 1, "packages": 1}}
