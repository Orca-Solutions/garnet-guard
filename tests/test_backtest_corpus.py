from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from backtest import corpus
from garnet_guard.models import (
    ArtifactFacts,
    FactError,
    ReleaseFacts,
    UnparsedWheelFile,
    WheelCalls,
)
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
            "wheel_calls": (
                WheelCalls("Windows", "demo/legacy.py", None, "a" * 64),
                WheelCalls("any", "demo/__init__.py", ("os.system",), "b" * 64),
            ),
            "read_wheel_family": "any",
            "wheel_unparsed": (
                UnparsedWheelFile(
                    "demo-1.0-cp313-cp313-win_amd64.whl", "Windows", "demo/legacy.py", "a" * 64
                ),
            ),
        }
    )
    assert rel.artifacts[0].modules[0].sensitive == ("os.system",)
    cache = corpus.FactCache(tmp_path)
    assert cache.get("pypi", "demo", "1.0") is None
    cache.put(rel)
    assert cache.get("pypi", "demo", "1.0") == rel


def test_cache_round_trips_npm_facts(tmp_path: Path) -> None:
    art = ArtifactFacts(
        filename="demo-1.0.0.tgz",
        sha256="0" * 64,
        packagetype="tarball",
        uploaded_at=None,
        provenance=None,
        inspected=True,
        integrity="sha512-AAAA",
        downloaded_integrity="sha512-AAAA",
        install_scripts=(("postinstall", "node x.js"), ("prepare", "npm run build")),
    )
    rel = ReleaseFacts("npm", "@scope/demo", "1.0.0", False, (art,), tag_repos=("o/r",))
    cache = corpus.FactCache(tmp_path)
    cache.put(rel)
    assert cache.get("npm", "@scope/demo", "1.0.0") == rel


def test_pick_npm_versions_skips_prereleases_and_deprecated() -> None:
    pack = {
        "versions": {
            "1.0.0": {},
            "1.10.0": {},
            "1.2.0": {},
            "2.0.0-beta.1": {},
            "1.3.0": {"deprecated": "use 1.10"},
            "2.0.0": {},
            "junk": {},
        }
    }
    assert corpus.pick_npm_versions(pack, 10) == ["1.0.0", "1.2.0", "1.10.0", "2.0.0"]
    assert corpus.pick_npm_versions(pack, 2) == ["1.10.0", "2.0.0"]


def test_run_package_records_every_finding(tmp_path: Path) -> None:
    cache = corpus.FactCache(tmp_path)
    cache.put(release("1.0", {"demo/__init__.py": "x = 1\n"}))
    cache.put(release("1.1", {"demo/__init__.py": "x = 1\n"}))
    cache.put(release("1.2", {"demo/__init__.py": "x = 1\n", "demo-hook.pth": "import demo\n"}))
    rows = corpus.run_package("pypi", "demo", ["1.0", "1.1", "1.2"], cache, lambda _: None)
    assert [(r["candidate"], r["warn_rules"]) for r in rows] == [("1.1", []), ("1.2", ["GRN-C001"])]
    assert rows[1]["findings"][0]["rule"] == "GRN-C001"
    summary = corpus.summarize(rows)
    assert summary["updates_warned"] == 1
    assert summary["warns_by_rule"] == {"GRN-C001": {"updates": 1, "packages": 1}}


def test_cache_round_trips_source_match(tmp_path: Path) -> None:
    from dataclasses import replace

    from garnet_guard.models import CallSite, SourceMatch, UnsourcedFile

    rel = release("1.0", {"demo/__init__.py": "import os\n"})
    match = SourceMatch(
        repo="o/r",
        tag="v1.0",
        commit="c" * 40,
        prefix="src/",
        matched=1,
        unmatched=(UnsourcedFile("demo/dl.py", True, (CallSite("os.system", 3, "run"),)),),
        unchecked=("demo/vendored/x.py",),
    )
    rel = replace(rel, artifacts=(replace(rel.artifacts[0], source_match=match),))
    cache = corpus.FactCache(tmp_path)
    cache.put(rel)
    assert cache.get("pypi", "demo", "1.0") == rel
    assert rel.artifacts[0].modules[0].blob_sha1  # recorded at inspection, survives the cache
