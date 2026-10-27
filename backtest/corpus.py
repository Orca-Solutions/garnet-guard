"""Clean-corpus backtest: the last releases of the top PyPI packages.

    uv run python -m backtest select     # pick versions, write corpus.json
    uv run python -m backtest corpus     # run every consecutive update in corpus.json

Every update in the corpus is a legitimate release, so every warn from a
detection rule is either a false positive or a real finding worth a look.
Each release is fetched once and diffed against the release before it, the
way a Dependabot or Renovate PR would see it. Release facts are cached as
JSON (never pickle) so a rerun only re-runs the pure checks.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sys
import time
import types
import typing
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from garnet_guard import __version__, models
from garnet_guard.ecosystems import github, pypi
from garnet_guard.engine import run_checks
from garnet_guard.models import Change, ChangeResult, Limits, ReleaseFacts, Severity
from garnet_guard.net import Http, NetError

HERE = Path(__file__).parent
TOP = HERE / "top-pypi-100.json"
CORPUS = HERE / "corpus.json"
NOT_DETECTION = {"GRN-K001", "GRN-E001", "GRN-E002", "GRN-E003"}
RELEASES_PER_PACKAGE = 11  # 11 releases give 10 updates per package
CACHE_FORMAT = 1


# --- Choosing versions ---------------------------------------------------


def pick_versions(releases: dict[str, list[dict[str, Any]]], count: int) -> list[str]:
    """The last ``count`` final releases that still have a non-yanked file.

    Pre-releases and dev releases are skipped, as Dependabot and Renovate skip
    them by default. Order is by version, which is the order an update takes.
    """
    keep: list[tuple[Version, str]] = []
    for raw, files in releases.items():
        try:
            v = Version(raw)
        except InvalidVersion:
            continue
        if v.is_prerelease or v.is_devrelease:
            continue
        if not any(not f.get("yanked") for f in files):
            continue
        keep.append((v, raw))
    keep.sort()
    return [raw for _, raw in keep[-count:]]


def select(argv: list[str]) -> int:
    top = json.loads(TOP.read_text())
    count = int(argv[0]) if argv else len(top["projects"])
    packages: list[dict[str, Any]] = []
    with Http() as http:
        for name in top["projects"][:count]:
            norm = pypi.normalize(name)
            resp = http.get(f"https://pypi.org/pypi/{norm}/json", max_bytes=512 * 1024 * 1024)
            if resp.status != 200:
                print(f"select: {norm}: HTTP {resp.status}", file=sys.stderr)
                return 3
            versions = pick_versions(resp.json().get("releases", {}), RELEASES_PER_PACKAGE)
            packages.append({"package": norm, "versions": versions})
            print(f"{norm}: {' '.join(versions)}")
    out = {
        "selected_on": datetime.now().astimezone().date().isoformat(),
        "rule": f"last {RELEASES_PER_PACKAGE} final, non-yanked releases by version",
        "top_list": {"source": top["source"], "last_update": top["last_update"]},
        "packages": packages,
    }
    CORPUS.write_text(json.dumps(out, indent=2) + "\n")
    return 0


# --- Fact cache (JSON, typed decode) -------------------------------------


def encode(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: encode(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, tuple | list):
        return [encode(x) for x in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


def decode(tp: Any, data: Any) -> Any:
    if data is None:
        return None
    origin = typing.get_origin(tp)
    if origin is typing.Union or origin is types.UnionType:
        inner = [a for a in typing.get_args(tp) if a is not type(None)]
        return decode(inner[0], data) if len(inner) == 1 else data
    if origin is tuple:
        return tuple(decode(typing.get_args(tp)[0], x) for x in data)
    if origin is typing.Literal:
        return data
    if tp is datetime:
        return datetime.fromisoformat(data)
    if dataclasses.is_dataclass(tp):
        hints = typing.get_type_hints(tp, vars(models))
        return typing.cast(Callable[..., Any], tp)(
            **{k: decode(hints[k], v) for k, v in data.items()}
        )
    return data


class FactCache:
    def __init__(self, root: Path) -> None:
        self.root = root / f"v{CACHE_FORMAT}-garnet-{__version__}"

    def _path(self, package: str, version: str) -> Path:
        return self.root / package / f"{version}.json"

    def get(self, package: str, version: str) -> ReleaseFacts | None:
        p = self._path(package, version)
        if not p.exists():
            return None
        facts: ReleaseFacts = decode(ReleaseFacts, json.loads(p.read_text()))
        return facts

    def put(self, facts: ReleaseFacts) -> None:
        p = self._path(facts.package, facts.version)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(encode(facts), sort_keys=True))
        tmp.replace(p)


def _transient(facts: ReleaseFacts) -> bool:
    """Don't cache a release whose facts are missing because a request failed."""
    return any(e.code == "GRN-E001" for e in facts.errors)


# --- Running -------------------------------------------------------------


def fetch_package(
    package: str, versions: list[str], cache: FactCache, *, workers: int = 3
) -> dict[str, ReleaseFacts]:
    out: dict[str, ReleaseFacts] = {}
    todo = []
    for v in versions:
        hit = cache.get(package, v)
        if hit is not None:
            out[v] = hit
        else:
            todo.append(v)
    if not todo:
        return out
    with Http() as http:
        ctx = pypi.FetchContext(http=http, limits=Limits(), tags=github.TagLookup(http))

        def fetch(v: str) -> ReleaseFacts:
            return pypi.release_facts(package, v, ctx, advisories=False)

        # The first release warms the tag cache, so the rest don't each fetch it.
        got = [fetch(todo[0])]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            got += list(pool.map(fetch, todo[1:]))
        for facts in got:
            out[facts.version] = facts
            if not _transient(facts):
                cache.put(facts)
    return out


def finding_rows(result: ChangeResult) -> list[dict[str, Any]]:
    return [
        {
            "rule": f.rule_id,
            "severity": f.severity.label,
            "title": f.title,
            "release": f.release,
            "evidence": [e.summary for e in f.evidence],
        }
        for f in result.findings
    ]


def run_package(
    package: str, versions: list[str], cache: FactCache, log: Callable[[str], None]
) -> list[dict[str, Any]]:
    t0 = time.monotonic()
    facts = fetch_package(package, versions, cache)
    rows: list[dict[str, Any]] = []
    for old, new in zip(versions, versions[1:], strict=False):
        result = run_checks(Change("pypi", package, old, new), facts[old], facts[new])
        findings = finding_rows(result)
        warn_rules = sorted(
            {
                f["rule"]
                for f in findings
                if f["rule"] not in NOT_DETECTION
                and Severity[f["severity"].upper()] >= Severity.WARN
            }
        )
        gaps = sorted({f["rule"] for f in findings if f["rule"].startswith("GRN-E")})
        rows.append(
            {
                "package": package,
                "baseline": old,
                "candidate": new,
                "verdict": result.verdict.value,
                "warned": bool(warn_rules),
                "warn_rules": warn_rules,
                "coverage_gaps": gaps,
                "findings": findings,
            }
        )
    log(
        f"{package}: {len(rows)} updates, {sum(r['warned'] for r in rows)} warned ({time.monotonic() - t0:.0f}s)"
    )
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    warned = [r for r in rows if r["warned"]]
    by_rule: Counter[str] = Counter(rule for r in rows for rule in r["warn_rules"])
    pkgs_by_rule: dict[str, set[str]] = {}
    for r in rows:
        for rule in r["warn_rules"]:
            pkgs_by_rule.setdefault(rule, set()).add(r["package"])
    gaps: Counter[str] = Counter(g for r in rows for g in r["coverage_gaps"])
    return {
        "updates": len(rows),
        "packages": len({r["package"] for r in rows}),
        "updates_warned": len(warned),
        "warn_rate": round(len(warned) / len(rows), 4) if rows else None,
        "packages_with_a_warn": len({r["package"] for r in warned}),
        "warns_by_rule": {
            rule: {"updates": n, "packages": len(pkgs_by_rule[rule])}
            for rule, n in sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0]))
        },
        "updates_with_coverage_gaps": sum(1 for r in rows if r["coverage_gaps"]),
        "coverage_gaps_by_rule": dict(sorted(gaps.items())),
    }


def corpus(argv: list[str]) -> int:
    out_dir = Path(argv[0]) if argv else HERE / "corpus-results"
    cache_root = Path(
        os.environ.get(
            "GARNET_BACKTEST_CACHE", Path.home() / ".cache" / "garnet-guard" / "backtest"
        )
    )
    cache = FactCache(cache_root)
    spec = json.loads(CORPUS.read_text())
    workers = int(os.environ.get("GARNET_BACKTEST_WORKERS", "4"))

    def log(msg: str) -> None:
        print(msg, flush=True)

    def one(p: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            return run_package(p["package"], p["versions"], cache, log)
        except NetError as err:
            log(f"{p['package']}: FAILED {err}")
            raise

    with ThreadPoolExecutor(max_workers=workers) as pool:
        per_pkg = list(pool.map(one, spec["packages"]))
    rows = sorted(
        (r for rs in per_pkg for r in rs), key=lambda r: (r["package"], Version(r["candidate"]))
    )
    summary = summarize(rows)
    summary["garnet_version"] = __version__
    summary["corpus"] = {k: spec[k] for k in ("selected_on", "rule", "top_list")}
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "updates.json").write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("\nSUMMARY")
    print(
        f"  {summary['updates_warned']}/{summary['updates']} clean updates warned ({summary['warn_rate']:.1%})"
    )
    for rule, c in summary["warns_by_rule"].items():
        print(f"  {rule}: {c['updates']} updates in {c['packages']} packages")
    print(f"  updates with a coverage gap (GRN-E): {summary['updates_with_coverage_gaps']}")
    return 0
