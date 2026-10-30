"""Clean-corpus backtest: the last releases of the top PyPI and npm packages.

    uv run python -m backtest select           # pick versions, write corpus.json
    uv run python -m backtest corpus           # run every consecutive update in corpus.json
    uv run python -m backtest select npm       # the same for npm (corpus-npm.json)
    uv run python -m backtest corpus npm       # results go to corpus-results-npm/
    uv run python -m backtest select pypi 1000 # the top 1,000 (corpus-pypi-1000.json)
    uv run python -m backtest corpus pypi 1000 # results go to corpus-results-pypi-1000/

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
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from garnet_guard import __version__, models
from garnet_guard.checks.content import new_requirement_names
from garnet_guard.ecosystems import github, gittree, npm, pypi
from garnet_guard.engine import run_checks
from garnet_guard.models import (
    Change,
    ChangeResult,
    DependencyProfile,
    FactError,
    Limits,
    ReleaseFacts,
    Severity,
)
from garnet_guard.net import Http, NetError

HERE = Path(__file__).parent
TOP = {"pypi": HERE / "top-pypi-1000.json", "npm": HERE / "top-npm-1000.json"}
DEFAULT_SIZE = {"pypi": 100, "npm": 200}
# The first corpora keep the names they were published under.
FIRST = {
    ("pypi", 100): ("corpus.json", "corpus-results"),
    ("npm", 200): ("corpus-npm.json", "corpus-results-npm"),
}
NOT_DETECTION = {"GRN-K001", "GRN-E001", "GRN-E002", "GRN-E003"}
RELEASES_PER_PACKAGE = 11  # 11 releases give 10 updates per package
CACHE_FORMAT = 7


def _ecosystem(argv: list[str]) -> tuple[str, int, list[str]]:
    """``[pypi|npm] [SIZE]``: the ecosystem (PyPI by default) and how many top packages."""
    eco = "pypi"
    if argv and argv[0] in ("pypi", "npm"):
        eco, argv = argv[0], argv[1:]
    size = DEFAULT_SIZE[eco]
    if argv and argv[0].isdigit():
        size, argv = int(argv[0]), argv[1:]
    return eco, size, argv


def _paths(eco: str, size: int) -> tuple[Path, Path]:
    """The corpus file and the results folder for the top ``size`` packages."""
    corpus_file, results = FIRST.get(
        (eco, size), (f"corpus-{eco}-{size}.json", f"corpus-results-{eco}-{size}")
    )
    return HERE / corpus_file, HERE / results


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


def pick_npm_versions(packument: dict[str, Any], count: int) -> list[str]:
    """The last ``count`` final, non-deprecated versions of an npm package.

    A version with a pre-release part (``1.0.0-beta.1``) is skipped, as npm's
    own semver ranges skip it. Order is by semver.
    """
    keep: list[tuple[tuple[int, ...], str]] = []
    for raw, doc in (packument.get("versions") or {}).items():
        core, _, pre = raw.partition("-")
        parts = core.split(".")
        if pre or len(parts) != 3 or not all(p.isdigit() for p in parts):
            continue
        if isinstance(doc, dict) and doc.get("deprecated"):
            continue
        keep.append((tuple(int(p) for p in parts), raw))
    keep.sort()
    return [raw for _, raw in keep[-count:]]


def _select_one(eco: str, http: Http, name: str) -> dict[str, Any]:
    if eco == "npm":
        norm = npm.normalize(name)
        resp = http.get(npm.registry_url(norm), max_bytes=npm.PACKUMENT_MAX_BYTES)
    else:
        norm = pypi.normalize(name)
        resp = http.get(f"https://pypi.org/pypi/{norm}/json", max_bytes=512 * 1024 * 1024)
    if resp.status != 200:
        raise NetError(f"select: {norm}: HTTP {resp.status}")
    if eco == "npm":
        versions = pick_npm_versions(resp.json(), RELEASES_PER_PACKAGE)
    else:
        versions = pick_versions(resp.json().get("releases", {}), RELEASES_PER_PACKAGE)
    print(f"{norm}: {' '.join(versions)}", flush=True)
    return {"package": norm, "versions": versions}


def select(argv: list[str]) -> int:
    eco, size, _ = _ecosystem(argv)
    top = json.loads(TOP[eco].read_text())
    if size > len(top["projects"]):
        print(f"select: {TOP[eco].name} lists {len(top['projects'])} packages", file=sys.stderr)
        return 3
    with Http() as http, ThreadPoolExecutor(max_workers=8) as pool:
        try:
            packages = list(
                pool.map(lambda name: _select_one(eco, http, name), top["projects"][:size])
            )
        except NetError as err:
            print(err, file=sys.stderr)
            return 3
    out = {
        "ecosystem": eco,
        "selected_on": datetime.now().astimezone().date().isoformat(),
        "rule": f"last {RELEASES_PER_PACKAGE} final, non-{'deprecated' if eco == 'npm' else 'yanked'} releases by version",
        "top_list": {k: top[k] for k in ("source", "last_update", "package_version") if k in top},
        "packages": packages,
    }
    _paths(eco, size)[0].write_text(json.dumps(out, indent=2) + "\n")
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
        args = typing.get_args(tp)
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(decode(args[0], x) for x in data)
        return tuple(decode(a, x) for a, x in zip(args, data, strict=True))
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

    def _path(self, ecosystem: str, package: str, version: str) -> Path:
        return self.root / ecosystem / package / f"{version}.json"

    def get(self, ecosystem: str, package: str, version: str) -> ReleaseFacts | None:
        p = self._path(ecosystem, package, version)
        if not p.exists():
            return None
        facts: ReleaseFacts = decode(ReleaseFacts, json.loads(p.read_text()))
        return facts

    def put(self, facts: ReleaseFacts) -> None:
        p = self._path(facts.ecosystem, facts.package, facts.version)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(encode(facts), sort_keys=True))
        tmp.replace(p)


class ProfileCache:
    """Registry profiles of new dependencies (GRN-C008), one JSON file per name.

    A profile says how old a package is as of the day it was fetched, so it is
    cached with the facts and a rerun sees the same answer.
    """

    def __init__(self, root: Path) -> None:
        self.root = root / f"v{CACHE_FORMAT}-garnet-{__version__}" / "profiles"

    def _path(self, ecosystem: str, name: str) -> Path:
        return self.root / ecosystem / f"{name.replace('/', '__')}.json"

    def get(self, ecosystem: str, name: str) -> DependencyProfile | None:
        p = self._path(ecosystem, name)
        if not p.exists():
            return None
        profile: DependencyProfile = decode(DependencyProfile, json.loads(p.read_text()))
        return profile

    def put(self, ecosystem: str, profile: DependencyProfile) -> None:
        p = self._path(ecosystem, profile.name)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(encode(profile), sort_keys=True))
        tmp.replace(p)


def with_profiles(
    ecosystem: str, base: ReleaseFacts, cand: ReleaseFacts, cache: ProfileCache
) -> ReleaseFacts:
    """The candidate with a registry profile for each dependency the baseline
    didn't declare, as ``engine.with_dependency_profiles`` does, cached on disk."""
    names = new_requirement_names(base, cand)
    if not names:
        return cand
    profiles: list[DependencyProfile] = []
    errors: list[FactError] = []
    todo: list[str] = []
    for name in names:
        hit = cache.get(ecosystem, name)
        if hit is None:
            todo.append(name)
        else:
            profiles.append(hit)
    if todo:
        with Http() as http:
            tags = github.TagLookup(http)
            for name in todo:
                try:
                    if ecosystem == "npm":
                        nctx = npm.FetchContext(http=http, limits=Limits(), tags=tags)
                        profile = npm.package_profile(nctx, name)
                    else:
                        pctx = pypi.FetchContext(
                            http=http, limits=Limits(), tags=tags, trees=gittree.TreeLookup(http)
                        )
                        profile = pypi.package_profile(pctx, name)
                except NetError as err:
                    errors.append(
                        FactError(
                            "GRN-E001",
                            f"registry lookup for dependency {name}: {err}",
                            ("GRN-C008",),
                        )
                    )
                    continue
                cache.put(ecosystem, profile)
                profiles.append(profile)
    return dataclasses.replace(
        cand, dependencies=tuple(profiles), errors=cand.errors + tuple(errors)
    )


def _transient(facts: ReleaseFacts) -> bool:
    """Don't cache a release whose facts are missing because a request failed."""
    return any(e.code == "GRN-E001" for e in facts.errors)


# --- Running -------------------------------------------------------------


def fetch_package(
    ecosystem: str, package: str, versions: list[str], cache: FactCache, *, workers: int = 3
) -> dict[str, ReleaseFacts]:
    out: dict[str, ReleaseFacts] = {}
    todo = []
    for v in versions:
        hit = cache.get(ecosystem, package, v)
        if hit is not None:
            out[v] = hit
        else:
            todo.append(v)
    if not todo:
        return out
    with Http() as http:
        tags = github.TagLookup(http)

        if ecosystem == "npm":
            nctx = npm.FetchContext(http=http, limits=Limits(), tags=tags)

            def fetch(v: str) -> ReleaseFacts:
                return npm.release_facts(package, v, nctx, advisories=False)

        else:
            trees = gittree.TreeLookup(http)
            pctx = pypi.FetchContext(http=http, limits=Limits(), tags=tags, trees=trees)

            def fetch(v: str) -> ReleaseFacts:
                return pypi.release_facts(package, v, pctx, advisories=False)

        # The first release warms the tag (and packument) cache, so the rest
        # don't each fetch it.
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
    ecosystem: str,
    package: str,
    versions: list[str],
    cache: FactCache,
    log: Callable[[str], None],
) -> list[dict[str, Any]]:
    t0 = time.monotonic()
    facts = fetch_package(ecosystem, package, versions, cache)
    profiles = ProfileCache(cache.root.parent)
    rows: list[dict[str, Any]] = []
    for old, new in zip(versions, versions[1:], strict=False):
        cand = with_profiles(ecosystem, facts[old], facts[new], profiles)
        result = run_checks(Change(ecosystem, package, old, new), facts[old], cand)
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


def _version_key(v: str) -> tuple[int, Version | str]:
    try:
        return (1, Version(v))
    except InvalidVersion:
        return (0, v)


def _run_one(job: tuple[str, str, list[str], Path]) -> list[dict[str, Any]]:
    """One package, in a worker process: the fact inspection is CPU-bound."""
    eco, package, versions, cache_root = job

    def log(msg: str) -> None:
        print(msg, flush=True)

    try:
        return run_package(eco, package, versions, FactCache(cache_root), log)
    except NetError as err:
        log(f"{package}: FAILED {err}")
        raise


def corpus(argv: list[str]) -> int:
    eco, size, argv = _ecosystem(argv)
    corpus_file, results = _paths(eco, size)
    out_dir = Path(argv[0]) if argv else results
    cache_root = Path(
        os.environ.get(
            "GARNET_BACKTEST_CACHE", Path.home() / ".cache" / "garnet-guard" / "backtest"
        )
    )
    spec = json.loads(corpus_file.read_text())
    workers = int(os.environ.get("GARNET_BACKTEST_WORKERS", "4"))
    jobs = [(eco, p["package"], p["versions"], cache_root) for p in spec["packages"]]

    with ProcessPoolExecutor(max_workers=workers) as pool:
        per_pkg = list(pool.map(_run_one, jobs))
    rows = sorted(
        (r for rs in per_pkg for r in rs),
        key=lambda r: (r["package"], _version_key(r["candidate"])),
    )
    summary = summarize(rows)
    summary["garnet_version"] = __version__
    summary["ecosystem"] = eco
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
