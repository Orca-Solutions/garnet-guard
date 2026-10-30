"""Replay real incidents and clean updates through the engine.

    uv run python -m backtest                  # incidents and clean updates, PyPI and npm
    uv run python -m backtest incidents        # incidents only
    uv run python -m backtest select [npm]     # pick the clean corpus (top packages x last 11 releases)
    uv run python -m backtest corpus [npm] [DIR]  # run the clean corpus; see backtest/corpus.py

Known-bad lookups (GRN-K001) are off: the question is what Garnet catches
before any feed lists a release. Incidents are replayed against the git tags
as they stood when the release was uploaded (``tags_on_the_day`` in
incidents.toml), and again against today's tags where those differ. Results
go to backtest/results.json.
"""

from __future__ import annotations

import json
import sys
import tomllib
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any

from garnet_guard.ecosystems import npm
from garnet_guard.ecosystems.pypi import RegistryFile, ReplayRelease
from garnet_guard.engine import Options, compare, report
from garnet_guard.models import ChangeResult, Severity
from garnet_guard.report import to_text

HERE = Path(__file__).parent
DETECTION_RULES_EXCLUDED = {"GRN-K001", "GRN-E001", "GRN-E002", "GRN-E003"}


def _detected(result: ChangeResult) -> list[str]:
    return sorted(
        {
            f.rule_id
            for f in result.findings
            if f.severity >= Severity.WARN and f.rule_id not in DETECTION_RULES_EXCLUDED
        }
    )


def _tags_then(inc: dict[str, Any]) -> dict[str, dict[str, str | None]]:
    """The incident's tag changes since the upload, as ``Options.tags_then``."""
    out: dict[str, dict[str, str | None]] = {}
    for t in inc.get("tags_on_the_day", []):
        out.setdefault(t["repo"], {})[t["tag"]] = None if t.get("absent") else t["sha"]
    return out


def _pypi_options(inc: dict[str, Any]) -> Options:
    """PyPI incidents: the removed files are still served by URL and hash."""
    files = inc["files"]
    assert isinstance(files, list)
    replay = ReplayRelease(
        files=tuple(
            RegistryFile(
                filename=f["filename"],
                url=f["url"],
                sha256=f["sha256"],
                packagetype=f["packagetype"],
                uploaded_at=datetime.fromisoformat(f["uploaded_at"]),
            )
            for f in files
        ),
        source_repo=str(inc["source_repo"]),
        note="replayed: release removed from PyPI; files fetched by URL and hash, provenance not available",
    )
    return Options(
        replay={str(inc["candidate"]): replay}, check_known_bad=False, tags_then=_tags_then(inc)
    )


def _npm_options(inc: dict[str, Any]) -> Options:
    """npm incidents: the registry record is gone, so facts come from write-ups."""
    scripts = inc.get("scripts", [])
    assert isinstance(scripts, list)
    tp = inc.get("trusted_publisher")
    replay = npm.ReplayRelease(
        uploaded_at=datetime.fromisoformat(str(inc["uploaded_at"])),
        attestation=bool(inc.get("attestation", False)),
        trusted_publisher=bool(tp) if tp is not None else None,
        scripts=tuple((str(k), str(v)) for k, v in scripts),
        source_repo=str(inc["source_repo"]),
        note=str(inc["note"]),
    )
    return Options(
        npm_replay={str(inc["candidate"]): replay},
        check_known_bad=False,
        tags_then=_tags_then(inc),
    )


def run_incidents() -> list[dict[str, object]]:
    """Replay each incident against the tags as they stood on the day.

    Where an incident records tags that changed since (``tags_on_the_day``),
    it is replayed again against today's tags, so both results are on the
    record.
    """
    incidents: list[dict[str, Any]] = []
    for name in ("incidents.toml", "npm-incidents.toml"):
        incidents += tomllib.loads((HERE / name).read_text())["incident"]
    rows = []
    for inc in incidents:
        eco = str(inc.get("ecosystem", "pypi"))
        opts = _npm_options(inc) if eco == "npm" else _pypi_options(inc)
        package, baseline, candidate = (
            str(inc["package"]),
            str(inc["baseline"]),
            str(inc["candidate"]),
        )
        result = compare(eco, package, baseline, candidate, options=opts)
        rules = _detected(result)
        print(f"=== incident {inc['id']}: {inc['summary']}")
        if opts.tags_then:
            print("tags as of the upload:")
        print(to_text(report([result])))
        row: dict[str, object] = {
            "id": inc["id"],
            "ecosystem": eco,
            "baseline": baseline,
            "candidate": candidate,
            "caught": bool(rules),
            "rules": rules,
            "verdict": result.verdict.value,
        }
        if opts.tags_then:
            today = compare(eco, package, baseline, candidate, options=replace(opts, tags_then={}))
            print("tags as of today:")
            print(to_text(report([today])))
            row["rules_with_todays_tags"] = _detected(today)
        rows.append(row)
    return rows


def run_clean() -> list[dict[str, object]]:
    data = tomllib.loads((HERE / "clean.toml").read_text())
    pairs = [("pypi", *p) for p in data["pairs"]] + [("npm", *p) for p in data.get("npm_pairs", [])]
    rows = []
    for eco, package, old, new in pairs:
        result = compare(eco, package, old, new, options=Options(check_known_bad=False))
        rules = _detected(result)
        errors = sorted({f.rule_id for f in result.findings if f.rule_id.startswith("GRN-E")})
        print(
            f"--- clean {eco} {package} {old} → {new}: {result.verdict.value} {rules or ''} {errors or ''}"
        )
        if rules or errors:
            print(to_text(report([result])))
        rows.append(
            {
                "ecosystem": eco,
                "package": package,
                "baseline": old,
                "candidate": new,
                "warned": bool(rules),
                "rules": rules,
                "errors": errors,
            }
        )
    return rows


def main(argv: list[str]) -> int:
    which = argv[0] if argv else "all"
    if which in ("select", "corpus"):
        from . import corpus

        return corpus.select(argv[1:]) if which == "select" else corpus.corpus(argv[1:])
    out: dict[str, object] = {}
    ok = True
    if which in ("all", "incidents"):
        inc = run_incidents()
        out["incidents"] = inc
        ok = all(r["caught"] for r in inc)
    if which in ("all", "clean"):
        clean = run_clean()
        out["clean"] = clean
        warned = sum(1 for r in clean if r["warned"])
        out["clean_warn_rate"] = f"{warned}/{len(clean)}"
    print("\nSUMMARY")
    for r in out.get("incidents", []):  # type: ignore[union-attr]
        line = f"  incident {r['id']}: {'CAUGHT' if r['caught'] else 'MISSED'} by {', '.join(r['rules']) or 'nothing'}"
        if "rules_with_todays_tags" in r:
            line += f" (with today's tags: {', '.join(r['rules_with_todays_tags']) or 'nothing'})"
        print(line)
    if "clean_warn_rate" in out:
        print(f"  clean updates with a warn from a detection rule: {out['clean_warn_rate']}")
    (HERE / "results.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
