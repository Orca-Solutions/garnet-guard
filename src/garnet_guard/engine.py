"""Orchestration: fetch facts, run checks, apply default severities."""

from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import __version__
from .checks import ALL_CHECKS, DOCS
from .checks.docs import rule_url
from .ecosystems import github, pypi
from .models import (
    Change,
    ChangeResult,
    Evidence,
    Finding,
    Limits,
    RawFinding,
    ReleaseFacts,
    Severity,
    Verdict,
)
from .net import Http


@dataclass(frozen=True)
class Options:
    github_token: str | None = None
    limits: Limits = field(default_factory=Limits)
    # Registry data for releases the registry no longer lists (incident replay).
    replay: Mapping[str, pypi.ReplayRelease] = field(default_factory=dict)
    # OSV is queried for the candidate only. The backtest turns it off so
    # results show what Garnet catches before any feed lists a release.
    check_known_bad: bool = True


@dataclass(frozen=True)
class Report:
    garnet_version: str
    verdict: Verdict
    results: tuple[ChangeResult, ...]

    def exit_code(self, fail_on: Severity) -> int:
        worst = max((f.severity for r in self.results for f in r.findings), default=Severity.OFF)
        if fail_on == Severity.OFF or worst < fail_on or worst < Severity.WARN:
            return 0
        return 2 if worst >= Severity.BLOCK else 1


def run_checks(change: Change, base: ReleaseFacts | None, cand: ReleaseFacts) -> ChangeResult:
    """Pure: facts in, findings out. Used by the engine, the backtest and tests."""
    raws: list[RawFinding] = []
    for _rule, fn, ecos in ALL_CHECKS:
        if change.ecosystem in ecos:
            raws.extend(fn(change, base, cand))
    for rel in (cand, base):
        if rel is None:
            continue
        for err in rel.errors:
            ev = [Evidence("note", err.summary, path=err.path)]
            if err.rules:
                ev.append(Evidence("note", "not evaluated: " + ", ".join(err.rules)))
            raws.append(
                RawFinding(
                    err.code,
                    f"Couldn't fully check {rel.version}: {err.summary}",
                    tuple(ev),
                    release=rel.version if rel is base else None,
                )
            )
    findings = sorted(
        {_finding(change, r) for r in raws},
        key=lambda f: (-int(f.severity), f.rule_id, f.release or "", f.title),
    )
    worst = max((f.severity for f in findings), default=Severity.OFF)
    return ChangeResult(change, Verdict.from_severity(worst), tuple(findings))


def _finding(change: Change, raw: RawFinding) -> Finding:
    doc = DOCS[raw.rule_id]
    severity = doc.default
    if raw.lowered_to is not None and raw.lowered_to < doc.default:
        severity = raw.lowered_to
    return Finding(
        rule_id=raw.rule_id,
        name=doc.name,
        severity=severity,
        default_severity=doc.default,
        change=change,
        title=raw.title,
        evidence=raw.evidence,
        explanation=doc.explanation,
        remediation=doc.remediation,
        release=raw.release,
        docs_url=rule_url(raw.rule_id),
    )


def fetch_facts(
    package: str, versions: list[str], options: Options, *, candidate: str
) -> dict[str, ReleaseFacts]:
    with Http(github_token=options.github_token) as http:
        ctx = pypi.FetchContext(http=http, limits=options.limits, tags=github.TagLookup(http))
        with ThreadPoolExecutor(max_workers=max(1, len(versions))) as pool:
            futures = {
                v: pool.submit(
                    pypi.release_facts,
                    package,
                    v,
                    ctx,
                    replay=options.replay.get(v),
                    advisories=options.check_known_bad and v == candidate,
                )
                for v in versions
            }
            return {v: f.result() for v, f in futures.items()}


def compare(
    ecosystem: str,
    package: str,
    baseline: str | None,
    candidate: str,
    *,
    options: Options | None = None,
) -> ChangeResult:
    if ecosystem != "pypi":
        raise ValueError(f"unsupported ecosystem: {ecosystem!r} (0.1 supports pypi)")
    opts = options or Options()
    name = pypi.normalize(package)
    versions = [candidate] + ([baseline] if baseline else [])
    facts = fetch_facts(name, versions, opts, candidate=candidate)
    change = Change(ecosystem, name, baseline, candidate)
    return run_checks(change, facts.get(baseline) if baseline else None, facts[candidate])


def report(results: list[ChangeResult]) -> Report:
    worst = max((f.severity for r in results for f in r.findings), default=Severity.OFF)
    return Report(__version__, Verdict.from_severity(worst), tuple(results))
