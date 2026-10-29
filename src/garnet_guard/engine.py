"""Orchestration: fetch facts, run checks, apply the policy."""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field, fields, replace
from datetime import UTC, date, datetime
from pathlib import Path

from . import __version__
from . import policy as pol
from .checks import ALL_CHECKS, DOCS
from .checks.docs import rule_url
from .ecosystems import github, pypi
from .models import (
    Change,
    ChangeResult,
    Evidence,
    Finding,
    Ignore,
    Limits,
    Policy,
    RawFinding,
    ReleaseFacts,
    Severity,
    Verdict,
)
from .net import Http


@dataclass(frozen=True)
class Options:
    """How to fetch: credentials, limits and the switches the backtest uses."""

    github_token: str | None = None
    limits: Limits = field(default_factory=Limits)
    # Registry data for releases the registry no longer lists (incident replay).
    replay: Mapping[str, pypi.ReplayRelease] = field(default_factory=dict)
    # Tags as they stood on the day of an incident, per repository, laid over
    # the tags fetched now: a sha restores a tag deleted since, None hides a
    # tag pushed later (incident replay).
    tags_then: Mapping[str, Mapping[str, str | None]] = field(default_factory=dict)
    # OSV is queried for the candidate only. The backtest turns it off so
    # results show what Garnet catches before any feed lists a release.
    check_known_bad: bool = True
    # The day ignores expire against. None means today in UTC.
    today: date | None = None


@dataclass(frozen=True)
class Report:
    """The results for every change checked in one run, worst first."""

    garnet_version: str
    verdict: Verdict
    results: tuple[ChangeResult, ...]
    policy: Policy = field(default_factory=Policy)
    expired: tuple[Ignore, ...] = ()  # ignores past their until date

    def exit_code(self, fail_on: Severity) -> int:
        """0 below ``fail_on``, else 1 for warn and 2 for block (SPEC §8).

        ``info`` and suppressed findings never fail a run. Exit code 3 (Garnet
        itself failed) is the CLI's to return.
        """
        worst = _worst(f for r in self.results for f in r.findings)
        if fail_on == Severity.OFF or worst < fail_on or worst < Severity.WARN:
            return 0
        return 2 if worst >= Severity.BLOCK else 1


def _utc_today() -> date:
    return datetime.now(UTC).date()


def _lowest(a: Limits, b: Limits) -> Limits:
    """Each limit at the lower of two settings (a policy may only lower them)."""
    return replace(a, **{f.name: min(getattr(a, f.name), getattr(b, f.name)) for f in fields(a)})


def _worst(findings: Iterable[Finding]) -> Severity:
    """The highest severity among findings no ignore suppressed (SPEC §8)."""
    return max((f.severity for f in findings if f.suppressed_by is None), default=Severity.OFF)


def run_checks(
    change: Change,
    base: ReleaseFacts | None,
    cand: ReleaseFacts,
    *,
    policy: Policy | None = None,
    today: date | None = None,
) -> ChangeResult:
    """Pure: facts in, findings out. Used by the engine, the backtest and tests.

    ``policy`` sets severities and suppresses ignored findings; rules set to
    "off" are left out. Ignores expire against ``today`` (default: UTC today).
    """
    policy = policy or Policy()
    day = today or _utc_today()
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
    found = {_finding(change, r, policy, day) for r in raws}
    findings = sorted(
        (f for f in found if f.severity > Severity.OFF),
        key=lambda f: (
            f.suppressed_by is not None,
            -int(f.severity),
            f.rule_id,
            f.release or "",
            f.title,
        ),
    )
    return ChangeResult(change, Verdict.from_severity(_worst(findings)), tuple(findings))


def _finding(change: Change, raw: RawFinding, policy: Policy, today: date) -> Finding:
    doc = DOCS[raw.rule_id]
    severity = pol.severity_for(policy, doc)
    if raw.lowered_to is not None and raw.lowered_to < severity:
        severity = raw.lowered_to
    ignore, expired = pol.suppression(policy, raw.rule_id, change, today)
    evidence = raw.evidence + tuple(
        Evidence(
            "note",
            f"an ignore for this expired on {e.until.isoformat()} and no longer applies "
            f"(reason given: {e.reason})",
        )
        for e in expired
    )
    return Finding(
        rule_id=raw.rule_id,
        name=doc.name,
        severity=severity,
        default_severity=doc.default,
        change=change,
        title=raw.title,
        evidence=evidence,
        explanation=doc.explanation,
        remediation=doc.remediation,
        release=raw.release,
        docs_url=rule_url(raw.rule_id),
        suppressed_by=ignore,
    )


def fetch_facts(
    package: str, versions: list[str], options: Options, *, candidate: str
) -> dict[str, ReleaseFacts]:
    """Fetch facts for several versions of one package in parallel."""
    with Http(github_token=options.github_token) as http:
        ctx = pypi.FetchContext(
            http=http, limits=options.limits, tags=github.TagLookup(http, options.tags_then)
        )
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
    policy: Policy | None = None,
    options: Options | None = None,
) -> ChangeResult:
    """Compare two releases of one package (``garnet diff``).

    Fetches both releases, so it needs the network. Problems fetching or
    reading them come back as GRN-E findings, not exceptions.
    """
    if ecosystem != "pypi":
        raise ValueError(f"unsupported ecosystem: {ecosystem!r} (0.1 supports pypi)")
    policy = policy or Policy()
    opts = options or Options()
    opts = replace(opts, limits=_lowest(opts.limits, policy.limits))
    name = pypi.normalize(package)
    versions = [candidate] + ([baseline] if baseline else [])
    facts = fetch_facts(name, versions, opts, candidate=candidate)
    change = Change(ecosystem, name, baseline, candidate)
    return run_checks(
        change,
        facts.get(baseline) if baseline else None,
        facts[candidate],
        policy=policy,
        today=opts.today,
    )


def evaluate(
    changes: list[Change], *, policy: Policy | None = None, options: Options | None = None
) -> list[ChangeResult]:
    """Check many changes with one HTTP client, fetching each release once."""
    policy = policy or Policy()
    opts = options or Options()
    opts = replace(opts, limits=_lowest(opts.limits, policy.limits))
    for c in changes:
        if c.ecosystem != "pypi":
            raise ValueError(f"unsupported ecosystem: {c.ecosystem!r} (0.1 supports pypi)")
    if not changes:
        return []
    with Http(github_token=opts.github_token) as http:
        ctx = pypi.FetchContext(
            http=http, limits=opts.limits, tags=github.TagLookup(http, opts.tags_then)
        )
        cache: dict[tuple[str, str, bool], Future[ReleaseFacts]] = {}
        lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=8) as pool:

            def facts(package: str, version: str, advisories: bool) -> Future[ReleaseFacts]:
                key = (package, version, advisories)
                with lock:
                    if key not in cache:
                        cache[key] = pool.submit(
                            pypi.release_facts,
                            package,
                            version,
                            ctx,
                            replay=opts.replay.get(version),
                            advisories=advisories,
                        )
                    return cache[key]

            pending = []
            for c in changes:
                cand = facts(c.package, c.candidate, opts.check_known_bad)
                base = facts(c.package, c.baseline, False) if c.baseline else None
                pending.append((c, base, cand))
            return [
                run_checks(
                    c,
                    base.result() if base else None,
                    cand.result(),
                    policy=policy,
                    today=opts.today,
                )
                for c, base, cand in pending
            ]


def unchecked_result(
    change: Change,
    rule_id: str,
    detail: str,
    *,
    policy: Policy | None = None,
    today: date | None = None,
) -> ChangeResult:
    """A change Garnet didn't evaluate (GRN-E004 / GRN-E005): reported, never passed."""
    where = f"{change.lockfile}:{change.line}" if change.lockfile and change.line else None
    raw = RawFinding(
        rule_id,
        f"{change.package} was not checked: {detail}",
        (Evidence("file", detail, path=change.lockfile, line=change.line),) if where else (),
    )
    finding = _finding(change, raw, policy or Policy(), today or _utc_today())
    return ChangeResult(change, Verdict.from_severity(_worst([finding])), (finding,))


def diff_lockfiles(
    base: Path | bytes | None, head: Path | bytes, *, name: str | None = None
) -> list[Change]:
    """Checkable changes between two lockfiles of the same format (SPEC §3.2)."""
    from .workspace import changes_for

    head_name = name or (head.name if isinstance(head, Path) else "uv.lock")
    head_data = head.read_bytes() if isinstance(head, Path) else head
    base_data = base.read_bytes() if isinstance(base, Path) else base
    return changes_for(head_name, head_data, base_data)[0]


def report(
    results: list[ChangeResult], *, policy: Policy | None = None, today: date | None = None
) -> Report:
    """Collect results into a ``Report``, worst change first, with the overall verdict.

    With a ``policy``, the report names it and lists its expired ignores.
    """
    policy = policy or Policy()
    worst = _worst(f for r in results for f in r.findings)
    ordered = sorted(
        results,
        key=lambda r: (-int(_worst(r.findings)), r.change.package, r.change.candidate),
    )
    expired = pol.expired_ignores(policy, today or _utc_today())
    return Report(__version__, Verdict.from_severity(worst), tuple(ordered), policy, expired)
