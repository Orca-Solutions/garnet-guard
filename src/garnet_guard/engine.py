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
from .checks.content import new_requirement_names, owned_young_dependencies
from .checks.docs import rule_url
from .checks.trust import coverage_notes
from .ecosystems import github, gittree, npm, pypi
from .models import (
    Change,
    ChangeResult,
    DependencyInstalls,
    DependencyProfile,
    Evidence,
    FactError,
    Finding,
    Ignore,
    Limits,
    Policy,
    ProjectReleases,
    RawFinding,
    ReleaseFacts,
    Requirement,
    Severity,
    Verdict,
)
from .net import Http, NetError

ChangeKey = tuple[str, str, str | None, str]


@dataclass(frozen=True)
class Options:
    """How to fetch: credentials, limits and the switches the backtest uses."""

    github_token: str | None = None
    limits: Limits = field(default_factory=Limits)
    # Registry data for releases the registry no longer lists (incident
    # replay), by version: PyPI files still served by URL, npm recorded facts.
    replay: Mapping[str, pypi.ReplayRelease] = field(default_factory=dict)
    npm_replay: Mapping[str, npm.ReplayRelease] = field(default_factory=dict)
    # Tags as they stood on the day of an incident, per repository, laid over
    # the tags fetched now: a sha restores a tag deleted since, None hides a
    # tag pushed later (incident replay).
    tags_then: Mapping[str, Mapping[str, str | None]] = field(default_factory=dict)
    # OSV is queried for the candidate only. The backtest turns it off so
    # results show what Garnet catches before any feed lists a release.
    check_known_bad: bool = True
    # The day ignores expire against. None means today in UTC.
    today: date | None = None
    # Per change (ecosystem, package, baseline, candidate): the versions the
    # lockfiles that change came from pin, by (ecosystem, normalized name).
    # GRN-C008 reads a young dependency's pinned versions instead of every
    # version its range allows.
    pins: Mapping[ChangeKey, Mapping[tuple[str, str], tuple[str, ...]]] = field(
        default_factory=dict
    )
    # Per change: the option (``--extra-index-url``, ``--find-links``, ...)
    # in a lockfile it came from that lets pip install from somewhere other
    # than PyPI. GRN-C008 then can't tell which index serves a young
    # dependency, so it doesn't read one and keeps its severity.
    other_index: Mapping[ChangeKey, str] = field(default_factory=dict)


ECOSYSTEMS = ("pypi", "npm")


class Fetcher:
    """One HTTP client and the per-run caches, shared by every release fetched."""

    def __init__(self, options: Options) -> None:
        self.options = options
        self.http = Http(github_token=options.github_token)
        tags = github.TagLookup(self.http, options.tags_then)
        trees = gittree.TreeLookup(self.http)
        self._pypi = pypi.FetchContext(
            http=self.http, limits=options.limits, tags=tags, trees=trees
        )
        self._npm = npm.FetchContext(http=self.http, limits=options.limits, tags=tags)
        self._profiles: dict[tuple[str, str], DependencyProfile] = {}
        self._dep_installs: dict[tuple[str, str, str, tuple[str, ...]], DependencyInstalls] = {}
        self._profiles_lock = threading.Lock()

    def __enter__(self) -> Fetcher:
        return self

    def __exit__(self, *exc: object) -> None:
        self.http.close()

    def release_facts(
        self, ecosystem: str, package: str, version: str, *, advisories: bool
    ) -> ReleaseFacts:
        if ecosystem == "npm":
            return npm.release_facts(
                package,
                version,
                self._npm,
                replay=self.options.npm_replay.get(version),
                advisories=advisories,
            )
        return pypi.release_facts(
            package,
            version,
            self._pypi,
            replay=self.options.replay.get(version),
            advisories=advisories,
        )

    def pypi_releases(self, package: str) -> ProjectReleases:
        """PyPI's release list for one project. Raises ``NetError``."""
        return pypi.project_releases(self._pypi, package)

    def dependency_profile(self, ecosystem: str, name: str) -> DependencyProfile:
        """What the registry says about a package, fetched once per run. Raises ``NetError``."""
        key = (ecosystem, name)
        with self._profiles_lock:
            hit = self._profiles.get(key)
        if hit is None:
            if ecosystem == "npm":
                hit = npm.package_profile(self._npm, name)
            else:
                hit = pypi.package_profile(self._pypi, name)
            with self._profiles_lock:
                self._profiles[key] = hit
        return hit

    def dependency_installs(
        self, ecosystem: str, req: Requirement, pinned: tuple[str, ...] = ()
    ) -> DependencyInstalls:
        """The releases of a new dependency GRN-C008 reads, once per run.
        Raises ``NetError``."""
        key = (ecosystem, req.package, req.spec, pinned)
        with self._profiles_lock:
            hit = self._dep_installs.get(key)
        if hit is None:
            if ecosystem == "npm":
                hit = npm.dependency_installs(self._npm, req, pinned)
            else:
                hit = pypi.dependency_installs(self._pypi, req, pinned)
            with self._profiles_lock:
                self._dep_installs[key] = hit
        return hit


def with_dependency_profiles(
    fetcher: Fetcher,
    base: ReleaseFacts | None,
    cand: ReleaseFacts,
    pins: Mapping[tuple[str, str], tuple[str, ...]] | None = None,
    other_index: str | None = None,
) -> ReleaseFacts:
    """The candidate with a registry profile for each dependency the baseline
    didn't declare (GRN-C008). A lookup that fails is a GRN-E001 on the
    candidate naming GRN-C008, so the rule never passes a name it couldn't see.
    Profiles the facts already carry (an incident replay) are kept. Then reads
    the releases ``with_dependency_installs`` needs.
    """
    known = {p.name for p in cand.dependencies}
    names = [n for n in new_requirement_names(base, cand) if n not in known]
    if not names:
        return with_dependency_installs(fetcher, base, cand, pins, other_index)
    profiles: list[DependencyProfile] = []
    errors: list[FactError] = []
    for name in names:
        try:
            profiles.append(fetcher.dependency_profile(cand.ecosystem, name))
        except NetError as err:
            errors.append(
                FactError(
                    "GRN-E001", f"registry lookup for dependency {name}: {err}", ("GRN-C008",)
                )
            )
    cand = replace(
        cand,
        dependencies=cand.dependencies + tuple(profiles),
        errors=cand.errors + tuple(errors),
    )
    return with_dependency_installs(fetcher, base, cand, pins, other_index)


def install_lookup_error(err: Exception, package: str, version: str) -> FactError:
    """GRN-E001 for a dependency's releases Garnet couldn't read. A response it
    couldn't parse counts the same as one that never came."""
    why = str(err) if isinstance(err, NetError) else f"unreadable response ({type(err).__name__})"
    return FactError(
        "GRN-E001",
        f"releases of dependency {package} that {version} could install: {why}",
        ("GRN-C008",),
    )


def with_dependency_installs(
    fetcher: Fetcher,
    base: ReleaseFacts | None,
    cand: ReleaseFacts,
    pins: Mapping[tuple[str, str], tuple[str, ...]] | None = None,
    other_index: str | None = None,
) -> ReleaseFacts:
    """The candidate with the releases GRN-C008 reads for each young
    dependency that shares an owner with the trusted package, read after the
    profiles: the versions ``pins`` (the lockfiles this change came from)
    gives for it, else every published version its range allows. One the
    pins map to ``()`` installs from outside the registry: nothing is read,
    and its ``problem`` says so. A read
    that fails is a GRN-E001 naming GRN-C008, and the rule keeps its
    severity for that dependency. Releases the facts already carry are kept.
    When a lockfile the change came from lets pip use another index
    (``other_index``), nothing is read: each gets a ``problem`` saying so.
    """
    known = {d.name for d in cand.dependency_installs}
    wanted = [r for r in owned_young_dependencies(base, cand) if r.package not in known]
    if not wanted:
        return cand
    got: list[DependencyInstalls] = []
    errors: list[FactError] = []
    for r in wanted:
        if other_index is not None:
            why = (
                f"the lockfile sets {other_index}, so pip can install {r.package} from "
                "somewhere other than PyPI and Garnet can't tell which release that is"
            )
            got.append(DependencyInstalls(r.package, r.spec, problem=why))
            continue
        pinned = (pins or {}).get((cand.ecosystem, normalize(cand.ecosystem, r.package)))
        if pinned == ():
            why = (
                f"the lockfile installs {r.package} from outside the registry (a URL, a path, "
                "git, another index or a bundled copy), so no release Garnet can read is the "
                "one that installs"
            )
            got.append(DependencyInstalls(r.package, r.spec, problem=why))
            continue
        try:
            got.append(fetcher.dependency_installs(cand.ecosystem, r, pinned or ()))
        except (NetError, ValueError, TypeError, KeyError, AttributeError) as err:
            errors.append(install_lookup_error(err, r.package, cand.version))
    return replace(
        cand,
        dependency_installs=cand.dependency_installs + tuple(got),
        errors=cand.errors + tuple(errors),
    )


def normalize(ecosystem: str, package: str) -> str:
    """The ecosystem's canonical spelling of a package name."""
    if ecosystem not in ECOSYSTEMS:
        raise ValueError(f"unsupported ecosystem: {ecosystem!r} (supported: pypi, npm)")
    return npm.normalize(package) if ecosystem == "npm" else pypi.normalize(package)


@dataclass(frozen=True)
class Report:
    """The results for every change checked in one run, worst first."""

    garnet_version: str
    verdict: Verdict
    results: tuple[ChangeResult, ...]
    policy: Policy = field(default_factory=Policy)
    expired: tuple[Ignore, ...] = ()  # ignores past their until date
    # (policy file, what the pull request changes in it), for the reviewer
    policy_changes: tuple[tuple[str, tuple[str, ...]], ...] = ()

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
    return ChangeResult(
        change,
        Verdict.from_severity(_worst(findings)),
        tuple(findings),
        coverage_notes(base),
    )


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
    package: str,
    versions: list[str],
    options: Options,
    *,
    candidate: str,
    ecosystem: str = "pypi",
) -> dict[str, ReleaseFacts]:
    """Fetch facts for several versions of one package in parallel."""
    with Fetcher(options) as fetcher:
        return _fetch_all(fetcher, package, versions, candidate=candidate, ecosystem=ecosystem)


def _fetch_all(
    fetcher: Fetcher, package: str, versions: list[str], *, candidate: str, ecosystem: str
) -> dict[str, ReleaseFacts]:
    with ThreadPoolExecutor(max_workers=max(1, len(versions))) as pool:
        futures = {
            v: pool.submit(
                fetcher.release_facts,
                ecosystem,
                package,
                v,
                advisories=fetcher.options.check_known_bad and v == candidate,
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
    policy = policy or Policy()
    opts = options or Options()
    opts = replace(opts, limits=_lowest(opts.limits, policy.limits))
    name = normalize(ecosystem, package)
    versions = [candidate] + ([baseline] if baseline else [])
    with Fetcher(opts) as fetcher:
        facts = _fetch_all(fetcher, name, versions, candidate=candidate, ecosystem=ecosystem)
        base = facts.get(baseline) if baseline else None
        cand = with_dependency_profiles(fetcher, base, facts[candidate])
    change = Change(ecosystem, name, baseline, candidate)
    return run_checks(change, base, cand, policy=policy, today=opts.today)


def pypi_releases(package: str, options: Options | None = None) -> ProjectReleases:
    """Every release PyPI lists for ``package``, with its files (the install
    wrapper's newest-release check). Raises ``NetError``."""
    with Fetcher(options or Options()) as fetcher:
        return fetcher.pypi_releases(package)


def evaluate(
    changes: list[Change], *, policy: Policy | None = None, options: Options | None = None
) -> list[ChangeResult]:
    """Check many changes with one HTTP client, fetching each release once."""
    policy = policy or Policy()
    opts = options or Options()
    opts = replace(opts, limits=_lowest(opts.limits, policy.limits))
    for c in changes:
        if c.ecosystem not in ECOSYSTEMS:
            raise ValueError(f"unsupported ecosystem: {c.ecosystem!r} (supported: pypi, npm)")
    if not changes:
        return []
    with Fetcher(opts) as fetcher:
        cache: dict[tuple[str, str, str, bool], Future[ReleaseFacts]] = {}
        lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=8) as pool:

            def facts(
                ecosystem: str, package: str, version: str, advisories: bool
            ) -> Future[ReleaseFacts]:
                key = (ecosystem, package, version, advisories)
                with lock:
                    if key not in cache:
                        cache[key] = pool.submit(
                            fetcher.release_facts,
                            ecosystem,
                            package,
                            version,
                            advisories=advisories,
                        )
                    return cache[key]

            pending = []
            for c in changes:
                cand = facts(c.ecosystem, c.package, c.candidate, opts.check_known_bad)
                base = facts(c.ecosystem, c.package, c.baseline, False) if c.baseline else None
                pending.append((c, base, cand))
            results = []
            for c, base, cand in pending:
                b = base.result() if base else None
                key = (c.ecosystem, c.package, c.baseline, c.candidate)
                results.append(
                    run_checks(
                        c,
                        b,
                        with_dependency_profiles(
                            fetcher,
                            b,
                            cand.result(),
                            opts.pins.get(key),
                            opts.other_index.get(key),
                        ),
                        policy=policy,
                        today=opts.today,
                    )
                )
            return results


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
    results: list[ChangeResult],
    *,
    policy: Policy | None = None,
    today: date | None = None,
    policy_changes: tuple[tuple[str, tuple[str, ...]], ...] = (),
) -> Report:
    """Collect results into a ``Report``, worst change first, with the overall verdict.

    With a ``policy``, the report names it and lists its expired ignores.
    ``policy_changes`` are carried as given; they never change the verdict.
    """
    policy = policy or Policy()
    worst = _worst(f for r in results for f in r.findings)
    ordered = sorted(
        results,
        key=lambda r: (-int(_worst(r.findings)), r.change.package, r.change.candidate),
    )
    expired = pol.expired_ignores(policy, today or _utc_today())
    return Report(
        __version__, Verdict.from_severity(worst), tuple(ordered), policy, expired, policy_changes
    )
