"""GRN-C008 new-dependency: reading declared dependencies, registry profiles
and the engine's lookups. Synthetic data only; no network."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from backtest.corpus import ProfileCache
from garnet_guard.checks.content import new_requirement_names
from garnet_guard.ecosystems import npm, pypi
from garnet_guard.ecosystems.github import TagLookup
from garnet_guard.ecosystems.gittree import TreeLookup
from garnet_guard.engine import run_checks, with_dependency_profiles
from garnet_guard.facts.inventory import declared_requirements
from garnet_guard.facts.npmmeta import declared_dependencies
from garnet_guard.models import (
    Change,
    DependencyProfile,
    Limits,
    ReleaseFacts,
    Requirement,
    Severity,
    Verdict,
)
from garnet_guard.net import Http, NetError, Response
from tests.builders import release

CHANGE = Change("pypi", "demo", "1.0", "1.1")
UPLOADED = datetime(2026, 9, 1, tzinfo=UTC)


def _meta(*lines: str, version: str = "2.1") -> bytes:
    return "\n".join([f"Metadata-Version: {version}", "Name: demo", *lines, ""]).encode()


def _depends(version: str, *requires: str) -> ReleaseFacts:
    body = _meta(*(f"Requires-Dist: {r}" for r in requires)).decode()
    rel = release(version, {"demo/__init__.py": "", f"demo-{version}.dist-info/METADATA": body})
    return replace(rel, artifacts=tuple(replace(a, uploaded_at=UPLOADED) for a in rel.artifacts))


# Reading Requires-Dist


def test_requires_dist_skips_extras_and_keeps_markers() -> None:
    reqs = declared_requirements(
        _meta(
            "Requires-Dist: Requests>=2.31",
            'Requires-Dist: tomli>=1; python_version < "3.11"',
            'Requires-Dist: pytest; extra == "test"',
            "Requires-Dist: requests[socks]",
        )
    )
    assert reqs == (
        Requirement("requests", "Requests>=2.31", also=("requests[socks]",)),
        Requirement("tomli", 'tomli>=1; python_version < "3.11"'),
    )


def test_an_unparsable_requirement_is_kept_under_its_name() -> None:
    reqs = declared_requirements(_meta("Requires-Dist: Odd_Name ((>=1"))
    assert reqs == (Requirement("odd-name", "Odd_Name ((>=1"),)


def test_sdist_dependencies_count_only_when_pkg_info_fixes_them() -> None:
    line = "Requires-Dist: requests"
    assert declared_requirements(_meta(line, version="2.1"), sdist=True) is None
    assert declared_requirements(_meta(line, version="2.2"), sdist=True) == (
        Requirement("requests", "requests"),
    )
    dynamic = _meta(line, "Dynamic: Requires-Dist", version="2.4")
    assert declared_requirements(dynamic, sdist=True) is None
    assert declared_requirements(_meta(line, version="2.1")) == (
        Requirement("requests", "requests"),
    )


def test_package_json_dependencies() -> None:
    doc = {
        "dependencies": {"through": "~2.3.1", "from": "~0"},
        "optionalDependencies": {"fsevents": "^2"},
        "peerDependencies": {"react": ">=18", "react-dom": ">=18"},
        "peerDependenciesMeta": {"react-dom": {"optional": True}},
        "devDependencies": {"tap": "*"},
        "bundleDependencies": ["through"],
    }
    assert declared_dependencies(json.dumps(doc).encode()) == (
        Requirement("through", "through@~2.3.1"),
        Requirement("from", "from@~0"),
        Requirement("fsevents", "fsevents@^2 (optional)"),
        Requirement("react", "react@>=18 (peer)"),
    )
    assert declared_dependencies(b"not json") == ()
    assert declared_dependencies(b"[]") == ()


# Registry profiles


class _Http:
    def __init__(self, routes: dict[str, tuple[int, Any]]) -> None:
        self.routes = routes
        self.calls: list[str] = []

    def get(self, url: str, **kwargs: object) -> Response:
        self.calls.append(url)
        status, body = self.routes.get(url, (404, {}))
        return Response(status=status, content=json.dumps(body).encode(), url=url)


def _pypi_ctx(http: _Http) -> pypi.FetchContext:
    h = cast(Http, http)
    return pypi.FetchContext(http=h, limits=Limits(), tags=TagLookup(h), trees=TreeLookup(h))


def test_pypi_profile() -> None:
    doc = {
        "info": {"version": "0.2", "project_urls": {"Source": "https://github.com/a/helper"}},
        "releases": {
            "0.1": [{"upload_time_iso_8601": "2026-08-01T10:00:00Z"}],
            "0.2": [{"upload_time_iso_8601": "2026-08-20T10:00:00Z"}],
            "0.0": [],
        },
    }
    http = _Http({"https://pypi.org/pypi/stream-helper/json": (200, doc)})
    p = pypi.package_profile(_pypi_ctx(http), "Stream_Helper")
    assert p == DependencyProfile(
        "stream-helper",
        True,
        datetime(2026, 8, 1, 10, tzinfo=UTC),
        2,
        source_repo="a/helper",
        latest_version="0.2",
    )
    missing = pypi.package_profile(_pypi_ctx(_Http({})), "nothing-here")
    assert missing == DependencyProfile("nothing-here", on_registry=False)


def test_pypi_profile_error_raises() -> None:
    http = _Http({"https://pypi.org/pypi/flaky/json": (503, {})})
    try:
        pypi.package_profile(_pypi_ctx(http), "flaky")
    except NetError as err:
        assert "HTTP 503" in str(err)
    else:
        raise AssertionError("expected NetError")


def test_npm_profile() -> None:
    doc = {
        "name": "streamhelper",
        "time": {"created": "2018-08-05T01:00:00Z", "0.1.0": "2018-08-05T01:00:00Z"},
        "versions": {"0.1.0": {"repository": "github:hugeglass/streamhelper"}},
        "dist-tags": {"latest": "0.1.0"},
    }
    http = _Http({"https://registry.npmjs.org/streamhelper": (200, doc)})
    h = cast(Http, http)
    p = npm.package_profile(
        npm.FetchContext(http=h, limits=Limits(), tags=TagLookup(h)), "streamhelper"
    )
    assert p.on_registry and p.releases == 1 and p.latest_version == "0.1.0"
    assert p.first_release_at == datetime(2018, 8, 5, 1, tzinfo=UTC)
    assert p.source_repo == "hugeglass/streamhelper"


def test_npm_profile_of_a_name_npm_cannot_hold() -> None:
    # A package.json key is the package's own text: a name npm would refuse is
    # not on the registry, without a request, and never raises.
    http = _Http({})
    h = cast(Http, http)
    ctx = npm.FetchContext(http=h, limits=Limits(), tags=TagLookup(h))
    for bad in ("../../etc", " lodash", "Has Space", "@scope/", "a" * 215):
        assert npm.package_profile(ctx, bad) == DependencyProfile(bad, on_registry=False)
    assert http.calls == []


# The check


def _profile(name: str, days_before: int, releases: int = 1) -> DependencyProfile:
    return DependencyProfile(name, True, UPLOADED - timedelta(days=days_before), releases)


def test_young_dependency_warns_with_evidence() -> None:
    cand = replace(_depends("1.1", "requests", "helper"), dependencies=(_profile("helper", 12),))
    result = run_checks(CHANGE, _depends("1.0", "requests"), cand)
    (f,) = [f for f in result.findings if f.rule_id == "GRN-C008"]
    assert f.severity == Severity.WARN and result.verdict == Verdict.WARN
    assert (
        f.title
        == "1.1 depends on 1 package(s) that 1.0 didn't; helper was first released 12 day(s) before it"
    )
    assert f.evidence[0].summary == (
        "helper: first released 2026-08-20, 12 day(s) before 1.1; 1 release(s); no repository link"
    )
    assert f.evidence[0].url == "https://pypi.org/project/helper/"


def test_dependency_published_after_the_release_says_so() -> None:
    cand = replace(_depends("1.1", "helper"), dependencies=(_profile("helper", -3),))
    (f,) = [
        f for f in run_checks(CHANGE, _depends("1.0"), cand).findings if f.rule_id == "GRN-C008"
    ]
    assert f.severity == Severity.WARN
    assert "after 1.1 itself" in f.evidence[0].summary
    assert f.title.endswith("helper was first released 0 day(s) before it")


def test_established_dependency_is_info() -> None:
    cand = replace(_depends("1.1", "idna"), dependencies=(_profile("idna", 4000, 40),))
    result = run_checks(CHANGE, _depends("1.0"), cand)
    (f,) = [f for f in result.findings if f.rule_id == "GRN-C008"]
    assert f.severity == Severity.INFO and result.verdict == Verdict.PASS


def test_no_baseline_means_nothing_to_compare() -> None:
    assert new_requirement_names(None, _depends("1.1", "helper")) == ()
    result = run_checks(replace(CHANGE, baseline=None), None, _depends("1.1", "helper"))
    assert "GRN-C008" not in {f.rule_id for f in result.findings}


# The engine's lookups


class _Fetcher:
    def __init__(self, profiles: dict[str, DependencyProfile], fail: set[str]) -> None:
        self.profiles, self.fail, self.calls = profiles, fail, []

    def dependency_profile(self, ecosystem: str, name: str) -> DependencyProfile:
        self.calls.append((ecosystem, name))
        if name in self.fail:
            raise NetError("connection reset")
        return self.profiles[name]


def test_engine_looks_up_only_new_dependencies() -> None:
    fetcher = _Fetcher({"helper": _profile("helper", 12)}, set())
    cand = with_dependency_profiles(
        cast(Any, fetcher), _depends("1.0", "requests"), _depends("1.1", "requests", "helper")
    )
    assert fetcher.calls == [("pypi", "helper")]
    assert cand.dependencies == (_profile("helper", 12),)


def test_failed_lookup_is_e001_and_never_a_pass() -> None:
    fetcher = _Fetcher({}, {"helper"})
    base, cand = _depends("1.0"), _depends("1.1", "helper")
    cand = with_dependency_profiles(cast(Any, fetcher), base, cand)
    (err,) = cand.errors
    assert err.code == "GRN-E001" and err.rules == ("GRN-C008",)
    result = run_checks(CHANGE, base, cand)
    ids = {f.rule_id for f in result.findings}
    assert {"GRN-C008", "GRN-E001"} <= ids and result.verdict == Verdict.WARN
    (f,) = [f for f in result.findings if f.rule_id == "GRN-C008"]
    assert "PyPI was not consulted" in f.evidence[0].summary


def test_replayed_profiles_are_not_looked_up_again() -> None:
    fetcher = _Fetcher({}, set())
    cand = replace(_depends("1.1", "helper"), dependencies=(_profile("helper", 12),))
    assert with_dependency_profiles(cast(Any, fetcher), _depends("1.0"), cand) is cand
    assert fetcher.calls == []


def test_profile_cache_round_trip(tmp_path: Path) -> None:
    cache = ProfileCache(tmp_path)
    p = DependencyProfile("@scope/pkg", True, UPLOADED, 3, "o/r", "1.0.0")
    assert cache.get("npm", "@scope/pkg") is None
    cache.put("npm", p)
    assert cache.get("npm", "@scope/pkg") == p


# Aliases, sources outside the registry, and owners


def test_npm_aliases_and_sources_outside_the_registry() -> None:
    doc = {
        "dependencies": {
            "react-is-18": "npm:react-is@^18.3.1",
            "@jest/react-is-19": "npm:@scope/react-is@^19",
            "lib-a": "github:someone/lib-a",
            "lib-b": "someone/lib-b#main",
            "lib-c": "https://example.invalid/lib-c.tgz",
            "lib-d": "file:../lib-d",
            "lib-e": ">=1.2.3 <2 || ^3.0.0-beta.1",
            "lib-f": "latest",
        }
    }
    reqs = {r.name: r for r in declared_dependencies(json.dumps(doc).encode())}
    assert reqs["react-is-18"].alias_of == "react-is" and reqs["react-is-18"].source is None
    assert reqs["@jest/react-is-19"].package == "@scope/react-is"
    assert {n for n, r in reqs.items() if r.source} == {"lib-a", "lib-b", "lib-c", "lib-d"}
    assert reqs["lib-e"].source is None and reqs["lib-f"].source is None


def test_pypi_direct_reference_is_a_source() -> None:
    (req,) = declared_requirements(_meta("Requires-Dist: helper @ https://example.invalid/h.whl"))
    assert req.name == "helper" and req.source == "https://example.invalid/h.whl"


def test_owners_from_pypi_and_npm() -> None:
    data = {
        "ownership": {
            "organization": "acme",
            "roles": [{"role": "Owner", "user": "bob"}, {"role": "Maintainer", "user": "al"}],
        }
    }
    assert pypi.owners(data) == ("al", "bob", "org:acme")
    assert pypi.owners({}) == ()
    assert npm.maintainers({"maintainers": [{"name": "zed"}, {"name": "amy"}, "x"]}) == (
        "amy",
        "zed",
    )


def _npm_rel(version: str, *reqs: Requirement, owners: tuple[str, ...] = ()) -> ReleaseFacts:
    rel = release(version, {"demo/__init__.py": ""})
    art = replace(
        rel.artifacts[0],
        filename=f"demo-{version}.tgz",
        packagetype="tarball",
        uploaded_at=UPLOADED,
        requirements=reqs,
        requirements_read=True,
    )
    return replace(rel, ecosystem="npm", artifacts=(art,), owners=owners)


NPM_CHANGE = Change("npm", "demo", "1.0", "1.1")


def _c008(base: ReleaseFacts, cand: ReleaseFacts) -> Any:
    found = [f for f in run_checks(NPM_CHANGE, base, cand).findings if f.rule_id == "GRN-C008"]
    return found[0] if found else None


def test_young_dependency_from_a_trusted_owner_still_warns() -> None:
    # A maintainer who splits out a helper often publishes the release that
    # uses it the same day, but whoever holds a maintainer's account can do the
    # same: the shared owner alone never lowers the finding. Only releases
    # that were read and have no install-time hook and provenance from the
    # trusted repository do (tests/test_dependency_releases.py).
    helper = replace(_profile("helper", 0), owners=("amy",))
    base = _npm_rel("1.0", owners=("amy", "bob"))
    cand = replace(_npm_rel("1.1", Requirement("helper", "helper@^1.0.0")), dependencies=(helper,))
    f = _c008(base, cand)
    assert f.severity == Severity.WARN
    assert "helper was first released 0 day(s) before it" in f.title
    assert "owned by amy, who also own(s) demo" in f.evidence[0].summary
    assert "kept at warn: the releases of helper that 1.1 could install weren't read" in (
        f.evidence[0].summary
    )
    other = replace(helper, owners=("mallory",))
    f = _c008(base, replace(cand, dependencies=(other,)))
    assert f.severity == Severity.WARN and "who also own" not in f.evidence[0].summary


def test_alias_is_looked_up_under_the_package_it_installs() -> None:
    alias = Requirement("react-is-18", "react-is-18@npm:react-is@^18", alias_of="react-is")
    base, cand = _npm_rel("1.0"), _npm_rel("1.1", alias)
    assert new_requirement_names(base, cand) == ("react-is",)
    cand = replace(cand, dependencies=(_profile("react-is", 3000, 200),))
    f = _c008(base, cand)
    assert f.severity == Severity.INFO
    assert f.evidence[0].summary.startswith("react-is-18@npm:react-is@^18: installs react-is;")


def test_kept_dependency_that_now_installs_another_package_warns() -> None:
    base = _npm_rel("1.0", Requirement("lodash", "lodash@^4.17.21"))
    swapped = Requirement("lodash", "lodash@npm:lodash-fast@^1", alias_of="lodash-fast")
    cand = replace(_npm_rel("1.1", swapped), dependencies=(_profile("lodash-fast", 400, 9),))
    assert new_requirement_names(base, cand) == ("lodash-fast",)
    f = _c008(base, cand)
    assert f.severity == Severity.WARN
    assert "lodash now installs lodash-fast" in f.title


def test_dependency_from_outside_the_registry_warns_without_a_lookup() -> None:
    base = _npm_rel("1.0", Requirement("through", "through@~2.3"))
    git = Requirement("through", "through@github:someone/through", source="github:someone/through")
    new = Requirement("helper", "helper@https://x.invalid/h.tgz", source="https://x.invalid/h.tgz")
    cand = _npm_rel("1.1", git, new)
    assert new_requirement_names(base, cand) == ()
    f = _c008(base, cand)
    assert f.severity == Severity.WARN
    assert "through now installs from outside npm" in f.title
    assert "helper installs from outside npm" in f.title


# A name that was unpublished and created again (call-bound in 2024)


def test_npm_profile_keeps_unpublished_history() -> None:
    doc = {
        "name": "call-helper",
        "time": {
            "created": "2024-12-05T10:00:00Z",
            "modified": "2025-01-02T10:00:00Z",
            "1.0.0": "2024-06-10T10:00:00Z",
            "1.0.1": "2024-12-05T10:00:00Z",
            "1.0.2": "2024-12-20T10:00:00Z",
        },
        "versions": {"1.0.1": {}, "1.0.2": {}},
        "dist-tags": {"latest": "1.0.2"},
    }
    http = _Http({"https://registry.npmjs.org/call-helper": (200, doc)})
    h = cast(Http, http)
    ctx = npm.FetchContext(http=h, limits=Limits(), tags=TagLookup(h))
    p = npm.package_profile(ctx, "call-helper")
    assert p.first_release_at == datetime(2024, 12, 5, 10, tzinfo=UTC)
    assert p.unpublished_versions == ("1.0.0",)
    assert p.earliest_unpublished_at == datetime(2024, 6, 10, 10, tzinfo=UTC)
    # a version unpublished after the name was created is not earlier history
    doc["time"]["1.0.3"] = "2025-01-01T10:00:00Z"
    assert npm.package_profile(ctx, "call-helper").unpublished_versions == ("1.0.0",)


def test_unpublished_history_is_said_and_still_warns() -> None:
    helper = replace(
        _profile("helper", 14),
        unpublished_versions=("1.0.0",),
        earliest_unpublished_at=UPLOADED - timedelta(days=190),
    )
    base = _npm_rel("1.0")
    cand = replace(_npm_rel("1.1", Requirement("helper", "helper@^1.0.1")), dependencies=(helper,))
    f = _c008(base, cand)
    assert f.severity == Severity.WARN
    assert f.title.endswith(
        "helper's earliest version still published was released 14 day(s) before it"
    )
    assert f.evidence[0].summary == (
        "helper@^1.0.1: earliest version still published 2026-08-18, 14 day(s) before 1.1; "
        "npm also lists 1.0.0 from 2026-02-23, since unpublished; 1 release(s); "
        "no repository link"
    )
