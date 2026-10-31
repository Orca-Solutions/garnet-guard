"""GRN-C008 for a young dependency an owner of the trusted package also owns:
info only when the release it would install has no install-time hook and
verified provenance from the trusted package's repository (DECISIONS 92).
Synthetic data only; no network."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from backtest.corpus import DependencyReleaseCache
from garnet_guard.checks.content import owned_young_dependencies
from garnet_guard.ecosystems import npm, npm_range, pypi
from garnet_guard.ecosystems.github import TagLookup
from garnet_guard.ecosystems.gittree import TreeLookup
from garnet_guard.engine import run_checks, with_dependency_profiles
from garnet_guard.facts.npmmeta import install_hooks
from garnet_guard.models import (
    Change,
    DependencyProfile,
    DependencyRelease,
    FileProvenance,
    Finding,
    Limits,
    ReleaseFacts,
    Requirement,
    Severity,
    Verdict,
)
from garnet_guard.net import Http, NetError, Response
from tests.builders import prov, release, sdist, wheel

UPLOADED = datetime(2026, 9, 1, tzinfo=UTC)
NPM = Change("npm", "demo", "1.0", "1.1")
PYPI = Change("pypi", "demo", "1.0", "1.1")
HELPER = Requirement("helper", "helper@^1.0.0")
TGZ = "helper-1.0.2.tgz"


def _profile(name: str = "helper", days: int = 2, owners: tuple[str, ...] = ("amy",)) -> Any:
    return DependencyProfile(name, True, UPLOADED - timedelta(days=days), 3, owners=owners)


def _rel(
    ecosystem: str,
    version: str,
    *reqs: Requirement,
    owners: tuple[str, ...] = ("amy", "bob"),
    provenance: FileProvenance | None | str = "ok",
) -> ReleaseFacts:
    rel = release(version, {"demo/__init__.py": ""}, provenance=provenance)
    art = replace(
        rel.artifacts[0],
        filename=f"demo-{version}.tgz" if ecosystem == "npm" else rel.artifacts[0].filename,
        packagetype="tarball" if ecosystem == "npm" else rel.artifacts[0].packagetype,
        uploaded_at=UPLOADED,
        requirements=reqs,
        requirements_read=True,
    )
    return replace(rel, ecosystem=ecosystem, artifacts=(art,), owners=owners)


def _npm_release(**kw: Any) -> DependencyRelease:
    base = DependencyRelease("helper", HELPER.spec, "1.0.2", files=(TGZ,), provenance=(prov(TGZ),))
    return replace(base, **kw)


def _c008(
    change: Change,
    base: ReleaseFacts,
    cand: ReleaseFacts,
    releases: tuple[DependencyRelease, ...] = (),
    profiles: tuple[DependencyProfile, ...] | None = None,
) -> Finding:
    cand = replace(
        cand,
        dependencies=profiles if profiles is not None else (_profile(),),
        dependency_releases=releases,
    )
    (f,) = [f for f in run_checks(change, base, cand).findings if f.rule_id == "GRN-C008"]
    return f


def _npm(releases: tuple[DependencyRelease, ...], **base_kw: Any) -> Finding:
    return _c008(NPM, _rel("npm", "1.0", **base_kw), _rel("npm", "1.1", HELPER), releases)


# npm


def test_same_owner_clean_helper_is_info() -> None:
    f = _npm((_npm_release(),))
    assert f.severity == Severity.INFO
    assert f.title == "1.1 depends on 1 package(s) that 1.0 didn't"
    assert f.evidence[0].summary.endswith(
        "owned by amy, who also own(s) demo; "
        "info: same owner, no install scripts in helper 1.0.2, provenance from github.com/o/r"
    )


def test_same_owner_with_postinstall_warns() -> None:
    f = _npm((_npm_release(install_scripts=(("postinstall", "node setup.js"),)),))
    assert f.severity == Severity.WARN
    assert "helper was first released 2 day(s) before it" in f.title
    assert f.evidence[0].summary.endswith(
        "kept at warn: helper 1.0.2 has a postinstall script (node setup.js)"
    )


def test_binding_gyp_counts_as_an_install_script_unless_turned_off() -> None:
    f = _npm((_npm_release(binding_gyp=True),))
    assert f.severity == Severity.WARN
    assert "has a binding.gyp, for which npm runs node-gyp rebuild" in f.evidence[0].summary
    # "gypfile": false stops npm's implicit node-gyp rebuild
    assert _npm((_npm_release(binding_gyp=True, gypfile_off=True),)).severity == Severity.INFO
    # an install script replaces node-gyp rebuild; the script is reported instead
    f = _npm((_npm_release(binding_gyp=True, install_scripts=(("install", "node x.js"),)),))
    assert f.severity == Severity.WARN and "node-gyp" not in f.evidence[0].summary
    assert "has an install script (node x.js)" in f.evidence[0].summary


def test_same_owner_without_provenance_warns() -> None:
    f = _npm((_npm_release(provenance=(prov(TGZ, present=False),)),))
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary.endswith("kept at warn: helper 1.0.2 has no provenance")


def test_same_owner_with_provenance_from_another_repository_warns() -> None:
    other = prov(TGZ, repo="github.com/amy/helper", repo_id="99")
    f = _npm((_npm_release(provenance=(other,)),))
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary.endswith(
        "kept at warn: helper 1.0.2 has provenance from github.com/amy/helper, "
        "not github.com/o/r like demo 1.0"
    )


def test_renamed_repository_matches_by_repository_id() -> None:
    renamed = prov(TGZ, repo="github.com/o/renamed", repo_id="1")
    assert _npm((_npm_release(provenance=(renamed,)),)).severity == Severity.INFO


def test_trusted_package_without_provenance_warns() -> None:
    f = _npm((_npm_release(),), provenance="none")
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary.endswith(
        "kept at warn: demo 1.0 has no verified provenance to compare with"
    )


def test_provenance_garnet_could_not_verify_warns() -> None:
    unverifiable = replace(prov(TGZ, verified=False), verification_ran=False)
    f = _npm((_npm_release(provenance=(unverifiable,)),))
    assert f.severity == Severity.WARN
    assert "Garnet couldn't verify the provenance of helper 1.0.2" in f.evidence[0].summary
    f = _npm((_npm_release(provenance=(prov(TGZ, verified=False),)),))
    assert f.severity == Severity.WARN
    assert "the provenance of helper 1.0.2 doesn't verify (bad signature)" in f.evidence[0].summary
    f = _npm((_npm_release(),), provenance=None)
    assert f.severity == Severity.WARN
    assert "Garnet couldn't verify the provenance of demo 1.0" in f.evidence[0].summary


def test_a_read_that_stopped_part_way_warns_and_says_what_is_known() -> None:
    f = _npm((_npm_release(provenance=(prov(TGZ, present=False),), problem="bad tarball"),))
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary.endswith(
        "kept at warn: helper 1.0.2 has no provenance, and bad tarball"
    )
    stopped = _npm_release(problem="helper-1.0.2.tgz has no package.json")
    assert _npm((stopped,)).severity == Severity.WARN


def test_no_version_published_by_the_release_warns() -> None:
    none = DependencyRelease(
        "helper", HELPER.spec, None, problem="no version matching ^1.0.0 was published by …"
    )
    f = _npm((none,))
    assert f.severity == Severity.WARN
    assert "kept at warn: no version matching ^1.0.0" in f.evidence[0].summary


def test_release_not_read_warns() -> None:
    f = _npm(())
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary.endswith(
        "kept at warn: the release of helper that 1.1 would install wasn't read"
    )


def test_different_owner_is_unchanged_and_not_read() -> None:
    base, cand = _rel("npm", "1.0"), _rel("npm", "1.1", HELPER)
    stranger = (_profile(owners=("mallory",)),)
    assert owned_young_dependencies(base, replace(cand, dependencies=stranger)) == ()
    f = _c008(NPM, base, cand, (_npm_release(),), profiles=stranger)
    assert f.severity == Severity.WARN
    assert "who also own" not in f.evidence[0].summary and "info:" not in f.evidence[0].summary


def test_established_and_shared_dependency_is_not_read() -> None:
    base, cand = _rel("npm", "1.0"), _rel("npm", "1.1", HELPER)
    old = (_profile(days=400),)
    assert owned_young_dependencies(base, replace(cand, dependencies=old)) == ()
    assert owned_young_dependencies(base, replace(cand, dependencies=(_profile(),))) == (HELPER,)
    assert owned_young_dependencies(None, cand) == ()


def test_one_clean_helper_does_not_lower_another_young_dependency() -> None:
    other = Requirement("fresh", "fresh@^2.0.0")
    base, cand = _rel("npm", "1.0"), _rel("npm", "1.1", HELPER, other)
    profiles = (_profile(), _profile("fresh", owners=("mallory",)))
    f = _c008(NPM, base, cand, (_npm_release(),), profiles=profiles)
    assert f.severity == Severity.WARN
    assert f.title.endswith("fresh was first released 2 day(s) before it")
    assert "helper was first released" not in f.title


# PyPI

PYREQ = Requirement("helper", "helper>=1.0")
WHL = "helper-1.0.2-py3-none-any.whl"
SDIST = "helper-1.0.2.tar.gz"


def _py_release(files: tuple[str, ...] = (WHL, SDIST), **kw: Any) -> DependencyRelease:
    rel = DependencyRelease(
        "helper",
        PYREQ.spec,
        "1.0.2",
        files=files,
        wheels_read=tuple(f for f in files if f.endswith(".whl")),
        provenance=tuple(prov(f) for f in files),
    )
    return replace(rel, **kw)


def _py(releases: tuple[DependencyRelease, ...], **base_kw: Any) -> Finding:
    return _c008(PYPI, _rel("pypi", "1.0", **base_kw), _rel("pypi", "1.1", PYREQ), releases)


def test_pypi_same_owner_clean_helper_is_info() -> None:
    f = _py((_py_release(),))
    assert f.severity == Severity.INFO
    assert f.evidence[0].summary.endswith(
        "info: same owner, helper 1.0.2 installs from a wheel with no .pth file, "
        "provenance from github.com/o/r"
    )


def test_pypi_sdist_only_helper_warns() -> None:
    f = _py((_py_release(files=(SDIST,)),))
    assert f.severity == Severity.WARN
    assert (
        "helper 1.0.2 has no wheel, so pip builds it from the sdist and runs its build code"
        in f.evidence[0].summary
    )


def test_pypi_platform_wheels_beside_an_sdist_warn() -> None:
    files = ("helper-1.0.2-cp312-cp312-manylinux_2_28_x86_64.whl", SDIST)
    f = _py((_py_release(files=files),))
    assert f.severity == Severity.WARN
    assert "wheels only for some platforms" in f.evidence[0].summary
    # without an sdist pip has nothing to build
    assert _py((_py_release(files=files[:1]),)).severity == Severity.INFO


def test_pypi_pth_file_warns() -> None:
    f = _py((_py_release(pth_files=(f"{WHL}: helper.pth",)),))
    assert f.severity == Severity.WARN
    assert f"installs the .pth file {WHL}: helper.pth" in f.evidence[0].summary


def test_pypi_every_file_needs_provenance_from_the_repository() -> None:
    partial = (prov(WHL), prov(SDIST, present=False))
    f = _py((_py_release(provenance=partial),))
    assert f.severity == Severity.WARN
    assert "1 of 2 file(s) of helper 1.0.2 have no provenance" in f.evidence[0].summary
    elsewhere = (prov(WHL), prov(SDIST, repo="github.com/x/y", repo_id="7"))
    assert _py((_py_release(provenance=elsewhere),)).severity == Severity.WARN
    assert _py((_py_release(provenance=(prov(WHL),)),)).severity == Severity.WARN


def test_pypi_trusted_package_without_provenance_warns() -> None:
    f = _py((_py_release(),), provenance="none")
    assert f.severity == Severity.WARN
    assert "demo 1.0 has no verified provenance to compare with" in f.evidence[0].summary


# The engine's lookups


class _Fetcher:
    def __init__(self, rel: DependencyRelease | None) -> None:
        self.rel, self.calls = rel, []

    def dependency_profile(self, ecosystem: str, name: str) -> DependencyProfile:
        return cast(DependencyProfile, _profile(name))

    def dependency_release(
        self, ecosystem: str, req: Requirement, at: datetime
    ) -> DependencyRelease:
        self.calls.append((ecosystem, req, at))
        if self.rel is None:
            raise NetError("connection reset")
        return self.rel


def test_engine_reads_the_release_with_the_candidate_upload_time() -> None:
    fetcher = _Fetcher(_npm_release())
    base, cand = _rel("npm", "1.0"), _rel("npm", "1.1", HELPER)
    cand = with_dependency_profiles(cast(Any, fetcher), base, cand)
    assert fetcher.calls == [("npm", HELPER, UPLOADED)]
    assert cand.dependency_releases == (_npm_release(),)
    assert run_checks(NPM, base, cand).verdict == Verdict.PASS


def test_failed_release_lookup_is_e001_and_stays_warn() -> None:
    fetcher = _Fetcher(None)
    base, cand = _rel("npm", "1.0"), _rel("npm", "1.1", HELPER)
    cand = with_dependency_profiles(cast(Any, fetcher), base, cand)
    (err,) = cand.errors
    assert err.code == "GRN-E001" and err.rules == ("GRN-C008",)
    assert "release of dependency helper that 1.1 would install" in err.summary
    result = run_checks(NPM, base, cand)
    assert {"GRN-C008", "GRN-E001"} <= {f.rule_id for f in result.findings}
    (f,) = [f for f in result.findings if f.rule_id == "GRN-C008"]
    assert f.severity == Severity.WARN and result.verdict == Verdict.WARN


def test_releases_the_facts_carry_are_not_read_again() -> None:
    fetcher = _Fetcher(None)
    base = _rel("npm", "1.0")
    cand = replace(
        _rel("npm", "1.1", HELPER),
        dependencies=(_profile(),),
        dependency_releases=(_npm_release(),),
    )
    assert with_dependency_profiles(cast(Any, fetcher), base, cand) is cand
    assert fetcher.calls == []


def test_dependency_release_cache_round_trip(tmp_path: Path) -> None:
    cache = DependencyReleaseCache(tmp_path)
    rel = _npm_release(install_scripts=(("postinstall", "node x.js"),))
    assert cache.get("npm", HELPER, UPLOADED) is None
    cache.put("npm", HELPER, UPLOADED, rel)
    assert cache.get("npm", HELPER, UPLOADED) == rel
    assert cache.get("npm", HELPER, UPLOADED + timedelta(seconds=1)) is None


# Fetching the release (fake registry)


class _Http:
    def __init__(self, routes: dict[str, tuple[int, bytes]]) -> None:
        self.routes, self.calls = routes, []

    def get(self, url: str, **kwargs: object) -> Response:
        self.calls.append(url)
        status, body = self.routes.get(url, (404, b"{}"))
        return Response(status=status, content=body, url=url)


def _sri(data: bytes) -> str:
    import base64
    import hashlib

    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def _packument(tarballs: dict[str, bytes], times: dict[str, str], **doc: Any) -> bytes:
    versions = {
        v: {
            "name": "helper",
            "version": v,
            "dist": {
                "tarball": f"https://registry.npmjs.org/helper/-/helper-{v}.tgz",
                "integrity": _sri(data),
            },
            **doc.get(v, {}),
        }
        for v, data in tarballs.items()
    }
    return json.dumps({"name": "helper", "versions": versions, "time": times}).encode()


def _npm_ctx(routes: dict[str, tuple[int, bytes]]) -> tuple[npm.FetchContext, _Http]:
    http = _Http(routes)
    h = cast(Http, http)
    return npm.FetchContext(http=h, limits=Limits(), tags=TagLookup(h)), http


def test_npm_release_picks_the_newest_match_published_by_then_and_reads_hooks() -> None:
    pkg = {"name": "helper", "scripts": {"postinstall": "node setup.js", "test": "x"}}
    tarballs = {
        "1.0.1": sdist("package", {"package.json": json.dumps({"name": "helper"})}),
        "1.0.2": sdist(
            "package", {"package.json": json.dumps(pkg), "binding.gyp": "{}", "index.js": ""}
        ),
        "1.1.0": sdist("package", {"package.json": json.dumps({"name": "helper"})}),
        "2.0.0": sdist("package", {"package.json": json.dumps({"name": "helper"})}),
    }
    times = {
        "1.0.1": "2026-08-01T00:00:00Z",
        "1.0.2": "2026-08-31T00:00:00Z",
        "1.1.0": "2026-09-02T00:00:00Z",  # after the candidate
        "2.0.0": "2026-08-15T00:00:00Z",  # outside the range
    }
    doc = _packument(tarballs, times, **{"1.0.2": {"scripts": {"preinstall": "node pre.js"}}})
    routes = {"https://registry.npmjs.org/helper": (200, doc)}
    for v, data in tarballs.items():
        routes[f"https://registry.npmjs.org/helper/-/helper-{v}.tgz"] = (200, data)
    ctx, http = _npm_ctx(routes)
    rel = npm.dependency_release(ctx, HELPER, UPLOADED)
    assert rel.version == "1.0.2" and rel.problem is None and rel.files == (TGZ,)
    # the tarball's script and the registry copy's both count
    assert rel.install_scripts == (("preinstall", "node pre.js"), ("postinstall", "node setup.js"))
    assert rel.binding_gyp and not rel.gypfile_off
    assert rel.provenance == (FileProvenance(TGZ, present=False, verified=False),)
    assert not any("attestations" in u for u in http.calls)


def test_npm_release_with_no_version_by_then_or_an_unreadable_range() -> None:
    tarballs = {"1.0.0": sdist("package", {"package.json": "{}"})}
    doc = _packument(tarballs, {"1.0.0": "2026-09-05T00:00:00Z"})
    ctx, _ = _npm_ctx({"https://registry.npmjs.org/helper": (200, doc)})
    rel = npm.dependency_release(ctx, HELPER, UPLOADED)
    assert rel.version is None
    assert rel.problem == "no version matching ^1.0.0 was published by 2026-09-01 00:00 UTC"
    odd = Requirement("helper", "helper@next")
    assert npm.dependency_release(ctx, odd, UPLOADED).problem == (
        "Garnet can't read the range 'next'"
    )


def test_npm_release_tarball_that_does_not_match_its_integrity() -> None:
    tarballs = {"1.0.2": sdist("package", {"package.json": "{}"})}
    doc = _packument(tarballs, {"1.0.2": "2026-08-31T00:00:00Z"})
    ctx, _ = _npm_ctx(
        {
            "https://registry.npmjs.org/helper": (200, doc),
            "https://registry.npmjs.org/helper/-/helper-1.0.2.tgz": (200, b"other bytes"),
        }
    )
    rel = npm.dependency_release(ctx, HELPER, UPLOADED)
    assert rel.version == "1.0.2"
    assert rel.problem == "helper-1.0.2.tgz doesn't match the registry's integrity hash"


def test_npm_release_download_failure_raises() -> None:
    tarballs = {"1.0.2": sdist("package", {"package.json": "{}"})}
    doc = _packument(tarballs, {"1.0.2": "2026-08-31T00:00:00Z"})
    ctx, _ = _npm_ctx({"https://registry.npmjs.org/helper": (200, doc)})
    with pytest.raises(NetError, match="HTTP 404"):
        npm.dependency_release(ctx, HELPER, UPLOADED)


def test_install_hooks_reads_gypfile_false() -> None:
    data = sdist("package", {"package.json": '{"gypfile": false}', "binding.gyp": "{}"})
    hooks = install_hooks("x.tgz", data, Limits())
    assert hooks.binding_gyp and hooks.gypfile_off and hooks.problem is None
    nested = sdist("package", {"package.json": "{}", "deps/binding.gyp": "{}"})
    assert not install_hooks("x.tgz", nested, Limits()).binding_gyp
    assert install_hooks("x.tgz", b"not a tarball", Limits()).problem is not None


def test_requirement_range() -> None:
    assert npm.requirement_range(Requirement("a", "a@^1.2 (peer)")) == "^1.2"
    assert npm.requirement_range(Requirement("a", "a@>=1 <2 (optional)")) == ">=1 <2"
    alias = Requirement("a", "a@npm:@s/b@~3.1", alias_of="@s/b")
    assert npm.requirement_range(alias) == "~3.1"
    assert npm.requirement_range(Requirement("a", "a@npm:b", alias_of="b")) == ""


@pytest.mark.parametrize(
    ("rng", "want"),
    [
        ("^1.2.3", "1.3.0"),
        ("~1.2.3", "1.2.9"),
        ("^0.1.0", "0.1.5"),
        ("^0.0.1", "0.0.1"),
        ("1.x", "1.3.0"),
        ("*", "2.1.0"),
        ("", "2.1.0"),
        ("latest", "2.1.0"),
        (">=1.2.3 <2", "1.3.0"),
        (">= 1.2.3 < 2", "1.3.0"),
        ("1.2.3 - 1.3", "1.3.0"),
        ("1.2.3 - 1.2.5", "1.2.3"),
        ("^1.4.0-beta.0", "1.4.0-beta.1"),
        ("<2.0.0", "1.3.0"),
        ("^1 || ^2", "2.1.0"),
        ("=1.2.3", "1.2.3"),
        ("v1.2.3", "1.2.3"),
        ("~1", "1.3.0"),
        ("^0", "0.2.0"),
        (">1.2", "2.1.0"),
        ("<=1.2", "1.2.9"),
        ("^4", None),
    ],
)
def test_npm_range_best_match(rng: str, want: str | None) -> None:
    versions = [
        "0.0.1",
        "0.1.0",
        "0.1.5",
        "0.2.0",
        "1.0.0",
        "1.2.3",
        "1.2.9",
        "1.3.0",
        "1.4.0-beta.1",
        "2.0.0-rc.1",
        "2.0.0",
        "2.1.0",
        "not-semver",
    ]
    assert npm_range.best_match(rng, versions) == want


def test_npm_range_refuses_what_it_cannot_read() -> None:
    for bad in ("next", "1.2.3.4", ">=abc"):
        with pytest.raises(ValueError):
            npm_range.best_match(bad, ["1.0.0"])


def _pypi_ctx(routes: dict[str, tuple[int, bytes]]) -> tuple[pypi.FetchContext, _Http]:
    http = _Http(routes)
    h = cast(Http, http)
    return pypi.FetchContext(http=h, limits=Limits(), tags=TagLookup(h), trees=TreeLookup(h)), http


def _pypi_file(filename: str, data: bytes, when: str) -> dict[str, Any]:
    import hashlib

    return {
        "filename": filename,
        "url": f"https://files.pythonhosted.org/{filename}",
        "digests": {"sha256": hashlib.sha256(data).hexdigest()},
        "packagetype": "bdist_wheel" if filename.endswith(".whl") else "sdist",
        "upload_time_iso_8601": when,
    }


def test_pypi_release_picks_the_version_and_finds_pth_files() -> None:
    good = wheel({"helper/__init__.py": "", "helper-1.0.2.dist-info/METADATA": ""})
    pth = wheel({"helper/__init__.py": "", "helper.pth": "import helper", "helper/x.pth": ""})
    files = {
        "1.0.1": [_pypi_file("helper-1.0.1-py3-none-any.whl", good, "2026-08-01T00:00:00Z")],
        "1.0.2": [
            _pypi_file(WHL, pth, "2026-08-30T00:00:00Z"),
            _pypi_file(SDIST, b"sdist", "2026-08-30T00:00:00Z"),
        ],
        "1.1.0": [_pypi_file("helper-1.1.0.tar.gz", b"s", "2026-09-03T00:00:00Z")],
        "2.0rc1": [_pypi_file("helper-2.0rc1.tar.gz", b"s", "2026-08-02T00:00:00Z")],
    }
    doc = json.dumps({"info": {}, "releases": files}).encode()
    ctx, http = _pypi_ctx(
        {
            "https://pypi.org/pypi/helper/json": (200, doc),
            f"https://files.pythonhosted.org/{WHL}": (200, pth),
        }
    )
    rel = pypi.dependency_release(ctx, PYREQ, UPLOADED)
    assert rel.version == "1.0.2" and rel.problem is None
    assert rel.files == (WHL, SDIST) and rel.wheels_read == (WHL,)
    # only a .pth that lands in site-packages itself is read at start-up
    assert rel.pth_files == (f"{WHL}: helper.pth",)
    assert [p.present for p in rel.provenance] == [False, False]
    assert f"https://pypi.org/integrity/helper/1.0.2/{SDIST}/provenance" in http.calls
    # the sdist is never downloaded
    assert f"https://files.pythonhosted.org/{SDIST}" not in http.calls


def test_pypi_release_with_no_match_by_then() -> None:
    files = {"1.0": [_pypi_file("helper-1.0.tar.gz", b"s", "2026-09-05T00:00:00Z")]}
    doc = json.dumps({"info": {}, "releases": files}).encode()
    ctx, _ = _pypi_ctx({"https://pypi.org/pypi/helper/json": (200, doc)})
    rel = pypi.dependency_release(ctx, PYREQ, UPLOADED)
    assert rel.version is None
    assert rel.problem == "no version matching >=1.0 had a file on PyPI by 2026-09-01 00:00 UTC"


def test_pypi_release_lookup_failure_raises() -> None:
    ctx, _ = _pypi_ctx({"https://pypi.org/pypi/helper/json": (503, b"")})
    with pytest.raises(NetError, match="HTTP 503"):
        pypi.dependency_release(ctx, PYREQ, UPLOADED)
