"""GRN-C008 for a young dependency an owner of the trusted package also owns:
info only when every release a user of the new version could install has no
install-time hook and verified provenance from the trusted package's
repository (DECISIONS 92). Synthetic data only; no network."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from backtest.corpus import DependencyInstallsCache
from garnet_guard.checks.content import _leaves_out, owned_young_dependencies
from garnet_guard.ecosystems import npm, npm_range, pypi
from garnet_guard.ecosystems.github import TagLookup
from garnet_guard.ecosystems.gittree import TreeLookup
from garnet_guard.engine import run_checks, with_dependency_profiles
from garnet_guard.facts.inventory import declared_requirements
from garnet_guard.facts.npmmeta import declared_dependencies, install_hooks
from garnet_guard.models import (
    MAX_DEPENDENCY_VERSIONS,
    Change,
    DependencyInstalls,
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
from garnet_guard.workspace import merge_pins, other_index, pinned_versions
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


def _npm_release(version: str = "1.0.2", **kw: Any) -> DependencyRelease:
    tgz = f"helper-{version}.tgz"
    return replace(
        DependencyRelease("helper", version, files=(tgz,), provenance=(prov(tgz),)), **kw
    )


def _installs(
    *releases: DependencyRelease, spec: str = HELPER.spec, **kw: Any
) -> DependencyInstalls:
    return DependencyInstalls("helper", spec, releases=releases, **kw)


def _c008(
    change: Change,
    base: ReleaseFacts,
    cand: ReleaseFacts,
    installs: tuple[DependencyInstalls, ...] = (),
    profiles: tuple[DependencyProfile, ...] | None = None,
) -> Finding:
    cand = replace(
        cand,
        dependencies=profiles if profiles is not None else (_profile(),),
        dependency_installs=installs,
    )
    (f,) = [f for f in run_checks(change, base, cand).findings if f.rule_id == "GRN-C008"]
    return f


def _npm(*releases: DependencyRelease, installs: Any = None, **base_kw: Any) -> Finding:
    found = installs if installs is not None else (_installs(*releases),)
    return _c008(NPM, _rel("npm", "1.0", **base_kw), _rel("npm", "1.1", HELPER), found)


# npm

CLEAN_NPM = (
    "info: same owner, no install scripts, provenance from github.com/o/r, in helper 1.0.2, "
    "the only published version matching helper@^1.0.0"
)


def test_same_owner_clean_helper_is_info() -> None:
    f = _npm(_npm_release())
    assert f.severity == Severity.INFO
    assert f.title == "1.1 depends on 1 package(s) that 1.0 didn't"
    assert f.evidence[0].summary.endswith("owned by amy, who also own(s) demo; " + CLEAN_NPM)


def test_every_installable_version_must_be_clean() -> None:
    # An account-only attacker publishes a dirty 1.0.3 after the release that
    # added the helper; ^1.0.0 installs it, so it counts.
    later = _npm_release("1.0.3", install_scripts=(("postinstall", "node x.js"),))
    f = _npm(_npm_release(), later)
    assert f.severity == Severity.WARN
    assert "kept at warn: helper 1.0.3 has a postinstall script (node x.js)" in (
        f.evidence[0].summary
    )
    f = _npm(_npm_release(), _npm_release("1.0.3"))
    assert f.severity == Severity.INFO
    assert f.evidence[0].summary.endswith(
        "in helper 1.0.2, 1.0.3, every published version matching helper@^1.0.0"
    )


def test_pinned_versions_say_so() -> None:
    f = _npm(installs=(_installs(_npm_release(), pinned=True),))
    assert f.severity == Severity.INFO
    assert f.evidence[0].summary.endswith("in helper 1.0.2, as the lockfile pins it")


def test_too_many_versions_to_read_warns() -> None:
    capped = _installs(problem="7 versions of helper could install (1.0.2 to 1.0.8); ...")
    f = _npm(installs=(capped,))
    assert f.severity == Severity.WARN
    assert "kept at warn: 7 versions of helper could install" in f.evidence[0].summary


def test_same_owner_with_postinstall_warns() -> None:
    f = _npm(_npm_release(install_scripts=(("postinstall", "node setup.js"),)))
    assert f.severity == Severity.WARN
    assert "helper was first released 2 day(s) before it" in f.title
    assert f.evidence[0].summary.endswith(
        "kept at warn: helper 1.0.2 has a postinstall script (node setup.js)"
    )


def test_binding_gyp_counts_as_an_install_script_unless_turned_off() -> None:
    f = _npm(_npm_release(binding_gyp=True))
    assert f.severity == Severity.WARN
    assert "has a binding.gyp, for which npm runs node-gyp rebuild" in f.evidence[0].summary
    # "gypfile": false stops npm's implicit node-gyp rebuild
    assert _npm(_npm_release(binding_gyp=True, gypfile_off=True)).severity == Severity.INFO
    # an install script replaces node-gyp rebuild; the script is reported instead
    f = _npm(_npm_release(binding_gyp=True, install_scripts=(("install", "node x.js"),)))
    assert f.severity == Severity.WARN and "node-gyp" not in f.evidence[0].summary
    assert "has an install script (node x.js)" in f.evidence[0].summary


def test_same_owner_without_provenance_warns() -> None:
    f = _npm(_npm_release(provenance=(prov(TGZ, present=False),)))
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary.endswith("kept at warn: helper 1.0.2 has no provenance")


def test_same_owner_with_provenance_from_another_repository_warns() -> None:
    other = prov(TGZ, repo="github.com/amy/helper", repo_id="99")
    f = _npm(_npm_release(provenance=(other,)))
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary.endswith(
        "kept at warn: helper 1.0.2 has provenance naming github.com/amy/helper, "
        "not github.com/o/r like demo 1.0"
    )


def test_renamed_repository_matches_by_github_repository_id() -> None:
    renamed = prov(TGZ, repo="github.com/o/renamed", repo_id="1")
    assert _npm(_npm_release(provenance=(renamed,))).severity == Severity.INFO


def test_repository_id_from_another_host_never_matches() -> None:
    # Fulcio carries GitLab project ids in the same extension; id 1 on
    # gitlab.com is not repository 1 on github.com.
    gitlab = prov(TGZ, repo="gitlab.com/evil/x", repo_id="1")
    f = _npm(_npm_release(provenance=(gitlab,)))
    assert f.severity == Severity.WARN
    assert "has provenance naming gitlab.com/evil/x, not github.com/o/r" in f.evidence[0].summary
    base = _rel("npm", "1.0", provenance=prov("demo-1.0.tgz", repo="gitlab.com/o/r", repo_id="1"))
    on_github = prov(TGZ, repo="github.com/evil/x", repo_id="1")
    cand = _rel("npm", "1.1", HELPER)
    f = _c008(NPM, base, cand, (_installs(_npm_release(provenance=(on_github,))),))
    assert f.severity == Severity.WARN


def test_provenance_naming_no_repository_warns_with_a_reason() -> None:
    unnamed = replace(prov(TGZ), repository=None)
    f = _npm(_npm_release(provenance=(unnamed,)))
    assert f.severity == Severity.WARN
    summary = f.evidence[0].summary
    assert not summary.endswith("kept at warn: ")
    assert summary.endswith(
        "helper 1.0.2 has provenance naming no repository, not github.com/o/r like demo 1.0"
    )


def test_trusted_package_without_provenance_warns() -> None:
    f = _npm(_npm_release(), provenance="none")
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary.endswith(
        "kept at warn: demo 1.0 has no verified provenance to compare with"
    )


def test_provenance_garnet_could_not_verify_warns() -> None:
    unverifiable = replace(prov(TGZ, verified=False), verification_ran=False)
    f = _npm(_npm_release(provenance=(unverifiable,)))
    assert f.severity == Severity.WARN
    assert "Garnet couldn't verify the provenance of helper 1.0.2" in f.evidence[0].summary
    f = _npm(_npm_release(provenance=(prov(TGZ, verified=False),)))
    assert f.severity == Severity.WARN
    assert "the provenance of helper 1.0.2 doesn't verify (bad signature)" in f.evidence[0].summary
    f = _npm(_npm_release(), provenance=None)
    assert f.severity == Severity.WARN
    assert "Garnet couldn't verify the provenance of demo 1.0" in f.evidence[0].summary


def test_a_read_that_stopped_part_way_warns_and_says_what_is_known() -> None:
    f = _npm(_npm_release(provenance=(prov(TGZ, present=False),), problem="bad tarball"))
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary.endswith(
        "kept at warn: helper 1.0.2 has no provenance, and bad tarball"
    )
    stopped = _npm_release(problem="helper-1.0.2.tgz has no package.json")
    assert _npm(stopped).severity == Severity.WARN


def test_no_version_published_by_the_release_warns() -> None:
    none = _installs(problem="no version matching ^1.0.0 was published by …")
    f = _npm(installs=(none,))
    assert f.severity == Severity.WARN
    assert "kept at warn: no version matching ^1.0.0" in f.evidence[0].summary
    assert _npm(installs=(_installs(),)).severity == Severity.WARN


def test_releases_not_read_warn() -> None:
    f = _npm(installs=())
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary.endswith(
        "kept at warn: the releases of helper that 1.1 could install weren't read"
    )


def test_different_owner_is_unchanged_and_not_read() -> None:
    base, cand = _rel("npm", "1.0"), _rel("npm", "1.1", HELPER)
    stranger = (_profile(owners=("mallory",)),)
    assert owned_young_dependencies(base, replace(cand, dependencies=stranger)) == ()
    f = _c008(NPM, base, cand, (_installs(_npm_release()),), profiles=stranger)
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
    f = _c008(NPM, base, cand, (_installs(_npm_release()),), profiles=profiles)
    assert f.severity == Severity.WARN
    assert f.title.endswith("fresh was first released 2 day(s) before it")
    assert "helper was first released" not in f.title


def test_a_dependency_declared_twice_warns_and_is_not_read() -> None:
    doc = {"dependencies": {"helper": "^1.0.0"}, "optionalDependencies": {"helper": "^2.0.0"}}
    (twice,) = declared_dependencies(json.dumps(doc).encode())
    assert twice.also == ("helper@^2.0.0 (optional)",)
    base, cand = _rel("npm", "1.0"), _rel("npm", "1.1", twice)
    assert owned_young_dependencies(base, replace(cand, dependencies=(_profile(),))) == ()
    f = _c008(NPM, base, cand, (_installs(_npm_release()),))
    assert f.severity == Severity.WARN
    assert (
        "kept at warn: helper is declared more than once (helper@^2.0.0 (optional) as well)"
        in f.evidence[0].summary
    )


@pytest.mark.parametrize("trusted_has_it", [False, True])
def test_an_alias_of_the_same_package_warns_and_is_not_read(trusted_has_it: bool) -> None:
    doc = {"dependencies": {"helper": "^1.0.0", "h2": "npm:helper@^2.0.0"}}
    alias, plain = sorted(declared_dependencies(json.dumps(doc).encode()), key=lambda r: r.name)
    assert (alias.name, alias.package, plain.name) == ("h2", "helper", "helper")
    base = _rel("npm", "1.0", plain) if trusted_has_it else _rel("npm", "1.0")
    cand = _rel("npm", "1.1", plain, alias)
    assert owned_young_dependencies(base, replace(cand, dependencies=(_profile(),))) == ()
    f = _c008(NPM, base, cand, (_installs(_npm_release()),))
    assert f.severity == Severity.WARN
    said = " ".join(e.summary for e in f.evidence)
    assert "helper is installed by more than one requirement" in said
    assert "kept at warn" in said and "info: same owner" not in said


@pytest.mark.parametrize("key", ["bundleDependencies", "bundledDependencies"])
@pytest.mark.parametrize("value", [["helper"], True])
def test_a_bundled_dependency_warns(key: str, value: Any) -> None:
    doc = {"dependencies": {"helper": "^1.0.0", "other": "^1"}, key: value}
    helper, other = declared_dependencies(json.dumps(doc).encode())
    assert helper.bundled and other.bundled == (value is True)
    base, cand = _rel("npm", "1.0"), _rel("npm", "1.1", helper)
    assert owned_young_dependencies(base, replace(cand, dependencies=(_profile(),))) == ()
    f = _c008(NPM, base, cand, (_installs(_npm_release()),))
    assert f.severity == Severity.WARN
    assert (
        "kept at warn: helper is in bundleDependencies, so the copy packed in the tarball "
        "installs, not a registry release" in f.evidence[0].summary
    )
    plain = declared_dependencies(json.dumps({"dependencies": {"helper": "^1.0.0"}}).encode())
    assert not plain[0].bundled


def _established(name: str) -> DependencyProfile:
    return DependencyProfile(name, True, UPLOADED - timedelta(days=900), 30, owners=("zed",))


@pytest.mark.parametrize(
    ("optional", "installs"),
    [("npm:young@^1", "young"), ("github:evil/helper", "github:evil/helper")],
)
def test_a_second_declaration_of_another_package_or_source_warns(
    optional: str, installs: str
) -> None:
    """Without a shared owner too: npm installs the optionalDependencies entry."""
    doc = {"dependencies": {"helper": "^1"}, "optionalDependencies": {"helper": optional}}
    (req,) = declared_dependencies(json.dumps(doc).encode())
    assert req.also_installs == (installs,)
    base, cand = _rel("npm", "1.0"), _rel("npm", "1.1", req)
    f = _c008(NPM, base, cand, profiles=(_established("helper"),))
    assert f.severity == Severity.WARN
    assert f.title.endswith(f"helper is declared again to install {installs}")
    assert f.evidence[0].summary == (
        f"helper@^1: also declared as helper@{optional} (optional), which installs "
        f"{installs}; Garnet didn't look that up"
    )
    # a dependency the trusted version had, now declared again elsewhere
    kept = declared_dependencies(json.dumps({"dependencies": {"helper": "^1"}}).encode())
    f = _c008(NPM, _rel("npm", "1.0", *kept), cand, profiles=())
    assert f.severity == Severity.WARN
    assert f.title.endswith(f"helper is declared again to install {installs}")
    # the trusted version already declared it that way: nothing new
    assert _c008_or_none(NPM, _rel("npm", "1.0", req), cand) is None


def test_a_second_range_of_the_same_package_is_unchanged_for_an_established_one() -> None:
    doc = {"dependencies": {"helper": "^1"}, "optionalDependencies": {"helper": "^2"}}
    (req,) = declared_dependencies(json.dumps(doc).encode())
    assert req.also == ("helper@^2 (optional)",) and req.also_installs == ()
    f = _c008(NPM, _rel("npm", "1.0"), _rel("npm", "1.1", req), profiles=(_established("helper"),))
    assert f.severity == Severity.INFO


def _c008_or_none(change: Change, base: ReleaseFacts, cand: ReleaseFacts) -> Finding | None:
    found = [f for f in run_checks(change, base, cand).findings if f.rule_id == "GRN-C008"]
    return found[0] if found else None


# PyPI

PYREQ = Requirement("helper", "helper>=1.0")
WHL = "helper-1.0.2-py3-none-any.whl"
SDIST = "helper-1.0.2.tar.gz"


def _py_release(files: tuple[str, ...] = (WHL, SDIST), **kw: Any) -> DependencyRelease:
    rel = DependencyRelease(
        "helper",
        "1.0.2",
        files=files,
        wheels_read=tuple(f for f in files if f.endswith(".whl")),
        provenance=tuple(prov(f) for f in files),
    )
    return replace(rel, **kw)


def _py(*releases: DependencyRelease, req: Requirement = PYREQ, **base_kw: Any) -> Finding:
    found = (DependencyInstalls("helper", req.spec, releases=releases),)
    return _c008(PYPI, _rel("pypi", "1.0", **base_kw), _rel("pypi", "1.1", req), found)


def test_pypi_same_owner_clean_helper_is_info() -> None:
    f = _py(_py_release())
    assert f.severity == Severity.INFO
    assert f.evidence[0].summary.endswith(
        "info: same owner, a py3-none-any wheel, no file that runs at start-up, provenance from "
        "github.com/o/r, in helper 1.0.2, the only published version matching helper>=1.0"
    )
    universal = "helper-1.0.2-py2.py3-none-any.whl"
    assert _py(_py_release(files=(universal, SDIST))).severity == Severity.INFO


def test_pypi_sdist_only_helper_warns() -> None:
    f = _py(_py_release(files=(SDIST,)))
    assert f.severity == Severity.WARN
    assert (
        "helper 1.0.2 has no py3-none-any wheel, so pip builds the sdist and runs its build "
        "code where no wheel fits" in f.evidence[0].summary
    )


@pytest.mark.parametrize(
    "wheel_name",
    [
        "helper-1.0.2-cp312-cp312-manylinux_2_28_x86_64.whl",
        "helper-1.0.2-py2-none-any.whl",
        "helper-1.0.2-cp311-none-any.whl",
        "helper-1.0.2-py312-none-any.whl",
        "not a wheel name.whl",
    ],
)
def test_pypi_wheels_that_do_not_fit_every_python_warn(wheel_name: str) -> None:
    f = _py(_py_release(files=(wheel_name, SDIST)))
    assert f.severity == Severity.WARN
    assert "has no py3-none-any wheel, so pip builds the sdist" in f.evidence[0].summary
    # without an sdist, pip picks another version where no wheel fits
    f = _py(_py_release(files=(wheel_name,)))
    assert f.severity == Severity.WARN
    assert "so where no wheel fits pip installs another version" in f.evidence[0].summary


def test_pypi_requires_python_that_leaves_out_a_current_python_warns() -> None:
    f = _py(_py_release(requires_python=(">=3.13",)))
    assert f.severity == Severity.WARN
    assert (
        "helper 1.0.2 requires Python >=3.13, so pip on Python 3.11.0 installs another version"
        in f.evidence[0].summary
    )
    assert _py(_py_release(requires_python=(">=3.8",))).severity == Severity.INFO


@pytest.mark.parametrize(
    ("requires_python", "left_out"),
    [
        ("<=3.15", "3.15.1"),
        ("!=3.12.4", "3.12.4"),
        ("<3.14.3", "3.14.3"),
        (">=3.11.1", "3.11.0"),
        ("==3.*,!=3.13.50", "3.13.50"),
        (">=3.8", None),
        (">=3.11,<4", None),
    ],
)
def test_requires_python_is_tested_at_every_patch_level(
    requires_python: str, left_out: str | None
) -> None:
    assert _leaves_out(requires_python) == left_out
    f = _py(_py_release(requires_python=(requires_python,)))
    if left_out is None:
        assert f.severity == Severity.INFO
    else:
        assert f.severity == Severity.WARN
        assert f"so pip on Python {left_out} installs another version" in f.evidence[0].summary


def test_unreadable_requires_python_warns() -> None:
    f = _py(_py_release(requires_python=("~~3",)))
    assert f.severity == Severity.WARN
    assert "has a Requires-Python Garnet can't read (~~3)" in f.evidence[0].summary


@pytest.mark.parametrize(
    ("path", "does"),
    [
        (f"{WHL}: helper.pth", "reads"),
        (f"{WHL}: sitecustomize.py", "runs"),
        (f"{WHL}: helper-1.0.2.data/data/lib/python3.12/site-packages/x.pth", "reads"),
    ],
)
def test_pypi_startup_files_warn(path: str, does: str) -> None:
    f = _py(_py_release(startup_files=(path,)))
    assert f.severity == Severity.WARN
    assert f"installs {path}, which Python {does} at every start" in f.evidence[0].summary


@pytest.mark.parametrize(
    "path",
    [
        "sitecustomize.py",
        "sitecustomize/__init__.py",
        "SiteCustomize/__init__.py",
        "sitecustomize.pyc",
        "__pycache__/sitecustomize.cpython-312.pyc",
        "sitecustomize.cpython-312-x86_64-linux-gnu.so",
        "sitecustomize.abi3.so",
        "sitecustomize.pyd",
        "usercustomize/__init__.py",
        "UserCustomize.cp312-win_amd64.pyd",
        "x.pth",
        "X.PTH",
        "h-1.data/purelib/sitecustomize/__init__.py",
        "h-1.data/purelib/x.pth",
        "h-1.data/platlib/x.PTH",
        "h-1.data/platlib/sitecustomize.abi3.so",
        "h-1.data/data/lib/python3.12/site-packages/sitecustomize/__init__.py",
        "h-1.data/data/lib/python3.12/site-packages/x.pth",
        "h-1.DATA/data/share/usercustomize.pyc",
    ],
)
def test_startup_module_forms(path: str) -> None:
    assert pypi._startup_file(path)


@pytest.mark.parametrize(
    "path",
    [
        "helper/sitecustomize.py",
        "helper/x.pth",
        "helper/__pycache__/sitecustomize.cpython-312.pyc",
        "sitecustomizer.py",
        "h-1.data/purelib/helper/sitecustomize.py",
        "h-1.data/scripts/sitecustomize",
        "h-1.dist-info/x.pth",
    ],
)
def test_files_that_do_not_run_at_start(path: str) -> None:
    assert not pypi._startup_file(path)


def test_pypi_every_file_needs_provenance_from_the_repository() -> None:
    partial = (prov(WHL), prov(SDIST, present=False))
    f = _py(_py_release(provenance=partial))
    assert f.severity == Severity.WARN
    assert "1 of 2 file(s) of helper 1.0.2 have no provenance" in f.evidence[0].summary
    elsewhere = (prov(WHL), prov(SDIST, repo="github.com/x/y", repo_id="7"))
    assert _py(_py_release(provenance=elsewhere)).severity == Severity.WARN
    assert _py(_py_release(provenance=(prov(WHL),))).severity == Severity.WARN


def test_pypi_trusted_package_without_provenance_warns() -> None:
    f = _py(_py_release(), provenance="none")
    assert f.severity == Severity.WARN
    assert "demo 1.0 has no verified provenance to compare with" in f.evidence[0].summary


def test_pypi_marker_or_second_requirement_warns_and_is_not_read() -> None:
    marked = Requirement("helper", 'helper>=1.0; python_version < "3.12"')
    f = _py(_py_release(), req=marked)
    assert f.severity == Severity.WARN
    assert (
        'kept at warn: the requirement has an environment marker (python_version < "3.12")'
        in f.evidence[0].summary
    )
    meta = (
        b"Metadata-Version: 2.1\nName: demo\n"
        b'Requires-Dist: helper>=1.0; python_version < "3.12"\n'
        b'Requires-Dist: helper @ https://example.invalid/h.whl; python_version >= "3.12"\n'
    )
    (twice,) = declared_requirements(meta)
    assert twice.also == ('helper @ https://example.invalid/h.whl; python_version >= "3.12"',)
    base, cand = _rel("pypi", "1.0"), _rel("pypi", "1.1", twice)
    assert owned_young_dependencies(base, replace(cand, dependencies=(_profile(),))) == ()
    f = _c008(
        PYPI, base, cand, (DependencyInstalls("helper", twice.spec, releases=(_py_release(),)),)
    )
    assert f.severity == Severity.WARN and "declared more than once" in f.evidence[0].summary


def test_pypi_requirement_with_an_extra_counts_as_a_second_one() -> None:
    meta = (
        b"Metadata-Version: 2.1\nName: demo\nVersion: 1.1\n"
        b"Requires-Dist: helper>=2; extra == 'x'\nRequires-Dist: helper<2\n"
        b"Requires-Dist: other @ https://example.invalid/o.whl ; extra == 'y'\n"
    )
    (req,) = declared_requirements(meta) or ()
    assert req.spec == "helper<2" and req.also == ("helper>=2; extra == 'x'",)
    assert req.also_installs == ()
    base, cand = _rel("pypi", "1.0"), _rel("pypi", "1.1", req)
    assert owned_young_dependencies(base, replace(cand, dependencies=(_profile(),))) == ()
    f = _c008(PYPI, base, cand, (_installs(_py_release(), spec=req.spec),))
    assert f.severity == Severity.WARN
    assert (
        "kept at warn: helper is declared more than once (helper>=2; extra == 'x' as well)"
        in f.evidence[0].summary
    )
    # an extra that installs the same name from a URL is flagged for anyone
    url = (
        b"Requires-Dist: helper<2\nRequires-Dist: helper @ https://x.invalid/h.whl ; extra == 'x'\n"
    )
    (req,) = declared_requirements(b"Metadata-Version: 2.1\nName: demo\n" + url) or ()
    assert req.also_installs == ("https://x.invalid/h.whl",)
    f = _c008(PYPI, base, _rel("pypi", "1.1", req), profiles=(_established("helper"),))
    assert f.severity == Severity.WARN
    assert f.title.endswith("helper is declared again to install https://x.invalid/h.whl")


# The engine's lookups


class _Fetcher:
    def __init__(self, found: DependencyInstalls | Exception) -> None:
        self.found, self.calls = found, []

    def dependency_profile(self, ecosystem: str, name: str) -> DependencyProfile:
        return cast(DependencyProfile, _profile(name))

    def dependency_installs(
        self, ecosystem: str, req: Requirement, pinned: tuple[str, ...] = ()
    ) -> DependencyInstalls:
        self.calls.append((ecosystem, req, pinned))
        if isinstance(self.found, Exception):
            raise self.found
        return self.found


def test_engine_reads_the_releases_of_a_young_shared_helper() -> None:
    fetcher = _Fetcher(_installs(_npm_release()))
    base, cand = _rel("npm", "1.0"), _rel("npm", "1.1", HELPER)
    cand = with_dependency_profiles(cast(Any, fetcher), base, cand)
    assert fetcher.calls == [("npm", HELPER, ())]
    assert cand.dependency_installs == (_installs(_npm_release()),)
    assert run_checks(NPM, base, cand).verdict == Verdict.PASS


def test_engine_passes_lockfile_pins() -> None:
    fetcher = _Fetcher(_installs(_npm_release(), pinned=True))
    base, cand = _rel("pypi", "1.0"), _rel("pypi", "1.1", PYREQ)
    pins = {("pypi", "helper"): ("1.0.2",)}
    with_dependency_profiles(cast(Any, fetcher), base, cand, pins)
    assert fetcher.calls == [("pypi", PYREQ, ("1.0.2",))]


def test_engine_reads_nothing_when_the_lockfile_names_another_index() -> None:
    fetcher = _Fetcher(_installs(_py_release()))
    base, cand = _rel("pypi", "1.0"), _rel("pypi", "1.1", PYREQ)
    pins = {("pypi", "helper"): ("1.0.2",)}
    got = with_dependency_profiles(cast(Any, fetcher), base, cand, pins, "--extra-index-url")
    assert fetcher.calls == []
    (installs,) = got.dependency_installs
    assert installs.problem == (
        "the lockfile sets --extra-index-url, so pip can install helper from somewhere other "
        "than PyPI and Garnet can't tell which release that is"
    )
    f = _c008(PYPI, base, got, got.dependency_installs)
    assert f.severity == Severity.WARN and "can't tell which release" in f.evidence[0].summary


@pytest.mark.parametrize(
    ("err", "said"),
    [
        (NetError("connection reset"), "connection reset"),
        (json.JSONDecodeError("Expecting value", "", 0), "unreadable response (JSONDecodeError)"),
        (AttributeError("'list' object has no attribute 'get'"), "unreadable response"),
    ],
)
def test_failed_release_lookup_is_e001_and_stays_warn(err: Exception, said: str) -> None:
    fetcher = _Fetcher(err)
    base, cand = _rel("npm", "1.0"), _rel("npm", "1.1", HELPER)
    cand = with_dependency_profiles(cast(Any, fetcher), base, cand)
    (e,) = cand.errors
    assert e.code == "GRN-E001" and e.rules == ("GRN-C008",)
    assert e.summary.startswith("releases of dependency helper that 1.1 could install: ")
    assert said in e.summary
    result = run_checks(NPM, base, cand)
    assert {"GRN-C008", "GRN-E001"} <= {f.rule_id for f in result.findings}
    (f,) = [f for f in result.findings if f.rule_id == "GRN-C008"]
    assert f.severity == Severity.WARN and result.verdict == Verdict.WARN


def test_releases_the_facts_carry_are_not_read_again() -> None:
    fetcher = _Fetcher(NetError("not called"))
    base = _rel("npm", "1.0")
    cand = replace(
        _rel("npm", "1.1", HELPER),
        dependencies=(_profile(),),
        dependency_installs=(_installs(_npm_release()),),
    )
    assert with_dependency_profiles(cast(Any, fetcher), base, cand) is cand
    assert fetcher.calls == []


def test_dependency_installs_cache_round_trip(tmp_path: Path) -> None:
    cache = DependencyInstallsCache(tmp_path)
    found = _installs(_npm_release(install_scripts=(("postinstall", "node x.js"),)), pinned=True)
    assert cache.get("npm", HELPER) is None
    cache.put("npm", HELPER, found)
    assert cache.get("npm", HELPER) == found
    assert cache.get("npm", Requirement("helper", "helper@^2.0.0")) is None


def test_pinned_versions_from_a_lockfile() -> None:
    body = b"helper==1.0.2\nhelper-two==2.0 ; python_version < '3.12'\nloose>=1\n"
    pins = pinned_versions("requirements.txt", body)
    assert pins == {("pypi", "helper"): ("1.0.2",)}
    # a pin under a marker, or a second entry under one, leaves the range to read
    body = b"helper==1.0.2 ; python_version < '3.12'\nHelper_Name==2\n"
    assert pinned_versions("requirements.txt", body) == {("pypi", "helper-name"): ("2",)}
    body = b"helper==1.0.2\nhelper==1.0.3 ; sys_platform == 'win32'\n"
    assert pinned_versions("requirements.txt", body) == {}


def test_pinned_versions_from_uv_and_pylock_markers() -> None:
    uv = b"""version = 1
[[package]]
name = "helper"
version = "1.0.2"
source = { registry = "https://pypi.org/simple" }
resolution-markers = ["python_full_version < '3.12'"]

[[package]]
name = "other"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
"""
    assert pinned_versions("uv.lock", uv) == {("pypi", "other"): ("2.0",)}


def test_pins_come_only_from_lockfiles_the_change_is_in() -> None:
    a = {("pypi", "helper"): ("1.0.2",), ("pypi", "x"): ("1",)}
    b = {("pypi", "helper"): ("1.0.3",)}
    assert merge_pins([a]) == a
    # every lockfile has to pin it; their versions are all read
    assert merge_pins([a, b]) == {("pypi", "helper"): ("1.0.2", "1.0.3")}
    assert merge_pins([]) == {}


def test_pylock_marker_drops_the_pin() -> None:
    pylock = b"""lock-version = "1.0"
[[packages]]
name = "helper"
version = "1.0.2"
index = "https://pypi.org/simple"
marker = "python_version < '3.12'"

[[packages]]
name = "other"
version = "2.0"
index = "https://pypi.org/simple"
"""
    assert pinned_versions("pylock.toml", pylock) == {("pypi", "other"): ("2.0",)}
    poetry = b"""[[package]]
name = "helper"
version = "1.0.2"
markers = "python_version < \\"3.12\\""

[[package]]
name = "other"
version = "2.0"
"""
    assert pinned_versions("poetry.lock", poetry) == {("pypi", "other"): ("2.0",)}


@pytest.mark.parametrize(
    ("line", "option"),
    [
        ("--extra-index-url https://mirror.invalid/simple", "--extra-index-url"),
        ("--find-links=./wheels", "--find-links"),
        ("-f ./wheels", "-f"),
        ("--no-index", "--no-index"),
        ("--index-url https://private.invalid/simple", "--index-url"),
        ("-i https://private.invalid/simple", "-i"),
    ],
)
def test_a_requirements_file_naming_another_index_pins_nothing(line: str, option: str) -> None:
    # anywhere in the file: pip applies the option to every line
    body = f"helper==1.0.2\n{line}\nother==2\n".encode()
    assert other_index("requirements.txt", body) == option
    assert pinned_versions("requirements.txt", body) == {}


def test_pypi_index_or_other_options_pin_as_before() -> None:
    body = b"-i https://pypi.org/simple\n--require-hashes\nhelper==1.0.2\n"
    assert other_index("requirements.txt", body) is None
    assert pinned_versions("requirements.txt", body) == {("pypi", "helper"): ("1.0.2",)}
    assert other_index("uv.lock", b"version = 1\n") is None


def _package_lock(packages: dict[str, Any]) -> bytes:
    doc = {
        "name": "app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {"": {"name": "app", "version": "1.0.0"}, **packages},
    }
    return json.dumps(doc, indent=2).encode()


def _npm_entry(pkg: str, version: str, **extra: Any) -> dict[str, Any]:
    return {
        "version": version,
        "resolved": f"https://registry.npmjs.org/{pkg}/-/{pkg}-{version}.tgz",
        "integrity": "sha512-" + "A" * 86 + "==",
        **extra,
    }


def test_npm_lockfile_versions_are_not_pins_but_outside_sources_are_flagged() -> None:
    """npm: the range is read, never the lockfile's versions; a package the
    lockfile installs from git, a URL, under another package's tarball or
    bundled keeps GRN-C008 at warn."""
    body = _package_lock(
        {
            "node_modules/helper": _npm_entry("helper", "1.0.2"),
            "node_modules/h2": _npm_entry("helper", "2.0.0", name="helper"),
            "node_modules/gitdep": {
                "version": "1.0.0",
                "resolved": "git+ssh://git@github.com/x/gitdep.git#abc",
            },
            "node_modules/parent": _npm_entry("parent", "1.0.0"),
            "node_modules/parent/node_modules/child": {"version": "2.0.0", "inBundle": True},
            "node_modules/ms-alias": _npm_entry("evil", "2.1.1", name="ms"),
        }
    )
    assert pinned_versions("package-lock.json", body) == {
        ("npm", "child"): (),
        ("npm", "gitdep"): (),
        ("npm", "ms"): (),
    }


def test_python_lockfile_package_from_outside_pypi_maps_to_nothing() -> None:
    uv = b"""version = 1
[[package]]
name = "helper"
version = "1.0.2"
source = { registry = "https://private.invalid/simple" }

[[package]]
name = "other"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
"""
    assert pinned_versions("uv.lock", uv) == {("pypi", "helper"): (), ("pypi", "other"): ("2.0",)}
    # one lockfile installing it from elsewhere wins over another's pin
    assert merge_pins([{("pypi", "helper"): ("1.0.2",)}, {("pypi", "helper"): ()}]) == {
        ("pypi", "helper"): ()
    }
    assert merge_pins([{("pypi", "x"): ("1",)}, {("pypi", "helper"): ()}]) == {
        ("pypi", "helper"): ()
    }


@pytest.mark.parametrize("ecosystem", ["npm", "pypi"])
def test_engine_reads_nothing_for_a_package_installed_from_outside(ecosystem: str) -> None:
    req = HELPER if ecosystem == "npm" else PYREQ
    fetcher = _Fetcher(_installs(_npm_release()))
    base, cand = _rel(ecosystem, "1.0"), _rel(ecosystem, "1.1", req)
    got = with_dependency_profiles(cast(Any, fetcher), base, cand, {(ecosystem, "helper"): ()})
    assert fetcher.calls == []
    (installs,) = got.dependency_installs
    assert installs.problem is not None and "from outside the registry" in installs.problem
    change = NPM if ecosystem == "npm" else PYPI
    f = _c008(change, base, got, got.dependency_installs)
    assert f.severity == Severity.WARN and "no release Garnet can read" in f.evidence[0].summary


def test_check_takes_pins_from_the_lockfiles_each_change_is_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    from garnet_guard import cli

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    git("config", "commit.gpgsign", "false")
    (tmp_path / "requirements.txt").write_text("demo==1.0\nhelper==1.0.2\n")
    (tmp_path / "requirements-dev.txt").write_text("other==1\nhelper==9.9\n")
    (tmp_path / "requirements-ci.txt").write_text("tool==1\nhelper==1.0.3\n")
    git("add", ".")
    git("commit", "-q", "-m", "base")
    (tmp_path / "requirements.txt").write_text("demo==1.1\nhelper==1.0.2\n")
    (tmp_path / "requirements-dev.txt").write_text("other==2\nhelper==9.9\n")
    (tmp_path / "requirements-ci.txt").write_text(
        "tool==2\nhelper==1.0.3 ; python_version < '3.12'\n"
    )
    seen: dict[Any, Any] = {}
    elsewhere: dict[Any, Any] = {}

    def fake_evaluate(changes: Any, *, policy: Any = None, options: Any = None) -> list[Any]:
        seen.update(options.pins)
        elsewhere.update(options.other_index)
        return []

    monkeypatch.setattr(cli, "evaluate", fake_evaluate)
    monkeypatch.chdir(tmp_path)
    heads = ["requirements.txt", "requirements-dev.txt", "requirements-ci.txt"]
    args = ["check", "--git-base", "HEAD", "--no-policy", "--format", "json"]
    cli.main(args + [a for h in heads for a in ("--head", h)])
    # demo's change reads helper 1.0.2 only, never the 9.9 another lockfile pins
    assert seen[("pypi", "demo", "1.0", "1.1")][("pypi", "helper")] == ("1.0.2",)
    assert seen[("pypi", "other", "1", "2")][("pypi", "helper")] == ("9.9",)
    # a pin under a marker leaves helper's range to be read
    assert ("pypi", "helper") not in seen[("pypi", "tool", "1", "2")]
    assert elsewhere == {}
    (tmp_path / "requirements-dev.txt").write_text(
        "other==2\nhelper==9.9\n--extra-index-url https://mirror.invalid/simple\n"
    )
    seen.clear()
    cli.main(args + [a for h in heads for a in ("--head", h)])
    assert seen[("pypi", "other", "1", "2")] == {}
    assert elsewhere == {("pypi", "other", "1", "2"): "--extra-index-url (requirements-dev.txt)"}


# Fetching the releases (fake registry)


class _Http:
    def __init__(self, routes: dict[str, tuple[int, bytes]]) -> None:
        self.routes, self.calls = routes, []

    def get(self, url: str, **kwargs: object) -> Response:
        self.calls.append(url)
        status, body = self.routes.get(url, (404, b"{}"))
        return Response(status=status, content=body, url=url)


def _sri(data: bytes) -> str:
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


def _npm_registry(
    tarballs: dict[str, bytes], times: dict[str, str], **doc: Any
) -> dict[str, tuple[int, bytes]]:
    routes = {"https://registry.npmjs.org/helper": (200, _packument(tarballs, times, **doc))}
    for v, data in tarballs.items():
        routes[f"https://registry.npmjs.org/helper/-/helper-{v}.tgz"] = (200, data)
    return routes


def _plain(name: str = "helper") -> bytes:
    return sdist("package", {"package.json": json.dumps({"name": name})})


def test_npm_reads_every_published_match_whenever_published() -> None:
    pkg = {"name": "helper", "scripts": {"postinstall": "node setup.js", "test": "x"}}
    tarballs = {
        "1.0.1": _plain(),
        "1.0.2": sdist(
            "package", {"package.json": json.dumps(pkg), "binding.gyp": "{}", "index.js": ""}
        ),
        "1.1.0": _plain(),
        "2.0.0": _plain(),
    }
    times = {
        "1.0.1": "2026-08-01T00:00:00Z",  # older: a dist-tag or reused tree can install it
        "1.0.2": "2026-08-31T00:00:00Z",
        "1.1.0": "2026-09-02T00:00:00Z",  # after the candidate
        "2.0.0": "2026-08-15T00:00:00Z",  # outside the range
    }
    routes = _npm_registry(tarballs, times, **{"1.0.2": {"scripts": {"preinstall": "node pre.js"}}})
    ctx, http = _npm_ctx(routes)
    found = npm.dependency_installs(ctx, HELPER)
    assert found.problem is None and not found.pinned
    assert [r.version for r in found.releases] == ["1.0.1", "1.0.2", "1.1.0"]
    first = found.releases[1]
    assert first.files == (TGZ,) and first.problem is None
    # the tarball's script and the registry copy's both count
    assert first.install_scripts == (
        ("preinstall", "node pre.js"),
        ("postinstall", "node setup.js"),
    )
    assert first.binding_gyp and not first.gypfile_off
    assert first.provenance == (FileProvenance(TGZ, present=False, verified=False),)
    assert not any("attestations" in u for u in http.calls)
    assert "https://registry.npmjs.org/helper/-/helper-2.0.0.tgz" not in http.calls


@pytest.mark.parametrize(
    "req",
    [
        Requirement("helper", "helper@*"),
        Requirement("helper", "helper@"),
        Requirement("helper", "helper@latest"),
        Requirement("helper", "helper@x"),
        Requirement("helper", "helper@x.x"),
        Requirement("h2", "h2@npm:helper", alias_of="helper"),
        Requirement("h2", "h2@npm:helper@latest", alias_of="helper"),
    ],
)
def test_npm_any_version_spec_reads_every_version_with_prereleases(req: Requirement) -> None:
    """npm installs the ``latest`` dist-tag for these, even a prerelease."""
    tarballs = {"1.0.0": _plain(), "1.1.0-evil.0": _plain(), "0.9.0": _plain()}
    times = dict.fromkeys(tarballs, "2026-08-31T00:00:00Z")
    ctx, _ = _npm_ctx(_npm_registry(tarballs, times))
    found = npm.dependency_installs(ctx, req)
    assert [r.version for r in found.releases] == ["0.9.0", "1.0.0", "1.1.0-evil.0"]
    assert npm_range.readable("^1.0.0", tarballs) == ["1.0.0"]
    assert npm_range.readable(">=0", tarballs) == ["0.9.0", "1.0.0"]


def test_npm_reads_only_the_pinned_versions() -> None:
    tarballs = {"1.0.1": _plain(), "1.0.2": _plain()}
    times = {"1.0.1": "2026-08-01T00:00:00Z", "1.0.2": "2026-08-31T00:00:00Z"}
    ctx, _ = _npm_ctx(_npm_registry(tarballs, times))
    found = npm.dependency_installs(ctx, HELPER, ("1.0.1",))
    assert found.pinned and [r.version for r in found.releases] == ["1.0.1"]
    gone = npm.dependency_installs(ctx, HELPER, ("9.9.9",))
    assert gone.problem == "the lockfile pins helper 9.9.9, which npm doesn't list"


def test_npm_more_versions_than_the_cap_are_not_read() -> None:
    n = MAX_DEPENDENCY_VERSIONS + 1
    tarballs = {f"1.0.{i}": _plain() for i in range(n)}
    times = {f"1.0.{i}": f"2026-09-{i + 1:02d}T00:00:00Z" for i in range(n)}
    ctx, http = _npm_ctx(_npm_registry(tarballs, times))
    found = npm.dependency_installs(ctx, HELPER)
    assert found.releases == ()
    assert found.problem == (
        f"{n} versions of helper could install (1.0.0 to 1.0.{n - 1}); Garnet reads a young "
        f"dependency's releases only up to {MAX_DEPENDENCY_VERSIONS}"
    )
    assert not any(u.endswith(".tgz") for u in http.calls)


def test_npm_with_no_match_or_an_unreadable_range() -> None:
    ctx, _ = _npm_ctx(_npm_registry({"2.0.0": _plain()}, {"2.0.0": "2026-08-05T00:00:00Z"}))
    found = npm.dependency_installs(ctx, HELPER)
    assert found.releases == ()
    assert found.problem == "no version of helper matches ^1.0.0"
    odd = Requirement("helper", "helper@next")
    assert npm.dependency_installs(ctx, odd).problem == "Garnet can't read the range 'next'"


def test_npm_tarball_that_does_not_match_its_integrity() -> None:
    routes = _npm_registry({"1.0.2": _plain()}, {"1.0.2": "2026-08-31T00:00:00Z"})
    routes["https://registry.npmjs.org/helper/-/helper-1.0.2.tgz"] = (200, b"other bytes")
    ctx, _ = _npm_ctx(routes)
    (rel,) = npm.dependency_installs(ctx, HELPER).releases
    assert rel.problem == "helper-1.0.2.tgz doesn't match the registry's integrity hash"


def test_npm_download_failure_raises() -> None:
    routes = _npm_registry({"1.0.2": _plain()}, {"1.0.2": "2026-08-31T00:00:00Z"})
    del routes["https://registry.npmjs.org/helper/-/helper-1.0.2.tgz"]
    ctx, _ = _npm_ctx(routes)
    with pytest.raises(NetError, match="HTTP 404"):
        npm.dependency_installs(ctx, HELPER)


def _tgz(entries: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_install_hooks_reads_gypfile_false_and_any_case() -> None:
    data = sdist("package", {"package.json": '{"gypfile": false}', "binding.gyp": "{}"})
    hooks = install_hooks("x.tgz", data, Limits())
    assert hooks.binding_gyp and hooks.gypfile_off and hooks.problem is None
    nested = sdist("package", {"package.json": "{}", "deps/binding.gyp": "{}"})
    assert not install_hooks("x.tgz", nested, Limits()).binding_gyp
    assert install_hooks("x.tgz", b"not a tarball", Limits()).problem is not None
    # a case-insensitive file system finds Binding.gyp for npm's binding.gyp
    upper = _tgz([("package/package.json", b"{}"), ("package/Binding.gyp", b"{}")])
    assert install_hooks("x.tgz", upper, Limits()).binding_gyp


def test_install_hooks_refuses_a_tarball_without_one_top_level_folder() -> None:
    clean = json.dumps({"name": "helper"}).encode()
    bad = json.dumps({"name": "helper", "scripts": {"postinstall": "node x"}}).encode()
    for entries in (
        [("package.json", clean), ("package/package.json", bad)],
        [("package/package.json", clean), ("other/package.json", bad)],
    ):
        hooks = install_hooks("h.tgz", _tgz(entries), Limits())
        assert hooks.problem == "h.tgz's files don't all sit under one top-level folder"
        assert hooks.scripts == ()


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


def test_npm_range_matching_is_in_precedence_order() -> None:
    got = npm_range.matching("^1.0.0", ["1.10.0", "1.2.0", "2.0.0", "1.2.0-rc.1", "1.0.0"])
    assert got == ["1.0.0", "1.2.0", "1.10.0"]


def test_npm_range_refuses_what_it_cannot_read() -> None:
    for bad in ("next", "1.2.3.4", ">=abc"):
        with pytest.raises(ValueError):
            npm_range.best_match(bad, ["1.0.0"])


def _pypi_ctx(routes: dict[str, tuple[int, bytes]]) -> tuple[pypi.FetchContext, _Http]:
    http = _Http(routes)
    h = cast(Http, http)
    return pypi.FetchContext(http=h, limits=Limits(), tags=TagLookup(h), trees=TreeLookup(h)), http


def _pypi_file(filename: str, data: bytes, when: str, rp: str | None = None) -> dict[str, Any]:
    return {
        "filename": filename,
        "url": f"https://files.pythonhosted.org/{filename}",
        "digests": {"sha256": hashlib.sha256(data).hexdigest()},
        "packagetype": "bdist_wheel" if filename.endswith(".whl") else "sdist",
        "upload_time_iso_8601": when,
        "requires_python": rp,
    }


def test_pypi_reads_every_installable_version_and_finds_startup_files() -> None:
    good = wheel({"helper/__init__.py": "", "helper-1.0.2.dist-info/METADATA": ""})
    startup = wheel(
        {
            "helper/__init__.py": "",
            "helper.pth": "import helper",
            "helper/x.pth": "",
            "SiteCustomize.py": "",
            "helper/sitecustomize.py": "",
            "helper-1.0.2.data/data/lib/python3.12/site-packages/y.pth": "",
            "helper-1.0.2.data/data/share/usercustomize.py": "",
        }
    )
    whl_101 = "helper-1.0.1-py3-none-any.whl"
    whl_110 = "helper-1.1.0-py3-none-any.whl"
    files = {
        "1.0.1": [_pypi_file(whl_101, good, "2026-08-01T00:00:00Z")],
        "1.0.2": [
            _pypi_file(WHL, startup, "2026-08-30T00:00:00Z", ">=3.9"),
            _pypi_file(SDIST, b"sdist", "2026-08-30T00:00:00Z", ">=3.9"),
        ],
        "1.1.0": [_pypi_file(whl_110, good, "2026-09-03T00:00:00Z")],
        "2.0rc1": [_pypi_file("helper-2.0rc1.tar.gz", b"s", "2026-08-02T00:00:00Z")],
    }
    doc = json.dumps({"info": {}, "releases": files}).encode()
    ctx, http = _pypi_ctx(
        {
            "https://pypi.org/pypi/helper/json": (200, doc),
            f"https://files.pythonhosted.org/{WHL}": (200, startup),
            f"https://files.pythonhosted.org/{whl_110}": (200, good),
            f"https://files.pythonhosted.org/{whl_101}": (200, good),
        }
    )
    found = pypi.dependency_installs(ctx, PYREQ)
    assert found.problem is None
    # every listed version the range admits, whenever uploaded, prereleases too
    assert [r.version for r in found.releases] == ["1.0.1", "1.0.2", "1.1.0", "2.0rc1"]
    rel = found.releases[1]
    assert rel.problem is None and rel.requires_python == (">=3.9",)
    assert rel.files == (WHL, SDIST) and rel.wheels_read == (WHL,)
    # what imports from site-packages itself, and anything of the kind under .data/data/;
    # helper/sitecustomize.py imports as helper.sitecustomize and doesn't count
    assert rel.startup_files == (
        f"{WHL}: SiteCustomize.py",
        f"{WHL}: helper-1.0.2.data/data/lib/python3.12/site-packages/y.pth",
        f"{WHL}: helper-1.0.2.data/data/share/usercustomize.py",
        f"{WHL}: helper.pth",
    )
    assert [p.present for p in rel.provenance] == [False, False]
    assert f"https://pypi.org/integrity/helper/1.0.2/{SDIST}/provenance" in http.calls
    assert f"https://files.pythonhosted.org/{whl_101}" in http.calls
    rc = found.releases[3]
    assert rc.files == ("helper-2.0rc1.tar.gz",) and rc.wheels_read == ()
    # an sdist is never downloaded
    assert f"https://files.pythonhosted.org/{SDIST}" not in http.calls
    # a lockfile pin is read instead, matched by PEP 440 equality
    pinned = pypi.dependency_installs(ctx, PYREQ, ("1.0.1.0",))
    assert pinned.pinned and [r.version for r in pinned.releases] == ["1.0.1"]


def test_pypi_with_no_match_or_too_many() -> None:
    files = {"0.9": [_pypi_file("helper-0.9.tar.gz", b"s", "2026-08-05T00:00:00Z")]}
    doc = json.dumps({"info": {}, "releases": files}).encode()
    ctx, _ = _pypi_ctx({"https://pypi.org/pypi/helper/json": (200, doc)})
    found = pypi.dependency_installs(ctx, PYREQ)
    assert found.releases == ()
    assert found.problem == "no version of helper matches >=1.0"
    many = {
        v: [_pypi_file(f"helper-{v}.tar.gz", b"s", "2026-08-05T00:00:00Z")]
        for v in ("1.0", "1.1", "1.2", "1.3", "1.4", "1.5a1")
    }
    doc = json.dumps({"info": {}, "releases": many}).encode()
    ctx, http = _pypi_ctx({"https://pypi.org/pypi/helper/json": (200, doc)})
    found = pypi.dependency_installs(ctx, PYREQ)
    assert found.releases == () and http.calls == ["https://pypi.org/pypi/helper/json"]
    assert found.problem == (
        "6 versions of helper could install (1.0 to 1.5a1); Garnet reads a young "
        "dependency's releases only up to 5"
    )
    pinned = pypi.dependency_installs(ctx, PYREQ, ("2.0",))
    assert pinned.problem == "the lockfile pins helper 2.0, which PyPI doesn't list"


def test_pypi_lookup_failure_raises() -> None:
    ctx, _ = _pypi_ctx({"https://pypi.org/pypi/helper/json": (503, b"")})
    with pytest.raises(NetError, match="HTTP 503"):
        pypi.dependency_installs(ctx, PYREQ)
