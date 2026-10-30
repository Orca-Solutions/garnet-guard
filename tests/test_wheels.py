"""Which wheel Garnet reads, and GRN-T006 files-uploaded-late. No network."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

from packaging.tags import sys_tags

from garnet_guard.checks.wheel_tags import Displacement, displacements
from garnet_guard.ecosystems.pypi import select_wheel
from garnet_guard.engine import run_checks
from garnet_guard.models import ArtifactFacts, Change, ReleaseFacts, Severity, Verdict
from tests.builders import release

CHANGE = Change("pypi", "demo", "1.0", "1.1")
HERE = next(iter(sys_tags()))  # the most specific tag this interpreter installs
PLATFORM = f"demo-1.1-{HERE.interpreter}-{HERE.abi}-{HERE.platform}.whl"
PURE = "demo-1.1-py3-none-any.whl"


def test_the_wheel_pip_would_install_is_read() -> None:
    # A platform wheel added beside a pure-Python one is what pip installs here.
    assert select_wheel([PURE, PLATFORM, "demo-1.1.tar.gz"]) == PLATFORM
    assert select_wheel([PURE, "demo-1.1-cp39-cp39-not_a_real_platform.whl"]) == PURE
    assert select_wheel(["demo-1.1-cp39-cp39-not_a_real_platform.whl"]) == (
        "demo-1.1-cp39-cp39-not_a_real_platform.whl"
    )
    assert select_wheel(["demo-1.1.tar.gz"]) is None


def _uploaded(rel: ReleaseFacts, *hours: float) -> ReleaseFacts:
    start = datetime(2026, 9, 1, 12, tzinfo=UTC)
    arts = tuple(
        replace(a, uploaded_at=start + timedelta(hours=h))
        for a, h in zip(rel.artifacts, hours, strict=True)
    )
    return replace(rel, artifacts=arts)


def test_late_file_evidence() -> None:
    files = {"demo/__init__.py": ""}
    cand = _uploaded(release("1.1", files, sdist_files=files), 75, 0)
    result = run_checks(CHANGE, release("1.0", files, sdist_files=files), cand)
    (f,) = [f for f in result.findings if f.rule_id == "GRN-T006"]
    assert result.verdict == Verdict.WARN
    assert f.title == (
        "1 file(s) of 1.1 were uploaded more than 24 hours after its first file, "
        "and 1 can replace a file uploaded on time"
    )
    assert f.evidence[0].summary == (
        "demo-1.1-py3-none-any.whl: uploaded 2026-09-04T15:00Z, 3 days after the first file "
        "(demo-1.1.tar.gz, 2026-09-01T12:00Z); it is the release's first wheel, and pip "
        "installs a wheel before an sdist"
    )


def test_a_file_just_inside_a_day_is_not_late() -> None:
    files = {"demo/__init__.py": ""}
    cand = _uploaded(release("1.1", files, sdist_files=files), 24, 0)
    result = run_checks(CHANGE, release("1.0", files, sdist_files=files), cand)
    assert "GRN-T006" not in {f.rule_id for f in result.findings}


def _plus(rel: ReleaseFacts, **hours: float) -> ReleaseFacts:
    """``rel`` uploaded at noon, plus uninspected files uploaded ``hours`` later."""
    start = datetime(2026, 9, 1, 12, tzinfo=UTC)
    own = tuple(replace(a, uploaded_at=start) for a in rel.artifacts)
    prov = rel.artifacts[0].provenance
    extra = tuple(
        ArtifactFacts(
            filename=name,
            sha256="0" * 64,
            packagetype="bdist_wheel" if name.endswith(".whl") else "sdist",
            uploaded_at=start + timedelta(hours=h),
            provenance=replace(prov, filename=name) if prov else None,
        )
        for name, h in hours.items()
    )
    return replace(rel, artifacts=own + extra)


def test_a_late_wheel_that_takes_a_wheels_place_warns() -> None:
    files = {"demo/__init__.py": ""}
    late = "demo-1.1-cp312-cp312-win_amd64.whl"
    cand = _plus(release("1.1", files, sdist_files=files), **{late: 50})
    result = run_checks(CHANGE, release("1.0", files, sdist_files=files), cand)
    (f,) = [f for f in result.findings if f.rule_id == "GRN-T006"]
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary.endswith(
        "; on CPython 3.12 on 64-bit Windows, pip installs it instead of demo-1.1-py3-none-any.whl"
    )


def test_a_backfill_is_info() -> None:
    # Wheels for a Python version the release had none for: pip built the
    # sdist there before, so no reviewed wheel is replaced.
    files = {"demo/__init__.py": ""}
    linux = "demo-1.1-cp312-cp312-manylinux_2_17_x86_64.whl"
    cand = _plus(
        release("1.1", None, sdist_files=files, sdist_only=True),
        **{linux: 0, "demo-1.1-cp313-cp313-manylinux_2_17_x86_64.whl": 200},
    )
    result = run_checks(CHANGE, release("1.0", None, sdist_files=files, sdist_only=True), cand)
    (f,) = [f for f in result.findings if f.rule_id == "GRN-T006"]
    assert f.severity == Severity.INFO
    assert result.verdict == Verdict.PASS
    assert ";" not in f.evidence[0].summary
    assert f.evidence[-1].kind == "note"
    assert f.evidence[-1].summary.startswith("no late file takes the place of one uploaded on time")


LINUX_217 = "demo-1.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"


def test_new_python_versions_and_platforms_are_backfills() -> None:
    assert (
        displacements(
            [LINUX_217, "demo-1.1.tar.gz"],
            [
                "demo-1.1-cp313-cp313-manylinux_2_17_x86_64.whl",
                "demo-1.1-cp312-cp312-musllinux_1_2_x86_64.whl",
                "demo-1.1-cp312-cp312-manylinux_2_17_aarch64.whl",
                "demo-1.1-cp312-cp312-win_amd64.whl",
                "demo-1.1-cp312-cp312t-manylinux_2_17_x86_64.whl",
                "demo-1.1.zip",
            ],
        )
        == {}
    )
    # An older glibc than the on-time wheel needs: only machines it didn't fit.
    assert displacements(["demo-1.1-cp312-cp312-manylinux_2_28_x86_64.whl"], [LINUX_217]) == {}


def test_a_late_wheel_pip_prefers_is_reported() -> None:
    newer_glibc = "demo-1.1-cp312-cp312-manylinux_2_28_x86_64.whl"
    assert displacements([LINUX_217], [newer_glibc]) == {
        newer_glibc: Displacement(
            "CPython 3.12 on Linux x86_64 with glibc 2.28", LINUX_217, tie=False, build=False
        )
    }
    abi3, own = "demo-1.1-cp38-abi3-win_amd64.whl", "demo-1.1-cp313-cp313-win_amd64.whl"
    assert displacements([abi3], [own])[own].replaced == abi3
    universal, arm = (
        "demo-1.1-cp312-cp312-macosx_10_9_universal2.whl",
        "demo-1.1-cp312-cp312-macosx_11_0_arm64.whl",
    )
    assert displacements([universal], [arm])[arm].machine == "CPython 3.12 on macOS 11.0 arm64"


def test_same_tags_and_build_numbers() -> None:
    same = "demo-1.1-cp312-cp312-manylinux2014_x86_64.whl"
    assert displacements([LINUX_217], [same])[same] == Displacement(
        "CPython 3.12 on Linux x86_64 with glibc 2.17", LINUX_217, tie=True, build=False
    )
    built = "demo-1.1-1-py3-none-any.whl"
    assert displacements([PURE], [built])[built] == Displacement(
        "Python 3", PURE, tie=True, build=True
    )
    # pip keeps the on-time wheel when its build number is the higher one.
    assert displacements(["demo-1.1-2-py3-none-any.whl"], [built]) == {}


def test_a_long_list_of_late_files_is_cut_with_a_count() -> None:
    files = {"demo/__init__.py": ""}
    late = {f"demo-1.1-cp3{m}-cp3{m}-win_amd64.whl": 30 + m for m in range(12)}
    cand = _plus(
        release("1.1", None, sdist_files=files, sdist_only=True),
        **{"demo-1.1-cp313-cp313-manylinux_2_17_x86_64.whl": 0, **late},
    )
    result = run_checks(CHANGE, release("1.0", None, sdist_files=files, sdist_only=True), cand)
    (f,) = [f for f in result.findings if f.rule_id == "GRN-T006"]
    assert [e.kind for e in f.evidence] == ["file"] * 10 + ["note", "note"]
    assert f.evidence[10].summary == "and 2 more late file(s)"
