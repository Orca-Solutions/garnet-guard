"""GRN-C010 new-startup-file. Synthetic wheels only; no network."""

from __future__ import annotations

from garnet_guard.engine import run_checks
from garnet_guard.models import Change, Finding, Severity
from tests.builders import release

CHANGE = Change("pypi", "demo", "1.0", "1.1")
PKG = {"demo/__init__.py": ""}


def _c010(files: dict[str, str]) -> Finding | None:
    result = run_checks(CHANGE, release("1.0", PKG), release("1.1", {**PKG, **files}))
    found = [f for f in result.findings if f.rule_id == "GRN-C010"]
    return found[0] if found else None


def test_startup_module_under_purelib_counts() -> None:
    f = _c010({"demo-1.1.data/purelib/usercustomize.py": ""})
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary == (
        "demo-1.1.data/purelib/usercustomize.py: Python imports it from site-packages at every "
        "start (0 bytes)"
    )


def test_config_under_etc_warns() -> None:
    f = _c010({"demo-1.1.data/data/etc/jupyter/jupyter_server_config.d/demo.json": "{}"})
    assert f.severity == Severity.WARN
    assert "where other tools read their configuration" in f.evidence[0].summary


def test_own_command_is_info() -> None:
    f = _c010({"demo-1.1.data/scripts/demo-admin": "#!/bin/sh\n"})
    assert f.severity == Severity.INFO
    assert f.title == "1.1 adds 1 file(s) that run or install outside the package"


def test_windows_command_names_warn() -> None:
    f = _c010({"demo-1.1.data/scripts/Pip.exe": "MZ"})
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary == (
        "demo-1.1.data/scripts/Pip.exe: installs as the command Pip.exe, which can run instead "
        "of the usual pip (2 bytes)"
    )
    assert _c010({"demo-1.1.data/scripts/git.CMD": "@echo off\n"}).severity == Severity.WARN
    assert _c010({"demo-1.1.data/scripts/git.py": ""}).severity == Severity.INFO


def test_sdists_are_not_compared() -> None:
    # What an sdist installs is up to its build, which Garnet never runs.
    files = {"sitecustomize.py": "import os\n"}
    base = release("1.0", None, sdist_files=PKG, sdist_only=True)
    cand = release("1.1", None, sdist_files={**PKG, **files}, sdist_only=True)
    result = run_checks(CHANGE, base, cand)
    assert "GRN-C010" not in {f.rule_id for f in result.findings}


def test_startup_module_matched_by_module_name() -> None:
    # Python imports each of these as sitecustomize or usercustomize; a
    # case-insensitive filesystem treats the case variants as the same file.
    for path in (
        "sitecustomize/__init__.py",
        "sitecustomize.pyc",
        "sitecustomize.cpython-312-x86_64-linux-gnu.so",
        "sitecustomize.abi3.so",
        "usercustomize.cp312-win_amd64.pyd",
        "SiteCustomize.py",
        "USERCUSTOMIZE.PY",
        "demo-1.1.data/platlib/sitecustomize.abi3.so",
        "demo-1.1.data/purelib/sitecustomize/__init__.py",
    ):
        f = _c010({path: ""})
        assert f is not None and f.severity == Severity.WARN, path
        assert "Python imports it from site-packages at every start" in f.evidence[0].summary


def test_startup_module_under_data_site_packages_warns() -> None:
    for path in (
        "demo-1.1.data/data/lib/python3.12/site-packages/sitecustomize.py",
        "demo-1.1.data/data/Lib/Site-Packages/usercustomize/__init__.py",
        "demo-1.1.data/data/lib/python3/dist-packages/sitecustomize.abi3.so",
    ):
        f = _c010({path: ""})
        assert f is not None and f.severity == Severity.WARN, path
        name = path.split("/data/", 1)[1]
        assert f.evidence[0].summary == (
            f"{path}: installs as <prefix>/{name}, where Python imports it at every start (0 bytes)"
        )


def test_names_that_do_not_import_as_startup_modules_stay_quiet_or_info() -> None:
    # A sourceless __pycache__ file isn't imported; neither is a module inside
    # the package, or one whose name only starts with the startup name.
    for path in (
        "__pycache__/sitecustomize.cpython-312.pyc",
        "demo/sitecustomize.py",
        "demo/sitecustomize/__init__.py",
        "sitecustomize_helper.py",
        "mysitecustomize.py",
    ):
        assert _c010({path: ""}) is None, path
    # under .data/data/ but not in a site-packages folder: a plain data file
    f = _c010({"demo-1.1.data/data/share/demo/sitecustomize.py": ""})
    assert f is not None and f.severity == Severity.INFO
    f = _c010({"demo-1.1.data/data/lib/python3.12/site-packages/demo_extra.py": ""})
    assert f is not None and f.severity == Severity.INFO


def test_startup_package_already_shipped_is_quiet() -> None:
    files = {"sitecustomize/__init__.py": "import demo\n"}
    result = run_checks(CHANGE, release("1.0", {**PKG, **files}), release("1.1", {**PKG, **files}))
    assert "GRN-C010" not in {f.rule_id for f in result.findings}
