"""GRN-C009 new-entry-point and the entry_points.txt reader. No network."""

from __future__ import annotations

from garnet_guard.engine import run_checks
from garnet_guard.facts.inventory import parse_entry_points
from garnet_guard.models import Change, EntryPoint, ReleaseFacts, Severity
from tests.builders import release

CHANGE = Change("pypi", "demo", "1.0", "1.1")
PKG = {"demo/__init__.py": ""}


def _wheel(version: str, ini: str) -> ReleaseFacts:
    return release(version, {**PKG, f"demo-{version}.dist-info/entry_points.txt": ini})


def test_parse_entry_points() -> None:
    text = (
        b"# comment\n[console_scripts]\ndemo = demo.cli:main\ndemo = demo.other:main\n"
        b"[ setuptools.finalize_distribution_options ]\nhook=demo._hook:run\n"
        b"orphan\n[empty]\n"
    )
    assert parse_entry_points(text) == (
        EntryPoint("console_scripts", "demo", "demo.cli:main"),
        EntryPoint("setuptools.finalize_distribution_options", "hook", "demo._hook:run"),
    )


def test_retargeted_auto_loaded_entry_point_warns() -> None:
    base = _wheel("1.0", "[setuptools.finalize_distribution_options]\nhook = demo.opts:run\n")
    cand = _wheel("1.1", "[setuptools.finalize_distribution_options]\nhook = demo._x:run\n")
    (f,) = [f for f in run_checks(CHANGE, base, cand).findings if f.rule_id == "GRN-C009"]
    assert f.severity == Severity.WARN
    assert f.title == (
        "1.1 adds or changes 1 entry point(s), including "
        "[setuptools.finalize_distribution_options] hook"
    )
    assert f.evidence[0].summary.startswith(
        "[setuptools.finalize_distribution_options] hook = demo._x:run (was demo.opts:run); "
    )


def test_a_project_command_or_a_retargeted_script_is_info() -> None:
    # pytest 9.1.0 moved its own pytest script to another module.
    change = Change("pypi", "pytest", "1.0", "1.1")
    base = release("1.0", {"pytest/__init__.py": ""}, package="pytest")
    cand = release(
        "1.1",
        {
            "pytest/__init__.py": "",
            "pytest-1.1.dist-info/entry_points.txt": "[console_scripts]\npytest = pytest:main\n",
        },
        package="pytest",
    )
    (f,) = [f for f in run_checks(change, base, cand).findings if f.rule_id == "GRN-C009"]
    assert f.severity == Severity.INFO
    pip = _wheel("1.0", "[console_scripts]\npip = demo.cli:pip\n")
    moved = _wheel("1.1", "[console_scripts]\npip = demo.cli2:pip\n")
    (f,) = [f for f in run_checks(CHANGE, pip, moved).findings if f.rule_id == "GRN-C009"]
    assert f.severity == Severity.INFO


def test_spacing_in_a_target_is_not_a_change() -> None:
    # jinja2 3.1.0 wrote its babel extractor without the space before [i18n].
    base = _wheel("1.0", "[pytest11]\ndemo = demo.plugin:x [extra]\n")
    cand = _wheel("1.1", "[pytest11]\ndemo = demo.plugin:x[extra]\n")
    assert "GRN-C009" not in {f.rule_id for f in run_checks(CHANGE, base, cand).findings}


def test_sdist_only_releases_are_not_compared() -> None:
    files = {**PKG, "setup.py": "from setuptools import setup\nsetup()\n"}
    base = release("1.0", sdist_files=files, sdist_only=True)
    cand = release("1.1", sdist_files=files, sdist_only=True)
    assert "GRN-C009" not in {f.rule_id for f in run_checks(CHANGE, base, cand).findings}
