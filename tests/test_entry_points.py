"""GRN-C009 new-entry-point and the entry_points.txt reader. No network."""

from __future__ import annotations

import hashlib
from importlib.metadata import Distribution
from pathlib import Path
from typing import cast

import pytest

from garnet_guard.ecosystems import pypi
from garnet_guard.ecosystems.github import TagLookup
from garnet_guard.ecosystems.gittree import TreeLookup
from garnet_guard.engine import run_checks
from garnet_guard.facts.inventory import entry_point_modules, parse_entry_points
from garnet_guard.models import (
    ArtifactFacts,
    Change,
    EntryPoint,
    Finding,
    Limits,
    ReleaseFacts,
    Severity,
)
from garnet_guard.net import Http, Response
from tests.builders import release, wheel

CHANGE = Change("pypi", "demo", "1.0", "1.1")
PKG = {"demo/__init__.py": ""}
SCRIPT = "[console_scripts]\ndemo = demo.cli:main\n"


def _wheel(version: str, ini: str, extra: dict[str, str | bytes] | None = None) -> ReleaseFacts:
    files = {**PKG, f"demo-{version}.dist-info/entry_points.txt": ini, **(extra or {})}
    return release(version, files)


def _c009(base: ReleaseFacts, cand: ReleaseFacts, change: Change = CHANGE) -> list[Finding]:
    return [f for f in run_checks(change, base, cand).findings if f.rule_id == "GRN-C009"]


def test_parse_entry_points() -> None:
    # The second demo line used to be dropped (first target kept); pip installs it.
    text = (
        b"# comment\n[console_scripts]\ndemo = demo.cli:main\ndemo = demo.other:main\n"
        b"[ setuptools.finalize_distribution_options ]\nhook=demo._hook:run\n"
        b"orphan\n[empty]\n"
    )
    path = "demo-1.0.dist-info/entry_points.txt"
    assert parse_entry_points(text, path) == (
        EntryPoint("console_scripts", "demo", "demo.cli:main", path),
        EntryPoint("console_scripts", "demo", "demo.other:main", path),
        EntryPoint("setuptools.finalize_distribution_options", "hook", "demo._hook:run", path),
    )


# Each text as importlib.metadata reads it. Spaced headers are left out: Garnet
# also strips the spaces, as pkg_resources does. So is a line without "=",
# which makes importlib.metadata raise.
LIKE_IMPORTLIB = [
    "[pytest11]\n;demo = demo._plugin\n",
    "[pytest11]\n= demo._plugin\n",
    "[pytest11]\n; = demo._plugin\n",
    "[[pytest11]]\ndemo = demo._plugin\n",
    "[[pytest11]\ndemo = demo._plugin\n",
    "[pytest11]]\ndemo = demo._plugin\n",
    "early = demo.a\n[]\nblank = demo.b\n",
    "[keyring.backends]\ndemo = demo.a\ndemo = demo.b\nother = demo.c\ndemo = demo.a\n",
    "[pytest11]\n[x = demo.a\nempty =\n  # indented comment\n",
    "[console_scripts]\r\ndemo = demo.cli:main [extra]\r\n[gui_scripts]\r\ndemo = demo.gui\r\n",
]


@pytest.mark.parametrize("text", LIKE_IMPORTLIB)
def test_parse_entry_points_reads_what_importlib_metadata_reads(tmp_path: Path, text: str) -> None:
    folder = tmp_path / "demo-1.0.dist-info"
    folder.mkdir()
    (folder / "entry_points.txt").write_bytes(text.encode())
    stdlib = [(e.group, e.name, e.value) for e in Distribution.at(folder).entry_points]
    ours = [(e.group, e.name, e.target) for e in parse_entry_points(text.encode())]
    assert ours == sorted(stdlib, key=lambda t: (t[0], t[1]))


def test_a_line_without_an_equals_sign_is_skipped(tmp_path: Path) -> None:
    text = b"[pytest11]\norphan\ndemo = demo._plugin\n"
    assert parse_entry_points(text) == (EntryPoint("pytest11", "demo", "demo._plugin"),)
    folder = tmp_path / "demo-1.0.dist-info"
    folder.mkdir()
    (folder / "entry_points.txt").write_bytes(text)
    with pytest.raises(TypeError):
        list(Distribution.at(folder).entry_points)  # the docstring's claim


def test_entry_point_modules_reads_the_same_lines() -> None:
    text = b"early = demo.early\n[pytest11]\n;demo = demo.tests.plugin\n= demo.b:x [extra]\n"
    assert entry_point_modules(text) == {"demo.tests.plugin", "demo.b"}


@pytest.mark.parametrize(
    "ini",
    [
        "[pytest11]\n;demo = demo._plugin\n",
        "[pytest11]\n= demo._plugin\n",
        "[[pytest11]]\ndemo = demo._plugin\n",
    ],
)
def test_lines_importlib_metadata_loads_warn(ini: str) -> None:
    # These used to be skipped, or read as the group "[pytest11]" at info.
    (f,) = _c009(_wheel("1.0", SCRIPT), _wheel("1.1", SCRIPT + ini))
    assert f.severity == Severity.WARN
    assert f.title.startswith("1.1 declares 1 entry point(s) that 1.0 didn't, including [pytest11]")


def test_retargeted_auto_loaded_entry_point_warns() -> None:
    base = _wheel("1.0", "[setuptools.finalize_distribution_options]\nhook = demo.opts:run\n")
    cand = _wheel("1.1", "[setuptools.finalize_distribution_options]\nhook = demo._x:run\n")
    (f,) = _c009(base, cand)
    assert f.severity == Severity.WARN
    assert f.title == (
        "1.1 adds or changes 1 entry point(s), including "
        "[setuptools.finalize_distribution_options] hook"
    )
    assert f.evidence[0].summary.startswith(
        "[setuptools.finalize_distribution_options] hook = demo._x:run (was demo.opts:run); "
    )


def test_a_second_line_for_a_name_is_a_change() -> None:
    hook = "[setuptools.finalize_distribution_options]\nhook = demo.opts:run\n"
    (f,) = _c009(_wheel("1.0", hook), _wheel("1.1", hook + "hook = demo._x:run\n"))
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary == (
        "[setuptools.finalize_distribution_options] hook = demo.opts:run, then demo._x:run "
        "(was demo.opts:run); [setuptools.finalize_distribution_options] is loaded "
        "automatically by the tool that reads it; 2 lines for one name: a tool that loads "
        "the whole group loads each one; a lookup by name takes the first"
    )
    (f,) = _c009(_wheel("1.0", SCRIPT), _wheel("1.1", SCRIPT + "demo = demo._x:run\n"))
    assert f.severity == Severity.INFO
    assert f.evidence[0].summary.endswith("; 2 lines for one name: pip installs the last")


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
    (f,) = _c009(base, cand, change)
    assert f.severity == Severity.INFO
    pip = _wheel("1.0", "[console_scripts]\npip = demo.cli:pip\n")
    moved = _wheel("1.1", "[console_scripts]\npip = demo.cli2:pip\n")
    (f,) = _c009(pip, moved)
    assert f.severity == Severity.INFO


def test_spacing_in_a_target_is_not_a_change() -> None:
    # jinja2 3.1.0 wrote its babel extractor without the space before [i18n].
    base = _wheel("1.0", "[pytest11]\ndemo = demo.plugin:x [extra]\n")
    cand = _wheel("1.1", "[pytest11]\ndemo = demo.plugin:x[extra]\n")
    assert _c009(base, cand) == []


def test_sdist_only_releases_are_not_compared() -> None:
    files = {**PKG, "setup.py": "from setuptools import setup\nsetup()\n"}
    base = release("1.0", sdist_files=files, sdist_only=True)
    cand = release("1.1", sdist_files=files, sdist_only=True)
    assert _c009(base, cand) == []


@pytest.mark.parametrize(
    ("path", "why"),
    [
        ("demo-1.1.dist-info/Entry_Points.txt", "which macOS and Windows open as entry_points.txt"),
        ("demo_helper.egg-info/entry_points.txt", "a second metadata folder"),
        ("demo_helper-1.0.DIST-INFO/entry_points.txt", "a second metadata folder"),
        ("demo-1.1.data/purelib/demo_helper-1.0.dist-info/entry_points.txt", "a second"),
    ],
)
def test_every_entry_points_file_importlib_metadata_reads_counts(path: str, why: str) -> None:
    # The file used to be read only as demo-1.1.dist-info/entry_points.txt.
    cand = _wheel("1.1", SCRIPT, {path: "[pytest11]\ndemo = demo._plugin\n"})
    (f,) = _c009(_wheel("1.0", SCRIPT), cand)
    assert f.severity == Severity.WARN
    assert f"; read from {path}, {why}" in f.evidence[0].summary
    assert f.evidence[0].path == f"demo-1.1-py3-none-any.whl:{path}"
    assert "demo._plugin" in cand.artifacts[0].entry_points  # live code for GRN-C003


def test_a_script_installers_do_not_make_is_info() -> None:
    # pip makes commands only from the wheel's own .dist-info/entry_points.txt.
    cand = _wheel(
        "1.1",
        SCRIPT,
        {"demo_helper.egg-info/entry_points.txt": "[console_scripts]\npip = demo.x\n"},
    )
    (f,) = _c009(_wheel("1.0", SCRIPT), cand)
    assert f.severity == Severity.INFO
    inside = _wheel("1.1", SCRIPT, {"demo/entry_points.txt": "[pytest11]\ndemo = demo._plugin\n"})
    assert _c009(_wheel("1.0", SCRIPT), inside) == []  # not a metadata folder


@pytest.mark.parametrize(
    "path", ["demo_helper.egg-info/entry_points.txt", "demo-1.0.dist-info/Entry_Points.txt"]
)
def test_a_command_moved_into_the_wheels_own_file_warns(path: str) -> None:
    # 1.0 lists pip where pip makes no command (info); 1.1 moves the same line
    # into its own file, so installing 1.1 makes a pip command. That step used
    # to be quiet because the target was unchanged.
    pip = "[console_scripts]\npip = demo.cli:main\n"
    step1 = _wheel("1.0", SCRIPT, {path: pip})
    (f,) = _c009(_wheel("0.9", SCRIPT), step1, Change("pypi", "demo", "0.9", "1.0"))
    assert f.severity == Severity.INFO
    (f,) = _c009(step1, _wheel("1.1", SCRIPT + "pip = demo.cli:main\n"))
    assert f.severity == Severity.WARN
    assert f.title == "1.1 adds or changes 1 entry point(s), including script pip"
    assert f.evidence[0].summary == (
        "[console_scripts] pip = demo.cli:main (was demo.cli:main); a script named pip can "
        "shadow the pip command; 1.0 listed it only outside its own entry_points.txt, which "
        "makes no command"
    )
    assert f.evidence[0].path == "demo-1.1-py3-none-any.whl:demo-1.1.dist-info/entry_points.txt"


PLUGIN_LINE = "[pytest11]\ndemo = demo.plugin\n"
STRAY: dict[str, str | bytes] = {
    "demo.egg-info/entry_points.txt": PLUGIN_LINE,
    "demo.egg-info/PKG-INFO": "Name: demo\n",
}
# Sorts before demo-1.0.dist-info/: pytest reads the folders in the order the
# file system lists them, so either first line may have been the one it loaded.
STALE: dict[str, str | bytes] = {"Demo.egg-info/entry_points.txt": "[pytest11]\ndemo = demo.old\n"}
HOOK = "[setuptools.finalize_distribution_options]\n"
KEYRING = "[keyring.backends]\n"


@pytest.mark.parametrize(
    ("base", "cand"),
    [
        ((PLUGIN_LINE, STRAY), (PLUGIN_LINE, None)),  # a stray metadata copy dropped
        ((PLUGIN_LINE, None), (PLUGIN_LINE, STRAY)),  # an identical stray copy added
        ((PLUGIN_LINE + "demo = demo.plugin\n", None), (PLUGIN_LINE, None)),  # duplicate dropped
        ((PLUGIN_LINE, None), (PLUGIN_LINE + "demo = demo.plugin\n", None)),  # duplicate added
        ((PLUGIN_LINE + "demo = demo.b\n", None), (PLUGIN_LINE, None)),  # a skipped line dropped
        ((SCRIPT + "demo = demo.b\n", None), ("[console_scripts]\ndemo = demo.b\n", None)),
        ((PLUGIN_LINE, STALE), (PLUGIN_LINE, None)),  # a stale copy that sorts first dropped
        (
            (HOOK + "hook = demo.a:run\nhook = demo.b:run\n", None),
            (HOOK + "hook = demo.b:run\n", None),
        ),
        (
            (KEYRING + "k = demo.a\nk = demo.b\n", None),
            (KEYRING + "k = demo.b\nk = demo.a\n", None),
        ),
    ],
)
def test_lines_removed_or_repeated_with_nothing_new_running_are_quiet(
    base: tuple[str, dict[str, str | bytes] | None],
    cand: tuple[str, dict[str, str | bytes] | None],
) -> None:
    # Each used to warn or be listed: the list of targets for the name changed.
    assert _c009(_wheel("1.0", *base), _wheel("1.1", *cand)) == []


def test_a_change_in_the_line_that_runs_is_reported() -> None:
    # No new target, but pytest now loads demo.b, and pip installs demo.cli:main.
    two = PLUGIN_LINE + "demo = demo.b\n"
    (f,) = _c009(_wheel("1.0", two), _wheel("1.1", "[pytest11]\ndemo = demo.b\n"))
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary == (
        "[pytest11] demo = demo.b (was demo.plugin, then demo.b); [pytest11] is loaded "
        "automatically by the tool that reads it; pytest now loads demo.b"
    )
    (f,) = _c009(_wheel("1.0", SCRIPT + "demo = demo.b\n"), _wheel("1.1", SCRIPT))
    assert f.severity == Severity.INFO
    assert f.evidence[0].summary == (
        "[console_scripts] demo = demo.cli:main (was demo.cli:main, then demo.b); "
        "pip now installs demo.cli:main"
    )


# Groups whose tool loads every line: a line that runs now ran before unless
# its target is new, so dropping or reordering lines is quiet.
EVERY_LINE = [
    "setuptools.finalize_distribution_options",
    "setuptools.file_finders",
    "distutils.setup_keywords",
    "egg_info.writers",
    "flake8.extension",
    "flake8.report",
    "keyring.backends",
    "pydantic",
    "pdm",
    "poetry.plugin",
    "poetry.application.plugin",
    "virtualenv.create",
    "pygments.lexers",  # matched on the class a line loads, not its name
    "opentelemetry_instrumentor",
]


@pytest.mark.parametrize("group", EVERY_LINE)
def test_dropping_or_reordering_lines_the_tool_loads_every_one_of_is_quiet(group: str) -> None:
    # Each used to warn: the first line changed, though every line already ran.
    two = _wheel("1.0", f"[{group}]\nx = demo.a\nx = demo.b\n")
    assert _c009(two, _wheel("1.1", f"[{group}]\nx = demo.b\n")) == []
    assert _c009(two, _wheel("1.1", f"[{group}]\nx = demo.b\nx = demo.a\n")) == []
    (f,) = _c009(two, _wheel("1.1", f"[{group}]\nx = demo.a\nx = demo.c\n"))
    assert f.severity == Severity.WARN  # a new target still counts


# mako 1.3.12 and 1.4.1's entry_points.txt, as both wheels have them: 1.4.1
# renamed four lexers (css+mako to css_mako and so on) with the same classes,
# and dropped the extras from its babel and lingua extractors.
MAKO_OLD = """\
[babel.extractors]
mako = mako.ext.babelplugin:extract [babel]

[console_scripts]
mako-render = mako.cmd:cmdline

[lingua.extractors]
mako = mako.ext.linguaplugin:LinguaMakoExtractor [lingua]

[pygments.lexers]
css+mako = mako.ext.pygmentplugin:MakoCssLexer
html+mako = mako.ext.pygmentplugin:MakoHtmlLexer
js+mako = mako.ext.pygmentplugin:MakoJavascriptLexer
mako = mako.ext.pygmentplugin:MakoLexer
xml+mako = mako.ext.pygmentplugin:MakoXmlLexer

[python.templating.engines]
mako = mako.ext.turbogears:TGPlugin
"""
MAKO_NEW = (
    MAKO_OLD.replace(" [babel]", "")
    .replace(" [lingua]", "")
    .replace("css+mako", "css_mako")
    .replace("html+mako", "html_mako")
    .replace("js+mako", "js_mako")
    .replace("xml+mako", "xml_mako")
)
MAKO = Change("pypi", "mako", "1.3.12", "1.4.1")


def _mako(version: str, ini: str) -> ReleaseFacts:
    files = {"mako/__init__.py": "", f"mako-{version}.dist-info/entry_points.txt": ini}
    return release(version, files, package="mako")


def test_renamed_lexers_with_the_same_classes_are_quiet() -> None:
    # mako 1.4.1 used to warn for four "new" pygments.lexers entry points:
    # pygments loads every lexer by class, so no new class runs. The extras
    # dropped from the two extractors are still listed, at info.
    (f,) = _c009(_mako("1.3.12", MAKO_OLD), _mako("1.4.1", MAKO_NEW), MAKO)
    assert f.severity == Severity.INFO
    assert f.title == "1.4.1 adds or changes 2 entry point(s)"
    assert [e.summary for e in f.evidence] == [
        "[babel.extractors] mako = mako.ext.babelplugin:extract "
        "(was mako.ext.babelplugin:extract [babel])",
        "[lingua.extractors] mako = mako.ext.linguaplugin:LinguaMakoExtractor "
        "(was mako.ext.linguaplugin:LinguaMakoExtractor [lingua])",
    ]


def test_a_renamed_lexer_that_loads_another_class_warns() -> None:
    # The same rename, with css_mako now loading another class, or a class
    # from another module: that class never ran, so it warns.
    for target in ("mako.ext.pygmentplugin:MakoCssLexer2", "mako.ext._css:MakoCssLexer"):
        new = MAKO_NEW.replace(
            "css_mako = mako.ext.pygmentplugin:MakoCssLexer", f"css_mako = {target}"
        )
        (f,) = _c009(_mako("1.3.12", MAKO_OLD), _mako("1.4.1", new), MAKO)
        assert f.severity == Severity.WARN
        assert f.title == (
            "1.4.1 adds or changes 3 entry point(s), including [pygments.lexers] css_mako"
        )
        assert f.evidence[0].summary == (
            f"[pygments.lexers] css_mako = {target} (new); "
            "[pygments.lexers] is loaded automatically by the tool that reads it"
        )


# Groups whose tool loads every line's target whatever its name.
NAME_BLIND = [
    "keyring.backends",
    "opentelemetry_post_instrument",
    "opentelemetry_pre_instrument",
    "pdm",
    "poetry.application.plugin",
    "poetry.plugin",
    "pygments.lexers",
    "setuptools.file_finders",
    "setuptools.finalize_distribution_options",
]


@pytest.mark.parametrize("group", NAME_BLIND)
def test_a_target_under_a_new_name_where_the_name_is_ignored_is_quiet(group: str) -> None:
    base = _wheel("1.0", f"[{group}]\nx = demo.a:A\ny = demo.b:B\n")
    # Renamed, renamed onto another line's name, or listed a second time.
    for lines in ("z = demo.a:A\ny = demo.b:B\n", "y = demo.a:A\ny = demo.b:B\n", "w = demo.b:B\n"):
        assert _c009(base, _wheel("1.1", f"[{group}]\n{lines}")) == []
    # A new target under the new name, or an old target's object changed.
    for lines in ("z = demo.c:A\n", "z = demo.a:C\n", "x = demo.a:A\nz = demo.a:A [extra]\n"):
        (f,) = _c009(base, _wheel("1.1", f"[{group}]\n{lines}"))
        assert f.severity == Severity.WARN
        assert f.evidence[0].summary.startswith(f"[{group}] z = ")


@pytest.mark.parametrize("group", NAME_BLIND)
def test_a_target_that_never_loaded_does_not_cover_a_rename(group: str) -> None:
    # importlib can't load "demo.p q:L", so it never ran: "demo.pq:L" under
    # another name is new, although the two read the same without spaces.
    base = _wheel("1.0", f"[{group}]\nx = demo.p q:L\n")
    (f,) = _c009(base, _wheel("1.1", f"[{group}]\ny = demo.pq:L\n"))
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary.startswith(f"[{group}] y = demo.pq:L")


@pytest.mark.parametrize(
    "group",
    sorted(set(EVERY_LINE) - set(NAME_BLIND) | {"virtualenv.discovery", "pytest11"}),
)
def test_a_target_under_a_new_name_where_the_name_decides_warns(group: str) -> None:
    # distutils.setup_keywords loads a line when setup() uses the keyword it
    # names (a rename to packages runs it in every build), egg_info.writers
    # writes the file it names, pydantic and opentelemetry_instrumentor skip
    # the names a user turns off, virtualenv picks a creator or discovery by
    # name, flake8 a formatter: a renamed line can run where it didn't.
    base = _wheel("1.0", f"[{group}]\nuse_demo = demo.kw:run\n")
    (f,) = _c009(base, _wheel("1.1", f"[{group}]\npackages = demo.kw:run\n"))
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary.startswith(f"[{group}] packages = demo.kw:run (new); ")


def test_a_target_setuptools_skipped_by_its_name_is_new_under_another() -> None:
    # setuptools drops a finalize_distribution_options hook named 2to3_doctests,
    # so its target never ran; the same target under another name runs now.
    group = "setuptools.finalize_distribution_options"
    base = _wheel("1.0", f"[{group}]\n2to3_doctests = demo.x:run\n")
    (f,) = _c009(base, _wheel("1.1", f"[{group}]\nhook = demo.x:run\n"))
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary.startswith(f"[{group}] hook = demo.x:run (new); ")


def test_a_target_from_another_group_is_new() -> None:
    # Only the same group counts: a formatter class listed as a lexer is new.
    base = _wheel("1.0", "[pygments.formatters]\nx = demo.a:A\n")
    (f,) = _c009(
        base,
        _wheel("1.1", "[pygments.formatters]\nx = demo.a:A\n[pygments.lexers]\ny = demo.a:A\n"),
    )
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary.startswith("[pygments.lexers] y = demo.a:A (new); ")


@pytest.mark.parametrize(
    ("group", "now"),
    [
        ("pytest11", "pytest now loads demo.b"),  # pluggy registers a name once
        ("tox", "tox now loads demo.b"),
        ("hatch", "hatch now loads demo.b"),
        ("distutils.commands", "a lookup by name now returns demo.b"),
        # get_style_by_name, find_filter_class and find_formatter_class return
        # the first line that matches; each used to be quiet, as if pygments
        # loaded every line.
        ("pygments.styles", "a lookup by name now returns demo.b"),
        ("pygments.filters", "a lookup by name now returns demo.b"),
        ("pygments.formatters", "a lookup by name now returns demo.b"),
        ("opentelemetry_propagator", "a lookup by name now returns demo.b"),
        ("babel.extractors", "a lookup by name now returns demo.b"),
    ],
)
def test_a_new_first_line_where_the_first_line_is_used_is_reported(group: str, now: str) -> None:
    two = _wheel("1.0", f"[{group}]\nx = demo.a\nx = demo.b\n")
    for lines in ("x = demo.b\n", "x = demo.b\nx = demo.a\n"):  # first dropped, reordered
        (f,) = _c009(two, _wheel("1.1", f"[{group}]\n{lines}"))
        assert now in f.evidence[0].summary.split("; ")
        assert f.severity == (Severity.INFO if group == "babel.extractors" else Severity.WARN)


def test_a_first_line_in_another_folder_says_which_folder_decides() -> None:
    # 1.0 lists demo.old second, where pytest skips it; 1.1 lists it first in
    # a second metadata folder, which pytest may read before the wheel's own.
    base = _wheel("1.0", PLUGIN_LINE + "demo = demo.old\n")
    stray: dict[str, str | bytes] = {
        "demo_helper.egg-info/entry_points.txt": "[pytest11]\ndemo = demo.old\n"
    }
    cand = _wheel("1.1", PLUGIN_LINE, stray)
    (f,) = _c009(base, cand)
    assert f.severity == Severity.WARN
    assert (
        "; pytest now loads demo.old if demo_helper.egg-info/entry_points.txt is read first; "
        in f.evidence[0].summary
    )
    assert f.evidence[0].path == "demo-1.1-py3-none-any.whl:demo_helper.egg-info/entry_points.txt"


def test_a_long_repeated_name_is_listed_in_part() -> None:
    # 16,000 lines for one name used to make one 2.8 MB evidence line, listing
    # every target, and took a second to compare.
    lines = "".join(f"demo = demo.m{i:05}_{'x' * 60}:run\n" for i in range(16_000))
    base = _wheel("1.0", "[console_scripts]\n" + lines + "demo = demo.last:run\n")
    (f,) = _c009(base, _wheel("1.1", "[console_scripts]\n" + lines))
    (ev,) = f.evidence
    assert len(ev.summary) <= 1000
    assert ", then 15,997 more line(s), then demo.m15999_" in ev.summary
    assert (
        "(was demo.m00000_" in ev.summary
        and "15,998 more line(s), then demo.last:run)" in ev.summary
    )
    hooks = "[pytest11]\n" + "".join(f"demo = demo.p{i}\n" for i in range(6))
    (f,) = _c009(_wheel("1.0", hooks), _wheel("1.1", hooks.replace("demo.p3", "demo.other")))
    assert " demo.p5); first new target: demo.other; [pytest11] is loaded" in f.evidence[0].summary
    # With an 80-character group and name and 120-character targets, the note
    # used to be clipped off the end of the line.
    group, name = "setuptools." + "g" * 75, "n" * 80
    hooks = f"[{group}]\n" + "".join(f"{name} = demo.{'t' * 120}{i}:run\n" for i in range(6))
    new = hooks.replace(f"demo.{'t' * 120}3:run", "demo.NEW:run")
    (f,) = _c009(_wheel("1.0", hooks), _wheel("1.1", new))
    assert len(f.evidence[0].summary) <= 1000
    assert "); first new target: demo.NEW:run" in f.evidence[0].summary
    group = "setuptools." + "x" * 5000
    (f,) = _c009(_wheel("1.0", SCRIPT), _wheel("1.1", f"[{group}]\n{'n' * 5000} = demo.a\n"))
    assert len(f.title) < 300 and len(f.evidence[0].summary) <= 1000


def test_a_metadata_folder_installed_as_data_is_not_read() -> None:
    # The rule page's "What it doesn't check": a .dist-info folder installed
    # through <name>.data/data/ lands in site-packages only under some install
    # schemes, so GRN-C009 doesn't read it; GRN-C010 lists the file at info.
    path = "demo-1.1.data/data/lib/python3.12/site-packages/demo_helper-1.0.dist-info"
    cand = _wheel("1.1", SCRIPT, {f"{path}/entry_points.txt": PLUGIN_LINE})
    result = run_checks(CHANGE, _wheel("1.0", SCRIPT), cand)
    assert [(f.rule_id, f.severity) for f in result.findings] == [("GRN-C010", Severity.INFO)]


# A namespace layout: acme/ sorts before acme_plugin-1.0.dist-info/, so a limit
# hit in acme/ stops the reading before entry_points.txt.
NS = {"acme/__init__.py": "", "acme/plugin/__init__.py": ""}
PLUGIN = "[pytest11]\nacme_plugin = acme.plugin\n"
PAD = {"acme/plugin/tests/pad.bin": b"\0" * 5000}
SMALL = Limits(max_total_uncompressed=4000)


def _ns(version: str, ini: str, pad: bool = False) -> ReleaseFacts:
    files = {**NS, f"acme_plugin-{version}.dist-info/entry_points.txt": ini, **(PAD if pad else {})}
    return release(version, files, package="acme_plugin", limits=SMALL if pad else None)


def test_a_wheel_read_in_part_is_not_compared_and_says_so() -> None:
    change = Change("pypi", "acme-plugin", "1.0", "1.1")
    for base, cand in (
        (_ns("1.0", PLUGIN, pad=True), _ns("1.1", PLUGIN)),
        (_ns("1.0", ""), _ns("1.1", PLUGIN, pad=True)),
    ):
        result = run_checks(change, base, cand)
        # The trusted wheel used to look as if it had no entry points, so 1.1's
        # existing plugin was reported as new; GRN-E003 didn't name this rule.
        assert "GRN-C009" not in {f.rule_id for f in result.findings}
        (e003,) = [f for f in result.findings if f.rule_id == "GRN-E003"]
        assert "GRN-C009" in e003.evidence[-1].summary.split("not evaluated: ")[1]


def test_entry_points_that_warn_lead_the_evidence() -> None:
    many = SCRIPT + "".join(f"demo-tool{i:02} = demo.cli:t{i}\n" for i in range(26))
    cand = _wheel("1.1", many + "[pytest11]\ndemo = demo._plugin\n")
    (f,) = _c009(_wheel("1.0", SCRIPT), cand)
    assert f.title == "1.1 declares 27 entry point(s) that 1.0 didn't, including [pytest11] demo"
    assert f.evidence[0].summary.startswith("[pytest11] demo = demo._plugin (new); ")
    assert len(f.evidence) == 26
    assert f.evidence[-1].summary == "and 2 more entry point(s)"
    plugins = "".join(f"p{i} = demo._p{i}\n" for i in range(5))
    (f,) = _c009(_wheel("1.0", SCRIPT), _wheel("1.1", SCRIPT + "[pytest11]\n" + plugins))
    assert f.title.endswith("including [pytest11] p0, [pytest11] p1, [pytest11] p2 and 2 more")


class _Http:
    def __init__(self, status: int, content: bytes) -> None:
        self.status, self.content = status, content

    def get(self, url: str, **kwargs: object) -> Response:
        return Response(status=self.status, content=self.content, url=url)


def _inspect(status: int, data: bytes) -> tuple[ArtifactFacts, list[str]]:
    name = "demo-1.1-py3-none-any.whl"
    f = pypi.RegistryFile(
        name, "https://files.invalid/x", hashlib.sha256(data).hexdigest(), "bdist_wheel", None
    )
    h = cast(Http, _Http(status, data))
    ctx = pypi.FetchContext(http=h, limits=Limits(), tags=TagLookup(h), trees=TreeLookup(h))
    art, errors, _, _ = pypi._inspect(
        ctx, f, ArtifactFacts(name, f.sha256, "bdist_wheel", None, None)
    )
    return art, [r for e in errors for r in e.rules]


def test_the_fetcher_carries_the_entry_points_and_names_the_rule_when_it_fails() -> None:
    data = wheel({**PKG, "demo-1.1.dist-info/entry_points.txt": "[pytest11]\ndemo = demo.p\n"})
    art, rules = _inspect(200, data)
    assert art.entry_points_read and rules == []
    assert [(e.group, e.name) for e in art.entry_point_specs] == [("pytest11", "demo")]
    _, rules = _inspect(503, b"")
    assert "GRN-C009" in rules
