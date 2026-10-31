"""GRN-C006: the wheel the content rules read compared with the release's own sdist.

The wheels and sdists here are built in memory; nothing is fetched or run.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import replace
from typing import cast

from garnet_guard.ecosystems.github import TagLookup
from garnet_guard.ecosystems.gittree import TreeLookup
from garnet_guard.ecosystems.pypi import FetchContext, RegistryFile, ReplayRelease, release_facts
from garnet_guard.ecosystems.sdist import match_sdist
from garnet_guard.engine import run_checks
from garnet_guard.facts.inventory import exec_lines, file_reader, other_exec_lines
from garnet_guard.models import (
    CallSite,
    Change,
    Limits,
    ReleaseFacts,
    SdistMatch,
    Verdict,
    WheelOnlyCode,
)
from garnet_guard.net import Http, Response
from tests.builders import artifact, release, sdist, wheel

INIT = "def hello():\n    return 1\n"
CLIENT = "def connect():\n    return 1\n"
# A function appended to a file, as issue #60 expected of telnyx's _client.py.
APPENDED = CLIENT + "\nimport subprocess\n\ndef setup():\n    subprocess.run(['sh', '-c', 'x'])\n"
PAIRED = {"demo/__init__.py": INIT, "demo/_client.py": CLIENT}
FETCH = "import urllib.request\n\ndef get(url):\n    return urllib.request.urlopen(url)\n"
PY2 = "def setup():\n    print 'hi'\n"
DEEP = "\nTABLE = " + " + ".join(["1"] * 1500) + "\n"  # parses, too deep to walk
WHEEL1, SDIST1 = "demo-1.1-py3-none-any.whl", "demo-1.1.tar.gz"
CHANGE = Change("pypi", "demo", "1.0", "1.1")


def _c006(base: ReleaseFacts | None, cand: ReleaseFacts) -> list[tuple[str, list[str]]]:
    result = run_checks(Change("pypi", "demo", "1.0", cand.version), base, cand)
    return [
        (f.title, [e.summary for e in f.evidence])
        for f in result.findings
        if f.rule_id == "GRN-C006"
    ]


def _head(matched: int, differ: int, absent: int) -> str:
    return (
        f"compared {WHEEL1} with {SDIST1}: {matched} Python file(s) match the sdist, "
        f"{differ} differ from their copy there, {absent} have none"
    )


def _matched(
    wheel_files: dict[str, str | bytes],
    sdist_files: dict[str, str | bytes],
    limits: Limits | None = None,
) -> tuple[SdistMatch, list[str], list[str]]:
    """``match_sdist`` on a wheel and an sdist of 1.1, and the paths it read back from each."""
    lim = limits or Limits()
    w, _, wd = artifact("1.1", wheel_files, limits=lim)
    s, _, sd = artifact("1.1", sdist_files, kind="sdist", limits=lim)
    assert wd is not None and sd is not None
    asked_w: list[str] = []
    asked_s: list[str] = []

    def logged(read: Callable[[str], bytes], asked: list[str]) -> Callable[[str], bytes]:
        def go(path: str) -> bytes:
            asked.append(path)
            return read(path)

        return go

    match = match_sdist(
        w,
        logged(file_reader(w.filename, wd, lim, sdist=False), asked_w),
        s,
        logged(file_reader(s.filename, sd, lim, sdist=True), asked_s),
        lim,
    )
    return match, asked_w, asked_s


# --- Facts: where the sdist keeps a wheel file, and what counts as the same ---


def test_a_call_appended_to_the_wheels_copy_is_recorded_with_its_line() -> None:
    match, asked_w, asked_s = _matched({**PAIRED, "demo/_client.py": APPENDED}, PAIRED)
    assert (match.matched, match.differ, match.absent) == (1, 1, 0)
    assert match.code == (
        WheelOnlyCode(
            "demo/_client.py", "demo/_client.py", (CallSite("subprocess.run", 7, "setup"),)
        ),
    )
    # Only the file whose bytes aren't in the sdist is read back, from each archive.
    assert asked_w == ["demo/_client.py"] and asked_s == ["demo/_client.py"]


def test_identical_files_match_wherever_the_sdist_keeps_them() -> None:
    """Same bytes anywhere in the sdist: a vendored copy, a src/ or python/ layout."""
    vendored = {"demo/__init__.py": INIT, "demo/_vendor/six.py": FETCH}
    for layout in (
        PAIRED,
        {f"src/{p}": b for p, b in PAIRED.items()},
        {f"python/{p}": b for p, b in PAIRED.items()},
    ):
        match, asked_w, _ = _matched(PAIRED, layout)
        assert (match.matched, match.differ, match.absent, match.code) == (2, 0, 0, ())
        assert asked_w == []
    match, _, _ = _matched(vendored, {"demo/__init__.py": INIT, "vendor/six.py": FETCH})
    assert (match.matched, match.code) == (2, ())


def test_a_changed_file_is_compared_with_its_copy_under_the_sdists_layout() -> None:
    for folder in ("src/", "python/"):
        layout = {f"{folder}{p}": b for p, b in PAIRED.items()}
        match, _, asked_s = _matched({**PAIRED, "demo/_client.py": APPENDED}, layout)
        assert [(w.path, w.at) for w in match.code] == [
            ("demo/_client.py", f"{folder}demo/_client.py")
        ]
        assert asked_s == [f"{folder}demo/_client.py"]


def test_a_package_published_under_another_name_is_compared_with_its_folder() -> None:
    """pycryptodomex: the sdist's lib/Crypto/ is the wheel's Cryptodome/. The
    sdist copy makes the same ctypes call, so nothing is new."""
    raw = "import ctypes\n\ndef load():\n    return ctypes.CDLL('x')\n"
    wheel_files = {
        "Cryptodome/__init__.py": INIT,
        "Cryptodome/Cipher/__init__.py": "",
        "Cryptodome/Cipher/_raw.py": "# Cryptodome\n" + raw,
    }
    sdist_files = {
        "lib/Crypto/__init__.py": INIT,
        "lib/Crypto/Cipher/__init__.py": "",
        "lib/Crypto/Cipher/_raw.py": "# Crypto\n" + raw,
    }
    match, _, asked_s = _matched(wheel_files, sdist_files)
    assert (match.matched, match.differ, match.absent, match.code) == (2, 1, 0, ())
    assert asked_s == ["lib/Crypto/Cipher/_raw.py"]


def test_crlf_line_endings_are_the_same_file() -> None:
    crlf = CLIENT.replace("\n", "\r\n")
    match, _, _ = _matched({**PAIRED, "demo/_client.py": crlf}, PAIRED)
    assert (match.matched, match.code) == (2, ())
    # The sdist's copy has them and the wheel's doesn't: the same.
    match, _, _ = _matched(PAIRED, {**PAIRED, "demo/_client.py": crlf})
    assert (match.matched, match.code) == (2, ())
    # Changed code with CRLF endings still reports the new call.
    match, _, _ = _matched({**PAIRED, "demo/_client.py": APPENDED.replace("\n", "\r\n")}, PAIRED)
    assert [c.name for w in match.code for c in w.calls] == ["subprocess.run"]


def test_a_call_the_sdist_copy_makes_is_not_recorded() -> None:
    sdist_copy = APPENDED.replace("def connect", "def open_connection")
    match, _, _ = _matched(
        {**PAIRED, "demo/_client.py": APPENDED}, {**PAIRED, "demo/_client.py": sdist_copy}
    )
    assert (match.differ, match.code) == (1, ())


def test_an_sdist_copy_garnet_cannot_parse_explains_nothing() -> None:
    """A Python 2 copy, or one over the parse limit: every call counts, and the
    facts say the copy wasn't parsed."""
    for sdist_copy, limits in (
        (PY2, None),
        (APPENDED + "# " + "x" * 200 + "\n", Limits(max_py_file_bytes=len(APPENDED) + 20)),
    ):
        match, _, _ = _matched(
            {**PAIRED, "demo/_client.py": APPENDED},
            {**PAIRED, "demo/_client.py": sdist_copy},
            limits,
        )
        ((w,),) = (match.code,)
        assert (w.path, w.sdist_parsed, [c.name for c in w.calls]) == (
            "demo/_client.py",
            False,
            ["subprocess.run"],
        )


def test_wheel_files_are_compared_by_where_they_install() -> None:
    """``.data/purelib/`` installs at the top of site-packages. Scripts and
    metadata don't install as importable code, so they aren't compared."""
    wheel_files = {
        "demo/__init__.py": INIT,
        "demo-1.1.data/purelib/demo/_fetch.py": FETCH,
        "demo-1.1.data/scripts/tool.py": FETCH,
        "demo-1.1.dist-info/hook.py": FETCH,
    }
    match, _, _ = _matched(wheel_files, {"demo/__init__.py": INIT})
    assert (match.matched, match.absent) == (1, 1)
    assert [(w.path, w.at) for w in match.code] == [("demo/_fetch.py", None)]


def test_pth_files_are_compared_with_the_sdists_copy() -> None:
    boot = "import demo._boot\n"
    # Copied to the top of the wheel from a folder in the sdist: the same bytes.
    match, _, _ = _matched({**PAIRED, "demo.pth": boot}, {**PAIRED, "src/demo/demo.pth": boot})
    assert match.code == ()
    # The same lines with another comment: nothing new runs.
    match, _, _ = _matched({**PAIRED, "demo.pth": "# built\n" + boot}, {**PAIRED, "demo.pth": boot})
    assert match.code == ()
    # A line the sdist's copy, found by name, lacks.
    extra = boot + "import os; os.system('id')\n"
    match, _, _ = _matched({**PAIRED, "demo.pth": extra}, {**PAIRED, "tools/demo.pth": boot})
    assert match.code == (
        WheelOnlyCode("demo.pth", "tools/demo.pth", lines=("import os; os.system('id')",)),
    )
    # No copy at all, even one with no executable lines.
    match, _, _ = _matched({**PAIRED, "demo.pth": "demo/lib\n"}, PAIRED)
    assert match.code == (WheelOnlyCode("demo.pth", None),)


def test_pth_lines_are_read_as_every_python_runs_them() -> None:
    """Python 3.11 and 3.12 end a .pth line only at \\n, \\r or \\r\\n, so a
    line with a form feed runs whole; 3.13 and later split at the form feed and
    a vertical tab too, and drop a leading BOM."""
    line = "import os; os.getcwd()"

    def both(pth: bytes) -> tuple[tuple[str, ...], tuple[str, ...]]:
        return exec_lines(pth), other_exec_lines(pth)

    assert both(f"{line}\x0c;os.system('id')\n".encode()) == (
        (line,),
        (f"{line}\x0c;os.system('id')",),
    )
    assert both(b"\xef\xbb\xbfimport os; os.system('id')\nlib\n") == (
        (),
        ("import os; os.system('id')",),
    )
    assert both(b"lib\x0bimport os\n") == (("import os",), ())
    # exec_lines keeps a line each time it appears, as GRN-C001 has always
    # compared them; the other readings add each line once.
    assert both(b"import a\r\nlib\rimport\tb\n\nimport a\n") == (
        ("import a", "import\tb", "import a"),
        (),
    )
    # Hidden behind a form feed or a BOM, a line the sdist's copy lacks is recorded.
    hidden = f"{line}\x0c;os.system('id')"
    match, _, _ = _matched({**PAIRED, "demo.pth": hidden + "\n"}, {**PAIRED, "demo.pth": line})
    assert match.code == (WheelOnlyCode("demo.pth", "demo.pth", lines=(hidden,)),)
    bom = b"\xef\xbb\xbfimport os; os.system('id')\nlib\n"
    match, _, _ = _matched({**PAIRED, "demo.pth": bom}, {**PAIRED, "demo.pth": "lib\n"})
    assert match.code == (
        WheelOnlyCode("demo.pth", "demo.pth", lines=("import os; os.system('id')",)),
    )


def test_a_wheel_file_too_deep_to_walk_is_recorded_not_dropped() -> None:
    """It parses, so the inventory keeps it, but its calls can't be listed:
    counted as differing, never matched, and named for GRN-E002."""
    match, _, _ = _matched({**PAIRED, "demo/_client.py": APPENDED + DEEP}, PAIRED)
    assert (match.matched, match.differ, match.absent) == (1, 1, 0)
    assert (match.code, match.unwalked) == ((), ("demo/_client.py",))
    match, _, _ = _matched({**PAIRED, "demo/_deep.py": DEEP}, PAIRED)
    assert (match.absent, match.unwalked) == (1, ("demo/_deep.py",))


# --- The rule: what it reports, and what the trusted version already had ---


def test_the_finding_names_the_file_line_call_and_sdist_copy() -> None:
    base = release("1.0", PAIRED, sdist_files=PAIRED)
    cand = release(
        "1.1",
        {**PAIRED, "demo/_client.py": APPENDED, "demo/_fetch.py": FETCH},
        sdist_files=PAIRED,
    )
    assert _c006(base, cand) == [
        (
            "1.1's wheel has code that is not in its sdist (2 file(s))",
            [
                _head(1, 1, 1),
                "demo/_client.py:7 calls subprocess.run (in setup()); demo/_client.py in "
                f"{SDIST1} doesn't",
                f"demo/_fetch.py:4 calls urllib.request.urlopen (in get()); {SDIST1} has no "
                "such file",
            ],
        )
    ]
    result = run_checks(Change("pypi", "demo", "1.0", "1.1"), base, cand)
    assert result.verdict == Verdict.WARN


def test_an_unparsable_sdist_copy_is_said() -> None:
    base = release("1.0", PAIRED, sdist_files=PAIRED)
    cand = release(
        "1.1",
        {**PAIRED, "demo/_client.py": APPENDED},
        sdist_files={**PAIRED, "demo/_client.py": PY2},
    )
    ((_, evidence),) = _c006(base, cand)
    assert evidence[1] == (
        f"demo/_client.py:7 calls subprocess.run (in setup()); demo/_client.py in {SDIST1} "
        "couldn't be parsed to compare"
    )


def test_a_new_call_beside_one_the_trusted_wheel_carried_is_reported_alone() -> None:
    both = (
        APPENDED + "\nimport socket\n\ndef dial():\n    return socket.create_connection(('h', 1))\n"
    )
    base = release("1.0", {**PAIRED, "demo/_client.py": APPENDED}, sdist_files=PAIRED)
    cand = release("1.1", {**PAIRED, "demo/_client.py": both}, sdist_files=PAIRED)
    ((_, evidence),) = _c006(base, cand)
    assert [e.split(";")[0] for e in evidence[1:]] == [
        "demo/_client.py:12 calls socket.create_connection (in dial())"
    ]
    # The same call moved to another file is new there: the comparison is by install path.
    moved = release("1.1", {**PAIRED, "demo/_setup.py": APPENDED}, sdist_files=PAIRED)
    assert [e.split(";")[0] for _, ev in _c006(base, moved) for e in ev[1:]] == [
        "demo/_setup.py:7 calls subprocess.run (in setup())"
    ]


def test_pth_lines_the_trusted_wheel_carried_are_not_new() -> None:
    """A namespace .pth that setuptools names after the version (GRN-C001 lets
    it be renamed too), and a path-only .pth at the same place."""
    nspkg = "import sys, types, os;has_mfs = sys.version_info > (3, 5)\n"
    base = release(
        "1.0", {**PAIRED, "demo-1.0-nspkg.pth": nspkg, "demo.pth": "lib\n"}, sdist_files=PAIRED
    )
    cand = release(
        "1.1", {**PAIRED, "demo-1.1-nspkg.pth": nspkg, "demo.pth": "lib\n"}, sdist_files=PAIRED
    )
    assert _c006(base, cand) == []
    fresh = release("1.0", PAIRED, sdist_files=PAIRED)
    ((_, evidence),) = _c006(fresh, cand)
    assert evidence[1:] == [
        f"demo-1.1-nspkg.pth (1 executable line(s)) has no copy in {SDIST1}: {nspkg.strip()}",
        f"demo.pth (no executable lines) has no copy in {SDIST1}",
    ]


# --- Test files and files outside the packages: info (the maintainer's 2026-10-31 decision) ---

QUIET_TITLE = (
    "1.1's wheel has code that is not in its sdist only in test files or files outside "
    "its packages ({n} file(s))"
)
LOUD_TITLE = "1.1's wheel has code that is not in its sdist ({n} file(s))"


def _c006_levels(wheel_files: dict[str, str | bytes]) -> list[tuple[str, str]]:
    """GRN-C006's findings, as (severity, title), for a 1.1 wheel with these
    files beside the clean sdist ``PAIRED``, after a 1.0 that matched."""
    base = release("1.0", PAIRED, sdist_files=PAIRED)
    cand = release("1.1", {**PAIRED, **wheel_files}, sdist_files=PAIRED)
    result = run_checks(Change("pypi", "demo", "1.0", "1.1"), base, cand)
    return [(f.severity.name, f.title) for f in result.findings if f.rule_id == "GRN-C006"]


def test_code_only_in_test_files_is_info() -> None:
    """aenum 3.1.16's ``aenum/test_stdlib_tests.py`` and oauth2client 4.0.0's
    top-level ``tests/`` tree, which only the wheel has."""
    for path in ("demo/test_stdlib.py", "tests/test_client.py", "demo/conftest.py", "test/x.py"):
        assert _c006_levels({path: FETCH}) == [("INFO", QUIET_TITLE.format(n=1))], path


def test_code_outside_the_packages_is_info() -> None:
    """google-auth-oauthlib 1.2.0's ``scripts/readme-gen/readme_gen.py``: a
    folder with no ``__init__.py`` that isn't named after the project."""
    assert _c006_levels({"scripts/readme-gen/readme_gen.py": FETCH}) == [
        ("INFO", QUIET_TITLE.format(n=1))
    ]
    base = release("1.0", PAIRED, sdist_files=PAIRED)
    cand = release(
        "1.1", {**PAIRED, "scripts/gen.py": FETCH, "demo/test_x.py": FETCH}, sdist_files=PAIRED
    )
    (found,) = [f for f in run_checks(CHANGE, base, cand).findings if f.rule_id == "GRN-C006"]
    assert [e.summary for e in found.evidence] == [
        _head(2, 0, 2),
        "demo/test_x.py:4 calls urllib.request.urlopen (in get()); demo-1.1.tar.gz has no such file",
        "scripts/gen.py:4 calls urllib.request.urlopen (in get()); demo-1.1.tar.gz has no such file",
        "test files and files outside the release's packages run only when run on their own, "
        "and no other module, entry point or .pth file in the wheel names these, so this is "
        "reported at info",
    ]


def test_package_modules_stay_warn() -> None:
    """ecdsa 0.14's ``ecdsa/six.py`` and reportlab 4.5.0's
    ``reportlab/lib/extformat.py``: modules of the package itself."""
    assert _c006_levels({"demo/six.py": FETCH}) == [("WARN", LOUD_TITLE.format(n=1))]
    assert _c006_levels({"demo/lib/extformat.py": FETCH}) == [("WARN", LOUD_TITLE.format(n=1))]
    # A folder with an __init__.py is a package, whatever its name.
    assert _c006_levels({"helpers/__init__.py": "", "helpers/net.py": FETCH}) == [
        ("WARN", LOUD_TITLE.format(n=1))
    ]


def test_a_test_or_script_file_something_runs_stays_warn() -> None:
    """As GRN-C003 does: a non-test module imports it, an entry point names
    it, or a .pth line in the wheel names it."""
    imported = {"demo/_client.py": "from demo import test_helpers\n", "demo/test_helpers.py": FETCH}
    assert _c006_levels(imported) == [("WARN", LOUD_TITLE.format(n=1))]
    entry = "[console_scripts]\ngen = scripts.gen:get\n"
    named = {"scripts/gen.py": FETCH, "demo-1.1.dist-info/entry_points.txt": entry}
    assert _c006_levels(named) == [("WARN", LOUD_TITLE.format(n=1))]
    pth = {"tools/boot.py": FETCH, "demo.pth": "import tools.boot\n"}
    assert ("WARN", LOUD_TITLE.format(n=2)) in _c006_levels(pth)
    assert all(level == "WARN" for level, _ in _c006_levels(pth))


def test_a_pth_file_is_never_info() -> None:
    """A .pth runs at every startup, whatever its name says."""
    assert _c006_levels({"test_boot.pth": "import os; os.system('id')\n"}) == [
        ("WARN", LOUD_TITLE.format(n=1))
    ]


def test_loud_and_quiet_files_are_two_findings() -> None:
    assert sorted(_c006_levels({"demo/_fetch.py": FETCH, "tests/test_fetch.py": FETCH})) == [
        ("INFO", QUIET_TITLE.format(n=1)),
        ("WARN", LOUD_TITLE.format(n=1)),
    ]


def test_a_trusted_version_with_nothing_to_compare_is_said() -> None:
    """Each reason the trusted version's wheel can't excuse a call is named."""
    cand = release("1.1", {**PAIRED, "demo/_client.py": APPENDED}, sdist_files=PAIRED)
    unread = replace(release("1.0"), artifacts=())
    no_sdist = release("1.0", PAIRED)
    no_wheel = release("1.0", sdist_files=PAIRED, sdist_only=True)
    not_compared = release("1.0", PAIRED, sdist_files=PAIRED, compare_sdist=False)
    notes = {
        "unread": (
            unread,
            "Garnet couldn't read 1.0's files, so it can't tell whether 1.0's wheel had this code",
        ),
        "no sdist": (
            no_sdist,
            "1.0 had no sdist, so nothing shows whether its wheel had this code",
        ),
        "no wheel": (no_wheel, "1.0 had no wheel, so this code is new to the wheel"),
        "not compared": (
            not_compared,
            "Garnet couldn't compare 1.0's wheel with its sdist, so it can't tell whether 1.0 "
            "had this code",
        ),
    }
    for label, (base, note) in notes.items():
        ((_, evidence),) = _c006(base, cand)
        assert evidence[-1] == note, label
    # A trusted version compared with nothing new to excuse adds no note.
    ((_, evidence),) = _c006(release("1.0", PAIRED, sdist_files=PAIRED), cand)
    assert len(evidence) == 2


def test_quiet_without_a_trusted_version_or_an_sdist() -> None:
    cand = release("1.1", {**PAIRED, "demo/_client.py": APPENDED}, sdist_files=PAIRED)
    assert _c006(None, cand) == []
    assert _c006(release("1.0", PAIRED), release("1.1", {**PAIRED, "demo/_fetch.py": FETCH})) == []


def test_lines_past_the_evidence_cap_are_counted() -> None:
    many = {f"demo/m{i:02}.py": FETCH for i in range(30)}
    base = release("1.0", PAIRED, sdist_files=PAIRED)
    ((title, evidence),) = _c006(base, release("1.1", {**PAIRED, **many}, sdist_files=PAIRED))
    assert title == "1.1's wheel has code that is not in its sdist (30 file(s))"
    assert len(evidence) == 27 and evidence[-1] == "and 5 more"


def _e002(base: ReleaseFacts | None, cand: ReleaseFacts) -> list[tuple[str, list[str]]]:
    result = run_checks(Change("pypi", "demo", "1.0", cand.version), base, cand)
    return [
        (f.title, [e.summary for e in f.evidence])
        for f in result.findings
        if f.rule_id == "GRN-E002"
    ]


def test_a_wheel_file_too_deep_to_walk_is_parse_failed_not_passed() -> None:
    """A payload in a function of a file both files carry, beside a table too
    deeply nested to walk: GRN-C006 can't list the calls, so GRN-E002 says so
    and the update doesn't pass."""
    base = release("1.0", PAIRED, sdist_files=PAIRED)
    cand = release("1.1", {**PAIRED, "demo/_client.py": APPENDED + DEEP}, sdist_files=PAIRED)
    assert _c006(base, cand) == []
    assert _e002(base, cand) == [
        (
            f"1 Python file(s) in {WHEEL1} are nested too deep to compare with {SDIST1}",
            [
                f"demo/_client.py: not byte for byte in {SDIST1}, and nested too deep for "
                "Garnet to list its calls (new or changed since 1.0's wheel)",
                "not evaluated: GRN-C006",
            ],
        )
    ]
    assert run_checks(Change("pypi", "demo", "1.0", "1.1"), base, cand).verdict == Verdict.WARN
    # The trusted version's files couldn't be read, or it had no wheel: said instead.
    unread = replace(release("1.0"), artifacts=())
    no_wheel = release("1.0", sdist_files=PAIRED, sdist_only=True)
    assert [ev[0].rpartition("(")[2] for _, ev in _e002(unread, cand)] == [
        "Garnet couldn't read 1.0's files, so it can't tell whether it changed)"
    ]
    assert [ev[0].rpartition("(")[2] for _, ev in _e002(no_wheel, cand)] == [
        "1.0 had no wheel to compare with)"
    ]
    # No trusted version: GRN-C006 compares nothing, so nothing is left unevaluated.
    assert _e002(None, cand) == []


def test_a_deep_wheel_file_unchanged_since_the_trusted_wheel_is_not_reported() -> None:
    """The trusted wheel installed the same bytes at the same path, so nothing
    new runs; a changed copy is reported again."""
    deep = {**PAIRED, "demo/_client.py": APPENDED + DEEP}
    base = release("1.0", deep, sdist_files=PAIRED)
    assert base.sdist_match is not None and base.sdist_match.unwalked == ("demo/_client.py",)
    assert _e002(base, release("1.1", deep, sdist_files=PAIRED)) == []
    changed = release(
        "1.1", {**PAIRED, "demo/_client.py": APPENDED + DEEP + "Y = 2\n"}, sdist_files=PAIRED
    )
    assert [title for title, _ in _e002(base, changed)] == [
        f"1 Python file(s) in {WHEEL1} are nested too deep to compare with {SDIST1}"
    ]


def test_pth_lines_hidden_by_a_form_feed_or_a_bom_are_reported() -> None:
    line = "import os; os.getcwd()"
    hidden = f"{line}\x0c;os.system('id')"
    base = release("1.0", {**PAIRED, "demo.pth": line}, sdist_files={**PAIRED, "demo.pth": line})
    cand = release(
        "1.1", {**PAIRED, "demo.pth": hidden + "\n"}, sdist_files={**PAIRED, "demo.pth": line}
    )
    ((_, evidence),) = _c006(base, cand)
    assert evidence[1] == (
        f"demo.pth has 1 executable line(s) that demo.pth in {SDIST1} doesn't: {hidden}"
    )
    lib = {**PAIRED, "demo.pth": "lib\n"}
    bom = b"\xef\xbb\xbfimport os; os.system('id')\nlib\n"
    cand = release("1.1", {**PAIRED, "demo.pth": bom}, sdist_files=lib)
    ((_, evidence),) = _c006(release("1.0", lib, sdist_files=lib), cand)
    assert evidence[1] == (
        f"demo.pth has 1 executable line(s) that demo.pth in {SDIST1} doesn't: "
        "import os; os.system('id')"
    )


# --- The fetcher: only a wheel and an sdist read to the end are compared ---


class _Http:
    def __init__(self, blobs: dict[str, bytes], missing: frozenset[str] = frozenset()) -> None:
        self.blobs = blobs
        self.missing = missing

    def get(self, url: str, **kwargs: object) -> Response:
        name = url.rsplit("/", 1)[-1]
        if name in self.missing:
            return Response(status=404, content=b"", url=url)
        if name in self.blobs:
            return Response(status=200, content=self.blobs[name], url=url)
        if url.endswith("/info/refs?service=git-upload-pack"):
            return Response(status=200, content=b"0000", url=url)
        raise AssertionError(f"unexpected request: {url}")


def _fetched(
    version: str,
    wheel_files: dict[str, str | bytes],
    sdist_files: dict[str, str | bytes],
    *,
    limits: Limits | None = None,
    missing: frozenset[str] = frozenset(),
) -> ReleaseFacts:
    """A replayed release of one pure wheel and one sdist, read by ``release_facts``."""
    blobs = {
        f"demo-{version}-py3-none-any.whl": wheel(wheel_files),
        f"demo-{version}.tar.gz": sdist(f"demo-{version}", sdist_files),
    }
    files = tuple(
        RegistryFile(
            filename=name,
            url=f"https://files.example/{name}",
            sha256=hashlib.sha256(data).hexdigest(),
            packagetype="sdist" if name.endswith(".tar.gz") else "bdist_wheel",
            uploaded_at=None,
        )
        for name, data in blobs.items()
    )
    http = cast(Http, _Http(blobs, missing))
    ctx = FetchContext(
        http=http, limits=limits or Limits(), tags=TagLookup(http), trees=TreeLookup(http)
    )
    replay = ReplayRelease(files=files, source_repo="example/demo", note="replayed")
    return release_facts("demo", version, ctx, replay=replay, advisories=False)


def test_the_fetcher_compares_the_read_wheel_with_the_read_sdist() -> None:
    base = _fetched("1.0", PAIRED, PAIRED)
    cand = _fetched("1.1", {**PAIRED, "demo/_client.py": APPENDED}, PAIRED)
    assert base.sdist_match is not None and base.sdist_match.code == ()
    assert _c006(base, cand) == [
        (
            "1.1's wheel has code that is not in its sdist (1 file(s))",
            [
                _head(1, 1, 0),
                "demo/_client.py:7 calls subprocess.run (in setup()); demo/_client.py in "
                f"{SDIST1} doesn't",
            ],
        )
    ]


def test_an_sdist_garnet_could_not_read_names_the_rule() -> None:
    """Not compared, never passed: the download or archive error says GRN-C006
    wasn't evaluated."""
    files = {**PAIRED, "demo/_client.py": APPENDED}
    gone = _fetched("1.1", files, PAIRED, missing=frozenset({SDIST1}))
    assert gone.sdist_match is None
    assert [(e.code, "GRN-C006" in e.rules) for e in gone.errors] == [("GRN-E001", True)]
    # Cut off by a §4.4 limit partway through the sdist.
    big = {**PAIRED, "docs/data.txt": "x = 1\n" * 400}
    cut = _fetched("1.1", files, big, limits=Limits(max_total_uncompressed=2000))
    assert cut.sdist_match is None
    assert [(e.code, "GRN-C006" in e.rules) for e in cut.errors] == [("GRN-E003", True)]


def test_a_wheel_file_over_the_parse_limit_names_the_rule() -> None:
    big = APPENDED + "# " + "x" * 200 + "\n"
    cand = _fetched(
        "1.1",
        {**PAIRED, "demo/_client.py": big},
        PAIRED,
        limits=Limits(max_py_file_bytes=len(APPENDED) + 20),
    )
    assert [(e.code, e.rules) for e in cand.errors] == [
        ("GRN-E003", ("GRN-C003", "GRN-C006", "GRN-C012"))
    ]
    assert cand.sdist_match is not None and cand.sdist_match.code == ()
