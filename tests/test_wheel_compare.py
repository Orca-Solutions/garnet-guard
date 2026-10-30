"""GRN-C012: a release's other wheels compared with the one Garnet read.

The wheels here are built in memory; nothing is fetched or run.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from garnet_guard.ecosystems import pypi
from garnet_guard.ecosystems.github import TagLookup
from garnet_guard.ecosystems.gittree import TreeLookup
from garnet_guard.ecosystems.pypi import (
    FetchContext,
    RegistryFile,
    ReplayRelease,
    release_facts,
    wheel_family,
    wheels_to_compare,
)
from garnet_guard.engine import run_checks
from garnet_guard.facts.inventory import wheel_own
from garnet_guard.models import (
    Change,
    ChangeResult,
    Limits,
    ReleaseFacts,
    Severity,
    UnparsedWheelFile,
    Verdict,
)
from garnet_guard.net import Http, NetError, Response

from .builders import wheel

START = datetime(2026, 9, 1, 12, tzinfo=UTC)
CLEAN = "def greet(name):\n    return f'hi {name}'\n"
CALLS_OUT = (
    "import subprocess\n\n\ndef greet(name):\n    subprocess.run(['true'])\n    return name\n"
)
DLL = "import ctypes\n\nctypes.WinDLL('demo.dll')\n\n\ndef greet(name):\n    return name\n"
LOAD = "import ctypes\n\n\ndef load():\n    return ctypes.CDLL('demo.dll')\n"
FORMAT = "import ctypes\n\n\ndef error():\n    return ctypes.FormatError()\n"
PY2 = "def greet(name):\n    print 'hi', name\n"


def _file(name: str, data: bytes, hours: float = 0) -> RegistryFile:
    return RegistryFile(
        filename=name,
        url=f"https://files.example/{name}",
        sha256=hashlib.sha256(data).hexdigest(),
        packagetype="bdist_wheel",
        uploaded_at=START + timedelta(hours=hours),
    )


class _Http:
    def __init__(self, blobs: dict[str, bytes], missing: frozenset[str] = frozenset()) -> None:
        self.blobs = blobs
        self.missing = missing
        self.fetched: list[str] = []

    def get(self, url: str, **kwargs: object) -> Response:
        name = url.rsplit("/", 1)[-1]
        if name in self.missing:
            return Response(status=404, content=b"", url=url)
        if name in self.blobs:
            self.fetched.append(name)
            return Response(status=200, content=self.blobs[name], url=url)
        if url.endswith("/info/refs?service=git-upload-pack"):
            return Response(status=200, content=b"0000", url=url)
        raise AssertionError(f"unexpected request: {url}")


def _release(
    version: str,
    wheels: dict[str, str | dict[str, str] | bytes],
    monkeypatch: pytest.MonkeyPatch,
    *,
    served: dict[str, bytes] | None = None,
    read: str | None = None,
    limits: Limits | None = None,
    late: tuple[str, ...] = (),
    missing: frozenset[str] = frozenset(),
) -> tuple[ReleaseFacts, list[str]]:
    """A replayed release of ``wheels`` (filename → demo/__init__.py, or
    filename → files, or the wheel's bytes), read as if this machine installs
    ``read``, by default the pure wheel. ``late`` wheels are uploaded two days
    after the rest."""
    blobs = {
        name: body
        if isinstance(body, bytes)
        else wheel(body if isinstance(body, dict) else {"demo/__init__.py": body})
        for name, body in wheels.items()
    }
    files = tuple(_file(name, data, 48 if name in late else 0) for name, data in blobs.items())
    chosen = read or next(n for n in wheels if n.endswith("-none-any.whl"))
    monkeypatch.setattr(pypi, "select_wheel", lambda names: chosen)
    http = _Http({**blobs, **(served or {})}, missing)
    ctx = FetchContext(
        http=cast(Http, http),
        limits=limits or Limits(),
        tags=TagLookup(http),
        trees=TreeLookup(http),
    )
    replay = ReplayRelease(files=files, source_repo="example/demo", note="replayed")
    return release_facts("demo", version, ctx, replay=replay, advisories=False), http.fetched


class _Down:
    """A registry that times out on every request."""

    def get(self, url: str, **kwargs: object) -> Response:
        raise NetError("timed out")


def _unreachable(version: str) -> ReleaseFacts:
    """A release whose registry lookup failed, so Garnet never saw its files."""
    http = cast(Http, _Down())
    ctx = FetchContext(http=http, limits=Limits(), tags=TagLookup(http), trees=TreeLookup(http))
    return release_facts("demo", version, ctx, advisories=False)


def _result(base: ReleaseFacts, cand: ReleaseFacts) -> ChangeResult:
    return run_checks(Change("pypi", "demo", base.version, cand.version), base, cand)


def _c012(base: ReleaseFacts, cand: ReleaseFacts, severity: Severity = Severity.WARN) -> list[str]:
    found = [f for f in _result(base, cand).findings if f.rule_id == "GRN-C012"]
    assert all(f.severity == severity for f in found)
    return [e.summary for f in found for e in f.evidence]


def _errors(rel: ReleaseFacts) -> list[tuple[str, str, tuple[str, ...]]]:
    return [(e.code, e.summary, e.rules) for e in rel.errors]


def _reported(base: ReleaseFacts, cand: ReleaseFacts, rule: str) -> list[tuple[str, list[str]]]:
    """Each ``rule`` finding about the new version: its title and evidence lines."""
    found = [f for f in _result(base, cand).findings if f.rule_id == rule and f.release is None]
    return [(f.title, [e.summary for e in f.evidence]) for f in found]


def _names(version: str) -> tuple[str, str]:
    return (f"demo-{version}-py3-none-any.whl", f"demo-{version}-cp313-cp313-win_amd64.whl")


def test_a_payload_only_in_the_windows_wheel_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    pure0, win0 = _names("1.0")
    pure1, win1 = _names("1.1")
    base, _ = _release("1.0", {pure0: CLEAN, win0: CLEAN}, monkeypatch)
    cand, fetched = _release("1.1", {pure1: CLEAN, win1: CALLS_OUT}, monkeypatch)
    assert fetched == [pure1, win1]
    assert cand.wheels_compared == ((win1, "Windows"),)
    assert _c012(base, cand) == [
        f"{win1}: demo/__init__.py:5 calls subprocess.run (in greet()); "
        f"the same file in {pure1} doesn't"
    ]


def test_identical_and_harmless_differences_stay_quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    pure0, win0 = _names("1.0")
    pure1, win1 = _names("1.1")
    base, _ = _release("1.0", {pure0: CLEAN, win0: CLEAN}, monkeypatch)
    same, _ = _release("1.1", {pure1: CLEAN, win1: CLEAN}, monkeypatch)
    assert same.wheel_differences == () and _c012(base, same) == []
    other, _ = _release("1.1", {pure1: CLEAN, win1: CLEAN + "\nVERSION = 2\n"}, monkeypatch)
    assert other.wheel_differences == () and _c012(base, other) == []


def test_a_difference_the_trusted_version_had_is_not_new(monkeypatch: pytest.MonkeyPatch) -> None:
    """delvewheel adds DLL loading to Windows wheels, release after release."""
    pure0, win0 = _names("1.0")
    pure1, win1 = _names("1.1")
    base, _ = _release("1.0", {pure0: CLEAN, win0: DLL}, monkeypatch)
    cand, _ = _release("1.1", {pure1: CLEAN, win1: DLL + "\n# 1.1\n"}, monkeypatch)
    assert [d.family for d in cand.wheel_differences] == ["Windows"]
    assert _c012(base, cand) == []


def test_a_platform_the_trusted_version_lacked_is_said(monkeypatch: pytest.MonkeyPatch) -> None:
    pure0, _ = _names("1.0")
    pure1, win1 = _names("1.1")
    base, _ = _release("1.0", {pure0: CLEAN}, monkeypatch)
    cand, _ = _release("1.1", {pure1: CLEAN, win1: DLL}, monkeypatch)
    (text,) = _c012(base, cand)
    assert text.endswith("(1.0 had no Windows wheel to compare with)")


def test_a_trusted_version_garnet_could_not_fetch_is_not_said_to_lack_the_wheel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The registry lookup for 1.0 timed out, so Garnet never saw its files:
    the evidence says Garnet couldn't read them, not that 1.0 had no Windows
    wheel. (Both lines said "1.0 had no Windows wheel to compare with".)"""
    pure1, win1 = _names("1.1")
    base = _unreachable("1.0")
    assert base.artifacts == () and [e.summary for e in base.errors] == ["timed out"]
    files = {"demo/__init__.py": CALLS_OUT, "demo/legacy.py": PY2}
    cand, _ = _release("1.1", {pure1: CLEAN, win1: files}, monkeypatch)
    assert _c012(base, cand) == [
        f"{win1}: demo/__init__.py:5 calls subprocess.run (in greet()); the same file in "
        f"{pure1} doesn't (Garnet couldn't read 1.0's files to compare with)"
    ]
    assert _reported(base, cand, "GRN-E002") == [
        (
            f"1 Python file(s) in {win1} couldn't be parsed to compare with {pure1}",
            [
                "demo/legacy.py: Garnet couldn't read 1.0's files, so it can't tell whether "
                "this copy changed",
                "not evaluated: GRN-C012",
            ],
        )
    ]
    assert _result(base, cand).verdict == Verdict.WARN


def test_a_read_copy_that_does_not_parse_is_not_called_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Old releases ship Python 2 code in their cp27 wheels; that copy says
    nothing about which calls the file makes. The trusted version's Windows
    wheel does: it didn't make the call, so the call is new for Windows.
    (This was listed at info, and the update passed: the read copy was
    unchanged, so GRN-E002 didn't warn either.)"""
    pure0, win0 = _names("1.0")
    pure1, win1 = _names("1.1")
    base, _ = _release("1.0", {pure0: PY2, win0: CLEAN}, monkeypatch)
    cand, _ = _release("1.1", {pure1: PY2, win1: CALLS_OUT}, monkeypatch)
    assert _c012(base, cand) == [
        f"{win1}: demo/__init__.py:5 calls subprocess.run (in greet()); "
        f"the same file in {pure1} couldn't be parsed to compare, "
        "and 1.0's Windows wheel didn't make this call there"
    ]
    assert _result(base, cand).verdict == Verdict.WARN
    already, _ = _release("1.0", {pure0: PY2, win0: CALLS_OUT}, monkeypatch)
    assert _c012(already, cand) == []


def test_an_unparsed_read_copy_with_nothing_to_compare_warns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No trusted Windows wheel, and the read copy is the same Python 2 file
    as before, so GRN-E002 says nothing: GRN-C012 warns itself."""
    pure0, _ = _names("1.0")
    pure1, win1 = _names("1.1")
    base, _ = _release("1.0", {pure0: PY2}, monkeypatch)
    cand, _ = _release("1.1", {pure1: PY2, win1: CALLS_OUT}, monkeypatch)
    (text,) = _c012(base, cand)
    assert text.endswith("couldn't be parsed to compare (1.0 had no Windows wheel to compare with)")
    assert "GRN-E002" not in {f.rule_id for f in _result(base, cand).findings}


def test_an_unparsed_read_copy_is_info_when_e002_warns_for_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The read copy changed, so GRN-E002 warns for it; with no trusted
    Windows wheel to compare with, the call is listed at info beside it."""
    pure0, _ = _names("1.0")
    pure1, win1 = _names("1.1")
    base, _ = _release("1.0", {pure0: PY2}, monkeypatch)
    cand, _ = _release("1.1", {pure1: PY2 + "# 1.1\n", win1: CALLS_OUT}, monkeypatch)
    lines = _c012(base, cand, Severity.INFO)
    assert lines[-1] == (
        f"the copies in {pure1} are new or changed and couldn't be parsed, which GRN-E002 "
        "reports, so this is reported at info"
    )
    result = _result(base, cand)
    assert "GRN-E002" in {f.rule_id for f in result.findings}
    assert result.verdict == Verdict.WARN


@pytest.mark.parametrize(
    "unparsable",
    [
        "\nprint 'x'\n",  # Python 2, or syntax newer than the Python Garnet runs on
        "\nTABLE = " + " + ".join(["1"] * 1500) + "\n",  # compiles, too deep to walk
    ],
    ids=["syntax", "depth"],
)
def test_a_differing_copy_garnet_cannot_parse_is_parse_failed(
    unparsable: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    pure0, win0 = _names("1.0")
    pure1, win1 = _names("1.1")
    base, _ = _release("1.0", {pure0: CLEAN, win0: CLEAN}, monkeypatch)
    cand, _ = _release("1.1", {pure1: CLEAN, win1: CALLS_OUT + unparsable}, monkeypatch)
    assert cand.wheel_differences == () and _errors(cand) == []
    (copy,) = cand.wheel_unparsed
    assert (copy.wheel, copy.family, copy.path) == (win1, "Windows", "demo/__init__.py")
    assert _reported(base, cand, "GRN-E002") == [
        (
            f"1 Python file(s) in {win1} couldn't be parsed to compare with {pure1}",
            [
                "demo/__init__.py: new or changed since 1.0's Windows wheel",
                "not evaluated: GRN-C012",
            ],
        )
    ]
    assert _result(base, cand).verdict == Verdict.WARN


def test_an_unparsable_copy_unchanged_since_the_trusted_wheel_is_not_reported_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Windows copy with syntax newer than the Python Garnet runs on, the
    same bytes in both versions: the trusted Windows wheel made whatever
    calls it makes. (Both versions' copies were GRN-E002, on every update.)"""
    pure0, win0 = _names("1.0")
    pure1, win1 = _names("1.1")
    newer = CALLS_OUT + "\nprint 'x'\n"
    base, _ = _release("1.0", {pure0: CLEAN, win0: newer}, monkeypatch)
    cand, _ = _release("1.1", {pure1: CLEAN, win1: newer}, monkeypatch)
    assert len(base.wheel_unparsed) == 1 and len(cand.wheel_unparsed) == 1
    result = _result(base, cand)
    assert result.findings == () and result.verdict == Verdict.PASS
    # Changed, or new at that path: reported, against the trusted Windows wheel.
    changed, _ = _release("1.1", {pure1: CLEAN, win1: newer + "# 1.1\n"}, monkeypatch)
    ((_, lines),) = _reported(base, changed, "GRN-E002")
    assert lines[0] == "demo/__init__.py: new or changed since 1.0's Windows wheel"
    # The same bytes in a trusted wheel of another family don't count.
    mac0 = "demo-1.0-cp313-cp313-macosx_11_0_arm64.whl"
    elsewhere, _ = _release("1.0", {pure0: CLEAN, mac0: newer}, monkeypatch)
    ((_, lines),) = _reported(elsewhere, cand, "GRN-E002")
    assert lines[0] == "demo/__init__.py: 1.0 had no Windows wheel to compare with"


def test_an_unparsable_copy_garnet_has_no_trusted_copy_of_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """1.0's Windows wheel was there, but Garnet couldn't read 1.0's wheel
    to compare with, so it read none of the others either."""
    pure0, win0 = _names("1.0")
    pure1, win1 = _names("1.1")
    newer = CALLS_OUT + "\nprint 'x'\n"
    broken = b"PK\x03\x04" + b"\x00" * 60
    base, _ = _release("1.0", {pure0: broken, win0: newer}, monkeypatch)
    assert base.wheels_compared == () and base.read_wheel_family is None
    cand, _ = _release("1.1", {pure1: CLEAN, win1: newer}, monkeypatch)
    ((_, lines),) = _reported(base, cand, "GRN-E002")
    assert lines == [
        "demo/__init__.py: Garnet didn't read 1.0's Windows wheel, so it can't tell whether "
        "this copy changed",
        "not evaluated: GRN-C012",
    ]
    # A new dependency has no trusted version: every such copy is reported.
    new = run_checks(Change("pypi", "demo", None, "1.1"), None, cand)
    (found,) = [f for f in new.findings if f.rule_id == "GRN-E002"]
    assert found.evidence[0].summary == "demo/__init__.py: no trusted version to compare with"


def test_unparsable_copies_past_the_evidence_cap_are_counted() -> None:
    win = "demo-1.1-cp313-cp313-win_amd64.whl"
    files = tuple(
        UnparsedWheelFile(win, "Windows", f"demo/m{i:02}.py", f"{i:064}") for i in range(30)
    )
    base = ReleaseFacts("pypi", "demo", "1.0", False, (), wheel_families=("Windows",))
    cand = ReleaseFacts("pypi", "demo", "1.1", False, (), wheel_unparsed=files)
    ((title, lines),) = _reported(base, cand, "GRN-E002")
    assert title == (
        f"30 Python file(s) in {win} couldn't be parsed to compare with the wheel Garnet read"
    )
    assert len(lines) == 27 and lines[-2:] == ["and 5 more", "not evaluated: GRN-C012"]


def test_files_over_the_parse_limit_are_budget_exceeded(monkeypatch: pytest.MonkeyPatch) -> None:
    """SPEC §4.4: no file over the single-file limit is parsed, in any wheel."""
    pure0, win0 = _names("1.0")
    pure1, win1 = _names("1.1")
    small = Limits(max_py_file_bytes=len(CLEAN) + 1)
    base, _ = _release("1.0", {pure0: CLEAN, win0: CLEAN}, monkeypatch, limits=small)
    cand, _ = _release("1.1", {pure1: CLEAN, win1: CALLS_OUT}, monkeypatch, limits=small)
    assert cand.wheel_differences == ()
    assert _errors(cand) == [
        ("GRN-E003", f"{win1}: demo/__init__.py is larger than the parse limit", ("GRN-C012",))
    ]
    big = CLEAN + "# " + "x" * 80 + "\n"
    read_big, _ = _release("1.1", {pure1: big, win1: CALLS_OUT}, monkeypatch, limits=small)
    assert _errors(read_big) == [
        (
            "GRN-E003",
            f"{pure1}: demo/__init__.py is larger than the parse limit",
            ("GRN-C003", "GRN-C012"),
        ),
        ("GRN-E003", f"{win1}: demo/__init__.py is larger than the parse limit", ("GRN-C012",)),
    ]


def test_the_trusted_versions_read_wheel_counts_for_its_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """1.0 shipped only a Windows wheel, so Garnet read it; 1.1 adds a pure
    wheel, read instead. 1.0's Windows wheel made the call already."""
    pure1, win1 = _names("1.1")
    _, win0 = _names("1.0")
    base, _ = _release("1.0", {win0: DLL}, monkeypatch, read=win0)
    assert base.read_wheel_family == "Windows" and base.wheels_compared == ()
    cand, _ = _release("1.1", {pure1: CLEAN, win1: DLL}, monkeypatch)
    assert _c012(base, cand) == []
    more, _ = _release("1.1", {pure1: CLEAN, win1: DLL + CALLS_OUT}, monkeypatch)
    (text,) = _c012(base, more)
    assert "calls subprocess.run" in text


def test_a_call_any_trusted_wheel_of_the_family_made_is_not_new(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pure0, win0 = _names("1.0")
    pure1, win1 = _names("1.1")
    # 1.0's Windows copy was the same file as the one read, so it isn't a
    # difference of 1.0; 1.1 drops the call from the pure wheel only.
    base, _ = _release("1.0", {pure0: LOAD, win0: LOAD}, monkeypatch)
    cand, _ = _release("1.1", {pure1: CLEAN, win1: LOAD}, monkeypatch)
    assert [d.family for d in cand.wheel_differences] == ["Windows"]
    assert _c012(base, cand) == []
    # Two trusted Windows wheels, each with its own call at the same path.
    w32 = {v: f"demo-{v}-cp313-cp313-win32.whl" for v in ("1.0", "1.1")}
    base, _ = _release(
        "1.0", {pure0: CLEAN, win0: DLL, w32["1.0"]: FORMAT}, monkeypatch, late=(w32["1.0"],)
    )
    cand, _ = _release(
        "1.1", {pure1: CLEAN, win1: DLL, w32["1.1"]: FORMAT}, monkeypatch, late=(w32["1.1"],)
    )
    assert len(cand.wheel_differences) == 2
    assert _c012(base, cand) == []


# Inert: each call sits in a function nothing calls.
EXEC = "def later(text):\n    exec(text)\n"
POST = "import requests\n\n\ndef later():\n    requests.post('https://example.invalid')\n"


@pytest.mark.parametrize("both", [False, True], ids=["windows-only", "both-wheels"])
@pytest.mark.parametrize(
    ("shadow", "body", "call"),
    [
        ("subprocess.py", CALLS_OUT, "5 calls subprocess.run (in greet())"),
        ("exec.py", EXEC, "2 calls exec (in later())"),
        ("requests.py", POST, "5 calls requests.post (in later())"),
        ("requests/__init__.py", POST, "5 calls requests.post (in later())"),
    ],
    ids=["stdlib", "builtin", "listed-module", "listed-package"],
)
def test_a_top_level_module_named_like_a_listed_call_hides_nothing(
    shadow: str, body: str, call: str, both: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty ``subprocess.py`` in site-packages never shadows the standard
    library's, a module file never stands in for the builtin ``exec``, and
    ``requests.post`` is listed whoever answers it: none of these makes the
    call the package's own. (An ``exec.py`` or ``requests.py`` in both wheels
    hid the call, and the update passed.)"""
    pure0, win0 = _names("1.0")
    pure1, win1 = _names("1.1")
    base, _ = _release("1.0", {pure0: CLEAN, win0: CLEAN}, monkeypatch)
    extra = {shadow: ""}
    cand, _ = _release(
        "1.1",
        {
            pure1: {"demo/__init__.py": CLEAN, **(extra if both else {})},
            win1: {"demo/__init__.py": body, **extra},
        },
        monkeypatch,
    )
    assert _c012(base, cand) == [
        f"{win1}: demo/__init__.py:{call}; the same file in {pure1} doesn't"
    ]


def test_the_own_packages_leave_out_every_name_the_call_set_needs() -> None:
    paths = [
        "exec.py",
        "eval.py",
        "compile.py",
        "__import__.py",
        "subprocess.py",
        "httpx.py",
        "requests/__init__.py",
        "aiohttp/__init__.py",
        "demo/__init__.py",
        "demo/util.py",
        "demo_extra.py",
    ]
    assert wheel_own(paths) == {"demo", "demo_extra"}


def test_a_read_wheel_garnet_could_not_read_whole_is_not_compared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Its file list says nothing about what it lacks: no "has no such file"."""
    pure0, win0 = _names("1.0")
    pure1, win1 = _names("1.1")
    base, _ = _release("1.0", {pure0: CLEAN, win0: CLEAN}, monkeypatch)
    broken = b"PK\x03\x04" + b"\x00" * 60  # a zip header and nothing after it
    cand, fetched = _release("1.1", {pure1: broken, win1: DLL}, monkeypatch)
    assert fetched == [pure1]
    assert cand.wheel_calls == () and cand.read_wheel_family is None
    ((code, _, rules),) = _errors(cand)
    assert code == "GRN-E002" and "GRN-C012" in rules
    assert _c012(base, cand) == []
    # Cut off by a §4.4 limit partway: the same.
    data = "x = 1\n" * 400
    tight = Limits(max_total_uncompressed=1000)
    read = {"demo-1.1.dist-info/RECORD": data, "demo/__init__.py": DLL}
    cut, fetched = _release("1.1", {pure1: read, win1: DLL + "# 1.1\n"}, monkeypatch, limits=tight)
    assert fetched == [pure1]
    ((code, _, rules),) = _errors(cut)
    assert code == "GRN-E003" and "GRN-C012" in rules


def test_a_read_wheel_that_cannot_be_downloaded_names_the_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pure1, win1 = _names("1.1")
    cand, _ = _release(
        "1.1", {pure1: CLEAN, win1: CALLS_OUT}, monkeypatch, missing=frozenset({pure1})
    )
    ((code, summary, rules),) = _errors(cand)
    assert (code, summary) == ("GRN-E001", f"download {pure1}: HTTP 404")
    assert "GRN-C012" in rules


def test_lines_past_the_evidence_cap_are_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    pure0, win0 = _names("1.0")
    pure1, win1 = _names("1.1")
    mac0, mac1 = (f"demo-{v}-cp313-cp313-macosx_11_0_arm64.whl" for v in ("1.0", "1.1"))
    many = "import subprocess\n\n\ndef greet():\n" + "".join(
        f"    subprocess.run(['{i}'])\n" for i in range(30)
    )
    base, _ = _release("1.0", {pure0: CLEAN, win0: CLEAN, mac0: CLEAN}, monkeypatch)
    cand, _ = _release("1.1", {pure1: CLEAN, win1: CALLS_OUT, mac1: many}, monkeypatch)
    lines = _c012(base, cand)
    assert len(lines) == 26
    assert lines[-1] == f"and 6 more call site(s), in {mac1}, {win1}"


def test_a_trusted_wheel_of_the_family_counts_even_if_it_was_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pure0, win0 = _names("1.0")
    pure1, win1 = _names("1.1")
    base, _ = _release("1.0", {pure0: CLEAN, win0: CLEAN}, monkeypatch)
    base = replace(base, wheels_compared=())  # as if 1.0's Windows wheel was the one read
    cand, _ = _release("1.1", {pure1: CLEAN, win1: CALLS_OUT}, monkeypatch)
    (text,) = _c012(base, cand)
    assert "had no Windows wheel" not in text


def test_a_wheel_that_fails_its_hash_is_hash_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    pure1, win1 = _names("1.1")
    swapped = wheel({"demo/__init__.py": CALLS_OUT})
    cand, _ = _release("1.1", {pure1: CLEAN, win1: CLEAN}, monkeypatch, served={win1: swapped})
    assert cand.wheel_differences == () and cand.wheels_compared == ()
    base, _ = _release("1.0", dict(zip(_names("1.0"), (CLEAN, CLEAN), strict=True)), monkeypatch)
    result = run_checks(Change("pypi", "demo", "1.0", "1.1"), base, cand)
    assert "GRN-T008" in {f.rule_id for f in result.findings}


def test_one_wheel_per_family_and_every_late_one() -> None:
    data = b"x"
    files = (
        _file("demo-1.0-cp312-cp312-manylinux_2_17_x86_64.whl", data),
        _file("demo-1.0-cp313-cp313-manylinux_2_17_aarch64.whl", data),
        _file("demo-1.0-cp313-cp313-manylinux_2_17_x86_64.whl", data),
        _file("demo-1.0-cp312-cp312-win_amd64.whl", data),
        _file("demo-1.0-cp313-cp313-win32.whl", data),
        _file("demo-1.0-cp313-cp313-win_amd64.whl", data),
        _file("demo-1.0-cp313-cp313-macosx_11_0_arm64.whl", data),
        _file("demo-1.0-cp312-cp312-musllinux_1_2_x86_64.whl", data, hours=30),
        _file("demo-1.0.tar.gz", data),
    )
    chosen, left = wheels_to_compare(files, "demo-1.0-cp313-cp313-manylinux_2_17_x86_64.whl")
    assert [f.filename for f in chosen] == [
        "demo-1.0-cp312-cp312-musllinux_1_2_x86_64.whl",  # late, though Linux like the read one
        "demo-1.0-cp313-cp313-macosx_11_0_arm64.whl",
        "demo-1.0-cp313-cp313-win_amd64.whl",  # the newest CPython, then x86-64
    ]
    assert left == []


def test_late_wheels_past_the_cap_are_budget_exceeded() -> None:
    """The uploader decides how many late wheels there are, so the ones left
    out are a check Garnet couldn't run: GRN-E003, never a pass. (They were
    a note, and the update passed.)"""
    data = b"x"
    late = tuple(
        _file(f"demo-1.1-cp3{i}-cp3{i}-manylinux_2_17_aarch64.whl", data, hours=48)
        for i in range(10, 23)
    )
    files = (_file("demo-1.1-py3-none-any.whl", data), *late)
    chosen, left = wheels_to_compare(files, "demo-1.1-py3-none-any.whl")
    # ten late ones, and the newest stands for Linux too, so two are left out
    assert len(chosen) == 11 and len(left) == 2
    base = ReleaseFacts("pypi", "demo", "1.0", False, ())
    cand = ReleaseFacts("pypi", "demo", "1.1", False, (), wheels_not_compared=tuple(left))
    result = _result(base, cand)
    assert result.verdict == Verdict.WARN and result.notes == ()
    assert _reported(base, cand, "GRN-E003") == [
        (
            "Couldn't fully check 1.1: 2 late wheel(s) weren't compared with the wheel Garnet "
            "read; GRN-C012 compares up to 10",
            [*sorted(left), "not evaluated: GRN-C012"],
        )
    ]
    many = tuple(f"demo-1.1-cp3{i}-cp3{i}-win32.whl" for i in range(40, 10, -1))
    lines = _reported(base, replace(cand, wheels_not_compared=many), "GRN-E003")[0][1]
    assert lines[:2] == ["demo-1.1-cp311-cp311-win32.whl", "demo-1.1-cp312-cp312-win32.whl"]
    assert len(lines) == 27 and lines[-2:] == ["and 5 more", "not evaluated: GRN-C012"]
    # A new dependency gets it too: the absolute rules run without a baseline.
    new = run_checks(Change("pypi", "demo", None, "1.1"), None, cand)
    assert [f.rule_id for f in new.findings] == ["GRN-E003"]


def test_late_wheels_past_the_cap_say_why_and_what_to_do() -> None:
    """Every finding carries its rule's explain text. The cap on late wheels
    isn't a limit policy sets, and policy only lowers limits, so the reader
    can't be told to raise one. (It gave archive bombs as the reason, and
    said to "raise the limit only if you trust the source".)"""
    base = ReleaseFacts("pypi", "demo", "1.0", False, ())
    late = ("demo-1.1-cp314-cp314-win32.whl",)
    cand = ReleaseFacts("pypi", "demo", "1.1", False, (), wheels_not_compared=late)
    (found,) = [f for f in _result(base, cand).findings if f.rule_id == "GRN-E003"]
    assert "late wheel past the 10 GRN-C012 compares" in found.explanation
    assert "For late wheels, compare each one's Python files with the wheel Garnet read" in (
        found.remediation
    )
    assert "raise" not in found.remediation


def test_an_odd_python_tag_ranks_last_without_stopping_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The uploader names the file: ``py3x`` parses as a wheel tag."""
    data = b"x"
    odd, good = "demo-1.0-py3x-none-win_amd64.whl", "demo-1.0-cp313-cp313-win_amd64.whl"
    files = (_file("demo-1.0-py3-none-any.whl", data), _file(odd, data), _file(good, data))
    chosen, _ = wheels_to_compare(files, "demo-1.0-py3-none-any.whl")
    assert [f.filename for f in chosen] == [good]
    pure1, _ = _names("1.1")
    cand, _ = _release(
        "1.1", {pure1: CLEAN, "demo-1.1-cp3k-none-macosx_11_0_arm64.whl": CLEAN}, monkeypatch
    )
    assert cand.wheels_compared == (("demo-1.1-cp3k-none-macosx_11_0_arm64.whl", "macOS"),)


def test_wheel_families() -> None:
    assert wheel_family("demo-1.0-py3-none-any.whl") == "any"
    assert wheel_family("demo-1.0-cp313-cp313-win_arm64.whl") == "Windows"
    assert wheel_family("demo-1.0-cp313-cp313-macosx_10_13_universal2.whl") == "macOS"
    assert wheel_family("demo-1.0-cp313-cp313-musllinux_1_2_x86_64.whl") == "Linux"
    assert wheel_family("demo-1.0-cp313-cp313-android_24_arm64_v8a.whl") == "android"
