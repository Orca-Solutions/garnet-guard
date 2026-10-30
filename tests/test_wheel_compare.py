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
from garnet_guard.models import Change, Limits, ReleaseFacts, Severity
from garnet_guard.net import Http, Response

from .builders import wheel

START = datetime(2026, 9, 1, 12, tzinfo=UTC)
CLEAN = "def greet(name):\n    return f'hi {name}'\n"
CALLS_OUT = (
    "import subprocess\n\n\ndef greet(name):\n    subprocess.run(['true'])\n    return name\n"
)
DLL = "import ctypes\n\nctypes.WinDLL('demo.dll')\n\n\ndef greet(name):\n    return name\n"


def _file(name: str, data: bytes, hours: float = 0) -> RegistryFile:
    return RegistryFile(
        filename=name,
        url=f"https://files.example/{name}",
        sha256=hashlib.sha256(data).hexdigest(),
        packagetype="bdist_wheel",
        uploaded_at=START + timedelta(hours=hours),
    )


class _Http:
    def __init__(self, blobs: dict[str, bytes]) -> None:
        self.blobs = blobs
        self.fetched: list[str] = []

    def get(self, url: str, **kwargs: object) -> Response:
        name = url.rsplit("/", 1)[-1]
        if name in self.blobs:
            self.fetched.append(name)
            return Response(status=200, content=self.blobs[name], url=url)
        if url.endswith("/info/refs?service=git-upload-pack"):
            return Response(status=200, content=b"0000", url=url)
        raise AssertionError(f"unexpected request: {url}")


def _release(
    version: str,
    wheels: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    *,
    served: dict[str, bytes] | None = None,
) -> tuple[ReleaseFacts, list[str]]:
    """A replayed release of ``wheels`` (filename → demo/__init__.py), read as
    if this machine installs the pure wheel."""
    blobs = {name: wheel({"demo/__init__.py": text}) for name, text in wheels.items()}
    files = tuple(_file(name, data) for name, data in blobs.items())
    pure = next(n for n in wheels if n.endswith("-none-any.whl"))
    monkeypatch.setattr(pypi, "select_wheel", lambda names: pure)
    http = _Http({**blobs, **(served or {})})
    ctx = FetchContext(
        http=cast(Http, http), limits=Limits(), tags=TagLookup(http), trees=TreeLookup(http)
    )
    replay = ReplayRelease(files=files, source_repo="example/demo", note="replayed")
    return release_facts("demo", version, ctx, replay=replay, advisories=False), http.fetched


def _c012(base: ReleaseFacts, cand: ReleaseFacts, severity: Severity = Severity.WARN) -> list[str]:
    result = run_checks(Change("pypi", "demo", base.version, cand.version), base, cand)
    found = [f for f in result.findings if f.rule_id == "GRN-C012"]
    assert all(f.severity == severity for f in found)
    return [e.summary for f in found for e in f.evidence]


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


def test_a_read_copy_that_does_not_parse_is_not_called_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Old releases ship Python 2 code in their cp27 wheels; that copy says
    nothing about which calls the file makes. Listed at info, not warned:
    nothing shows the other wheel differs (PyYAML 5.3.1 and 5.4)."""
    py2 = "def greet(name):\n    print 'hi', name\n"
    pure0, win0 = _names("1.0")
    pure1, win1 = _names("1.1")
    base, _ = _release("1.0", {pure0: py2, win0: CLEAN}, monkeypatch)
    cand, _ = _release("1.1", {pure1: py2, win1: CALLS_OUT}, monkeypatch)
    assert _c012(base, cand, Severity.INFO) == [
        f"{win1}: demo/__init__.py:5 calls subprocess.run (in greet()); "
        f"the same file in {pure1} couldn't be parsed to compare"
    ]


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


def test_late_wheels_past_the_cap_are_noted() -> None:
    data = b"x"
    late = tuple(
        _file(f"demo-1.0-cp3{i}-cp3{i}-manylinux_2_17_aarch64.whl", data, hours=48)
        for i in range(10, 22)
    )
    files = (_file("demo-1.0-py3-none-any.whl", data), *late)
    chosen, left = wheels_to_compare(files, "demo-1.0-py3-none-any.whl")
    # ten late ones, and the newest stands for Linux too, so one is left out
    assert len(chosen) == 11 and len(left) == 1


def test_wheel_families() -> None:
    assert wheel_family("demo-1.0-py3-none-any.whl") == "any"
    assert wheel_family("demo-1.0-cp313-cp313-win_arm64.whl") == "Windows"
    assert wheel_family("demo-1.0-cp313-cp313-macosx_10_13_universal2.whl") == "macOS"
    assert wheel_family("demo-1.0-cp313-cp313-musllinux_1_2_x86_64.whl") == "Linux"
    assert wheel_family("demo-1.0-cp313-cp313-android_24_arm64_v8a.whl") == "android"
