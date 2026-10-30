"""GRN-C004 new-binary and native-code detection. Synthetic headers only; no network."""

from __future__ import annotations

from dataclasses import replace

from garnet_guard.checks.content import _install_key, _named_as
from garnet_guard.engine import run_checks
from garnet_guard.facts.inventory import native_format, unchecked_pyc
from garnet_guard.models import Change, Finding, ReleaseFacts, Severity
from tests.builders import release

CHANGE = Change("pypi", "demo", "1.0", "1.1")
PKG = {"demo/__init__.py": ""}
ELF = b"\x7fELF" + b"\0" * 60
PE = b"MZ" + b"\0" * 58 + (64).to_bytes(4, "little") + b"PE\0\0" + b"\0" * 16
EXT = "demo/_speed.cpython-313-x86_64-linux-gnu.so"
# A .pyc header: magic, flags, then a source hash (flags 1, 3) or mtime and size (flags 0).
UNCHECKED = b"\xcb\r\r\n" + (1).to_bytes(4, "little") + b"\0" * 8
CHECKED = b"\xcb\r\r\n" + (3).to_bytes(4, "little") + b"\0" * 8


def _c004(base: ReleaseFacts, cand: ReleaseFacts) -> list[Finding]:
    return [f for f in run_checks(CHANGE, base, cand).findings if f.rule_id == "GRN-C004"]


def test_native_format() -> None:
    assert native_format(ELF) == "ELF"
    assert native_format(PE) == "PE"
    assert native_format(b"\xcf\xfa\xed\xfe" + b"\0" * 8) == "Mach-O"
    assert native_format(b"\xca\xfe\xba\xbe\0\0\0\x02") == "Mach-O"  # universal, 2 slices
    assert native_format(b"\xca\xfe\xba\xbf\0\0\0\x02") == "Mach-O"  # universal, 64-bit
    assert native_format(b"\xfe\xed\xfa\xcf" + b"\0" * 8) == "Mach-O"  # big-endian
    assert native_format(b"\xca\xfe\xba\xbe\0\0\0\x41") is None  # a Java class file
    assert native_format(b"MZ_LIMIT = 3\n" + b"#" * 80) is None  # Python that starts with MZ
    assert native_format(b"import os\n") is None


def test_names() -> None:
    assert _named_as("libssl.so.3") == "native"
    assert _named_as("libfoo.so.debug") == "native"
    assert _named_as("vcruntime140.dll") == "native"
    assert _named_as("ruff") == ""
    assert _named_as("python3.12") == ""
    assert _named_as("_build.py") == "python"
    assert _named_as("helper.png") == "other"
    assert _install_key("ruff-0.16.2.data/scripts/ruff") == ".data/scripts/ruff"
    assert _install_key("demo-1.0.data/platlib/demo/x.so") == "demo/x.so"
    assert _install_key("Pillow.libs/libz.so.1") == "pillow.libs/libz.so.1"
    assert _install_key("scikit-learn.libs/libgomp.so.1") == "scikit_learn.libs/libgomp.so.1"


def test_unchecked_pyc() -> None:
    assert unchecked_pyc(UNCHECKED)
    assert not unchecked_pyc(CHECKED)
    assert not unchecked_pyc(b"\xcb\r\r\n" + b"\0" * 12)  # timestamp-based
    assert not unchecked_pyc(b"\xcb\r\r\n")


def test_evidence_names_the_format_and_the_disguise() -> None:
    result = run_checks(CHANGE, release("1.0", PKG), release("1.1", {**PKG, "demo/_build.py": PE}))
    (f,) = [f for f in result.findings if f.rule_id == "GRN-C004"]
    assert f.severity is Severity.WARN
    assert (
        f.evidence[0].summary
        == "demo/_build.py: PE native code (84 bytes) under the name _build.py"
    )
    # The file is still a .py to the rules that read Python, which can't parse it.
    assert "GRN-E002" in {x.rule_id for x in result.findings}


def test_a_disguise_in_a_first_wheel_beside_an_sdist_is_reported() -> None:
    # The trusted release shipped only an sdist; pip installs the new wheel,
    # not the clean sdist uploaded beside it.
    base = release("1.0", None, sdist_files=PKG, sdist_only=True)
    cand = release("1.1", {**PKG, "demo/_build.py": PE}, sdist_files=PKG)
    (f,) = _c004(base, cand)
    assert f.evidence[0].summary.startswith("demo/_build.py: PE native code")


def test_a_changed_disguise_is_reported_as_changed() -> None:
    base = release("1.0", {**PKG, "demo/_build.py": PE})
    (f,) = _c004(base, release("1.1", {**PKG, "demo/_build.py": PE + b"\1"}))
    assert f.title == "1.1 adds or changes 1 file(s) of native code or bytecode"


def test_native_bytes_in_a_pth_are_still_a_pth() -> None:
    result = run_checks(CHANGE, release("1.0", PKG), release("1.1", {**PKG, "demo.pth": ELF}))
    ids = {f.rule_id for f in result.findings}
    assert {"GRN-C001", "GRN-C004"} <= ids


def test_new_library_in_a_folder_without_native_code() -> None:
    base = release("1.0", {**PKG, EXT: ELF})
    cand = release("1.1", {**PKG, EXT: ELF, "demo/vendor/libhelper.so": ELF})
    (f,) = _c004(base, cand)
    assert f.evidence[0].summary == (
        "demo/vendor/libhelper.so: ELF native code (64 bytes) in a folder that held no native "
        "code in 1.0"
    )
    # The release already shipped native code, so this is a pointer, not a warning.
    assert f.severity is Severity.INFO


def test_a_rebuilt_executable_in_the_wheel_data_folder_is_quiet() -> None:
    # ruff ships its binary as ruff-<version>.data/scripts/ruff, with no extension.
    base = release("1.0", {**PKG, "demo-1.0.data/scripts/demo": ELF})
    cand = release("1.1", {**PKG, "demo-1.1.data/scripts/demo": ELF + b"\1"})
    assert _c004(base, cand) == []


def test_renamed_libs_folder_is_the_same_folder() -> None:
    # auditwheel names it for the project as the wheel spells it, and hashes each library.
    base = release("1.0", {**PKG, EXT: ELF, "Demo.libs/libjpeg-1a2b.so.62": ELF})
    cand = release("1.1", {**PKG, EXT: ELF, "demo.libs/libjpeg-3c4d.so.62": ELF})
    assert _c004(base, cand) == []


def test_new_extension_modules_in_a_compiled_release_are_quiet() -> None:
    base = release("1.0", {**PKG, EXT: ELF})
    cand = release(
        "1.1",
        {
            **PKG,
            EXT: ELF,
            "demo/signal/_new.cpython-313-x86_64-linux-gnu.so": ELF,  # a new subpackage
            "81d243bd2c585b0f4821__mypyc.cpython-313-x86_64-linux-gnu.so": ELF,  # mypyc's
        },
    )
    assert _c004(base, cand) == []


def test_a_pure_wheel_read_in_place_of_compiled_ones_proves_nothing() -> None:
    # frozenlist 1.4.1 had no CPython 3.13 wheel, so Garnet read its pure-Python one.
    base = release("1.0", PKG)
    built = replace(
        base.artifacts[0],
        filename="demo-1.0-cp312-cp312-manylinux_2_17_x86_64.whl",
        inspected=False,
        files=(),
    )
    cand = release("1.1", {**PKG, EXT: ELF})
    assert _c004(replace(base, artifacts=(*base.artifacts, built)), cand) == []
    (f,) = _c004(base, cand)
    assert f.evidence[0].summary == f"{EXT}: ELF native code (64 bytes); 1.0 shipped no native code"


def test_wheels_for_different_systems_are_not_compared() -> None:
    # pillow 10.3.0 had no CPython 3.13 wheel; the one Garnet read was for macOS.
    base = release("1.0", {**PKG, "demo/.dylibs/libz.1.dylib": ELF, EXT: ELF})
    mac = replace(base.artifacts[0], filename="demo-1.0-cp310-cp310-macosx_10_10_x86_64.whl")
    cand = release("1.1", {**PKG, "demo.libs/libz-1a2b.so.1": ELF, EXT: ELF})
    linux = replace(cand.artifacts[0], filename="demo-1.1-cp313-cp313-manylinux_2_28_x86_64.whl")
    assert _c004(replace(base, artifacts=(mac,)), replace(cand, artifacts=(linux,))) == []
    # The same pair from one system is compared: a new folder of libraries.
    same = replace(mac, filename="demo-1.0-cp313-cp313-manylinux_2_28_x86_64.whl")
    (f,) = _c004(replace(base, artifacts=(same,)), replace(cand, artifacts=(linux,)))
    assert f.severity is Severity.INFO


def test_pyc_beside_its_source_or_in_pycache_is_quiet() -> None:
    cand = release(
        "1.1",
        {
            **PKG,
            "demo/a.py": "",
            "demo/a.pyc": b"\0" * 16,
            "demo/__pycache__/b.cpython-313.pyc": b"\0",
            "demo/__pycache__/a.cpython-313.pyc": CHECKED,
            "demo/__pycache__/c.cpython-313.pyc": UNCHECKED,  # no c.py: never loaded
            "demo/x__pycache__/d.pyc": b"\0" * 16,
        },
    )
    (f,) = _c004(release("1.0", PKG), cand)
    # Only the last: a folder named like __pycache__ isn't one.
    assert [e.path for e in f.evidence] == ["demo/x__pycache__/d.pyc"]


def test_an_unchecked_pyc_beside_its_source_is_reported() -> None:
    files = {**PKG, "demo/a.py": "", "demo/__pycache__/a.cpython-313.pyc": UNCHECKED}
    (f,) = _c004(release("1.0", {**PKG, "demo/a.py": ""}), release("1.1", files))
    assert f.severity is Severity.WARN
    assert f.evidence[0].summary == (
        "demo/__pycache__/a.cpython-313.pyc: compiled bytecode (16 bytes) that Python loads "
        "in place of demo/a.py without checking it against that file"
    )
