"""GRN-C004 new-binary and native-code detection. Synthetic headers only; no network."""

from __future__ import annotations

from dataclasses import replace

import pytest

from garnet_guard.checks.content import _install_key, _named_as
from garnet_guard.engine import run_checks
from garnet_guard.facts.inventory import hash_based_pyc, native_format
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
TIMESTAMP = b"\xcb\r\r\n" + b"\0" * 12
# Wheel tags: interpreter, ABI and platform.
PURE = "py3-none-any"
LINUX = "cp313-cp313-manylinux_2_17_x86_64"
FREE_THREADED = "cp313-cp313t-manylinux_2_17_x86_64"
MACOS = "cp313-cp313-macosx_11_0_arm64"
WINDOWS = "cp313-cp313-win_amd64"
ABI3 = "cp39-abi3-manylinux_2_28_x86_64"  # CPython 3.9 and later, as cryptography ships
ANY_VERSION = "py3-none-manylinux_2_17_x86_64"  # any Python 3, as bundled tools ship


def _c004(base: ReleaseFacts, cand: ReleaseFacts) -> list[Finding]:
    return [f for f in run_checks(CHANGE, base, cand).findings if f.rule_id == "GRN-C004"]


def _tagged(rel: ReleaseFacts, tag: str) -> ReleaseFacts:
    """``rel`` with its wheel named for ``tag`` (``cp313-cp313-win_amd64``)."""
    art = replace(rel.artifacts[0], filename=f"demo-{rel.version}-{tag}.whl", wheel_tag=tag)
    return replace(rel, artifacts=(art,))


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
    # The last extension decides: a native part earlier in the name isn't enough.
    assert _named_as("logo.so.png") == "other"
    assert _named_as("_build.bin.dat") == "other"
    assert _named_as("cfg.out.json") == "other"
    assert _named_as("x.png.debug") == "other"
    assert _named_as("libfoo.so.1.debug") == "native"
    assert _named_as("libpython3.11.so.1.0") == "native"
    # A version is parts of digits, a part after them that starts with one, or
    # a version with a platform after it.
    assert _named_as("libfoo.so.1.2.3") == "native"
    assert _named_as("libssl.so.1.0.2k") == "native"
    assert _named_as("tool-1.2.3rc1") == ""
    assert _named_as("protoc-25.1-linux-x86_64") == ""
    # So is one part of digits with a pre-release, post-release, dev or
    # free-threading suffix: python3.13t is the free-threaded interpreter.
    for name in ("python3.13t", "tool-2.0rc1", "foo-1.0b2", "tool-1.1post1", "tool-1.1dev0"):
        assert _named_as(name) == "", name
    assert _named_as("libpython3.13t.so.1.0") == "native"
    # An extension that starts with a digit is still an extension.
    for name in ("data.7z", "file2.7z", "_assets.3ds", "clip.3gp", "data.7z.001", "clip.mp4"):
        assert _named_as(name) == "other", name
    # Native code that isn't a host library: GPU code objects, a Node.js addon, LLVM's linker.
    for name in ("k.cubin", "Kernels.so-000-gfx1030.hsaco", "TensileLibrary_gfx90a.co"):
        assert _named_as(name) == "native"
    assert _named_as("addon.node") == "native"
    assert _named_as("ld.lld") == "native"
    assert _install_key("ruff-0.16.2.data/scripts/ruff") == ".data/scripts/ruff"
    assert _install_key("demo-1.0.data/platlib/demo/x.so") == "demo/x.so"
    assert _install_key("Pillow.libs/libz.so.1") == "pillow.libs/libz.so.1"
    assert _install_key("scikit-learn.libs/libgomp.so.1") == "scikit_learn.libs/libgomp.so.1"


def test_hash_based_pyc() -> None:
    assert hash_based_pyc(UNCHECKED)
    assert hash_based_pyc(CHECKED)
    assert not hash_based_pyc(TIMESTAMP)
    assert not hash_based_pyc(b"\xcb\r\r\n" + (2).to_bytes(4, "little") + b"\0" * 8)  # timestamp
    assert not hash_based_pyc(b"\xcb\r\r\n")
    assert not hash_based_pyc(
        b"\xcb\r\r\n" + (5).to_bytes(4, "little") + b"\0" * 8
    )  # invalid flags
    # Before 3.7 the flags word was a timestamp: 3.6 (magic 3379) and 2.7 (62211).
    for magic in (3379, 62211):
        for flags in (1, 3):
            old = magic.to_bytes(2, "little") + b"\r\n" + flags.to_bytes(4, "little") + b"\0" * 8
            assert not hash_based_pyc(old)


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


def _with_compiled_sibling(rel: ReleaseFacts) -> ReleaseFacts:
    """``rel`` plus a CPython 3.12 wheel that wasn't read (not for this machine)."""
    built = replace(
        rel.artifacts[0],
        filename=f"demo-{rel.version}-cp312-cp312-manylinux_2_17_x86_64.whl",
        inspected=False,
        files=(),
    )
    return replace(rel, artifacts=(*rel.artifacts, built))


def test_a_pure_wheel_read_in_place_of_compiled_ones_proves_nothing() -> None:
    # frozenlist 1.4.1 had no CPython 3.13 wheel, so Garnet read its pure-Python
    # one; 1.5.0 had one, so Garnet read that.
    base = release("1.0", PKG)
    cand = release("1.1", {**PKG, EXT: ELF})
    cp313 = "demo-1.1-cp313-cp313-manylinux_2_17_x86_64.whl"
    cand = replace(cand, artifacts=(replace(cand.artifacts[0], filename=cp313),))
    assert _c004(_with_compiled_sibling(base), cand) == []
    (f,) = _c004(base, cand)
    assert f.evidence[0].summary == f"{EXT}: ELF native code (64 bytes); 1.0 shipped no native code"


def test_two_pure_wheels_are_compared_beside_compiled_ones() -> None:
    # Neither release has a wheel for this machine, so pip installs the
    # pure-Python one of each, and native code new in it is reported.
    base = _with_compiled_sibling(release("1.0", PKG))
    cand = _with_compiled_sibling(release("1.1", {**PKG, "demo/bin/helper": ELF}))
    (f,) = _c004(base, cand)
    assert f.severity is Severity.WARN
    # The release shipped compiled wheels, so the claim is about the wheel read.
    assert f.evidence[0].summary == (
        "demo/bin/helper: ELF native code (64 bytes); demo-1.0-py3-none-any.whl had no native code"
    )


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
            # Python loads it only if the time and size it records match a.py's.
            "demo/__pycache__/a.cpython-313.pyc": TIMESTAMP,
            "demo/__pycache__/c.cpython-313.pyc": UNCHECKED,  # no c.py: never loaded
            "demo/x__pycache__/d.pyc": b"\0" * 16,
        },
    )
    (f,) = _c004(release("1.0", PKG), cand)
    # Only the last: a folder named like __pycache__ isn't one.
    assert [e.path for e in f.evidence] == ["demo/x__pycache__/d.pyc"]


@pytest.mark.parametrize("header", [UNCHECKED, CHECKED], ids=["unchecked", "checked"])
def test_a_hash_based_pyc_beside_its_source_is_reported(header: bytes) -> None:
    # A checked one too: Python compares only the hash in its header with a.py,
    # and the release supplies both.
    files = {**PKG, "demo/a.py": "", "demo/__pycache__/a.cpython-313.pyc": header}
    (f,) = _c004(release("1.0", {**PKG, "demo/a.py": ""}), release("1.1", files))
    assert f.severity is Severity.WARN
    assert f.evidence[0].summary == (
        "demo/__pycache__/a.cpython-313.pyc: hash-based bytecode (16 bytes) that Python can load "
        "in place of demo/a.py without comparing its code with that file"
    )


def test_a_pyc_in_pycache_without_a_cache_tag_is_sourceless() -> None:
    # A __pycache__ folder is a namespace package: demo/__pycache__/m.pyc imports
    # as demo.__pycache__.m. Python only uses a.cpython-313.pyc as a cache.
    cand = release(
        "1.1",
        {
            **PKG,
            "demo/a.py": "",
            "demo/__pycache__/a.cpython-313.opt-1.pyc": TIMESTAMP,
            "demo/__pycache__/m.pyc": TIMESTAMP,
            "demo/__pycache__/sub/n.pyc": TIMESTAMP,
        },
    )
    (f,) = _c004(release("1.0", {**PKG, "demo/a.py": ""}), cand)
    assert [e.summary for e in f.evidence] == [
        "demo/__pycache__/m.pyc: compiled bytecode (16 bytes) with no source beside it",
        "demo/__pycache__/sub/n.pyc: compiled bytecode (16 bytes) with no source beside it",
    ]


@pytest.mark.parametrize(
    ("before", "after", "title"),
    [
        (TIMESTAMP, TIMESTAMP + b"\1", "1.1 adds or changes 1 file(s) of native code or bytecode"),
        (
            TIMESTAMP,
            TIMESTAMP,
            "1.1 removes the source of 1 .pyc file(s), so Python imports the bytecode instead",
        ),
        (None, TIMESTAMP, "1.1 adds 1 file(s) of native code or bytecode that 1.0 didn't have"),
    ],
    ids=["changed", "unchanged", "new"],
)
def test_a_pyc_whose_source_was_removed_is_reported(
    before: bytes | None, after: bytes, title: str
) -> None:
    # Python imports a.py when both exist, so a.pyc runs only once a.py is gone.
    base = release("1.0", {**PKG, "demo/a.py": "", **({"demo/a.pyc": before} if before else {})})
    (f,) = _c004(base, release("1.1", {**PKG, "demo/a.pyc": after}))
    assert f.severity is Severity.WARN
    # The title says what 1.1 did to the file: an unchanged one was neither added nor changed.
    assert f.title == title
    assert f.evidence[0].summary == (
        f"demo/a.pyc: compiled bytecode ({len(after)} bytes) with no source beside it; "
        "1.0 shipped demo/a.py"
    )


def test_a_removed_source_beside_new_bytecode_is_in_the_title() -> None:
    base = release("1.0", {**PKG, "demo/a.py": "", "demo/a.pyc": TIMESTAMP})
    (f,) = _c004(base, release("1.1", {**PKG, "demo/a.pyc": TIMESTAMP, "demo/b.pyc": TIMESTAMP}))
    assert f.title == (
        "1.1 adds, changes or removes the source of 2 file(s) of native code or bytecode"
    )


@pytest.mark.parametrize(
    ("tag", "module"),
    [
        (PURE, "demo/a/__init__.py"),
        (LINUX, "demo/a/__init__.abi3.so"),
        (LINUX, "demo/a.cpython-313-x86_64-linux-gnu.so"),
        (f"{LINUX}.manylinux2014_x86_64", "demo/a.cpython-313-x86_64-linux-gnu.so"),
        (LINUX, "demo/a.abi3.so"),
        (LINUX, "demo/a.so"),
        (FREE_THREADED, "demo/a.cpython-313t-x86_64-linux-gnu.so"),
        ("cp313-cp313-manylinux_2_17_i686", "demo/a.cpython-313-i386-linux-gnu.so"),
        ("cp313-cp313-manylinux_2_31_armv7l", "demo/a.cpython-313-arm-linux-gnueabihf.so"),
        ("cp37-cp37m-manylinux_2_17_x86_64", "demo/a.cpython-37m-x86_64-linux-gnu.so"),
        (ABI3, "demo/a.abi3.so"),
        (ABI3, "demo/a.so"),
        (ANY_VERSION, "demo/a.so"),
        (MACOS, "demo/a.cpython-313-darwin.so"),
        (WINDOWS, "demo/a.cp313-win_amd64.pyd"),
        (WINDOWS, "demo/a.pyd"),
        (WINDOWS, "demo/a.pyw"),
        ("cp38-abi3-win_amd64", "demo/a.pyd"),
    ],
)
def test_a_pyc_that_python_finds_after_a_package_or_extension_is_quiet(
    tag: str, module: str
) -> None:
    # Every Python the wheel installs on finds a package, then an extension
    # module under a suffix it tries, ahead of a.pyc, so removing a.py for
    # either leaves a.pyc unread, as it was beside a.py.
    base = release("1.0", {**PKG, EXT: ELF, "demo/a.py": "", "demo/a.pyc": TIMESTAMP})
    body = "" if module.endswith((".py", ".pyw")) else ELF
    cand = release("1.1", {**PKG, EXT: ELF, module: body, "demo/a.pyc": TIMESTAMP})
    assert _c004(_tagged(base, tag), _tagged(cand, tag)) == []


def test_a_pyc_beside_its_source_in_an_src_layout_is_quiet() -> None:
    # An sdist's src/ folder isn't part of the installed name, so src/demo/a.py
    # comes ahead of src/demo/a.pyc as demo/a.py does.
    src = {"src/demo/__init__.py": "", "src/demo/a.py": ""}
    base = release("1.0", None, sdist_files=src, sdist_only=True)
    cand = release("1.1", None, sdist_files={**src, "src/demo/a.pyc": TIMESTAMP}, sdist_only=True)
    assert _c004(base, cand) == []


@pytest.mark.parametrize(
    ("tag", "decoy"),
    [
        (PURE, "demo/evil/__init__.cpython-313.pyc"),
        (PURE, "demo/evil/__init__.x.py"),
        (PURE, "demo/evil.x.so"),
        (PURE, "demo/evil.pyd"),
        # A pure-Python wheel installs on every Python and platform, and no
        # extension suffix is one they all try.
        (PURE, "demo/evil.cpython-313-x86_64-linux-gnu.so"),
        (PURE, "demo/evil.cpython-313-aarch64-linux-gnu.so"),
        (PURE, "demo/evil.cpython-313-darwin.so"),
        (PURE, "demo/evil.cpython-399.so"),
        (PURE, "demo/evil.abi3.so"),
        (PURE, "demo/evil.so"),
        (LINUX, "demo/evil.x.so"),
        (LINUX, "demo/evil.cpython-312-x86_64-linux-gnu.so"),
        (LINUX, "demo/evil.cpython-313-aarch64-linux-gnu.so"),
        (LINUX, "demo/evil.cpython-313-x86_64-linux-musl.so"),
        (LINUX, "demo/evil.cpython-313t-x86_64-linux-gnu.so"),
        (LINUX, "demo/evil.cpython-313.so"),
        (LINUX, "demo/evil.pyd"),
        (LINUX, "demo/evil.pyw"),
        ("cp37-cp37m-manylinux_2_17_x86_64", "demo/evil.cpython-37-x86_64-linux-gnu.so"),
        (FREE_THREADED, "demo/evil.abi3.so"),
        # Each CPython tries only its own version's tag, so in a wheel for
        # several versions no version-tagged suffix is one they all try.
        (ABI3, "demo/evil.cpython-399-x86_64-linux-gnu.so"),
        (ABI3, "demo/evil.cpython-312-x86_64-linux-gnu.so"),
        (ABI3, "demo/evil.cpython-313-x86_64-linux-gnu.so"),
        (ANY_VERSION, "demo/evil.cpython-399-x86_64-linux-gnu.so"),
        (ANY_VERSION, "demo/evil.cpython-312-x86_64-linux-gnu.so"),
        # Free-threaded CPython installs it too, and doesn't try .abi3.so.
        (ANY_VERSION, "demo/evil.abi3.so"),
        # CPython 3.13 and 3.13t both install an ABI-less cp313 tag.
        ("cp313-none-manylinux_2_17_x86_64", "demo/evil.cpython-313-x86_64-linux-gnu.so"),
        (MACOS, "demo/evil.cpython-313-x86_64-linux-gnu.so"),
        (MACOS, "demo/evil.cpython-312-darwin.so"),
        (WINDOWS, "demo/evil.so"),
        (WINDOWS, "demo/evil.abi3.so"),
        (WINDOWS, "demo/evil.cp313-win32.pyd"),
        ("cp38-abi3-win_amd64", "demo/evil.cp313-win_amd64.pyd"),
    ],
)
def test_a_name_python_does_not_try_leaves_the_pyc_imported(tag: str, decoy: str) -> None:
    # Only the names above, under a suffix every Python the wheel installs on
    # tries, come ahead of demo/evil.pyc. With any other file beside it, some
    # Python still imports demo/evil.pyc: the decoy hides nothing.
    if decoy.endswith(".pyc"):
        body: bytes | str = TIMESTAMP
    else:
        body = "" if decoy.endswith((".py", ".pyw")) else ELF
    base = release("1.0", {**PKG, EXT: ELF})
    cand = release("1.1", {**PKG, EXT: ELF, decoy: body, "demo/evil.pyc": TIMESTAMP})
    (f,) = _c004(_tagged(base, tag), _tagged(cand, tag))
    assert f.severity is Severity.WARN
    assert [e.summary for e in f.evidence] == [
        "demo/evil.pyc: compiled bytecode (16 bytes) with no source beside it"
    ]


@pytest.mark.parametrize(
    "decoy",
    ["demo/evil.cpython-313-x86_64-linux-musl.so", "demo/evil.cpython-313-x86_64-linux-gnu.so"],
)
def test_a_musllinux_wheel_counts_no_version_tagged_suffix(decoy: str) -> None:
    # CPython names its musl triplet linux-gnu or linux-musl depending on its
    # version and build, so neither name is one every musl CPython 3.13 tries.
    tag = "cp313-cp313-musllinux_1_2_x86_64"
    base = release("1.0", {**PKG, EXT: ELF})
    cand = release("1.1", {**PKG, EXT: ELF, decoy: ELF, "demo/evil.pyc": TIMESTAMP})
    (f,) = _c004(_tagged(base, tag), _tagged(cand, tag))
    assert [e.path for e in f.evidence] == ["demo/evil.pyc"]
    quiet = release("1.1", {**PKG, EXT: ELF, "demo/evil.so": ELF, "demo/evil.pyc": TIMESTAMP})
    assert _c004(_tagged(base, tag), _tagged(quiet, tag)) == []


@pytest.mark.parametrize("decoy", ["demo/evil.cpython-399.so", "demo/evil.cpython-313-darwin.so"])
def test_a_tagged_decoy_in_a_pure_wheel_after_a_compiled_one_is_reported(decoy: str) -> None:
    # A compiled project that ships one pure-Python wheel installs it
    # everywhere; CPython 3.13 on Linux tries neither name for demo.evil. The
    # two wheels aren't compared for native code, so only the .pyc is reported.
    base = _tagged(release("1.0", {**PKG, EXT: ELF}), LINUX)
    cand = _tagged(release("1.1", {**PKG, decoy: b"", "demo/evil.pyc": TIMESTAMP}), PURE)
    (f,) = _c004(base, cand)
    assert [e.summary for e in f.evidence] == [
        "demo/evil.pyc: compiled bytecode (16 bytes) with no source beside it",
        f"compared wheels with different tags: {LINUX} vs {PURE}",
    ]


def test_a_decoy_package_does_not_hide_a_pyc_whose_source_was_removed() -> None:
    base = release("1.0", {**PKG, "demo/a.py": "", "demo/a.pyc": TIMESTAMP})
    cand = release(
        "1.1", {**PKG, "demo/a.pyc": TIMESTAMP, "demo/a/__init__.cpython-313.pyc": TIMESTAMP}
    )
    (f,) = _c004(base, cand)
    assert [e.summary for e in f.evidence] == [
        "demo/a.pyc: compiled bytecode (16 bytes) with no source beside it; 1.0 shipped demo/a.py"
    ]


def test_a_package_of_bytecode_is_reported_in_place_of_the_pyc_behind_it() -> None:
    # demo/a/__init__.pyc makes demo/a a package, which Python imports ahead of
    # demo/a.pyc; the package's own bytecode has no source.
    base = release("1.0", {**PKG, "demo/a.py": "", "demo/a.pyc": TIMESTAMP})
    cand = release("1.1", {**PKG, "demo/a/__init__.pyc": TIMESTAMP, "demo/a.pyc": TIMESTAMP})
    (f,) = _c004(base, cand)
    assert [e.path for e in f.evidence] == ["demo/a/__init__.pyc"]


def test_a_pyc_beside_a_folder_without_init_is_still_imported() -> None:
    # demo/a/ without __init__ is a namespace package, which Python only uses
    # when it finds no module named a.
    base = release("1.0", {**PKG, "demo/a.py": "", "demo/a.pyc": TIMESTAMP})
    (f,) = _c004(base, release("1.1", {**PKG, "demo/a/x.py": "", "demo/a.pyc": TIMESTAMP}))
    assert [e.path for e in f.evidence] == ["demo/a.pyc"]


def test_an_unchanged_disguise_whose_source_was_removed_is_quiet() -> None:
    # Native bytes named a.pyc were already a disguise in 1.0, and Python can't
    # import them as bytecode.
    base = release("1.0", {**PKG, "demo/a.py": "", "demo/a.pyc": ELF})
    assert _c004(base, release("1.1", {**PKG, "demo/a.pyc": ELF})) == []


@pytest.mark.parametrize("sdist", [False, True], ids=["wheel", "sdist"])
def test_pytests_assertion_cache_is_not_bytecode_python_imports(sdist: bool) -> None:
    # pytest writes test_x.cpython-311-pytest-8.0.0.pyc beside Python's own
    # cache. Python never imports a .pyc whose name has another dot, in
    # __pycache__ or out of it.
    root = "" if sdist else "demo/"
    tests = {f"{root}tests/__init__.py": "", f"{root}tests/test_x.py": ""}
    old = {**tests, f"{root}tests/__pycache__/test_x.cpython-311-pytest-7.4.0.pyc": TIMESTAMP}
    new = {
        **tests,
        f"{root}tests/conftest.py": "",
        f"{root}tests/__pycache__/test_x.cpython-311-pytest-8.0.0.pyc": TIMESTAMP,
        f"{root}tests/__pycache__/conftest.cpython-311-pytest-8.0.0.pyc": UNCHECKED,
        f"{root}tests/x.cpython-311.pyc": TIMESTAMP,
    }
    if sdist:
        base = release("1.0", None, sdist_files={"setup.py": "", **PKG, **old}, sdist_only=True)
        cand = release("1.1", None, sdist_files={"setup.py": "", **PKG, **new}, sdist_only=True)
    else:
        base, cand = release("1.0", {**PKG, **old}), release("1.1", {**PKG, **new})
    assert _c004(base, cand) == []


def test_native_code_named_with_an_extension_that_starts_with_a_digit() -> None:
    # Beside an extension module: _assets.7z isn't a version, it says 7-Zip.
    base = release("1.0", {**PKG, EXT: ELF})
    (f,) = _c004(base, release("1.1", {**PKG, EXT: ELF, "demo/_assets.7z": ELF}))
    assert f.severity is Severity.WARN
    assert f.evidence[0].summary == (
        "demo/_assets.7z: ELF native code (64 bytes) under the name _assets.7z"
    )


def test_a_changed_pyc_that_was_already_sourceless_is_quiet() -> None:
    base = release("1.0", {**PKG, "demo/a.pyc": TIMESTAMP})
    assert _c004(base, release("1.1", {**PKG, "demo/a.pyc": TIMESTAMP + b"\1"})) == []


@pytest.mark.parametrize("path", ["demo/bin/helper", "demo-{v}.data/scripts/demo"])
def test_a_file_that_becomes_native_code_is_new_native_code(path: str) -> None:
    # The path held a script, not native code, and the release shipped none.
    base = release("1.0", {**PKG, path.format(v="1.0"): "#!/bin/sh\necho hi\n"})
    cand = release("1.1", {**PKG, path.format(v="1.1"): ELF})
    (f,) = _c004(base, cand)
    assert f.severity is Severity.WARN
    assert f.evidence[0].summary == (
        f"{path.format(v='1.1')}: ELF native code (64 bytes); 1.0 shipped no native code"
    )


def test_a_file_that_becomes_native_code_in_a_compiled_release_is_info() -> None:
    base = release("1.0", {**PKG, EXT: ELF, "demo/bin/helper": "#!/bin/sh\necho hi\n"})
    (f,) = _c004(base, release("1.1", {**PKG, EXT: ELF, "demo/bin/helper": ELF}))
    assert f.severity is Severity.INFO


def test_a_native_part_inside_the_name_is_still_a_disguise() -> None:
    # Beside an extension module, in a release that already shipped native code.
    base = release("1.0", {**PKG, EXT: ELF})
    (f,) = _c004(base, release("1.1", {**PKG, EXT: ELF, "demo/_build.bin.dat": ELF}))
    assert f.severity is Severity.WARN
    assert f.evidence[0].summary == (
        "demo/_build.bin.dat: ELF native code (64 bytes) under the name _build.bin.dat"
    )
    # Against a trusted sdist only the name and bytecode cases apply; this is one.
    sdist = release("1.0", None, sdist_files={"setup.py": "", **PKG}, sdist_only=True)
    (f,) = _c004(sdist, release("1.1", {**PKG, "demo/assets/logo.so.png": ELF}))
    assert f.evidence[0].summary == (
        "demo/assets/logo.so.png: ELF native code (64 bytes) under the name logo.so.png"
    )


def test_rebuilt_gpu_code_and_bundled_tools_are_quiet() -> None:
    # CUDA and ROCm kernels are ELF files, and so is a Node.js addon or LLVM's
    # linker; compiled releases rebuild them every time.
    natives = (
        "demo/kernels/gemm.cubin",
        "demo/lib/rocblas/Kernels.so-000-gfx1030.hsaco",
        "demo/lib/rocblas/TensileLibrary_gfx90a.co",
        "demo/js/addon.node",
        "demo/llvm/bin/ld.lld",
        # Executables named for their version: the free-threaded interpreter, a release candidate.
        "demo/bin/python3.13t",
        "demo/bin/tool-2.0rc1",
    )
    base = release("1.0", {**PKG, EXT: ELF, **{p: ELF for p in natives}})
    cand = release("1.1", {**PKG, EXT: ELF + b"\1", **{p: ELF + b"\1" for p in natives}})
    assert _c004(base, cand) == []
