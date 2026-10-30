---
id: GRN-C004
name: new-binary
kind: diff
default_severity: warn
status: implemented
---

# GRN-C004 new-binary

| | |
|---|---|
| Default severity | `warn` (`info` for a new library in a new folder of a release that already shipped native code) |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.2 (PyPI) |

## What it checks

Garnet reads a file's first bytes as well as its name: ELF (Linux), Mach-O (macOS) and PE
(Windows) executables and libraries are native code wherever they sit and whatever they are
called. The rule compares the new version's files with the trusted version's and warns for:

- **Native code under a name that says otherwise**, such as a DLL named `_build.py` or a
  library named `.png`, when it is new or has changed. The last extension decides, so
  `logo.so.png` is a disguise too. A name with no extension, as an executable usually has,
  or with a version at the end (`libssl.so.3`, `libssl.so.1.0.2k`, `tool-1.2.3rc1`,
  `tool-2.0rc1`, `python3.13t`) is not a disguise, and neither is a debug file named for its
  library (`libfoo.so.debug`). An extension that starts with a digit and doesn't read as a
  version is still an extension, so `data.7z` and `clip.3gp` are disguises.
  Native extensions include GPU code (`.cubin`, `.hsaco`, `.co`), Node.js addons (`.node`),
  JNI and MATLAB libraries (`.jnilib`, `.mexa64`) and LLVM's linker, `ld.lld`.
- **Any native file when the trusted release shipped no native code at all**: a new one, or
  one that replaces a file that wasn't native, such as a shell script.
- **A sourceless `.pyc`**: bytecode named for a module, such as `a.pyc`, in `__pycache__` or
  out of it, that Python would import. Python imports such a file as the module `a`, so it
  runs like a module nobody can read. It stays quiet only when every Python the wheel
  installs on finds another file for `a` first: a folder `a/` holding `__init__.py` or
  `__init__.pyc`, `a.py` (or `a.pyw` in a Windows wheel), or an extension module `a` or
  `a/__init__` under a suffix all of those Pythons try. A version-tagged suffix
  (`.cpython-313-x86_64-linux-gnu.so`, `.cpython-313-darwin.so`, `.cp313-win_amd64.pyd`)
  counts only in a manylinux, macOS or Windows wheel tagged for that one CPython build and
  platform (`cp313-cp313-manylinux_2_17_x86_64`), `.abi3.so` only in an `abi3` wheel or one
  for a single CPython build with the GIL, `.so` in any Linux or macOS wheel and `.pyd` in
  any Windows wheel; in a pure-Python wheel or an sdist no extension module counts. So
  `a.cpython-312-x86_64-linux-gnu.so` keeps `a.pyc` quiet in neither a wheel for 3.13 nor a
  `cp39-abi3` one, `a.x.so`, `a.pyd` outside a Windows wheel and
  `a/__init__.cpython-313.pyc` never do, and a `.pyc` that only some of those Pythons import
  is reported. A `.pyc` whose name has another dot isn't imported under its own name, so
  neither the files Python caches (`a.cpython-313.pyc`, below) nor pytest's
  (`test_a.cpython-313-pytest-8.4.1.pyc`) count. It is reported when it is new, and when the
  new version removes the `.py` beside it, even if the `.pyc` itself is unchanged: Python
  then imports the `.pyc` instead.
- **A new or changed hash-based `.pyc` in `__pycache__`**, beside the source it was compiled
  from ([PEP 552](https://peps.python.org/pep-0552/)). Python loads it in place of the `.py`
  file without comparing its code with that file: an unchecked one without looking at the
  source, a checked one when a hash in its own header matches the source's, which anyone can
  compute. So the code that runs needn't be the code anyone reads. An installer that compiles
  bytecode replaces it; one that doesn't, such as uv by default, leaves it. Bytecode from
  Python 3.6 or earlier has no such setting, so it isn't reported (pycparser 2.18 shipped
  some by accident).

It reports at `info` a new shared library or executable in a folder that held no native
code, in a release that already shipped some: a pointer for review, not a warning.

A compiled release that adds an extension module (`name.cpython-313-x86_64-linux-gnu.so`,
`name.abi3.so`, `name.pyd`), anywhere, or ships a rebuilt copy of a library it already
bundled, stays quiet. Here a `.so` without an interpreter tag, such as `a.so`, counts as a
library, not an extension module, though Python can import it as one, so in a Linux or
macOS wheel it does keep `a.pyc` quiet. Paths are compared by where they install, so the version in a
wheel's `<name>-<version>.data/` folder and the spelling of auditwheel's `<name>.libs/`
folder don't make every file look new.

## Why it matters

Garnet Guard reads Python source, not machine code. A payload compiled into a library or an
executable, or shipped as bytecode with no source, is invisible to the rules that read code,
and Python will load all three. num2words 0.5.15 (July 2025) shipped a Windows DLL under the
name `num2words/_build.py` and loaded it with `ctypes` at import.

## Example finding

From the replay of num2words 0.5.15 (July 2025), uploaded after a maintainer was phished.

```text
num2words 0.5.14 → 0.5.15: WARN
  WARN  GRN-C004 new-binary: 0.5.15 adds 1 file(s) of native code or bytecode that 0.5.14 didn't have
           - num2words/_build.py: PE native code (1,291,264 bytes) under the name _build.py
```

The same replay also reports the `ctypes.CDLL` call that loads it (GRN-C003), the missing git
tag (GRN-T004), and GRN-E002, because `_build.py` doesn't parse as Python.

## How to resolve it

1. Find the source of the new compiled component in the project's repository: the C, C++,
   Rust or Cython files, and the build configuration that compiles them. A release's notes
   don't settle it, because whoever published the release wrote them.
2. Confirm the binary was built by the project's CI: its build logs, or an attestation
   (GRN-T001 to GRN-T003 report when that changes).
3. A file whose name hides what it is, such as a DLL named `.py`, or bytecode with no source
   in the repository, has no ordinary explanation. Don't merge, and tell the maintainers.
4. A hash-based `.pyc` in `__pycache__` can be left over from a build: `py_compile` and
   `compileall` write checked ones when `SOURCE_DATE_EPOCH` is set, as reproducible builds
   do. Where the installer doesn't recompile it, Python still runs it rather than the `.py`
   beside it, so ask the maintainers to drop `__pycache__` from the wheel.
5. If the binary is expected, merge and add an ignore for that version range. Don't ignore
   this rule for all versions of a compiled package: that also hides a DLL named `.py`, the
   case it exists for.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = ">=2.6"
rules = ["GRN-C004"]
reason = "ships compiled wheels from 2.6 on, see release notes"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-C004" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## What it doesn't check

- **What the binary does.** Garnet never runs or disassembles it; the finding says that it
  is there and what format it is.
- **Rebuilt binaries.** Native code at a path where the trusted version shipped native code
  isn't reported when its bytes change, and new native code in a folder that already held
  some isn't reported unless its name hides it: compiled releases rebuild every binary every
  time, and auditwheel gives bundled libraries new names. A payload compiled into an existing
  extension module, or a new executable beside one, is not seen.
- **New extension modules in a compiled release**, wherever they sit: projects add them
  routinely. The code that loads anything else new (`ctypes.CDLL`) is GRN-C003's.
- **Native code when the two wheels don't show it.** Content rules compare the wheel pip
  would install where Garnet runs with the trusted version's. When the trusted release had
  no wheel for that Python, Garnet read another: a pure-Python wheel beside compiled ones,
  or one for another operating system. When that pure-Python wheel is compared with a
  compiled one, or the two wheels are for different systems, the trusted release did ship
  native code the wheel doesn't show, so the rule doesn't claim it didn't, and compares only
  names and bytecode. The same applies when one side is a wheel and the other an sdist,
  which compiles its own. Two pure-Python wheels are compared in full: they are what pip
  installs here on both sides.
- **A changed sourceless `.pyc`** in a release that already shipped it without a source, for
  the same reason as rebuilt binaries; a new one is reported.
- **A timestamp-based `.pyc` in `__pycache__`.** Python loads it in place of its source only
  when the modification time and size it records match the installed source file's.
- **Other wheels of the release.** This rule reads the wheel the content rules read, not
  the release's wheels for other systems.
- **npm.** Packages that ship prebuilt binaries are common there, and the rule doesn't run on
  npm releases yet.

## See also

- `garnet explain GRN-C004` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
