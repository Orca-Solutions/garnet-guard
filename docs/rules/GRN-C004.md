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
  library named `.png`, when it is new or has changed. A name with no extension, as an
  executable usually has, or with a version after the extension (`libssl.so.3`) is not a
  disguise.
- **Any new native file when the trusted release shipped no native code at all.**
- **A new sourceless `.pyc`**: compiled bytecode outside `__pycache__` with no `.py` of the
  same name beside it. Python imports such a file when there is no source, so it runs like a
  module nobody can read.
- **A new or changed unchecked `.pyc` in `__pycache__`**, beside the source it was compiled
  from. A hash-based `.pyc` can say it is not to be checked
  ([PEP 552](https://peps.python.org/pep-0552/)), and Python then loads it in place of the
  `.py` file without comparing the two, so the code that runs isn't the code anyone reads.
  An installer that compiles bytecode replaces it; one that doesn't, such as uv by default,
  leaves it.

It reports at `info` a new shared library or executable in a folder that held no native
code, in a release that already shipped some: a pointer for review, not a warning.

A compiled release that adds an extension module (`name.cpython-313-x86_64-linux-gnu.so`,
`name.abi3.so`, `name.pyd`), anywhere, or ships a rebuilt copy of a library it already
bundled, stays quiet. Paths are compared by where they install, so the version in a wheel's
`<name>-<version>.data/` folder and the spelling of auditwheel's `<name>.libs/` folder don't
make every file look new.

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
4. If the binary is expected, merge and add an ignore for that version range. Don't ignore
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
- **Rebuilt binaries.** A library the trusted version already shipped at the same path, or in
  the same folder, isn't reported when its bytes change: compiled releases rebuild every
  binary every time. A payload compiled into an existing extension module is not seen.
- **New extension modules in a compiled release**, wherever they sit: projects add them
  routinely. The code that loads anything else new (`ctypes.CDLL`) is GRN-C003's.
- **Native code when the two wheels don't show it.** Content rules compare the wheel pip
  would install where Garnet runs with the trusted version's. When the trusted release had
  no wheel for that Python, Garnet read another: a pure-Python wheel beside compiled ones,
  or one for another operating system. The trusted release did ship native code, so the
  rule doesn't claim it didn't, and compares only names and bytecode. The same applies when
  one side is a wheel and the other an sdist, which compiles its own.
- **A changed sourceless `.pyc`** in a release that already shipped it, for the same reason
  as rebuilt binaries; a new one is reported.
- **Other wheels of the release.** This rule reads the wheel the content rules read, not
  the release's wheels for other systems.
- **npm.** Packages that ship prebuilt binaries are common there, and the rule doesn't run on
  npm releases yet.

## See also

- `garnet explain GRN-C004` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
