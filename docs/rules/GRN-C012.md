---
id: GRN-C012
name: wheels-differ
kind: diff
default_severity: warn
status: implemented
---

# GRN-C012 wheels-differ

| | |
|---|---|
| Default severity | `warn` (`info` when the read wheel's copies couldn't be parsed to compare) |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.2 (PyPI wheels) |

## What it checks

A release with compiled code ships one wheel per platform: Linux, Windows, macOS, sometimes
more. The content rules read one of them, the one pip would install on the machine Garnet runs
on ([SPEC §4.2](../SPEC-v1.md#42-artifact-selection)). This rule reads others and compares
them with it.

Garnet picks, from the new version's wheels:

- **one wheel for each other platform family**: Windows, macOS, Linux, a pure-Python
  (`py3-none-any`) wheel, and any other platform, such as Android or iOS. Within a family it
  takes the newest CPython build, then x86-64, then the first by name, so the same release
  always gives the same pick;
- **every wheel uploaded more than 24 hours after the release's first file**, up to 10. The
  threshold is GRN-T006's. A late wheel past the 10th is not compared, and the report says
  so in a note.

Each picked wheel is downloaded, checked against PyPI's published hash, and opened through
the same archive reader as every other artifact. Its Python files are compared with the read
wheel's by SHA-256. A file that matches is skipped. A file that differs, or that the read
wheel doesn't have, is parsed (never run) and its calls are checked against the
[sensitive call set](GRN-C003.md#sensitive-call-set), anywhere in the file. The rule fires
for a call the read wheel's copy of that file doesn't make.

A platform's wheel can differ for good reasons. delvewheel, the tool that bundles DLLs into
Windows wheels, adds lines to the package's `__init__.py` that can load them with `ctypes`.
So the rule asks the same question of the trusted version: a call its wheel for the same
platform family already made, in the same file, is not new. When the trusted version had no
wheel for that family, the evidence says so.

Old releases sometimes leave Garnet reading a Python 2 wheel (`cp27`), whose files don't parse
as Python 3. Then nothing shows which calls the read copy makes, so every call in the other
wheel's file is listed, with the evidence saying the read copy "couldn't be parsed to
compare", and the finding reports at `info` instead of `warn`. It is not a pass: GRN-E002
warns for a new or changed file the read wheel can't parse.

## Why it matters

A wheel is chosen per machine. If an attacker adds a payload to the Windows wheel only, every
Windows user who installs the release runs it, while the Linux wheel a CI runner reads is
clean, and so are the content rules' results. GRN-T006 catches a wheel added days after the
release. This rule covers a wheel uploaded with the rest, and a late one that only adds a
platform, which GRN-T006 reports at `info`.

No replayed malicious release did this: each of the 47 replayed PyPI releases ships at most
one wheel. The rule closes a gap the [threat model](../../THREAT_MODEL.md)
names, rather than one an attack has used so far.

## Example finding

From the test fixture: a release whose Windows wheel adds a process call that the pure-Python
wheel doesn't have.

```text
demo 1.0 → 1.1: WARN
  WARN  GRN-C012 wheels-differ: 1 other wheel(s) of 1.1 have code the wheel Garnet read doesn't
           - demo-1.1-cp313-cp313-win_amd64.whl: demo/__init__.py:5 calls subprocess.run (in greet()); the same file in demo-1.1-py3-none-any.whl doesn't
```

## How to resolve it

1. Open the file the evidence names in the wheel it names, and the same file in the
   project's repository at the release's tag. Read what the extra call does.
2. Pure Python code is normally the same in every wheel of a release. A project that writes
   platform code at build time says so in its build scripts, and the code won't download or
   run anything.
3. If it is expected, merge and add a time-limited ignore with the reason. If the repository
   doesn't explain it, don't merge, and tell the maintainers.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-C012"]
reason = "Windows wheel loads its bundled DLLs with ctypes, added by delvewheel 1.9"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-C012" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## What it doesn't check

- Every wheel. A release with 40 wheels gets one per platform family plus the late ones, so
  a payload in, say, the Linux aarch64 wheel alone, beside a clean Linux x86-64 wheel Garnet
  reads, isn't seen.
- Files other than `.py`. A new `.pth` in another wheel, or a compiled extension that
  differs, as every compiled extension does between platforms, isn't compared.
- Code that is the same in every wheel. That is the other content rules' job, on the wheel
  they read.
- What the extra wheels cost. Each one is a full download; see the measurements in
  [docs/rule-coverage.md](../rule-coverage.md).
- A release with no wheel the content rules read (sdist only): there is nothing to compare
  with.

A wheel that fails its hash is GRN-T008. One that can't be downloaded is GRN-E001, one that
can't be opened GRN-E002, and one over a §4.4 limit GRN-E003, each naming this rule, never a
pass.

## See also

- `garnet explain GRN-C012` prints this rule's summary in your terminal.
- [GRN-T006](GRN-T006.md), which reports a file uploaded after the release.
- [GRN-C003](GRN-C003.md), the sensitive call set this rule shares.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
