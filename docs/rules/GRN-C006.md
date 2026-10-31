---
id: GRN-C006
name: sdist-wheel-mismatch
kind: diff
default_severity: warn
status: implemented
---

# GRN-C006 sdist-wheel-mismatch

| | |
|---|---|
| Default severity | `warn` (`info` in test files and files outside the packages) |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.3 (PyPI) |

## What it checks

A release on PyPI usually ships two files: an sdist, the source archive that reviewers and
rebuilds read, and a wheel, the archive pip installs. The wheel is built from the sdist, or
from the same tagged source, so each Python file in it should be, byte for byte, a file in
the sdist. Garnet compares the wheel the content rules read
([SPEC §4.2](../SPEC-v1.md#42-artifact-selection)) with the release's own sdist, file by
file, from the bytes it has already downloaded and checked against PyPI's hashes.

- A Python file whose exact bytes are anywhere in the sdist matches, wherever the build put
  it. A file that differs only in CRLF line endings, as a wheel built on Windows writes
  them, matches too.
- Any other Python file is looked for at its install path in the sdist: below the sdist's
  top `<name>-<version>/` folder, under the folder most of the wheel's files are found in
  (`src/`, or `python/` in a maturin project), and, for a package published under another
  name, under the folder most of its files come from, when that holds at least half of
  them (pycryptodomex's `Cryptodome/` is `lib/Crypto/` in its sdist), as
  [GRN-C007](GRN-C007.md) does in the repository. A file under the wheel's
  `<name>.data/purelib/` or `platlib/` is compared by where it installs, at the top of
  site-packages.
- A file that differs from its sdist copy, or has none, is parsed (never run), and the rule
  fires for each call in the [sensitive call set](GRN-C003.md#sensitive-call-set),
  anywhere in the file, that the sdist's copy doesn't make. When the sdist has no copy,
  every such call counts. When its copy doesn't parse, or is over the 5 MB parse limit,
  every call counts too, and the evidence says the copy couldn't be parsed to compare.
- A `.pth` file in the wheel fires when the sdist has no copy of it (looked for at its
  install path, then by name anywhere in the sdist), or when it has executable (`import`)
  lines that copy lacks. Lines are read as every supported Python reads them: Python 3.11
  and 3.12 run a line past a form feed whole, and 3.13 and later skip a leading UTF-8 BOM
  and run the line behind it.

A call the trusted version's wheel already carried outside its own sdist, in the same file,
isn't new. Neither is a `.pth` line the trusted wheel carried in a `.pth` file its sdist
lacked, at any path, because setuptools names namespace `.pth` files after the version, nor
a `.pth` file with no executable lines at a path where the trusted wheel had a `.pth` file
its sdist lacked. When the trusted version gives nothing to compare with (it had no sdist or
no wheel, or Garnet couldn't read them), the evidence says so.

Code only in test files, or in files outside the release's packages, is listed in its own
finding at `info` (the maintainer's decision of 2026-10-31, as [GRN-C003](GRN-C003.md)
reports such files). A test file is one GRN-C003 counts as a test: under a `tests/` folder
or a top-level `test/` folder, or named `test_*.py` or `conftest.py` (aenum 3.1.16's
`aenum/test_stdlib_tests.py`). A file outside the packages is in a folder at the top of
site-packages with no `__init__.py` anywhere under it and not named after the project
(google-auth-oauthlib 1.2.0's `scripts/readme-gen/readme_gen.py`). Both run only when someone
runs them. Such a file stays at `warn` when a module outside these files imports it, directly
or through them, an entry point names it, or a `.pth` line in the wheel names it. A `.pth`
file is never at `info`: it runs at every startup.

Files a build writes, such as a `_version.py` from setuptools-scm or hatch-vcs, are in the
wheel and not the sdist, or differ between the two. They don't run processes, load code or
use the network, so they stay quiet.

## Why it matters

Reviewers read the sdist, or the repository it was made from; pip installs the wheel. Code
that is only in the wheel is the part nobody read. [GRN-C007](GRN-C007.md) ties the wheel to
the repository when the release has a matching git tag. This rule ties it to the sdist
uploaded beside it, with or without a tag.

An uploader who controls both files can put the same code in each, and then there is no
mismatch to report. telnyx 4.87.1 and 4.87.2 (March 2026) did that. Issue #60 listed telnyx
4.87.1 as a payload in the wheel only; reading both files shows otherwise. In each release,
`telnyx/_client.py` in the wheel is byte for byte `src/telnyx/_client.py` in the sdist
(SHA-256 `23b1ec58…` in 4.87.1, `ab4c4aeb…` in 4.87.2), and so is each of the other 2,490
Python files. This rule stays quiet on both; GRN-C003 reports them, because the appended code
runs at import. The same holds for the other replayed malicious releases that ship both
files: in each, every Python and `.pth` file of the wheel is in the sdist byte for byte,
apart from a `conftest.py` that xinference's trusted 2.5.0 wheel already carried. On the 974
routine updates of the top-100 PyPI corpus the rule reports nothing
([docs/rule-coverage.md](../rule-coverage.md) has the details).

## Example finding

From the test fixture: a function appended to the wheel's copy of a file that the sdist
carries without it, the shape issue #60 expected of telnyx.

```text
demo 1.0 → 1.1: WARN
  WARN  GRN-C006 sdist-wheel-mismatch: 1.1's wheel has code that is not in its sdist (1 file(s))
           - compared demo-1.1-py3-none-any.whl with demo-1.1.tar.gz: 1 Python file(s) match the sdist, 1 differ from their copy there, 0 have none
           - demo/_client.py:7 calls subprocess.run (in setup()); demo/_client.py in demo-1.1.tar.gz doesn't
```

At `info`, from the test fixture: a script in a folder that holds no package, which only the
wheel has.

```text
demo 1.0 → 1.1: PASS
  info  GRN-C006 sdist-wheel-mismatch: 1.1's wheel has code that is not in its sdist only in test files or files outside its packages (1 file(s))
           - compared demo-1.1-py3-none-any.whl with demo-1.1.tar.gz: 1 Python file(s) match the sdist, 0 differ from their copy there, 1 have none
           - scripts/readme-gen/gen.py:4 calls urllib.request.urlopen (in get()); demo-1.1.tar.gz has no such file
           - test files and files outside the release's packages run only when run on their own, and no other module, entry point or .pth file in the wheel names these, so this is reported at info
```

## How to resolve it

1. Open the flagged line in the wheel and the file the evidence names in the sdist. Read
   what the extra code does.
2. Ask whether the build is supposed to write it. A build hook or code generator is named in
   the project's `pyproject.toml`, `setup.py` or build scripts, and the call the evidence
   names is what that hook is there to generate: a `ctypes` loader for a library the
   project bundles, say, not a download or a shell command. Then look at the same file in
   the repository at the release's tag.
3. If it is expected, merge and add a time-limited ignore with the reason. If nothing
   explains it, don't merge, and tell the maintainers: the wheel they published wasn't built
   from the sdist beside it.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-C006"]
reason = "build hook writes _native.py with a ctypes loader, see hatch_build.py"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-C006" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## What it doesn't check

- Code that is in both files, byte for byte (telnyx 4.87.1 and 4.87.2). GRN-C003 reports it
  when it runs at import, and GRN-C007 when it isn't at the release's tag.
- A release with no sdist, or no wheel: there is nothing to compare. A release whose sdist
  or wheel Garnet couldn't download or read to the end isn't compared either, and the
  GRN-E001, GRN-E002 or GRN-E003 for that file names this rule, so the update doesn't pass.
  One that fails its hash is GRN-T008.
- What a call does. Calls are compared by name, as in GRN-C007, so a call the sdist's copy
  also makes, with another command or address, isn't reported.
- Files the wheel installs outside site-packages: scripts and data under
  `<name>.data/scripts/` or `data/`, and files in its metadata folder. GRN-C010 lists new
  scripts and data files.
- Files other than `.py` and `.pth`. A native library is GRN-C004's.
- The release's other wheels. GRN-C012 compares them with the wheel this rule reads.
- A wheel file Garnet couldn't parse. It is GRN-E002 when it is new or changed since the
  trusted version, and one over the 5 MB parse limit is GRN-E003, which names this rule. A
  file that parses but is nested too deep for Garnet to list its calls, and isn't in the
  sdist byte for byte, is GRN-E002 naming this rule, unless the trusted version's wheel had
  the same bytes at the same path.

## See also

- `garnet explain GRN-C006` prints this rule's summary and the sensitive call set in your
  terminal.
- [GRN-C007](GRN-C007.md), which compares the wheel with the repository at the release's tag.
- [GRN-C012](GRN-C012.md), which compares the release's other wheels with this one.
- [GRN-C003](GRN-C003.md), the sensitive call set this rule shares.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
