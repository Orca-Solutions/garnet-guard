---
id: GRN-T006
name: files-uploaded-late
kind: absolute
default_severity: warn
status: implemented
---

# GRN-T006 files-uploaded-late

| | |
|---|---|
| Default severity | `warn`; `info` when every late file only adds Python versions or platforms |
| Kind | absolute rule: fires on the new version alone, whatever the trusted version looked like. |
| Status | Implemented in 0.2 (PyPI; an npm version has a single tarball) |

## What it checks

A file of the new version was uploaded more than 24 hours after the release's first file.
Upload times come from PyPI's JSON API, one per file. Each late file is listed with when it
arrived and how long after the first one.

The rule then asks, for each late wheel, whether pip would install it where it installed a
file that was uploaded on time. It builds the machines the release's wheels are made for
from their own tags (a Python version, and a platform such as Linux x86_64 with glibc 2.28,
macOS 11.0 arm64 or 64-bit Windows) and ranks the wheels on each one in pip's order. The
machine Garnet runs on plays no part. It is a warning when a late file:

- is the release's first wheel, since pip installs a wheel before an sdist;
- ranks above an on-time wheel on some machine, for example a platform wheel added to a
  pure-Python release, a wheel for one Python version beside an `abi3` wheel, or a wheel for
  a newer glibc or macOS than the on-time one;
- has the same tags as an on-time wheel, where a build number or pip's file order decides; or
- has a higher build number than the on-time wheel with its tags.

When no late file does any of these, each one fits only machines that had no wheel to install
before (pip built the sdist there, or had nothing to install), and the finding is `info`. That
is how compiled projects add a new Python version or platform after a release.

## Why it matters

Registries let a maintainer add files to an existing version, for example a wheel for a new
platform. The same feature lets an attacker with a token add a file to a release that
reviewers already looked at. pip installs the most specific wheel for the machine, so a late
wheel can be the file that installs in place of the one reviewers saw. A late file deserves
the same look as a new release.

Garnet reads the wheel pip would install on the machine it runs on (SPEC §4.2), so a late
wheel for that machine also gets the content rules. Late files for other machines get this
rule only.

## Example finding

From the 974-update clean corpus: 96 days after cffi 1.14.5 came out, its aarch64 wheels were
uploaded again under file names that add the `manylinux_2_17` tag, so each new file has the
same tags as one uploaded on time. Nothing marks these files as malicious, but it is the shape
of a file slipped into a reviewed release. The listing is cut after the first two files.

```text
cffi 1.14.4 → 1.14.5: WARN
  WARN  GRN-T006 files-uploaded-late: 12 file(s) of 1.14.5 were uploaded more than 24 hours after its first file, and 4 can replace a file uploaded on time
           - cffi-1.14.5-cp37-cp37m-manylinux_2_17_aarch64.manylinux2014_aarch64.whl: uploaded 2021-05-19T04:18Z, 96 days after the first file (cffi-1.14.5-cp27-cp27m-macosx_10_9_x86_64.whl, 2021-02-11T20:59Z); it has the same tags as cffi-1.14.5-cp37-cp37m-manylinux2014_aarch64.whl, so on CPython 3.7 on Linux aarch64 with glibc 2.17 pip may install either
           - cffi-1.14.5-cp36-cp36m-manylinux_2_17_aarch64.manylinux2014_aarch64.whl: uploaded 2021-05-19T04:18Z, 96 days after the first file (cffi-1.14.5-cp27-cp27m-macosx_10_9_x86_64.whl, 2021-02-11T20:59Z); it has the same tags as cffi-1.14.5-cp36-cp36m-manylinux2014_aarch64.whl, so on CPython 3.6 on Linux aarch64 with glibc 2.17 pip may install either
```

The corpus's other warning is iniconfig 1.1.1, whose only wheel arrived two days after its
sdist. Eleven more updates (lxml, markupsafe, pillow, pyyaml, cffi 1.14.6) backfilled wheels
for new Python versions and platforms and are reported at `info`.

## How to resolve it

1. Find the build that made the late file in the project's repository: a CI run on the
   release's tag that uploaded it, or a commit or issue that explains a rebuild.
2. Compare the late file with the on-time file the evidence says it can replace. For a
   rebuild of the same code, their Python files match.
3. If nothing in the repository explains the late file, don't merge until the maintainers
   confirm they uploaded it.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-T006"]
reason = "aarch64 wheels rebuilt by CI run 4567 on the v2.6.2 tag, see example/examplelib#300"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-T006" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## See also

- `garnet explain GRN-T006` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
