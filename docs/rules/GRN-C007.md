---
id: GRN-C007
name: code-not-in-source
kind: diff
default_severity: warn
status: implemented
---

# GRN-C007 code-not-in-source

| | |
|---|---|
| Default severity | `warn` |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.2 |

## What it checks

A release is built from its git tag, so every Python file in the wheel should be, byte for
byte, a file in the repository at that tag. Garnet reads the repository's file list at the
tagged commit and compares each `.py` file in the wheel with it (the sdist stands in when
there is no wheel). A file that differs, or has no counterpart, is then asked one more
question: does it contain a call in the [sensitive call set](GRN-C003.md#sensitive-call-set)
that the source file doesn't? Only then does the rule fire. A call the trusted version
already carried outside its source, in the same file, isn't new.

Files that differ from the source are normal: a `_version.py` written by the build, Cython
output, a `__config__.py` with compiler flags. None of those run processes, load code or use
the network, so they stay quiet. In the 974-update clean corpus, 158 updates had at least one
Python file that didn't match the source and none of them had such a call.

The repository is read over GitHub's git protocol on plain HTTPS, the same endpoint as the tag
lookup: one request per tagged release, no token and no API rate limit. Submodules hosted on
GitHub are followed one level. A file under a submodule Garnet can't read is reported as
GRN-E001, never passed.

## Why it matters

The trust rules ask who published the release and from where. This rule asks whether the
release is what that source says it should be. When an attacker controls the build rather
than the repository, the attestation is genuine, the workflow is the usual one, the tag
exists, and nothing in the repository's history shows the payload. ultralytics 8.3.42 (Dec
2024) was published that way: a GitHub Actions cache-poisoning attack injected code into the
wheel during the project's own release run. The two changed files were never committed. The
payload ran when a `YOLO` model was created, not at import, so GRN-C003 had nothing to see.

## Example finding

From the [replay](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/incidents.toml) of ultralytics 8.3.42
([PYSEC-2024-154](https://osv.dev/vulnerability/PYSEC-2024-154)), against the tag as it stood
on the day:

```text
ultralytics 8.3.40 → 8.3.42: WARN
  WARN  GRN-C007 code-not-in-source: 8.3.42 contains code that is not in github.com/ultralytics/ultralytics at tag v8.3.42 (1 file(s))
           - 8.3.42 → tag v8.3.42 at 950d9f73fc3e in github.com/ultralytics/ultralytics; 150 Python file(s) match the source, 2 don't <https://github.com/ultralytics/ultralytics/tree/v8.3.42>
           - ultralytics/utils/downloads.py:292 calls subprocess.Popen (in safe_run()); the source differs from ultralytics/utils/downloads.py at v8.3.42 <https://github.com/ultralytics/ultralytics/blob/950d9f73fc3e12c87e45f4f792281ee8e3cfc75f/ultralytics/utils/downloads.py>
```

The other changed file, `ultralytics/models/yolo/model.py`, is where `YOLO.__init__` gained the call
into `safe_run()`; it has no sensitive call of its own, so it is counted but not listed. Against
today's tags the same update is reported by GRN-T004 instead: the tag was deleted after the
incident, so there is nothing to compare with, and the rule says so by staying silent.

## How to resolve it

1. Open the flagged line in the wheel, then the same file at the tag (the evidence links to
   it). Read what the extra code does.
2. Ask whether the build is supposed to generate it. A project that stamps a version or
   bakes in a platform check at build time will say so in its build scripts, and the extra
   code won't download or run anything.
3. If it is expected, merge and add a time-limited ignore with the reason. If it isn't,
   don't merge, and tell the maintainers: their build, not their repository, produced this
   release.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-C007"]
reason = "build writes _platform.py with a ctypes probe, see tools/build.py"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-C007" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## What it doesn't check

- A release with no matching git tag has nothing to compare against; GRN-T004 reports the
  missing tag instead.
- Files other than `.py`: a `.pth` is GRN-C001's, a binary GRN-C004's.
- Code that was committed to the repository before the release. If the attacker got into the
  repository rather than the build, the code is in the source and this rule is quiet; GRN-C003
  reports it when it runs at import.
- Repositories not on GitHub.

## See also

- `garnet explain GRN-C007` prints this rule's summary in your terminal.
- [GRN-C003](GRN-C003.md), the sensitive call set this rule shares.
- [GRN-T004](GRN-T004.md), which reports a release with no tag at all.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
