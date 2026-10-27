---
id: GRN-T006
name: files-uploaded-late
kind: absolute
default_severity: warn
status: planned
---

# GRN-T006 files-uploaded-late

| | |
|---|---|
| Default severity | `warn` |
| Kind | absolute rule: fires on the new version alone, whatever the trusted version looked like. |
| Status | Specified for 1.0, not yet implemented |

## What it checks

A file of the new version was uploaded more than 24 hours after the release's first file.

## Why it matters

Registries let a maintainer add files to an existing version, for example a wheel for a new
platform. The same feature lets an attacker with a token add a file to a release that
reviewers already looked at. A late file deserves the same look as a new release.

## Example finding

Illustrative; not from a real release. The rule is specified but not yet implemented.

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-T006 files-uploaded-late: 1 file(s) in 2.6.2 were uploaded more than 24 hours after the first
           - examplelib-2.6.2-cp313-cp313-win_amd64.whl: uploaded 2026-05-04T09:12:00Z, first file 2026-05-01T14:30:00Z
```

## How to resolve it

1. Check the release notes or the project's CI history for a backfilled build (a new Python
   version or platform is the usual reason).
2. Compare the late file with the release's other files of the same kind.
3. If the backfill is expected, merge and add an ignore for this version.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-T006"]
reason = "Windows wheels backfilled by CI run 4567, see example/examplelib#300"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-T006" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. The policy format is in [SPEC §7](../SPEC-v1.md#7-policy); 0.1 doesn't read
policy files yet.

## See also

- `garnet explain GRN-T006` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
