---
id: GRN-C004
name: new-binary
kind: diff
default_severity: warn
status: planned
---

# GRN-C004 new-binary

| | |
|---|---|
| Default severity | `warn` |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Specified for 1.0, not yet implemented |

## What it checks

The new version adds a native executable or shared library that is not a compiled extension
module of a package path the trusted version already had, or the release changes from
pure Python to containing binaries.

## Why it matters

Garnet Guard can read Python source but not machine code. A new binary is content no
reviewer can read in a diff, and it can run when loaded or executed.

## Example finding

Illustrative; not from a real release. The rule is specified but not yet implemented.

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-C004 new-binary: 2.6.2 adds 1 native binary that 2.6.1 didn't have
           - examplelib/bin/helper (ELF executable, 1,204,512 bytes)
```

## How to resolve it

1. Check the release notes and the repository for a new compiled component.
2. Confirm the binary is built by the project's CI (its build logs or attestation).
3. If it is expected, merge and add an ignore. Packages that always ship compiled
   wheels can ignore this rule for all versions.

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
matched. The policy format is in [SPEC §7](../SPEC-v1.md#7-policy); 0.1 doesn't read
policy files yet.

## See also

- `garnet explain GRN-C004` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
