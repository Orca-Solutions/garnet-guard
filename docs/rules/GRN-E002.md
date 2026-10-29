---
id: GRN-E002
name: parse-failed
kind: absolute
default_severity: warn
status: implemented
---

# GRN-E002 parse-failed

| | |
|---|---|
| Default severity | `warn` |
| Kind | absolute rule: fires on the new version alone, whatever the trusted version looked like. |
| Status | Implemented in 0.1 |

## What it checks

An artifact, or a new or changed file inside one, couldn't be parsed: for example a `.py`
file that isn't valid Python 3 syntax, or metadata that doesn't follow its format.

## Why it matters

Content rules couldn't look inside the file, so they didn't pass it either. Python that
doesn't parse can still be loaded in other ways, and malformed files are sometimes made
that way on purpose to slip past scanners.

## Example finding

Illustrative; not from a real release.

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-E002 parse-failed: 1 new or changed Python file(s) in 2.6.2 couldn't be parsed
           - examplelib/_legacy.py: not valid Python 3 syntax
```

## How to resolve it

1. Look at the file named in the evidence.
2. Python 2 leftovers and templates with a `.py` extension are the common harmless causes.
3. If you've read it and it is expected, add an ignore for this version.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-E002"]
reason = "_legacy.py is a Python 2 template that is never imported"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-E002" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## See also

- `garnet explain GRN-E002` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
