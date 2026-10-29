---
id: GRN-T008
name: hash-mismatch
kind: absolute
default_severity: block
status: implemented
---

# GRN-T008 hash-mismatch

| | |
|---|---|
| Default severity | `block` |
| Kind | absolute rule: fires on the new version alone, whatever the trusted version looked like. |
| Status | Implemented in 0.1 |

## What it checks

A file Garnet Guard downloaded doesn't match the SHA-256 hash the registry published for it.
Garnet Guard checks every download against the published hash before reading it.

## Why it matters

The bytes you would install are not the bytes the registry listed. That points to tampering
between the registry and you, a misbehaving proxy or mirror, or corruption.

## Example finding

Illustrative; not from a real release.

```text
examplelib 2.6.1 → 2.6.2: BLOCK
  BLOCK GRN-T008 hash-mismatch: 1 downloaded file(s) of 2.6.2 don't match the registry's hash
           - examplelib-2.6.2-py3-none-any.whl: expected 3a7bd3e2…, got 9f86d081…
```

## How to resolve it

1. Don't install.
2. Retry from a different network, without any package proxy or mirror in between.
3. If the mismatch persists on a clean network, report it to the registry's security team.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-T008"]
reason = "internal mirror rewrites wheels; tracked in INFRA-42"
until = "2027-06-30"
acknowledge_critical = true
```

GRN-T008 is one of three critical rules (with [GRN-K001](GRN-K001.md), [GRN-T007](GRN-T007.md)). An ignore doesn't apply to it unless it sets `acknowledge_critical = true`.

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-T008" = "warn"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## See also

- `garnet explain GRN-T008` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
