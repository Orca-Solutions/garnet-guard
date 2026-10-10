---
id: GRN-T007
name: invalid-attestation
kind: absolute
default_severity: block
status: implemented
---

# GRN-T007 invalid-attestation

| | |
|---|---|
| Default severity | `block` |
| Kind | absolute rule: fires on the new version alone, whatever the trusted version looked like. |
| Status | Implemented in 0.1 |

## What it checks

An attestation is present for a file of the new version but fails Sigstore verification.

## Why it matters

A broken or forged attestation is worse than none: something tried to look trustworthy and
failed. Legitimate CI produces attestations that verify.

## Example finding

Illustrative; not from a real release.

```text
examplelib 2.6.1 → 2.6.2: BLOCK
  BLOCK GRN-T007 invalid-attestation: 1 attestation(s) in 2.6.2 failed verification
           - examplelib-2.6.2-py3-none-any.whl: signature does not match the file's digest
```

## How to resolve it

1. Don't install.
2. Re-run once. A verification failure can come from an outdated Sigstore trust root on your
   side; upgrading Garnet Guard refreshes it.
3. If it persists, report it to the project and to the registry's security team
   (security@pypi.org for PyPI).

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-T007"]
reason = "registry confirmed a broken attestation upload, see example/examplelib#400"
until = "2027-06-30"
acknowledge_critical = true
```

GRN-T007 is one of three critical rules (with [GRN-K001](GRN-K001.md), [GRN-T008](GRN-T008.md)). An ignore doesn't apply to it unless it sets `acknowledge_critical = true`.

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-T007" = "warn"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. The policy format is in [SPEC §7](../SPEC-v1.md#7-policy); 0.1's `garnet diff`
doesn't read policy files yet.

## See also

- `garnet explain GRN-T007` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
