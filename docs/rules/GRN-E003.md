---
id: GRN-E003
name: budget-exceeded
kind: absolute
default_severity: warn
status: implemented
---

# GRN-E003 budget-exceeded

| | |
|---|---|
| Default severity | `warn` |
| Kind | absolute rule: fires on the new version alone, whatever the trusted version looked like. |
| Status | Implemented in 0.1 |

## What it checks

A safety limit was hit while reading the release. The defaults
([SPEC §4.4](../SPEC-v1.md#44-safety-requirements)) are:

| Limit | Default |
|---|---|
| Compressed artifact size | 200 MB |
| Total uncompressed size | 1 GB |
| Entries per archive | 100,000 |
| Compression ratio per entry | 100:1 |
| Single Python file parsed with `ast` | 5 MB |
| Wall-clock budget per change | 120 s |

Policy can lower these limits but not raise them.

## Why it matters

The limits protect your CI from archive bombs and runaway parsing. Content past the limit
was not checked, and this finding says so instead of passing it.

## Example finding

Illustrative; not from a real release.

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-E003 budget-exceeded: a safety limit was hit reading 2.6.2
           - examplelib-2.6.2.tar.gz: entry examplelib/data.bin has compression ratio 1,840:1 (limit 100:1)
```

## How to resolve it

1. Look at what hit the limit. Large data packages and machine learning models are the
   usual reasons; an extreme compression ratio on a small file is not.
2. Review that part of the release by hand.
3. If it is expected, add an ignore for this version.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-E003"]
reason = "ships a 1.2 GB model file; reviewed by hand"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-E003" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. The policy format is in [SPEC §7](../SPEC-v1.md#7-policy); 0.1's `garnet diff`
doesn't read policy files yet.

## See also

- `garnet explain GRN-E003` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
