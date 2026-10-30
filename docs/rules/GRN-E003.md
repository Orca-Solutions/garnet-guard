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

Policy can lower these limits but not raise them. In 0.1 the wall-clock budget isn't
enforced yet, and limits can't be changed; each network request has its own timeout.

[GRN-C012](GRN-C012.md) compares up to 10 wheels uploaded late. When a release has more,
the rest aren't read, and this rule lists them in file-name order, naming GRN-C012.

## Why it matters

The limits protect your CI from archive bombs and runaway parsing. A late wheel past the 10
that GRN-C012 compares can carry Python code the wheel Garnet read doesn't. Content past a
limit, and a late wheel past the cap, was not checked, and this finding says so instead of
passing it.

## Example finding

Illustrative; not from a real release. This is 0.1's output for a synthetic sdist with a
40 MB file of zeros in it.

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-E003 budget-exceeded: Couldn't fully check 2.6.2: examplelib-2.6.2.tar.gz: archive exceeds compression ratio limit
           - examplelib-2.6.2.tar.gz: archive exceeds compression ratio limit
           - not evaluated: GRN-C001, GRN-C003
```

## How to resolve it

1. Look at what hit the limit. Large data packages and machine learning models are the
   usual reasons; an extreme compression ratio on a small file is not. Late wheels past
   GRN-C012's 10 are listed by file name, and GRN-T006 reports them as late files too.
2. Review that part of the release by hand. For late wheels, compare each one's Python files
   with the wheel Garnet read; the cap of 10 isn't a policy setting.
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
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## See also

- `garnet explain GRN-E003` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
