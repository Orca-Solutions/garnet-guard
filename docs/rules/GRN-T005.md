---
id: GRN-T005
name: outside-trusted-publishing
kind: diff
default_severity: warn
status: implemented
---

# GRN-T005 outside-trusted-publishing

| | |
|---|---|
| Default severity | `warn` |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.1 |

## What it checks

Files of the trusted version were published through Trusted Publishing, and at least one
file of the new version carries an attestation that was not.

## Why it matters

Trusted Publishing lets a registry accept uploads only from a named CI workflow, with no
long-lived token to steal. A file that arrived some other way bypassed that control.

On PyPI today an attestation implies Trusted Publishing, so a file without either is
reported by [GRN-T001](GRN-T001.md) and this rule stays quiet. It exists for registries
that separate the two.

## Example finding

Illustrative; not from a real release.

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-T005 outside-trusted-publishing: 1 file(s) in 2.6.2 were attested outside Trusted Publishing
           - examplelib-2.6.2.tar.gz
```

## How to resolve it

As for [GRN-T001](GRN-T001.md): look for a release workflow run and a tag, check the
project's advisories, and add a time-limited ignore only after the maintainers confirm the
upload.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-T005"]
reason = "maintainers confirmed a manual sdist upload in example/examplelib#123"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-T005" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. The policy format is in [SPEC §7](../SPEC-v1.md#7-policy); 0.1's `garnet diff`
doesn't read policy files yet.

## See also

- `garnet explain GRN-T005` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
