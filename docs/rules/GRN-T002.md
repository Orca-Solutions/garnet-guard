---
id: GRN-T002
name: publisher-changed
kind: diff
default_severity: warn
status: implemented
---

# GRN-T002 publisher-changed

| | |
|---|---|
| Default severity | `warn` |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.1 |

## What it checks

The source repository named in the new version's verified attestations differs from the
one named in the trusted version's attestations.

Repository renames that GitHub redirects don't fire: the rule compares GitHub's repository
id, which survives a rename.

## Why it matters

An attestation names the repository whose CI built the release. A different repository
means a different CI published this version. That can be a fork, a move to a new
organization, or an attacker's repository that has been granted publishing rights.

## Example finding

Illustrative; not from a real release.

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-T002 publisher-changed: 2.6.2 was published from github.com/someone-else/examplelib, not github.com/example/examplelib
           - examplelib-2.6.2-py3-none-any.whl: github.com/someone-else/examplelib
```

## How to resolve it

1. Confirm the move from the old home: an announcement or a commit in the old repository,
   or the project's page linking the new one. Don't rely on the release notes or on what the
   new repository says about itself; whoever published the release wrote them.
2. If the move is real, merge and add an ignore for this version. Later releases from the
   new repository compare against this one and stay quiet.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-T002"]
reason = "project moved to the example-org organization (announced in example/examplelib#200)"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-T002" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## See also

- `garnet explain GRN-T002` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
