---
id: GRN-T003
name: workflow-changed
kind: diff
default_severity: warn
status: implemented
---

# GRN-T003 workflow-changed

| | |
|---|---|
| Default severity | `warn` |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.1 |

## What it checks

The new version was attested by the same repository as the trusted version, but by a
different workflow file or with a different deployment environment (or none).

## Why it matters

Projects that publish from CI usually protect the publishing step: one workflow, often
behind a deployment environment that needs a reviewer's approval. Moving publishing to a
new workflow, or dropping the environment, skips those protections. It is a common step
when someone gains write access to a repository but not to its release approvals.

## Example finding

Illustrative; not from a real release.

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-T003 workflow-changed: 2.6.2 was published by a different workflow setup: workflow release.yml → ci.yml; environment pypi → none
           - examplelib-2.6.2-py3-none-any.whl: .github/workflows/ci.yml env=none
```

## How to resolve it

1. Find the commit in the project's repository that added or changed the publishing
   workflow, and who reviewed it.
2. If the change is deliberate and reviewed, merge and add an ignore for this version.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-T003"]
reason = "publishing moved to ci.yml in example/examplelib#150, reviewed by maintainers"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-T003" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. The policy format is in [SPEC §7](../SPEC-v1.md#7-policy); 0.1 doesn't read
policy files yet.

## See also

- `garnet explain GRN-T003` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
