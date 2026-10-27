---
id: GRN-E004
name: unpinned-requirement
kind: absolute
default_severity: info
status: planned
---

# GRN-E004 unpinned-requirement

| | |
|---|---|
| Default severity | `info` |
| Kind | absolute rule: fires on the new version alone, whatever the trusted version looked like. |
| Status | Specified for 1.0, not yet implemented |

## What it checks

A line in a requirements file isn't pinned to one version (`==` with a full version).

## Why it matters

Garnet Guard compares the version you had with the version you're getting. With a range,
there is no single candidate to compare, and the version installed can change without a
diff anyone reviews.

## Example finding

Illustrative. The rule is specified but not yet implemented.

```text
requirements.txt: INFO
  INFO  GRN-E004 unpinned-requirement: examplelib>=2.6 is not pinned
           - requirements.txt:7
```

## How to resolve it

Pin the requirement, or move to a lockfile (`uv.lock`, `poetry.lock` or `pylock.toml`).
`uv pip compile` and `pip-compile` turn a requirements file into a pinned one.

## Allowlisting

This rule reports at `info`, which doesn't change the verdict. To hide it, turn it off
in policy:

```toml
[garnet.rules]
"GRN-E004" = "off"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. The policy format is in [SPEC §7](../SPEC-v1.md#7-policy); 0.1's `garnet diff`
doesn't read policy files yet.

## See also

- `garnet explain GRN-E004` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
