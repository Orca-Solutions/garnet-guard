---
id: GRN-E004
name: unpinned-requirement
kind: absolute
default_severity: info
status: implemented
---

# GRN-E004 unpinned-requirement

| | |
|---|---|
| Default severity | `info` |
| Kind | absolute rule: fires on the new version alone, whatever the trusted version looked like. |
| Status | Implemented in 0.1 (`garnet check`) |

## What it checks

A line in a requirements file isn't pinned to one version (`==` with a full version).
`garnet check` reports lines that are new or changed since the trusted lockfile, so an
unpinned line you already had doesn't repeat on every update.

## Why it matters

Garnet Guard compares the version you had with the version you're getting. With a range,
there is no single candidate to compare, and the version installed can change without a
diff anyone reviews.

## Example finding

Illustrative; not from a real project. This is 0.1's output when `examplelib>=2.6` is
added to a requirements file.

```text
examplelib (new) → unpinned: PASS
  info  GRN-E004 unpinned-requirement: examplelib was not checked: not pinned with == (>=2.6)
           - not pinned with == (>=2.6)
```

The JSON report also gives the file and line in the evidence.

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
matched. The policy format is in [SPEC §7](../SPEC-v1.md#7-policy); 0.1 doesn't read
policy files yet.

## See also

- `garnet explain GRN-E004` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
