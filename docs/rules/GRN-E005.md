---
id: GRN-E005
name: unsupported-source
kind: absolute
default_severity: info
status: planned
---

# GRN-E005 unsupported-source

| | |
|---|---|
| Default severity | `info` |
| Kind | absolute rule: fires on the new version alone, whatever the trusted version looked like. |
| Status | Specified for 1.0, not yet implemented |

## What it checks

A dependency comes from a source Garnet Guard doesn't check: a git URL, a local path, a
direct file URL, or a registry other than PyPI and npm.

## Why it matters

Garnet Guard's rules are written against registry metadata. A dependency from somewhere
else isn't compared at all, and the report says so rather than leaving it out.

## Example finding

Illustrative. The rule is specified but not yet implemented.

```text
uv.lock: INFO
  INFO  GRN-E005 unsupported-source: examplelib comes from git+https://github.com/example/examplelib@3f2a1c9, which isn't checked
```

## How to resolve it

Nothing to do if you meant it. Review changes to that dependency by hand, as you would
any vendored code.

## Allowlisting

This rule reports at `info`, which doesn't change the verdict. To hide it, turn it off
in policy:

```toml
[garnet.rules]
"GRN-E005" = "off"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. The policy format is in [SPEC §7](../SPEC-v1.md#7-policy); 0.1's `garnet diff`
doesn't read policy files yet.

## See also

- `garnet explain GRN-E005` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
