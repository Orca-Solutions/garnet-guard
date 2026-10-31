---
id: GRN-E005
name: unsupported-source
kind: absolute
default_severity: info
status: implemented
---

# GRN-E005 unsupported-source

| | |
|---|---|
| Default severity | `info` |
| Kind | absolute rule: fires on the new version alone, whatever the trusted version looked like. |
| Status | Implemented in 0.1 (`garnet check`) |

## What it checks

A dependency comes from a source Garnet Guard doesn't check: a git URL, a local path, a
direct file URL, or a registry other than PyPI and npm. In an npm lockfile, a package
bundled inside another package's tarball (`inBundle`, with no `resolved` URL or integrity
of its own) and an entry whose name breaks npm's naming rules are reported the same way.

## Why it matters

Garnet Guard's rules are written against registry metadata. A dependency from somewhere
else isn't compared at all, and the report says so rather than leaving it out.

## Example finding

Illustrative; not from a real project. This is 0.1's output when a uv.lock entry starts
coming from a git repository.

```text
examplelib (new) → 2.6.2: PASS
  info  GRN-E005 unsupported-source: examplelib was not checked: git source
           - git source
```

The reason after "was not checked" names the source, for example `git source`,
`direct URL or path`, `editable install` or `private index`. From package-lock.json and
yarn.lock it can also be `private registry`, `file: source`, `tarball URL outside the npm
registry`, `bundled in <package>, checked only as part of it`, `resolved URL isn't this
package's registry tarball` or `not a valid npm package name`; an invalid name is shown as
`(invalid name)`, and the lockfile line points at it. The JSON report also gives the file
and line in the evidence.

## How to resolve it

Nothing to do if you meant it. Review changes to that dependency by hand, as you would
any vendored code. A bundled dependency changes only with the package that ships it, so
review that package's update, or the lockfile edit itself if that package didn't change.

## Allowlisting

This rule reports at `info`, which doesn't change the verdict. To hide it, turn it off
in policy:

```toml
[garnet.rules]
"GRN-E005" = "off"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## See also

- `garnet explain GRN-E005` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
