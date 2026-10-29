---
id: GRN-T004
name: no-matching-tag
kind: diff
default_severity: warn
status: implemented
---

# GRN-T004 no-matching-tag

| | |
|---|---|
| Default severity | `warn` |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.1 |

## What it checks

The trusted version has a matching git tag in the project's source repository and the new
version has none. A tag matches if it is named `X`, `vX`, `<name>-X` or `<name>-vX`, where
`<name>` is the package name. For npm packages `<name>@X` also matches, with or without
the `@scope/`, since monorepo tools tag that way. An exact name wins; otherwise `X` is
compared as a PEP 440 version, so tag `2026.01.04` matches release `2026.1.4`.

Garnet Guard looks for the tag in the repository named by the attestation first, then in
the repository in the package's project URLs, and accepts a tag in either. Some projects
publish from a separate release repository but tag the main one. When no tag is found, the
finding lists every repository it searched. GitHub repositories only, for now.

## Why it matters

Projects that tag releases normally tag every release. A version on the registry with no
tag in the repository was probably not built from the repository's history, which is what
a token-based upload looks like.

## Example finding

From the [replay](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/incidents.toml) of lightning 2.6.2
([MAL-2026-3201](https://osv.dev/vulnerability/MAL-2026-3201)), checked against the tags as
they exist today.

```text
lightning 2.6.1 → 2.6.2: WARN
  WARN  GRN-T004 no-matching-tag: github.com/Lightning-AI/pytorch-lightning has a tag for 2.6.1 but none for 2.6.2
           - 2.6.1 → tag 2.6.1 at 655a3a91828694b9bfc241177f474741e483aeaa <https://github.com/Lightning-AI/lightning/tree/2.6.1>
           - 2.6.2: no tag named 2.6.2, v2.6.2, lightning-2.6.2 or lightning-v2.6.2 <https://github.com/Lightning-AI/pytorch-lightning/tags>
```

The same rule reported lightning 2.6.3 and elementary-data 0.23.3
([MAL-2026-3083](https://osv.dev/vulnerability/MAL-2026-3083)) in the replay.

On npm it is the one signal shared by all four replayed account takeovers. chalk 5.6.1
([MAL-2025-47141](https://osv.dev/vulnerability/MAL-2025-47141)), published from a phished
maintainer account on 2025-09-08, had never used provenance and changed no install script,
so this rule is what reports it:

```text
chalk 5.6.0 → 5.6.1: WARN
  WARN  GRN-T004 no-matching-tag: github.com/chalk/chalk has a tag for 5.6.0 but none for 5.6.1
           - 5.6.0 → tag v5.6.0 at 5c91505e184aff4609c0a7fb235770c2f71db4a3 <https://github.com/chalk/chalk/tree/v5.6.0>
           - 5.6.1: no tag named 5.6.1, v5.6.1, chalk-5.6.1 or chalk-v5.6.1 in github.com/chalk/chalk <https://github.com/chalk/chalk/tags>
```

That is the same observation a debug maintainer made by hand that morning: the version on
npm was not in the repository ([debug-js/debug#1005](https://github.com/debug-js/debug/issues/1005)).

## How to resolve it

1. Check the repository's tags and releases pages. Tags are sometimes pushed late, so look
   again if the release is only minutes old.
2. A missing tag can be an oversight. Ask the maintainers before merging, or wait for the tag.
3. If the project has stopped tagging releases, or uses a tag format Garnet Guard doesn't
   recognize, add an ignore and say so in the reason.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-T004"]
reason = "project tags releases as release/X, confirmed in example/examplelib#90"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-T004" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## See also

- `garnet explain GRN-T004` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
