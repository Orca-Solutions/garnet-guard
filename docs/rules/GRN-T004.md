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
`<name>` is the package name. An exact name wins; otherwise `X` is compared as a PEP 440
version, so tag `2026.01.04` matches release `2026.1.4`.

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
([MAL-2026-3201](https://osv.dev/vulnerability/MAL-2026-3201)). The replay checks the tags as
they stood when the release was uploaded; for lightning they are the same today.

```text
lightning 2.6.1 → 2.6.2: WARN
  WARN  GRN-T004 no-matching-tag: github.com/Lightning-AI/pytorch-lightning has a tag for 2.6.1 but none for 2.6.2
           - 2.6.1 → tag 2.6.1 at 655a3a91828694b9bfc241177f474741e483aeaa <https://github.com/Lightning-AI/lightning/tree/2.6.1>
           - 2.6.2: no tag named 2.6.2, v2.6.2, lightning-2.6.2 or lightning-v2.6.2 <https://github.com/Lightning-AI/pytorch-lightning/tags>
```

The same rule reported lightning 2.6.3 and telnyx 4.87.1 and 4.87.2
([PYSEC-2026-3](https://osv.dev/vulnerability/PYSEC-2026-3)) in the replay.

Three replays show what this rule can and can't see:

- **elementary-data 0.23.3** ([MAL-2026-3083](https://osv.dev/vulnerability/MAL-2026-3083)):
  no finding on the day. The attacker controlled the project's CI and pushed a `v0.23.3` tag
  on an orphan commit before publishing, so a matching tag existed when the release went out
  ([StepSecurity](https://www.stepsecurity.io/blog/elementary-data-compromised-on-pypi-and-ghcr-forged-release-pushed-via-github-actions-script-injection)).
  The tag has since been deleted, so checking today's tags would report it. GRN-C001 caught
  the release instead. An attacker who can push to the repository can create a tag, so this
  rule is evidence of an upload from outside the repository, not proof that a release came
  from the project.
- **telnyx 4.87.1**: reported on the day, not today. The release was uploaded with a stolen
  token and had no tag. Telnyx later published its own 4.87.1 tag, so checking today's tags
  would miss it.
- **litellm 1.82.7 and 1.82.8**: no finding. litellm tags its builds `v1.82.6-nightly`,
  `v1.82.6.rc.1` and so on, never plain `1.82.6`, so the trusted version had no matching tag
  to lose.

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
matched. The policy format is in [SPEC §7](../SPEC-v1.md#7-policy); 0.1 doesn't read
policy files yet.

## See also

- `garnet explain GRN-T004` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
