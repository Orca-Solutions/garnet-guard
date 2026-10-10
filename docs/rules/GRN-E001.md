---
id: GRN-E001
name: fetch-failed
kind: absolute
default_severity: warn
status: implemented
---

# GRN-E001 fetch-failed

| | |
|---|---|
| Default severity | `warn` |
| Kind | absolute rule: fires on the new version alone, whatever the trusted version looked like. |
| Status | Implemented in 0.1 |

## What it checks

Data a rule needed couldn't be fetched: registry metadata, a file, an attestation, the tag
list or the OSV advisory list. The finding names which rules were not evaluated. With
`--offline`, anything missing from the cache is reported here.

## Why it matters

Garnet Guard never treats a check it couldn't run as a pass. If this finding were dropped,
an update could look clean only because the network failed.

## Example finding

Illustrative.

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-E001 fetch-failed: Couldn't evaluate GRN-T004: tag lookup failed
           - tag lookup: HTTP 503 from github.com/example/examplelib.git/info/refs
```

## How to resolve it

1. Re-run with network access. Most of these are transient.
2. If it keeps failing, open the URL in the evidence yourself; a rate limit, proxy or
   firewall is the usual cause. For GitHub rate limits, pass a token with
   `--github-token-env`.
3. If a source is permanently unreachable from your CI, you can lower this rule to `info`
   in policy, but the rules it names stay unchecked.

## Allowlisting

Prefer fixing the cause: while this finding stands, the rules it names were not
evaluated. If you accept that for your project, change its severity in policy:

```toml
[garnet.rules]
"GRN-E001" = "info"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. The policy format is in [SPEC §7](../SPEC-v1.md#7-policy); 0.1's `garnet diff`
doesn't read policy files yet.

## See also

- `garnet explain GRN-E001` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
