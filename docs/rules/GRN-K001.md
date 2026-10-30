---
id: GRN-K001
name: known-malicious
kind: absolute
default_severity: block
status: implemented
---

# GRN-K001 known-malicious

| | |
|---|---|
| Default severity | `block` |
| Kind | absolute rule: fires on the new version alone, whatever the trusted version looked like. |
| Status | Implemented in 0.1 |

## What it checks

[OSV](https://osv.dev) lists a `MAL-` advisory affecting the new version. `MAL-` advisories
come from the OpenSSF malicious packages project and other malware feeds that publish to OSV.

## Why it matters

A malware feed has already reported this version as malicious. Other rules look for signs;
this one is a match against a published report.

## Example finding

From OSV. The replay versions are listed there:
[MAL-2026-3201](https://osv.dev/vulnerability/MAL-2026-3201) (lightning 2.6.2 and 2.6.3) and
[MAL-2026-3083](https://osv.dev/vulnerability/MAL-2026-3083) (elementary-data 0.23.3),
[PYSEC-2026-2](https://osv.dev/vulnerability/PYSEC-2026-2) (litellm 1.82.7 and 1.82.8) and
[PYSEC-2026-3](https://osv.dev/vulnerability/PYSEC-2026-3) (telnyx 4.87.1 and 4.87.2). The
[replay](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/incidents.toml) judges releases from content alone and doesn't count this rule.

```text
lightning 2.6.1 → 2.6.2: BLOCK
  BLOCK GRN-K001 known-malicious: OSV lists lightning 2.6.2 as malicious
           - MAL-2026-3201 <https://osv.dev/vulnerability/MAL-2026-3201>
```

## How to resolve it

1. Don't install.
2. If the version is already installed anywhere (a laptop, CI, an image), treat that
   environment as compromised: rotate every credential it could reach and rebuild it.
3. Pin to the last version you trusted until the project publishes a clean release.
4. If you think the advisory is wrong, raise it with the advisory's source through OSV
   before ignoring it.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-K001"]
reason = "advisory disputed with its source; version never deployed"
until = "2027-06-30"
acknowledge_critical = true
```

GRN-K001 is one of three critical rules (with [GRN-T007](GRN-T007.md), [GRN-T008](GRN-T008.md)). An ignore doesn't apply to it unless it sets `acknowledge_critical = true`.

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-K001" = "warn"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## See also

- `garnet explain GRN-K001` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
