---
id: GRN-C001
name: new-pth-file
kind: diff
default_severity: warn
status: implemented
---

# GRN-C001 new-pth-file

| | |
|---|---|
| Default severity | `warn` |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.1 |

## What it checks

The new version contains a `.pth` file at a path the trusted version didn't have, or an
existing `.pth` file gained executable lines (lines starting with `import`).

## Why it matters

Python runs the `import` lines of every `.pth` file in site-packages each time the
interpreter starts, for every program on the machine, before any of your code. Almost no
package needs a new one, and it is an effective way to run code without the package ever
being imported.

## Example finding

From the [replay](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/incidents.toml) of elementary-data 0.23.3
([MAL-2026-3083](https://osv.dev/vulnerability/MAL-2026-3083)). The release was published by
the project's own CI after a GitHub Actions script injection, so its provenance looked
normal; the content change is what stands out.

```text
elementary-data 0.23.2 → 0.23.3: WARN
  WARN  GRN-C001 new-pth-file: 0.23.3 adds code that runs at every Python startup (.pth)
           - new elementary.pth (246,691 bytes, 1 executable line(s)): import os, subprocess, tempfile, base64; x = os.path.join(tempfile.gettempdir(), ".trinny-security-update"); result = "ignore" if os.path.exists(x) else exec(b…
```

The same rule reported litellm 1.82.8 ([PYSEC-2026-2](https://osv.dev/vulnerability/PYSEC-2026-2))
for a new `litellm_init.pth` that starts a base64 payload, and gpsea 0.9.14, pyphetools 0.9.120
and ppkt2synergy 0.1.1 (the June 2026 Hades campaign) for a new `<name>-setup.pth` that downloads
and runs Bun. It missed embiggen 0.11.97 from the same campaign: the trusted 0.11.96 shipped only
an sdist and 0.11.97 only a wheel, so there was no pair of artifacts to compare, and the content
rules passed without saying so. That's a bug, and a fix is planned.

## How to resolve it

1. Read the `.pth` file named in the evidence.
2. Legitimate uses exist: editable installs, namespace package helpers, and tools that
   configure coverage or instrumentation at startup. The release notes usually say so.
3. A `.pth` line that decodes, downloads or executes anything is a reason not to merge.
   Report it to the project and the registry.
4. If the file is expected, merge and add an ignore for the versions that ship it.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = ">=3.0"
rules = ["GRN-C001"]
reason = "ships examplelib-coverage.pth to start coverage in subprocesses, documented in its README"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-C001" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## See also

- `garnet explain GRN-C001` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
