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

In a wheel, only a `.pth` that lands in `site-packages` itself counts: at the wheel's root
or at the root of its `<name>-<version>.data/purelib/` or `platlib/` folder (the folder's
version is ignored when comparing releases). A `.pth` deeper in the package is never read by
Python. A `.pth` that was only renamed, with the same `import` lines as before, is not new.

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
for a new `litellm_init.pth` that starts a base64 payload, and 23 releases of 23 packages from the
June 2026 Hades campaign (gpsea, pyphetools, ppkt2synergy, bramin, cmd2func, coolbox, dreamgen,
ensmallen, executor-engine, executor-http, funcdesc, magique, magique-ai, mem8, mrbios, napari-ufish,
nucbox, okite, pantheon-agents, pantheon-toolsets, phenopacket-store-toolkit, synago and uprobe) for
a new `<name>-setup.pth` that downloads and runs Bun. For twelve of those packages it was the only
rule that fired. embiggen 0.11.97 from the same campaign was missed at first: the trusted 0.11.96
shipped only an sdist and 0.11.97 only a wheel, so there was no pair of artifacts to compare, and
the content rules passed without saying so. The rule now compares a wheel with an sdist when that
is the only pair, says so in the finding, and reports `embiggen-setup.pth`.

## How to resolve it

1. Read the `.pth` file named in the evidence.
2. Legitimate uses exist: editable installs, namespace package helpers, and tools that
   configure coverage or instrumentation at startup. Look for the file, or the code that
   generates it, in the repository at the release's tag. The release notes alone don't settle
   it: whoever published the release wrote them, an attacker included.
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
