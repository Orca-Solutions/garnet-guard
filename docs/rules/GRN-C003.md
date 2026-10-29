---
id: GRN-C003
name: new-import-time-exec
kind: diff
default_severity: warn
status: implemented
---

# GRN-C003 new-import-time-exec

| | |
|---|---|
| Default severity | `warn` (`info` in test files) |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.1 |

## What it checks

Code that runs when a module is imported gains a call in the
[sensitive call set](#sensitive-call-set). That covers module top-level code and functions it
calls, including code reached from `__init__.py`. Calls are resolved through imports and simple
aliasing by reading the source with `ast`; nothing is executed.

In test files (`tests/`, `test_*.py`, `conftest.py`) it reports at `info`, unless a non-test
module imports the file (directly or through other test modules) or an entry point names it.
Test files usually run only with the package's own test suite, which often starts processes
or opens sockets at module level. An imported test file runs whenever the package is
imported, and one named by an entry point, such as a `pytest11` plugin, loads in every
pytest run, so those stay at `warn`.

## Why it matters

Top-level module code runs the moment anything imports the package, including your test
suite and CI. Libraries rarely start processes, load code or open network connections at
import, so a new call like that deserves a look.

## Example finding

From the [replay](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/incidents.toml) of lightning 2.6.2
([MAL-2026-3201](https://osv.dev/vulnerability/MAL-2026-3201)). A thread started in
`lightning/__init__.py` launched a credential stealer at import.

```text
lightning 2.6.1 → 2.6.2: WARN
  WARN  GRN-C003 new-import-time-exec: 2.6.2 adds import-time calls to sensitive APIs in 1 module(s)
           - lightning/__init__.py:14 calls subprocess.Popen (in _run_runtime(), reached at import)
```

The same rule reported lightning 2.6.3, litellm 1.82.7 and 1.82.8
([PYSEC-2026-2](https://osv.dev/vulnerability/PYSEC-2026-2)), and telnyx 4.87.1 and 4.87.2
([PYSEC-2026-3](https://osv.dev/vulnerability/PYSEC-2026-3)) in the replay. In telnyx 4.87.1 a
typo stopped the payload before it ran; the rule reads code and reports what a module calls
at import, not whether the call succeeds.

## How to resolve it

1. Read the flagged lines.
2. Ask whether the release notes explain them. Some libraries legitimately probe the
   environment at import (for example, checking a GPU driver version with `subprocess`).
3. If the call is expected, merge and add an ignore for this version.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-C003"]
reason = "probes nvidia-smi at import, see release notes for 2.6.2"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-C003" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. The policy format is in [SPEC §7](../SPEC-v1.md#7-policy); 0.1 doesn't read
policy files yet.

## Sensitive call set

A call is sensitive if it resolves, through imports and simple aliasing and without running
any code, to one of these ([SPEC §6.3](../SPEC-v1.md#63-sensitive-call-set)):

- `exec`, `eval`, `compile`, `__import__`
- `importlib.import_module` with a non-literal argument
- `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `pty.spawn`
- `subprocess.*`
- `ctypes.*`
- `socket.*`, `urllib.request.*`, `http.client.*`, `httpx.*`, `requests.*`, `aiohttp.*`
- `base64.*decode` followed by any of the above
- `marshal.loads`, `pickle.loads`

The set is versioned with the rule. `garnet explain GRN-C003` prints the set your version uses.

## See also

- `garnet explain GRN-C003` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
