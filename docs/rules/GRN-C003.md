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
[sensitive call set](#sensitive-call-set). That covers module top-level code and what it runs:
functions it calls or hands to another call, lambdas it calls, classes it instantiates (their
`__init__`) and methods it calls on them, including code reached from `__init__.py`. A
function defined inside one of those and handed to a call is followed too (mrmustard 0.7.4
called a checker at import that started a thread on a `_run` defined inside it). A call
into one of the package's own other modules is followed there, as deep as it goes
(memoryos 2.0.34 ran `get_logger()` at module level, which called a helper, which imported
`_stage0` and ran the function that started a bundled binary), and the finding names the
module whose import started the chain. Calls are resolved through imports and simple
aliasing (`sp = subprocess`), `from os import *`, and `getattr(os, "system")`,
`getattr(sys.modules[__name__], "ctypes")`, `__import__("os")` or
`importlib.import_module("os")` with a literal name, by reading the source with `ast`;
nothing is executed. A dotted name counts only when its first part is a module the file
imports (a local list called `requests` is not the `requests` library), and a function or
class the module defines shadows a builtin of the same name. A `base64` decode whose result
reaches a sensitive call counts as a call of its own, so `exec(base64.b64decode(...))` is
new even in a module that already used `exec`.

A module is new when the trusted version had no module of that name; a file that only moved
or was renamed with a leading underscore is compared with the file it came from. When the
trusted version has the file but it couldn't be parsed (a wheel built for Python 2), the
calls are reported with a note that they may not be new, because Garnet couldn't compare.

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
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

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
