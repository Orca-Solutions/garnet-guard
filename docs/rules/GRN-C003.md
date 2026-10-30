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
finding says so in its title and notes that the calls may not be new, because Garnet
couldn't compare.

Three kinds of call are reported at `info`, each in its own finding, because the source
does not show them running when the package is imported. A call that a package module
reaches at import is reported once, at `warn`, whatever else reaches it:

- Calls in test files (a `tests/` folder, a top-level `test/` folder, `test_*.py`,
  `conftest.py`), or reached only from one,
  unless a non-test module imports the file (directly or through other test modules) or an
  entry point names it. Test files usually run only with the package's own test suite,
  which often starts processes or opens sockets at module level. An imported test file
  runs whenever the package is imported, and one named by an entry point, such as a
  `pytest11` plugin, loads in every pytest run, so those stay at `warn`.
- Calls in sdist files outside the package, or reached only from one: `docs/conf.py`,
  `examples/`, `benchmarks/`, or a lexer that ply 3.6's `example/` scripts build at import.
  They ship in the sdist but not in the installed package, and run only when run on their
  own.
- Calls in a function that import-time code only handed to another call, when nothing says
  that call runs it: `functools.partial(f)`, `map(f, xs)`, a wrapper or compose helper.
  The evidence reads `handed to functools.partial() at import`. A function handed to a
  call that does run it, such as `threading.Thread(target=f)`, `atexit.register(f)` or
  `executor.submit(f)`, is reported at `warn` as reached at import, which is how lightning
  2.6.2 and mrmustard 0.7.4 ran their payloads.

A fourth finding at `info` lists what the same import-time code newly
[reads that a credential stealer reads](#credential-and-ci-reads): a read is not a call, but
it says where a payload would look and when it would run.

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
([PYSEC-2026-2](https://osv.dev/vulnerability/PYSEC-2026-2)), telnyx 4.87.1 and 4.87.2
([PYSEC-2026-3](https://osv.dev/vulnerability/PYSEC-2026-3)), ultralytics 8.3.45 and 8.3.46,
xinference 2.6.0 to 2.6.2, mistralai 2.4.6, guardrails-ai 0.10.1 and durabletask 1.4.1 to 1.4.3
in the replay. In telnyx 4.87.1 a typo stopped the payload before it ran; the rule reads code
and reports what a module calls at import, not whether the call succeeds.

What it missed in the replay, and what changed:

- **ultralytics 8.3.41 and 8.3.42**: the miner runs when a model is downloaded, not at import,
  so this rule stays quiet by design. [GRN-C007](GRN-C007.md) reports 8.3.42 instead.
- **num2words 0.5.15 and 0.5.16**: `__init__.py` loads a DLL through
  `getattr(ctypes, "CDLL")`. The rule did not follow calls made through `getattr`; it now
  resolves a `getattr` with a literal name and reports `ctypes.CDLL`.
- **memoryos 2.0.34**: the payload starts from a logging setup function in another module. The
  rule stopped at the first module; it now follows the chain through the package's own modules.
- **mrmustard 0.7.4** ([MAL-2026-11049](https://osv.dev/vulnerability/MAL-2026-11049)):
  `__init__.py` calls a new function at import, and that function starts a thread whose target
  is a function defined inside it, where `subprocess` and `urllib.request` are called. The rule
  followed only module-level functions; it now follows a nested function handed to a call.

## How to resolve it

1. Read the flagged lines.
2. Find them in the repository: the commit on the default branch that added them, at the
   release's tag. Some libraries legitimately probe the environment at import (for example,
   checking a GPU driver version with `subprocess`). The release notes alone don't settle it:
   whoever published the release wrote them, an attacker included.
3. Read any condition around the call as evidence, not reassurance. Code that runs only in CI,
   or only when a token is set, is how a credential stealer stays quiet on a developer's
   machine and runs where the secrets are.
4. If the call is expected, merge and add an ignore for this version.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-C003"]
reason = "probes nvidia-smi at import, added in example/examplelib#512"
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

- `exec`, `eval`, `compile`, `__import__`, `importlib.__import__`
- `importlib.import_module` with a non-literal argument
- code loaded from a file or built from a code object: `runpy.*`, `zipimport.*`,
  `importlib.util.spec_from_file_location`, `importlib.util.spec_from_loader`,
  `importlib.machinery.SourceFileLoader`, `SourcelessFileLoader` and `ExtensionFileLoader`,
  `imp.load_source`, `load_compiled`, `load_dynamic`, `load_module` and `load_package`,
  `types.FunctionType` and its alias `types.LambdaType`, `types.CodeType`
- `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `os.posix_spawn*`, `os.fork`, `os.forkpty`,
  `os.startfile`, `pty.spawn`, `pty.fork`
- `subprocess.*`, `_posixsubprocess.*`, `asyncio.create_subprocess_exec`,
  `asyncio.create_subprocess_shell`, `multiprocessing.Process`, the `SpawnProcess`,
  `ForkProcess` and `ForkServerProcess` classes in `multiprocessing.context`,
  `_winapi.CreateProcess`, `distutils.spawn.spawn` and the same function in `distutils.util`,
  `distutils.ccompiler` and `distutils.archive_util`, `pydoc.pipepager`, `pydoc.tempfilepager`
- `ctypes.*`
- `socket.*` and the `ssl.create_connection` and `ssl.socket` that `ssl` imports from it,
  `asyncio.open_connection`, `asyncio.open_unix_connection`, `asyncio.start_server`,
  `asyncio.start_unix_server`, `ftplib.*`, `smtplib.*`, `poplib.*`, `imaplib.*`, `telnetlib.*`,
  `xmlrpc.client.*`, `webbrowser.*`
- `urllib.request.*`, `http.client.*`, `httpx.*`, `requests.*`, `aiohttp.*`, and urllib3's pool
  managers, connection pools and connections: `urllib3.PoolManager`, `ProxyManager`,
  `HTTPConnectionPool`, `HTTPSConnectionPool`, `connection_from_url`, `proxy_from_url` and
  `request`, `urllib3.connection.HTTPConnection`, `HTTPSConnection` and its alias
  `VerifiedHTTPSConnection`, `urllib3.contrib.socks.SOCKSProxyManager`
- `base64.*decode` followed by any of the above
- `marshal.loads`, `pickle.loads`

A name under a module that holds the same object as a listed name, because it defines it or
imports it, counts as the listed name: `builtins` for the bare names (`builtins.exec` is
`exec`, and in a script `__builtins__` is the same module), `posix` and `nt` for `os`
(`posix.system` is `os.system`), `_socket` for `socket`, `_ctypes` for `ctypes`, `_pickle`
for `pickle`, `asyncio.subprocess` and `asyncio.streams` for `asyncio`,
`multiprocessing.context` for `multiprocessing`, `importlib._bootstrap` and
`_frozen_importlib` for `importlib` and `importlib.util`, `importlib._bootstrap_external`
and `_frozen_importlib_external` for `importlib.util` and `importlib.machinery`,
`setuptools._distutils` for `distutils`, `urllib3.poolmanager` for `urllib3`, and
`urllib3.connectionpool` for `urllib3` and `urllib3.connection`. The evidence names the call
as the code writes it.

GRN-C003 follows a call into one of the release's own top-level packages into that module. When
the call's name is in the set it counts as a sensitive call as well, unless the release is the
library of that name: the `requests` project, as its wheel or sdist filename names it, calling
its own `requests.adapters` isn't reported, and GRN-C007 leaves it out. A module that any other
release ships under a name in the set may not be what Python imports: the standard library's
`os` comes before an `os.py` in site-packages, an installed `requests` package before a
`requests.py` beside it, and `builtins` is built in. So with an empty `os.py`, `requests.py` or
`builtins.py` beside the package, `os.system`, `requests.post` and `builtins.exec` still count,
and the call is followed into the release's module too, in case that is the one Python imports.

Set `2026-10-c` (October 30, 2026) added the file loaders, the process calls outside
`subprocess`, more network clients (`asyncio` streams, `urllib3`, mail, FTP, telnet, XML-RPC and
the browser), and the modules that define or import listed names. Left out, because packages
make these calls at import for ordinary reasons: `importlib.util.find_spec` and
`module_from_spec`, `urllib3.disable_warnings`, `multiprocessing.cpu_count`,
`distutils.spawn.find_executable`. Not in the set, because no corpus run has measured what they
would add: `pickle.load` and `pickle.Unpickler`, `multiprocessing.Pool`,
`concurrent.futures.ProcessPoolExecutor` and `importlib.machinery.PathFinder`. A listed function
passed to another call rather than called (`atexit.register(os.system, cmd)`,
`threading.Thread(target=os.system)`) isn't seen, and neither is a listed name reached through
what a call returns (`multiprocessing.get_context("spawn").Process`) or looked up by subscript
(`__builtins__["exec"]`).

The set is versioned with the rule. `garnet explain GRN-C003` prints the set your version uses.

## Credential and CI reads

Code that runs at import and reads one of these, where the trusted version's module didn't, is
listed in its own finding at `info` (read set `2026-10-a`):

- an environment variable named `CI` or `GOOGLE_APPLICATION_CREDENTIALS`, starting with
  `GITHUB_`, `ACTIONS_`, `AWS_`, `AZURE_`, `GCP_`, `NPM_`, `PYPI_` or `TWINE_`, or ending in
  `_TOKEN`, `_SECRET`, `_SECRET_KEY`, `_API_KEY`, `_ACCESS_KEY` or `_PASSWORD`, read with
  `os.environ[...]`, `os.environ.get`, `os.getenv` or `"CI" in os.environ`;
- the whole environment: `dict(os.environ)`, `os.environ.copy()`, `{**os.environ}`, or
  `os.environ` passed to a call (but not as `env=`, which only hands it to a process);
- a cloud metadata address: `169.254.169.254`, `169.254.170.2`, `fd00:ec2::254`,
  `metadata.google.internal` or `100.100.100.200`.

Reads in test files, in sdist files outside the package and in functions only handed to a
call are left out, as are writes (`os.environ["CI"] = "1"`). The finding never raises a
verdict on its own. Next to a new sensitive call it shows the condition the call runs under:
malware that runs only in CI, where the secrets are, reads `CI` or `GITHUB_ACTIONS` first.

## See also

- `garnet explain GRN-C003` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
