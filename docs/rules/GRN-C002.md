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
`postinstall` running `node bundle.js`. The Python case is illustrative, not from a real
release:

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-C002 new-build-hook: 2.6.2 adds code that runs when the sdist is built
           - setup.py:41 calls urllib.request.urlopen
```

## How to resolve it

1. Read the `setup.py` diff or the new backend named in the evidence. For npm, read the
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

- `exec`, `eval`, `compile`, `__import__`
- `importlib.import_module` with a non-literal argument
- `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `pty.spawn`
- `subprocess.*`
- `ctypes.*`
- `socket.*`, `urllib.request.*`, `http.client.*`, `httpx.*`, `requests.*`, `aiohttp.*`
- `base64.*decode` followed by any of the above
- `marshal.loads`, `pickle.loads`

The set is versioned with the rule. `garnet explain GRN-C002` prints the set your version uses.

## See also

- `garnet explain GRN-C002` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
