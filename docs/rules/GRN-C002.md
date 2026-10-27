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

- a new or changed `setup.py` adds a call in the [sensitive call set](#sensitive-call-set);
- the build backend changed to one that is not on the allowlist, or to an in-tree backend;
- an npm `preinstall`, `install`, `postinstall` or `prepare` script was added or changed
  (npm support is planned for 1.0).

Build backends on the allowlist: `setuptools.build_meta`, `setuptools.build_meta:__legacy__`,
`hatchling.build`, `flit_core.buildapi`, `poetry.core.masonry.api`, `poetry_core.masonry.api`,
`pdm.backend`, `pdm.pep517.api`, `maturin`, `scikit_build_core.build`, `mesonpy`, `uv_build`,
`pbr.build`, `whey`, `sipbuild.api`, `enscons.api`.

## Why it matters

Code in `setup.py`, a custom build backend or an npm install script runs on your machine when
the package is built or installed, before you ever import it. It runs in CI with whatever
credentials CI has.

## Example finding

Illustrative; not from a real release.

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-C002 new-build-hook: 2.6.2 adds code that runs when the sdist is built
           - setup.py:41 calls urllib.request.urlopen
```

## How to resolve it

1. Read the `setup.py` diff or the new backend named in the evidence.
2. Prefer installing a wheel if the release has one for your platform: wheels don't run
   build code. (`pip install --only-binary :all:` or `uv pip install --no-build`.)
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

The set is versioned with the rule. `garnet explain GRN-C002` prints the set your version uses.

## See also

- `garnet explain GRN-C002` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
