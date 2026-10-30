---
id: GRN-C009
name: new-entry-point
kind: diff
default_severity: warn
status: implemented
---

# GRN-C009 new-entry-point

| | |
|---|---|
| Default severity | `warn` for a group another tool loads by itself and for a new script named like a common command; `info` for any other new or changed entry point |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.2 (PyPI wheels) |

## What it checks

A wheel lists its entry points in `*.dist-info/entry_points.txt`: lines of `name = target`
under a `[group]`. Garnet compares the new version's list with the trusted version's and
reports every entry point that is new, or that now points at a different target.

It keeps its `warn` severity for:

- **A group another tool loads without being asked.** The tool imports every entry point in
  the group when it starts, so the target runs inside it:
  - `pytest11`: every pytest run;
  - `setuptools.*`, `distutils.*` and `egg_info.writers`: every setuptools build on the machine;
  - `flake8.extension` and `flake8.report`: every flake8 run;
  - `keyring.backends`: every program that uses keyring;
  - `pygments.*`, `virtualenv.*`, `opentelemetry_*`, `pydantic`, `tox`, `hatch`, `pdm`,
    `poetry.plugin` and `poetry.application.plugin`: the tools of those names.
- **A new script named like a common command**, such as `pip`, `python`, `git`, `curl` or
  `sudo`. It lands in the environment's `bin` folder and can run instead of the real command.
  The project's own command doesn't count (pytest installs `pytest`), and neither does a
  script the trusted version already had that now points somewhere else: the command was
  already there.

Any other new or changed entry point, such as a new console script with the project's own
name, is reported at `info`.

## Why it matters

GRN-C003 reports code that runs when a package is imported. An entry point in an auto-loaded
group runs code without anyone importing the package: installing a malicious pytest plugin
is enough for it to run in every test session, with the project's secrets in the
environment. A `setuptools.finalize_distribution_options` hook runs whenever any package is
built on that machine. Neither shows up as import-time code in the package itself.

## Example finding

Illustrative; not from a real release.

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-C009 new-entry-point: 2.6.2 declares 1 entry point(s) that 2.6.1 didn't, including [pytest11] examplelib
           - [pytest11] examplelib = examplelib._plugin (new); [pytest11] is loaded automatically by the tool that reads it
```

## How to resolve it

1. Read the target the evidence names: the module, and the function after the colon.
2. Find the commit that added the entry point in the project's repository. A library that has
   never been a pytest plugin rarely becomes one in a patch release.
3. If the repository explains the entry point, merge and add a time-limited ignore with the
   reason. If nothing there does, don't merge, and tell the maintainers.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-C009"]
reason = "2.6.2 ships its pytest fixtures as a plugin, see the changelog"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-C009" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## What it doesn't check

- **Sdists.** An sdist's entry points may be computed by `setup.py`, which Garnet never runs,
  so the rule compares wheels only.
- **Groups not on the list.** Many plugin systems load entry points only when configured to.
  A new entry point in one of those groups is reported at `info`.
- **What the target does.** The rule reports that the entry point exists. When the target
  module also runs sensitive calls at import, GRN-C003 reports them, because Garnet already
  counts entry-point modules as live code.

## See also

- `garnet explain GRN-C009` prints this rule's summary in your terminal.
- [GRN-C003](GRN-C003.md), which reports code that runs at import.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
