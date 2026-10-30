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
| Default severity | `warn` for a group another tool loads by itself and for a new script with the name of a common command; `info` for any other new or changed entry point |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.2 (PyPI wheels) |

## What it checks

A wheel lists its entry points in `*.dist-info/entry_points.txt`: lines of `name = target`
under a `[group]`. Garnet compares the new version's entry points with the trusted version's
and reports an entry point (a group and a name) when the new version lists a target for it
that the trusted version didn't, or when a line of it runs that didn't before.

Garnet reads them the way `importlib.metadata` does on Python 3.11 to 3.14, since pytest,
setuptools and pip all find entry points through it:

- **Each metadata folder at the top of site-packages.** Once a wheel is installed,
  `importlib.metadata` treats every folder at the top of `site-packages` whose name ends in
  `.dist-info` or `.egg-info`, in any case, as an installed package, and reads its
  `entry_points.txt`. On the default macOS and Windows file systems that name matches in any
  case too. So Garnet reads that file in each such folder at the wheel's root or under
  `<name>.data/purelib/` or `platlib/`, which install there, and the evidence names any file
  other than the wheel's own `*.dist-info/entry_points.txt`.
- **Every line it would load.** Only a line that starts with `#` is a comment: `;demo = x` is
  an entry point named `;demo`, and `= x` one with an empty name. A header's brackets are
  stripped, so `[[pytest11]]` is the group `pytest11`; Garnet also strips spaces, as
  `pkg_resources` does, so `[ pytest11 ]` counts as `pytest11`. Lines before the first header
  are skipped, as is a line with no `=` (on such a line `importlib.metadata` raises an error, so
  nothing in that file loads).
- **Every line of a repeated name.** A name listed twice in a group keeps both targets, in
  file order. Which one runs depends on the tool, and a new target for a name is always
  reported. Beyond that:
  - pip installs a script's last line in the wheel's own file, so a change in that line is
    reported;
  - pytest, tox and hatch (through pluggy) register a plugin name from the first line they
    read, and a lookup by name returns the first line: `distutils.commands`,
    `pygments.styles`, `pygments.filters` and `pygments.formatters` (pygments returns the
    first line that matches a style, filter or formatter it looks up), the `opentelemetry_*` groups other than the three below, and any group not on the
    list. A target that is now the first line of an `entry_points.txt` and was the first
    line of none of the trusted version's is reported. Tools read the metadata folders in
    the order the file system lists them, so when more than one folder lists the name, the
    evidence says the line runs if its folder is read first;
  - in `setuptools.*`, `distutils.setup_keywords`, `egg_info.writers`, `flake8.extension`,
    `flake8.report`, `keyring.backends`, `pydantic`, `pdm`, `poetry.plugin`,
    `poetry.application.plugin`, `virtualenv.*`, `opentelemetry_instrumentor`,
    `opentelemetry_pre_instrument` and `opentelemetry_post_instrument` the tool loads every
    line, so only a new target counts. Only a new target counts in `pygments.lexers` too:
    pygments picks a lexer by the class a line loads, not by the line's name, and it loads
    every lexer to match a file name or content.

  Lines removed, repeated or reordered with nothing new running are not reported, so
  dropping a duplicate line, a stray copy of a metadata folder or one of two setuptools
  hooks is quiet. The evidence lists a name's first two targets and its last, counts the
  others, names the first new one among them right after that list, and says which one
  runs. Each evidence line is clipped to 1,000 characters.

It keeps its `warn` severity for:

- **A group another tool loads without being asked.** The tool loads entries of the group
  without being configured to, so the target runs inside it, in the environment the package
  is installed in:
  - `pytest11`: every pytest run, unless plugin autoloading is turned off
    (`PYTEST_DISABLE_PLUGIN_AUTOLOAD`);
  - `setuptools.*`, `distutils.*` and `egg_info.writers`: setuptools builds that don't isolate
    themselves (`--no-build-isolation`, `python setup.py`). A
    `setuptools.finalize_distribution_options` hook or an `egg_info.writers` entry runs in each
    such build; a `distutils.commands` or `distutils.setup_keywords` entry when the build uses
    that command or keyword;
  - `flake8.extension` and `flake8.report`: every flake8 run;
  - `keyring.backends`: every program that uses keyring;
  - `pygments.*`, `virtualenv.*`, `opentelemetry_*`, `pydantic`, `tox`, `hatch`, `pdm`,
    `poetry.plugin` and `poetry.application.plugin`: the tools of those names.
- **A new script with the name of a common command**: a `console_scripts` or `gui_scripts`
  name that, ignoring case, is one of `bash`, `cat`, `cp`, `curl`, `docker`, `env`, `gcc`,
  `git`, `gpg`, `grep`, `kubectl`, `ls`, `make`, `mv`, `node`, `npm`, `npx`, `openssl`, `pip`,
  `pip3`, `pipx`, `poetry`, `pytest`, `python`, `python3`, `rm`, `scp`, `sh`, `ssh`, `sudo`,
  `tar`, `tox`, `uv`, `uvx`, `wget`, `which` or `zsh` (the list GRN-C010 uses). It lands in
  the environment's `bin` folder and can run instead of the real command. It counts only in
  the wheel's own `*.dist-info/entry_points.txt`, the one installers make commands from, and
  only when the trusted version's own file didn't list that name, so a script moved there
  from another metadata folder counts as new. The project's own command doesn't count (pytest
  installs `pytest`), and neither does a script the trusted version's own file already had
  that now points somewhere else: the command was already there. A versioned name such as
  `pip3.12` or `python3.12` is not on the list.

Any other new or changed entry point, such as a new console script with the project's own
name, is reported at `info`. The evidence lists the entry points that keep the `warn` first,
25 lines at most, and says how many more there are.

## Why it matters

GRN-C003 reports code that runs when a package is imported. An entry point in an auto-loaded
group runs code without anyone importing the package: installing a malicious pytest plugin
is enough for it to run in every test session in that environment, with the project's
secrets in the environment variables. A `setuptools.finalize_distribution_options` hook runs
in every setuptools build there that doesn't isolate itself. Neither shows up as import-time
code in the package itself.

## Example finding

Illustrative; not from a real release.

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-C009 new-entry-point: 2.6.2 declares 1 entry point(s) that 2.6.1 didn't, including [pytest11] examplelib
           - [pytest11] examplelib = examplelib._plugin (new); [pytest11] is loaded automatically by the tool that reads it
```

## How to resolve it

1. Read the target the evidence names: the module, and the function after the colon.
2. Find the commit that added or changed the entry point in the project's repository. A
   library that has never been a pytest plugin rarely becomes one in a patch release.
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
  so the rule compares wheels only. When either version ships no wheel, including a new
  version that drops its wheel, nothing is compared and nothing is reported.
- **A wheel Garnet couldn't read to the end.** A wheel whose reading stopped at a safety limit
  or an archive error may hold entry points Garnet didn't reach, so it isn't compared. The
  GRN-E003 or GRN-E002 finding names GRN-C009 among the rules not evaluated, as GRN-E001 does
  when a download failed.
- **Metadata installed by another route.** A `.dist-info` or `.egg-info` folder under
  `<name>.data/data/`, such as `demo-1.1.data/data/lib/python3.12/site-packages/`, lands in
  site-packages only under some install schemes and Python versions, and one in a folder that
  a `.pth` file adds to `sys.path` is found only once that file is read. Garnet doesn't read
  the `entry_points.txt` in either. GRN-C010 lists a new file under `.data/data/` at `info`,
  and GRN-C001 warns for a new `.pth` file in site-packages.
- **Groups not on the list.** The list names groups that common tools load by themselves; it
  is not complete. A new entry point in any other group, including one a tool not listed here
  loads on its own, is reported at `info`.
- **Who owns the group.** A tool's own entry points in its own groups warn like anyone else's:
  setuptools adding a command to `distutils.commands` is reported at `warn`.
- **What the target does.** The rule reports that the entry point exists. When the target
  module also makes sensitive calls at import, GRN-C003 reports them, because Garnet counts
  the modules entry points name as live code. A call inside the function the tool calls runs
  only when the tool calls it, so neither rule reports it.

## See also

- `garnet explain GRN-C009` prints this rule's summary in your terminal.
- [GRN-C003](GRN-C003.md), which reports code that runs at import.
- [GRN-C010](GRN-C010.md), which reports a script a wheel ships as a file under
  `<name>.data/scripts/`, such as `demo-1.1.data/scripts/pip`.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
