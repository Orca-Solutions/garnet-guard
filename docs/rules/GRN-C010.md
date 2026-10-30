---
id: GRN-C010
name: new-startup-file
kind: diff
default_severity: warn
status: implemented
---

# GRN-C010 new-startup-file

| | |
|---|---|
| Default severity | `warn` for `sitecustomize.py`, `usercustomize.py`, a script named like a common command and a file installed under `etc/`; `info` for any other new script or data file |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.2 (PyPI wheels) |

## What it checks

Most of a wheel installs into the package's own folder in `site-packages`. A few files land
somewhere else, where something other than an import of the package runs or reads them.
Garnet compares the new version's wheel with the trusted version's and reports each of these
files that is new:

- **`sitecustomize.py` or `usercustomize.py` at the top of `site-packages`.** Python imports
  them by itself at every start, before any of your code runs.
- **A script under `<name>.data/scripts/`.** The installer copies it into the environment's
  `bin` (or `Scripts`) folder, where it runs as a command.
- **A file under `<name>.data/data/`.** The installer copies it under the environment's prefix:
  `<name>.data/data/etc/tool.conf` becomes `<prefix>/etc/tool.conf`.

It keeps its `warn` severity for the two startup modules, for a script named like a common
command (`pip`, `python`, `git`, `curl`, `ssh`, `sudo` and others, also as `git.exe`, `.cmd`,
`.bat` or `.com` for Windows, in any case), which can run instead of the real one, and for a file installed under `etc/`, where other tools read their
configuration. Any other new script or data file, such as shared data under `share/`, is
reported at `info`.

## Why it matters

GRN-C001 reports a new `.pth` file, which Python runs at startup. `sitecustomize.py` does
the same thing under another name: it runs in every Python process in the environment, whether
or not anything imports the package, and GRN-C003 never sees it as import-time code of the
package. A script named `pip` or `git` in the environment's `bin` folder is found before the
real command whenever that environment is active, in CI as much as on a laptop.

## Example finding

No replayed malicious release ships one of these files; the rule closes a gap the threat model
names. On the 974-update clean corpus it reported one update, at `info`: jmespath 0.9.2 added
its `jp` command as a script. The OSV lookup line of the run is left out.

```text
jmespath 0.9.1 → 0.9.2: PASS
  info  GRN-C010 new-startup-file: 0.9.2 adds 1 file(s) that run or install outside the package
           - jmespath-0.9.2.data/scripts/jp: installs as the command jp (454 bytes)
```

A `sitecustomize.py` would read like this, at `warn`:

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-C010 new-startup-file: 2.6.2 adds 1 file(s) that run or install outside the package
           - sitecustomize.py: Python imports it from site-packages at every start (412 bytes)
```

## How to resolve it

1. Open the file the evidence names in the new wheel.
2. Find the commit that added it in the project's repository. A library rarely needs to run at
   Python startup, or to install a command named like a tool you already use.
3. If the repository explains the file, merge and add a time-limited ignore with the reason. If
   nothing there does, don't merge, and tell the maintainers.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-C010"]
reason = "2.6.2 installs its server config under etc/, see the changelog"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-C010" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## What it doesn't check

- **Sdists.** What an sdist installs is decided by its build, which Garnet never runs, so the
  rule compares wheels only. GRN-C002 reports new build code in an sdist.
- **What the file does.** The rule reports that it is there and where it installs. A new
  `.pth` file is GRN-C001's.
- **Console scripts declared as entry points.** Those are written by the installer from
  `entry_points.txt`, not shipped as files. [GRN-C009](GRN-C009.md) reports a new script
  declared in `entry_points.txt`, and warns for one with a common command's name other than
  the project's own.

## See also

- `garnet explain GRN-C010` prints this rule's summary in your terminal.
- [GRN-C001](GRN-C001.md), which reports a new `.pth` file.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
