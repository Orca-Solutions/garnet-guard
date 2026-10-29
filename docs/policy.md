# The policy file

A policy tells Garnet Guard how much each rule counts for your project and which findings you have already reviewed. It is one TOML file, read by `garnet check`, `garnet diff` and the GitHub Action. Without one, the default severities in [SPEC §6.2](SPEC-v1.md#62-rule-catalog) apply and nothing is ignored.

The format is specified in [SPEC §7](SPEC-v1.md#7-policy). This page says how to use it.

## Where it lives

Garnet Guard reads the first of these that exists:

1. The file named with `--policy PATH`.
2. `garnet.toml` in the current directory.
3. `[tool.garnet]` in `pyproject.toml` in the current directory.

`--no-policy` skips all three and runs with the defaults. In the GitHub Action, the policy is read from the pull request's base commit, never from the pull request itself (see [below](#in-the-github-action)).

An invalid policy stops the run with exit code 3 and a message naming the file and the key. Garnet Guard doesn't guess: an unknown key, a misspelled rule ID, or an ignore without a reason or an expiry date is an error, because a policy that silently did less than you meant would hide findings.

## A complete example

```toml
[garnet]
version = 1                 # required
default = "warn"            # optional: "info" | "warn" | "block" for every rule whose default is warn
fail_on = "block"           # optional: "warn" | "block" | "never"; the CLI's --fail-on overrides it

[garnet.rules]              # optional: per-rule severity, "off" | "info" | "warn" | "block"
"GRN-T001" = "block"        # losing provenance blocks the merge here
"GRN-C004" = "off"

[[garnet.ignore]]           # a finding you reviewed and accept, for a while
package = "numpy"
versions = ">=2.0"          # optional PEP 440 specifier, matched against the new version
rules = ["GRN-C004"]
reason = "ships compiled wheels; checked the release workflow on 2026-10-29"
until = "2027-06-30"        # required; the ignore stops applying the day after

[garnet.limits]             # optional: lower a limit from SPEC §4.4; raising one is an error
budget_seconds = 60
```

In `pyproject.toml` the same keys go under `[tool.garnet]`, `[tool.garnet.rules]`, `[[tool.garnet.ignore]]` and `[tool.garnet.limits]`.

## Severities

- `default` changes the severity of every rule whose default is `warn`, so one line makes a project strict (`"block"`) or quiet (`"info"`). It doesn't touch rules whose default is `info` or `block`.
- `[garnet.rules]` sets one rule, and wins over `default`. A rule set to `"off"` produces no findings at all.
- Two groups can't be turned down for every package at once:
  - **GRN-T007, GRN-T008 and GRN-K001** mean a release failed verification or is listed as malicious. They can be raised, never lowered. To accept one package after reviewing it, write an ignore with `acknowledge_critical = true`.
  - **GRN-E001 to GRN-E005** say a check didn't run. They can't go below their default, because a check that didn't run would then pass. An ignore for one package, with a reason and an expiry, still works.
- A rule may still lower its own finding below the policy's setting where the spec says so, for example GRN-C003 in test files.

## Ignores

An ignore is for a finding someone has looked at: the release notes explain the change, the maintainer confirmed the manual upload, the compiled wheel is expected. It says who-knows-what in `reason`, and it expires.

An ignore matches a finding when all of these hold:

- the finding's rule is in `rules`;
- the package name matches `package` (PyPI names are normalized, so `Pillow` and `pillow` are the same);
- `versions`, if set, contains the new version (pre-releases included);
- `ecosystem`, if set, matches;
- the rule is not GRN-T007, GRN-T008 or GRN-K001, unless `acknowledge_critical = true`;
- today is on or before `until`.

An ignored finding is not hidden. It still appears in the JSON report with `suppressed_by` set to the ignore that matched, in the text report as `ignored`, and in the pull request comment under "ignored by the policy". It just doesn't count toward the verdict or the exit code. Findings the ignore doesn't cover still count: an ignore for GRN-T004 on a package does nothing about a GRN-T001 on the same update.

The day after `until`, the ignore stops applying. The finding counts again, with a note that an ignore expired and the reason it gave, and the report lists every expired ignore so a lapsed review is visible even when nothing matched it. Review the package again, then renew the date or delete the entry.

Policies may name rules that are in the spec but not built yet (GRN-T006, GRN-C004 to GRN-C006). They produce no findings until they ship.

## Checking a policy

```sh
garnet policy check              # the file garnet check would read here
garnet policy check ci/garnet.toml
```

It prints the file's SHA-256, every rule setting, and every ignore with whether it applies today or has expired. Exit code 3 means the file is invalid, and the message says why.

## In the GitHub Action

The Action's `policy` input defaults to `auto`: `garnet.toml` at the pull request's base commit, else `[tool.garnet]` in `pyproject.toml` there. Give a path to use another file. Either way the policy is read from the **base commit**, so a pull request can't relax or remove the policy it is checked with, and a `garnet.toml` added by a pull request is not read. A change to the policy applies to later pull requests once it is merged.

The Action's `fail-on` input is empty by default, which means the policy's `fail_on`, else `block`. Details are in [docs/action.md](action.md#the-policy).

## Reports

The JSON report's `policy` field names the file and its SHA-256, and lists expired ignores:

```json
"policy": {"source": "garnet.toml", "sha256": "…", "expired": []}
```

It is `null` when no policy file was read. Each suppressed finding carries the matching ignore:

```json
"suppressed_by": {"package": "numpy", "versions": ">=2.0", "rules": ["GRN-C004"],
                  "reason": "ships compiled wheels", "until": "2027-06-30",
                  "acknowledge_critical": false}
```
