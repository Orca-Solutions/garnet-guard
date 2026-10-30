# Changelog

All notable changes to Garnet Guard. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow semantic versioning from 1.0 (SPEC §12).

## Unreleased

### Added

- npm: `garnet diff npm:<name> <old> <new>` compares two npm releases. It reads the registry's package document, npm provenance (verified with Sigstore, including the older `intoto` log-entry format that sigstore-python no longer accepts), git tags, OSV advisories and the tarball's `package.json`. The trust rules, GRN-K001 and GRN-T008 (Subresource Integrity) apply to npm; GRN-C002 reports an added or changed `preinstall`, `install` or `postinstall` script (not `prepare`, which npm doesn't run for a published tarball); GRN-T004 also accepts `<name>@X` tags. The backtest replays chalk 5.6.1, debug 4.4.2, nx 21.5.0 and @ctrl/tinycolor 4.1.1 from recorded registry facts, and `python -m backtest corpus npm` runs the top-200 npm clean corpus. npm lockfiles are not read yet.
- `python -m backtest select|corpus [pypi|npm] [SIZE]` runs a clean corpus of up to the top 1,000 packages, in worker processes (`GARNET_BACKTEST_WORKERS`). The top-1,000 PyPI and npm runs and their reports are in `backtest/corpus-results-pypi-1000/` and `backtest/corpus-results-npm-1000/`.

### Changed

- GRN-T004 reads more tag forms: `X` or `vX` after a prefix that names the package or is `release`, joined by `-`, `_`, `==` or `/` (and `@` for npm), as in `release-v1.0.0`, `azure-mgmt-core_1.1.0` and `prebuilt==1.0.11`. A monorepo's folder or `==` prefix may use the end of the name (`api/v1.4.1`, `utils/v2.8.1`) when the repository never tags the package by its full name. The top-1,000 corpora found 16 releases that it wrongly said had no tag.
- GRN-T001 on npm says "no attestation served", with the HTTP status, when a version document lists an attestation that the registry's attestations endpoint doesn't serve (whatwg-url 17.1.1).

## 0.1.0a1

The first pre-release. It claims the `garnet-guard` name on PyPI and lets people try the command line before the first full release. Expect changes before 0.2.0.

### Added

- `garnet diff <package> <old> <new>` compares two PyPI releases. It reads PEP 740 provenance (verified with Sigstore), git tags, OSV malicious-package advisories, and the contents of the sdist and one wheel.
- `garnet check` compares two lockfiles (`--base` and `--head`, or `--git-base <ref>` for every lockfile against the same files at that commit) and checks every package that changed. It reads uv.lock, poetry.lock, pylock.toml and requirements files.
- Rules:
  - trust: GRN-T001 to T005, T007 and T008
  - content: GRN-C001 to C003
  - known-bad: GRN-K001
  - couldn't-check: GRN-E001 to E005
- `garnet explain <RULE-ID>`, text and JSON reports, and exit codes per SPEC §8. The command is `garnet`; `garnet-guard` is the same command, so `uvx garnet-guard` works (ADR-0007).
- `python -m backtest` replays real incidents and a clean corpus. The incidents are lightning 2.6.2/2.6.3, elementary-data 0.23.3, litellm 1.82.7/1.82.8 and telnyx 4.87.1/4.87.2, checked against the git tags as they stood when each release was uploaded.
- A docs page for every rule ID in `docs/rules/`, with an example finding and how to resolve or allowlist it. Findings, `garnet explain` and the PR comment link to these pages on https://garnetguard.dev/rules/.
- CI on every pull request (ruff, mypy, import contracts, tests on Python 3.11 to 3.14, build), the OpenSSF Scorecard workflow, Dependabot for the repository itself, and a tag-triggered release that publishes to PyPI with Trusted Publishing and PEP 740 attestations. See docs/RELEASING.md.
- The GitHub Action (`action.yml`) checks a pull request's lockfile changes and posts or updates one comment. It includes a `workflow_run` comment job for forks (`action/comment`) and example workflows in `action/examples/`. See docs/action.md.
- `garnet check --format markdown` and `python -m garnet_guard.markdown` render the PR comment (SPEC §9.4) from a report.
- The policy file (SPEC §7): `garnet.toml`, or `[tool.garnet]` in `pyproject.toml`, sets rule severities and `fail_on`, lowers the input limits, and holds expiring ignores for findings someone has reviewed. `garnet check` and `garnet diff` read it (`--policy PATH`, `--no-policy`), `garnet policy check` validates it, and the Action's `policy` input reads it from the pull request's base commit. Ignored findings stay in the reports with `suppressed_by`; expired ignores are reported. See docs/policy.md.
- `garnet check --format sarif` and `python -m garnet_guard.sarif` render a SARIF 2.1.0 report (SPEC §9.3) for GitHub code scanning, with one alert per finding on the lockfile line that pins the new version. The Action's `sarif: true` input uploads it, so findings show in the pull request's changed lines and the Security tab.
