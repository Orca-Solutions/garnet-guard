# Changelog

All notable changes to Garnet Guard. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow semantic versioning from 1.0 (SPEC §12).

## Unreleased

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
- `python -m backtest` replays real incidents and a clean corpus.
- A docs page for every rule ID in `docs/rules/`, with an example finding and how to resolve or allowlist it. Findings, `garnet explain` and the PR comment link to these pages on https://garnetguard.dev/rules/.
- CI on every pull request (ruff, mypy, import contracts, tests on Python 3.11 to 3.14, build), the OpenSSF Scorecard workflow, Dependabot for the repository itself, and a tag-triggered release that publishes to PyPI with Trusted Publishing and PEP 740 attestations. See docs/RELEASING.md.
- The GitHub Action (`action.yml`) checks a pull request's lockfile changes and posts or updates one comment. It includes a `workflow_run` comment job for forks (`action/comment`) and example workflows in `action/examples/`. See docs/action.md.
- `garnet check --format markdown` and `python -m garnet_guard.markdown` render the PR comment (SPEC §9.4) from a report.
