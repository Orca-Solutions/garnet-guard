# Changelog

All notable changes to Garnet Guard. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow semantic versioning from 1.0 (SPEC §12).

## Unreleased

### Added

- `garnet diff <package> <old> <new>` compares two PyPI releases. It reads PEP 740 provenance (verified with Sigstore), git tags, OSV malicious-package advisories, and the contents of the sdist and one wheel.
- Rules:
  - trust: GRN-T001 to T005, T007 and T008
  - content: GRN-C001 to C003
  - known-bad: GRN-K001
  - couldn't-check: GRN-E001 to E003
- `garnet explain <RULE-ID>`, text and JSON reports, and exit codes per SPEC §8.
- `python -m backtest` replays real incidents and a clean corpus.
- A docs page for every rule ID in `docs/rules/`, with an example finding and how to resolve or allowlist it.
- CI on every pull request (ruff, mypy, import contracts, tests on Python 3.11 to 3.14, build), the OpenSSF Scorecard workflow, Dependabot for the repository itself, and a tag-triggered release that publishes to PyPI with Trusted Publishing and PEP 740 attestations. See docs/RELEASING.md.
- The GitHub Action (`action.yml`) checks a pull request's lockfile changes and posts or updates one comment. It includes a `workflow_run` comment job for forks (`action/comment`) and example workflows in `action/examples/`. See docs/action.md.
- `garnet check --format markdown` and `python -m garnet_guard.markdown` render the PR comment (SPEC §9.4) from a report.
- npm: `garnet diff npm:<name> <old> <new>` compares two npm releases. It reads the registry's package document, npm provenance (verified with Sigstore, including the older `intoto` log-entry format that sigstore-python no longer accepts), git tags, OSV advisories and the tarball's `package.json`. The trust rules, GRN-K001 and GRN-T008 (Subresource Integrity) apply to npm; GRN-C002 reports an added or changed `preinstall`, `install` or `postinstall` script (not `prepare`, which npm doesn't run for a published tarball); GRN-T004 also accepts `<name>@X` tags. The backtest replays chalk 5.6.1, debug 4.4.2, nx 21.5.0 and @ctrl/tinycolor 4.1.1 from recorded registry facts, and `python -m backtest corpus npm` runs the top-200 npm clean corpus. npm lockfiles are not read yet.
