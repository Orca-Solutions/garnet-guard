# Changelog

All notable changes to Garnet Guard. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow semantic versioning from 1.0 (SPEC §12).

## Unreleased

### Added

- npm: `garnet diff npm:<name> <old> <new>` compares two npm releases. It reads the registry's package document, npm provenance (verified with Sigstore, including the older `intoto` log-entry format that sigstore-python no longer accepts), git tags, OSV advisories and the tarball's `package.json`. The trust rules, GRN-K001 and GRN-T008 (Subresource Integrity) apply to npm; GRN-C002 reports an added or changed `preinstall`, `install` or `postinstall` script (not `prepare`, which npm doesn't run for a published tarball); GRN-T004 also accepts `<name>@X` tags. The backtest replays chalk 5.6.1, debug 4.4.2, nx 21.5.0 and @ctrl/tinycolor 4.1.1 from recorded registry facts, and `python -m backtest corpus npm` runs the top-200 npm clean corpus. npm lockfiles are not read yet.

### Changed

- GRN-C003 follows more of what runs at import: lambdas that are called or passed to a call, classes that are instantiated (their `__init__`) and methods called on them, names pulled in by `from os import *`, and `getattr(os, "system")`, `__import__("os")` or `importlib.import_module("os")` with a literal name. A `base64` decode whose result reaches `exec` or another sensitive call is reported as a call of its own, so a release that starts decoding what it executes is flagged even where `exec` was already used. Sensitive set version `2026-10-b`.
- GRN-C002 reads the whole of `setup.py`, not only what runs at import, so a `cmdclass` install hook that runs a command is reported (with the function it sits in). When the trusted version shipped no sdist, every build-time call in the new sdist is new; when the trusted sdist exists but couldn't be read, GRN-E001 reports that instead.
- GRN-C001 compares `.pth` files by where they land in `site-packages`: a file under `<name>-<version>.data/purelib/` is the same file release after release, a `.pth` deeper in the package (which Python never reads) is ignored, and a renamed `.pth` with the same `import` lines is not new. Modules under `.data/purelib/` keep their names across versions for GRN-C003.
- When the trusted version ships only a wheel and the new one only an sdist (or the reverse), the content rules compare the two kinds with each other and say so, instead of comparing nothing.
- GRN-C003 follows import-time calls into the package's own other modules, as deep as they go and through function-local imports, and names the module whose import started the chain. It also follows `sp = subprocess` style aliases and `getattr(sys.modules[__name__], "ctypes")`, the num2words 0.5.15 trick for reaching a module without naming it.
- GRN-C003 follows a function defined inside another function when it is called or handed to a call there, the mrmustard 0.7.4 shape: a checker run at import that started a thread on a `_run` nested inside it.
- GRN-C003 no longer makes four claims the top-1,000 PyPI corpus showed to be false: a dotted name whose first part is not an imported module (a local list called `requests`), a builtin shadowed by the module's own function or class (`def compile`), a module renamed with a leading underscore reported as new, and a module the trusted version had but couldn't parse reported as new (it now says the calls may not be new).
- GRN-C003 reports three more kinds of call at `info`, each in its own finding, instead of `warn`: a function that import-time code only handed to a call not known to run it (`functools.partial(f)`, a wrapper factory; the evidence now reads "handed to X() at import"), a call reached only from a test file that nothing imports, and a call in or reached only from an sdist file outside the package (`docs/conf.py`, `examples/`). Handing to `threading.Thread`, `atexit.register` or `executor.submit` still counts as running. A call that a package module reaches at import is reported once, at `warn`, whichever chain is followed first, and a module whose trusted copy couldn't be parsed is titled as such instead of "adds". A top-level `test/` folder counts as test files, like `tests/` (ply 3.6's `test/calclex.py`); one inside the package does not, because it is installed (`django.test`).

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
- `python -m backtest` replays real incidents and a clean corpus. The incidents are 47 malicious releases of 36 compromised PyPI packages (Dec 2024 to Sep 2026) and four npm account takeovers, checked against the git tags as they stood when each release was uploaded, and against attestations where public sources confirm a release had none.
- A docs page for every rule ID in `docs/rules/`, with an example finding and how to resolve or allowlist it. Findings, `garnet explain` and the PR comment link to these pages on https://garnetguard.dev/rules/.
- CI on every pull request (ruff, mypy, import contracts, tests on Python 3.11 to 3.14, build), the OpenSSF Scorecard workflow, Dependabot for the repository itself, and a tag-triggered release that publishes to PyPI with Trusted Publishing and PEP 740 attestations. See docs/RELEASING.md.
- The GitHub Action (`action.yml`) checks a pull request's lockfile changes and posts or updates one comment. It includes a `workflow_run` comment job for forks (`action/comment`) and example workflows in `action/examples/`. See docs/action.md.
- `garnet check --format markdown` and `python -m garnet_guard.markdown` render the PR comment (SPEC §9.4) from a report.
- The policy file (SPEC §7): `garnet.toml`, or `[tool.garnet]` in `pyproject.toml`, sets rule severities and `fail_on`, lowers the input limits, and holds expiring ignores for findings someone has reviewed. `garnet check` and `garnet diff` read it (`--policy PATH`, `--no-policy`), `garnet policy check` validates it, and the Action's `policy` input reads it from the pull request's base commit. Ignored findings stay in the reports with `suppressed_by`; expired ignores are reported. See docs/policy.md.
- `garnet check --format sarif` and `python -m garnet_guard.sarif` render a SARIF 2.1.0 report (SPEC §9.3) for GitHub code scanning, with one alert per finding on the lockfile line that pins the new version. The Action's `sarif: true` input uploads it, so findings show in the pull request's changed lines and the Security tab.
