<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/lockup/lockup-horizontal-reverse.svg">
    <img src="docs/brand/lockup/lockup-horizontal-plate.svg" alt="Garnet Guard" width="380">
  </picture>
</p>

# Garnet Guard

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-8E1B2C" alt="License: Apache-2.0" height="20"></a>
  <img src="https://img.shields.io/badge/status-pre--alpha-5C636B" alt="Status: pre-alpha" height="20">
  <a href="backtest/incidents.toml"><img src="https://img.shields.io/badge/replayed%20incidents-3%2F3%20warn-8E1B2C" alt="Replayed incidents: 3 of 3 warn" height="20"></a>
  <a href="backtest/clean.toml"><img src="https://img.shields.io/badge/clean%20updates-0%2F20%20warn-1B1F24" alt="Clean updates: 0 of 20 warn" height="20"></a>
</p>

<!-- Badges, once the first release and CI exist (the "checked by" badge goes live when Garnet Guard checks its own dependency PRs, SPEC §11):
[![Dependencies checked by Garnet Guard](docs/brand/badge/checked-by-garnet-guard.svg)](https://github.com/orca-solutions/garnet-guard)
[![PyPI](https://img.shields.io/pypi/v/garnet-guard)](https://pypi.org/project/garnet-guard/)
[![CI](https://github.com/orca-solutions/garnet-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/orca-solutions/garnet-guard/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/orca-solutions/garnet-guard/badge)](https://scorecard.dev/viewer/?uri=github.com/orca-solutions/garnet-guard)
-->

**Garnet Guard checks every dependency update against the last release you trusted, and tells you when it looks different in ways that matter.**

*Trust the last release. Check the next.*

> Status: pre-alpha. Nothing is published to PyPI yet. `garnet diff` works from a checkout today (see [Try it today](#try-it-today-01-preview)); the rest of this README describes the first release.

## Why

The most damaging supply-chain attacks of 2025–26 did not come from obscure typosquats. They came from packages people already trusted. An attacker took over a maintainer account, a stored publish token or a project's CI, and pushed a new version that looked routine:

- **lightning 2.6.2 / 2.6.3 (PyPI, April 2026)** was uploaded outside the project's CI, with no matching git tag, and ran its payload at import time.
- **elementary-data 0.23.3 (PyPI, April 2026)** was published by the project's own hijacked pipeline and added a `.pth` file that runs on every Python start.
- **chalk, debug and the Shai-Hulud worm (npm, September 2025)** spread through hijacked accounts to 500+ packages.

Malware feeds caught these only after the fact. Cooldowns only buy time. pip and uv do not verify PyPI's signing attestations at all. But each malicious release *differed from the previous good release* in ways a machine can check. Garnet checks them.

## What it flags

| Signal | Example |
|---|---|
| **Trust downgrade** | The new release has no provenance attestation when the old one did, was built by a different repo or workflow, or has no matching git tag. |
| **Risky content change** | A new `.pth` file, new build hooks, new import-time `exec`/`subprocess`/network code, new obfuscated blobs or binaries. |
| **Known bad** | The release matches an OSV / OpenSSF malicious-package advisory. |

Garnet never runs the code it inspects. It downloads both releases and reads them statically.

## How you'll use it

**On Dependabot and Renovate PRs (first release).** Add the Garnet Guard Action, and it posts one comment per dependency PR. Updates with nothing worth a look collapse out of the way:

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/pr-comment/pr-comment-dark.svg">
    <img src="docs/brand/pr-comment/pr-comment-light.svg" alt="Sample Garnet Guard PR comment: 1 of 3 updates needs a look. examplelib 2.6.1 to 2.6.2 lost its provenance attestation, has no git tag v2.6.2, and adds import-time subprocess code. requests and idna have nothing worth a look." width="720">
  </picture>
</p>

<sub>A sample comment. The examplelib findings are illustrative; the replays below are real.</sub>

**Locally and in agent hooks (planned).** `garnet check` compares two lockfiles, and a pre-install hook stops Claude Code or Codex from quietly adding a risky dependency.

## Replays of real attacks

We fed the original malicious files from the 2026 PyPI compromises through `garnet diff`, using each project's previous release as the baseline. The files are still served by files.pythonhosted.org and are checked against PyPI's published hashes. Nothing was executed. Known-bad feeds were switched off, so these results show only what the release diff found by itself.

| Release | Result | Rules that fired |
|---|---|---|
| lightning 2.6.1 → 2.6.2 | warn | GRN-C003 `subprocess.Popen` reached at import from `lightning/__init__.py:14`; GRN-T004 no tag `2.6.2` |
| lightning 2.6.1 → 2.6.3 | warn | GRN-C003, GRN-T004 |
| elementary-data 0.23.2 → 0.23.3 | warn | GRN-C001 new `elementary.pth` with an `exec` of a base64 payload; GRN-T004 no tag `v0.23.3` |
| 20 clean updates ([list](backtest/clean.toml)) | 0 warn | none |

Limits, stated plainly:
- GRN-T001 (lost provenance) couldn't fire in either case, because neither project signed its releases before the attack.
- GRN-T004 checks tags as they exist today.
- Twenty clean updates is a small sample. The month-2 backtest covers the last ~20 releases of the top ~500 PyPI packages.

Reproduce it with `uv run python -m backtest`. Incident sources: [Snyk on lightning](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer), [CSA on elementary-data](https://labs.cloudsecurityalliance.org/research/csa-research-note-pypi-elementarydata-supply-chain-20260429/), and the files from DataDog's malicious-software-packages dataset.

## Try it today (0.1 preview)

`garnet diff` compares two releases of one PyPI package:

```sh
uv sync
uv run garnet diff requests 2.32.4 2.32.5
uv run garnet diff pypi:lightning 2.6.4 2.6.5 --format json
uv run garnet explain GRN-C003
uv run python -m backtest        # replay the 2026 incidents and the clean corpus
```

The exit code is 0 below `--fail-on` (default `block`), 1 for warn, 2 for block and 3 if Garnet Guard itself failed.

## Ecosystems

Python first (uv.lock, poetry.lock, pylock.toml, pinned requirements.txt). npm (package-lock, pnpm-lock, yarn.lock) follows.

## Project

- [Vision](VISION.md) and [founding principles](PRINCIPLES.md)
- [v1.0 specification](docs/SPEC-v1.md) and [code design and API](docs/API.md)
- [Architecture](ARCHITECTURE.md): how the engine works.
- [Threat model](THREAT_MODEL.md): what Garnet catches, what it can't, and how Garnet protects itself.
- [Roadmap](ROADMAP.md)
- [Open core](OPEN_CORE.md): what's free forever, and what the paid Garnet Guard App adds.
- Questions and ideas: GitHub Discussions
- [Contributing](CONTRIBUTING.md), [Governance](GOVERNANCE.md), [Security policy](SECURITY.md), [Code of conduct](CODE_OF_CONDUCT.md)
- [Architecture decision records](docs/decisions/)

## License

Apache-2.0. See [LICENSE](LICENSE).
