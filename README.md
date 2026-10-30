<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/orca-solutions/garnet-guard/main/docs/brand/lockup/lockup-horizontal-reverse.svg">
    <img src="https://raw.githubusercontent.com/orca-solutions/garnet-guard/main/docs/brand/lockup/lockup-horizontal.svg" alt="Garnet Guard" width="360">
  </picture>
</p>

# Garnet Guard

<p align="center">
  <a href="https://github.com/orca-solutions/garnet-guard/actions/workflows/ci.yml"><img src="https://github.com/orca-solutions/garnet-guard/actions/workflows/ci.yml/badge.svg" alt="CI" height="20"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/orca-solutions/garnet-guard"><img src="https://api.scorecard.dev/projects/github.com/orca-solutions/garnet-guard/badge" alt="OpenSSF Scorecard" height="20"></a>
  <a href="https://github.com/orca-solutions/garnet-guard/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-8E1B2C" alt="License: Apache-2.0" height="20"></a>
  <img src="https://img.shields.io/badge/status-pre--alpha-5C636B" alt="Status: pre-alpha" height="20">
  <a href="https://github.com/orca-solutions/garnet-guard/blob/main/backtest/incidents.toml"><img src="https://img.shields.io/badge/replayed%20releases-24%2F26%20warn-8E1B2C" alt="Replayed malicious releases: 24 of 26 warn" height="20"></a>
  <a href="https://github.com/orca-solutions/garnet-guard/blob/main/backtest/clean.toml"><img src="https://img.shields.io/badge/clean%20updates-0%2F20%20warn-1B1F24" alt="Clean updates: 0 of 20 warn" height="20"></a>
</p>

<!-- Badges, once the first release exists (the "checked by" badge goes live when Garnet Guard checks its own dependency PRs, SPEC §11):
[![Dependencies checked by Garnet Guard](https://raw.githubusercontent.com/orca-solutions/garnet-guard/main/docs/brand/badge/checked-by-garnet-guard.svg)](https://github.com/orca-solutions/garnet-guard)
[![PyPI](https://img.shields.io/pypi/v/garnet-guard)](https://pypi.org/project/garnet-guard/)
-->

**Garnet Guard checks every dependency update against the last release you trusted, and tells you when it looks different in ways that matter.**

*Trust the last release. Check the next.*

> Status: pre-alpha. 0.1.0a1 is an early pre-release on PyPI: `pip install --pre garnet-guard`. The GitHub Action is a preview, and the rest of this README describes the first full release. Website, rule pages and replays: [garnetguard.dev](https://garnetguard.dev/).

## Why

The most damaging supply-chain attacks of 2025–26 did not come from obscure typosquats. They came from packages people already trusted. An attacker took over a maintainer account, a stored publish token or a project's CI, and pushed a new version that looked routine:

- **lightning 2.6.2 / 2.6.3 (PyPI, April 2026)** was uploaded outside the project's CI, with no matching git tag, and ran its payload at import time.
- **elementary-data 0.23.3 (PyPI, April 2026)** was published by the project's own hijacked pipeline and added a `.pth` file that runs on every Python start.
- **litellm 1.82.7 / 1.82.8 and telnyx 4.87.1 / 4.87.2 (PyPI, March 2026)** were uploaded with publish tokens stolen through a poisoned security scanner in CI, and ran their payloads at import time; litellm 1.82.8 also added a `.pth` file.
- **ultralytics 8.3.41 / 8.3.42 (PyPI, December 2024)** were built and signed by the project's own release workflow after its build cache was poisoned; 8.3.45 / 8.3.46 followed days later with a publish token left in CI.
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
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/orca-solutions/garnet-guard/main/docs/brand/pr-comment/pr-comment-dark.svg">
    <img src="https://raw.githubusercontent.com/orca-solutions/garnet-guard/main/docs/brand/pr-comment/pr-comment-light.svg" alt="Sample Garnet Guard PR comment: 1 of 3 updates needs a look. examplelib 2.6.1 to 2.6.2 lost its provenance attestation, has no git tag v2.6.2, and adds import-time subprocess code. requests and idna have nothing worth a look." width="720">
  </picture>
</p>

<sub>A sample comment. The examplelib findings are illustrative; the replays below are real.</sub>

Add it as `.github/workflows/garnet-guard.yml`:

```yaml
name: Garnet Guard
on:
  pull_request:
    paths: ["**/uv.lock", "**/poetry.lock", "**/pylock.toml", "**/pylock.*.toml", "**/requirements*.txt", "garnet.toml"]
permissions: {}
jobs:
  garnet-guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read        # read the lockfiles and the base commit
      pull-requests: write  # post or update the comment
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: orca-solutions/garnet-guard@<release-commit-sha> # v0.1.0
```

Until the Action has a tagged release, `<release-commit-sha>` is a placeholder. Inputs, permissions and the fork-safe two-workflow pattern are in [docs/action.md](https://github.com/orca-solutions/garnet-guard/blob/main/docs/action.md). The Action is a preview.

**Locally.** `garnet check` compares two lockfiles, for example your branch against `main`, and checks every package that changed. Once you've reviewed a finding, an ignore in `garnet.toml` silences it until a date you choose ([docs/policy.md](https://github.com/orca-solutions/garnet-guard/blob/main/docs/policy.md)).

**In agent hooks (planned).** A pre-install hook stops Claude Code or Codex from quietly adding a risky dependency.

## Replays of real attacks

We fed the original malicious files from 15 compromised PyPI packages (26 malicious releases, December 2024 to September 2026) through `garnet diff`, using each project's previous release as the baseline. The files are still served by files.pythonhosted.org and are checked against PyPI's published hashes. Nothing was executed. Known-bad feeds were switched off, so these results show only what the release diff found by itself. Git tags are checked as they stood on the day of each upload.

**24 of 26 malicious releases got a warning. 2 got none.**

| Package | Malicious releases | Result | Rules that fired |
|---|---|---|---|
| lightning | 2.6.2, 2.6.3 | warn | GRN-C003 `subprocess.Popen` reached at import from `lightning/__init__.py:14`; GRN-T004 no tag |
| elementary-data | 0.23.3 | warn | GRN-C001 new `elementary.pth` with an `exec` of a base64 payload |
| litellm | 1.82.7, 1.82.8 | warn | GRN-C003 `subprocess.run` at import in `litellm/proxy/proxy_server.py`; 1.82.8 also GRN-C001 new `litellm_init.pth` |
| telnyx | 4.87.1, 4.87.2 | warn | GRN-C003 `subprocess`, `urllib.request` reached at import in `telnyx/_client.py`; GRN-T004 no tag |
| ultralytics | 8.3.45, 8.3.46 | warn | GRN-T001 no attestation where 8.3.44 had one; GRN-C003 `os.system` at import in `ultralytics/__init__.py`; GRN-T004 no tag |
| ultralytics | 8.3.41 | warn | GRN-T004 only: no tag `v8.3.41` |
| ultralytics | **8.3.42** | **pass (missed)** | none: see the limits below |
| num2words | 0.5.15, 0.5.16 | warn | GRN-T004 no tag; GRN-E002 couldn't parse `num2words/_build.py`, a Windows DLL named `.py` |
| xinference | 2.6.0, 2.6.1, 2.6.2 | warn | GRN-C003 `subprocess` at import in `xinference/__init__.py`; GRN-T004 no tag |
| mistralai | 2.4.6 | warn | GRN-C003 `subprocess` reached at import in `mistralai/client/__init__.py`; GRN-T004 no tag |
| guardrails-ai | 0.10.1 | warn | GRN-C003 `urllib.request`, `subprocess.run` at import in `guardrails/__init__.py` |
| durabletask | 1.4.1, 1.4.2, 1.4.3 | warn | GRN-C003 `urllib.request.urlretrieve`, `subprocess.Popen` at import in `durabletask/__init__.py`; GRN-T004 no tag |
| memoryos | 2.0.34 | warn | GRN-C002 build backend changed to an in-tree `sckit_poetry_build` |
| gpsea, pyphetools, ppkt2synergy | 0.9.14, 0.9.120, 0.1.1 | warn | GRN-C001 new `.pth` file that downloads and runs Bun; gpsea also GRN-T004 |
| embiggen | **0.11.97** | **pass (missed)** | none: see the limits below |
| 20 clean updates ([list](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/clean.toml)) | | 0 warn | none |

Limits, stated plainly:
- **ultralytics 8.3.42 was missed.** The project's own release workflow built and published it through Trusted Publishing, with valid attestations and its usual git tag, after a GitHub Actions cache-poisoning attack. The miner runs when a model is downloaded, not at import, so no current rule sees it. Against today's tags GRN-T004 would report it, but only because the tag was deleted afterwards.
- **embiggen 0.11.97 was missed.** The trusted release, 0.11.96, shipped only an sdist, and 0.11.97 shipped only a wheel. Content rules found no pair of artifacts to compare, and they passed silently instead of saying they couldn't check. That's a bug, and a fix is planned. embiggen doesn't tag releases, so GRN-T004 couldn't fire either.
- GRN-T001 (lost provenance) fired only for ultralytics 8.3.45 and 8.3.46. ultralytics is the only one of these projects that attested its releases before the attack. PyPI no longer serves provenance for removed releases, so the replay records ultralytics' missing attestations from [PyPI's analysis](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/).
- When the attacker controls the project's CI (elementary-data, ultralytics 8.3.41/8.3.42, memoryos), provenance looks normal, and content rules carry the result. memoryos' payload hides behind a logging setup function, so GRN-C003 missed it, and only its sdist's changed build backend was flagged. num2words' payload loads a DLL through `getattr(ctypes, "CDLL")`, which GRN-C003 doesn't follow. Planned GRN-C004 (new binary) would report both.
- GRN-T004 uses the git tags as they stood when each release was uploaded, recorded with evidence in [incidents.toml](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/incidents.toml). Against today's tags it would also report elementary-data 0.23.3 and ultralytics 8.3.42 (both tags were deleted later), and miss telnyx 4.87.1 and gpsea 0.9.14 (both projects later tagged a real release with that number). It couldn't fire for litellm and embiggen, which don't tag plain version numbers, for guardrails-ai and ppkt2synergy, whose package links no repository or has no tags, or for pyphetools, whose repository is no longer public (reported as GRN-E001).
- In telnyx 4.87.1 a typo stopped the payload from running. GRN-C003 reads code; it reports what the module calls at import, not whether the call would succeed.
- The litellm 1.82.7 sdist isn't replayed, because no public source gives its URL. Its wheel is, and content rules compare wheels.
- Twenty clean updates is a small sample. The [clean-corpus backtest](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/corpus-results/REPORT.md) covers 974 updates of the top 100 PyPI packages.

Reproduce it with `uv run python -m backtest`. Incident sources: [Snyk on lightning](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer), [CSA on elementary-data](https://labs.cloudsecurityalliance.org/research/csa-research-note-pypi-elementarydata-supply-chain-20260429/), [PyPI's incident report on litellm and telnyx](https://blog.pypi.org/posts/2026-04-02-incident-report-litellm-telnyx-supply-chain-attack/), [PyPI's analysis of ultralytics](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/), the OSV advisory named on each entry in incidents.toml, and the files and PyPI snapshots from DataDog's malicious-software-packages dataset.

## Try it today (0.1 preview)

`garnet diff` compares two releases of one PyPI package, and `garnet check` compares two lockfiles:

```sh
pip install --pre garnet-guard   # or run it without installing: uvx garnet-guard check --git-base main
garnet diff requests 2.32.4 2.32.5
garnet diff pypi:lightning 2.6.4 2.6.5 --format json
garnet check --git-base main   # every lockfile here, against the same files on main
garnet check --base old/uv.lock --head uv.lock
garnet policy check            # validate garnet.toml and list its ignores
garnet explain GRN-C003
```

The replays run from a checkout of this repository:

```sh
uv sync
uv run python -m backtest      # replay 26 malicious releases and the clean corpus
```

`garnet check` reads uv.lock, poetry.lock, pylock.toml and requirements files. Lines it can't check (not pinned with `==`, or from git, a path or a private index) are listed as [GRN-E004](https://garnetguard.dev/rules/GRN-E004) or [GRN-E005](https://garnetguard.dev/rules/GRN-E005), never skipped. `garnet --help` lists every option.

The exit code is 0 below `--fail-on` (default: the policy's `fail_on`, else `block`), 1 for warn, 2 for block and 3 if Garnet Guard itself failed.

## Ecosystems

Python first (uv.lock, poetry.lock, pylock.toml, pinned requirements.txt). npm (package-lock, pnpm-lock, yarn.lock) follows.

## Project

- [Vision](https://github.com/orca-solutions/garnet-guard/blob/main/VISION.md) and [founding principles](https://github.com/orca-solutions/garnet-guard/blob/main/PRINCIPLES.md)
- [v1.0 specification](https://github.com/orca-solutions/garnet-guard/blob/main/docs/SPEC-v1.md) and [code design and API](https://github.com/orca-solutions/garnet-guard/blob/main/docs/API.md)
- [Architecture](https://github.com/orca-solutions/garnet-guard/blob/main/ARCHITECTURE.md): how the engine works.
- [Code tour](https://github.com/orca-solutions/garnet-guard/blob/main/docs/CODE_TOUR.md): a plain-language guide to the code as it is today, for new contributors and reviewers.
- [Rules](https://garnetguard.dev/rules/): one page per rule ID.
- [Threat model](https://github.com/orca-solutions/garnet-guard/blob/main/THREAT_MODEL.md): what Garnet catches, what it can't, and how Garnet protects itself.
- [Roadmap](https://github.com/orca-solutions/garnet-guard/blob/main/ROADMAP.md)
- [Open core](https://github.com/orca-solutions/garnet-guard/blob/main/OPEN_CORE.md): what's free forever, and what the paid Garnet Guard App adds.
- Questions and ideas: [GitHub issues](https://github.com/orca-solutions/garnet-guard/issues)
- [Contributing](https://github.com/orca-solutions/garnet-guard/blob/main/CONTRIBUTING.md), [Governance](https://github.com/orca-solutions/garnet-guard/blob/main/GOVERNANCE.md), [Security policy](https://github.com/orca-solutions/garnet-guard/blob/main/SECURITY.md), [Code of conduct](https://github.com/orca-solutions/garnet-guard/blob/main/CODE_OF_CONDUCT.md)
- [Architecture decision records](https://github.com/orca-solutions/garnet-guard/tree/main/docs/decisions/)

## License

Apache-2.0. See [LICENSE](https://github.com/orca-solutions/garnet-guard/blob/main/LICENSE).
