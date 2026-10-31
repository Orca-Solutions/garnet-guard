<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/orca-solutions/garnet-guard/main/docs/brand/lockup/lockup-horizontal-reverse.svg">
    <img src="https://raw.githubusercontent.com/orca-solutions/garnet-guard/main/docs/brand/lockup/lockup-horizontal.svg" alt="Garnet Guard" width="360">
  </picture>
</p>

# Garnet Guard

<p align="center">
  <a href="https://github.com/orca-solutions/garnet-guard/actions/workflows/ci.yml"><img src="https://github.com/orca-solutions/garnet-guard/actions/workflows/ci.yml/badge.svg" alt="CI" height="20"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/Orca-Solutions/garnet-guard"><img src="https://api.scorecard.dev/projects/github.com/Orca-Solutions/garnet-guard/badge" alt="OpenSSF Scorecard" height="20"></a>
  <a href="https://github.com/orca-solutions/garnet-guard/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-8E1B2C" alt="License: Apache-2.0" height="20"></a>
  <a href="https://pypi.org/project/garnet-guard/"><img src="https://img.shields.io/pypi/v/garnet-guard?color=8E1B2C" alt="PyPI version" height="20"></a>
  <img src="https://img.shields.io/badge/status-alpha-5C636B" alt="Status: alpha" height="20">
  <a href="https://github.com/orca-solutions/garnet-guard/blob/main/backtest/incidents.toml"><img src="https://img.shields.io/badge/replayed%20releases-52%2F52%20warn-8E1B2C" alt="Replayed malicious releases: 52 of 52 warn" height="20"></a>
  <a href="https://github.com/orca-solutions/garnet-guard#replays-of-real-malicious-releases"><img src="https://img.shields.io/badge/clean%20updates-3.3%25%20flagged%20(606%2F18%2C181)-1B1F24" alt="Clean updates: 606 of 18,181 flagged for a look (3.3%), none a false claim" height="20"></a>
  <a href="https://github.com/orca-solutions/garnet-guard/actions/workflows/garnet-guard.yml"><img src="https://raw.githubusercontent.com/orca-solutions/garnet-guard/main/docs/brand/badge/checked-by-garnet-guard.svg" alt="Dependencies checked by Garnet Guard" height="20"></a>
</p>

**Garnet Guard checks every dependency update against the last release you trusted, and tells you when it looks different in ways that matter.**

*Trust the last release. Check the next.*

> Status: alpha. 0.2.0 is on PyPI: `pip install garnet-guard`. The GitHub Action is a preview. Website, rule pages and replays: [garnetguard.dev](https://garnetguard.dev/).

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
| **Trust downgrade** | The new release has no provenance attestation when the old one did, was built by a different repo or workflow, has no matching git tag, or gained a file days after release that pip would install in place of a reviewed one. |
| **Risky content change** | A new `.pth` or `sitecustomize.py` file, new build hooks, a new pytest or setuptools plugin entry point, new import-time `exec`/`subprocess`/network code, code that isn't at the release's git tag, a new native binary or one named like a `.py` file, code in another platform's wheel that the checked wheel lacks, a new dependency that is new to the registry. |
| **Known bad** | The release matches an OSV / OpenSSF malicious-package advisory. |

Garnet never runs the code it inspects. It downloads both releases and reads them statically: the sdist and the wheel pip would install, plus one wheel for each other platform and up to 30 wheels uploaded late, to compare with it.

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
      - uses: orca-solutions/garnet-guard@e6e9f44a24bb11ca1b20d339650104a7e273efc1 # v0.2.0
```

The example pins the commit tagged `v0.2.0`, the release on PyPI. Inputs, permissions and the fork-safe two-workflow pattern are in [docs/action.md](https://github.com/orca-solutions/garnet-guard/blob/main/docs/action.md). The Action is a preview.

**Locally.** `garnet check` compares two lockfiles, for example your branch against `main`, and checks every package that changed. Once you've reviewed a finding, an ignore in `garnet.toml` silences it until a date you choose ([docs/policy.md](https://github.com/orca-solutions/garnet-guard/blob/main/docs/policy.md)). In VS Code, the same findings show on the lockfile lines through the SARIF Viewer extension ([docs/vscode.md](https://github.com/orca-solutions/garnet-guard/blob/main/docs/vscode.md)).

**In agent hooks (planned).** A pre-install hook stops Claude Code or Codex from quietly adding a risky dependency.

## Replays of real malicious releases

We fed the original malicious files from 36 compromised PyPI packages (47 malicious releases, December 2024 to September 2026) through `garnet diff`, using each project's previous release as the baseline. The files are still served by files.pythonhosted.org and are checked against PyPI's published hashes. Nothing was executed. Known-bad feeds were switched off, so these results show only what the release diff found by itself. Git tags are checked as they stood on the day of each upload.

**All 47 malicious releases got a warning.** Three of them only after fixes that the replay itself prompted (ultralytics 8.3.42, embiggen 0.11.97, mrmustard 0.7.4; see the limits below).

| Package | Malicious releases | Result | Rules that fired |
|---|---|---|---|
| lightning | 2.6.2, 2.6.3 | warn | GRN-C003 `subprocess.Popen` reached at import from `lightning/__init__.py:14`; GRN-T004 no tag |
| elementary-data | 0.23.3 | warn | GRN-C001 new `elementary.pth` with an `exec` of a base64 payload |
| litellm | 1.82.7, 1.82.8 | warn | GRN-C003 `subprocess.run` at import in `litellm/proxy/proxy_server.py`; 1.82.8 also GRN-C001 new `litellm_init.pth` |
| telnyx | 4.87.1, 4.87.2 | warn | GRN-C003 `subprocess`, `urllib.request` reached at import in `telnyx/_client.py`; GRN-T004 no tag |
| ultralytics | 8.3.45, 8.3.46 | warn | GRN-T001 no attestation where 8.3.44 had one; GRN-C003 `os.system` at import in `ultralytics/__init__.py`; GRN-T004 no tag |
| ultralytics | 8.3.41 | warn | GRN-T004 only: no tag `v8.3.41` |
| ultralytics | 8.3.42 | warn | GRN-C007 `ultralytics/utils/downloads.py` differs from the file at tag `v8.3.42` and calls `subprocess.Popen`; 150 of 152 Python files match the source |
| num2words | 0.5.15, 0.5.16 | warn | GRN-C003 `ctypes.CDLL` at import in `num2words/__init__.py`; GRN-T004 no tag; GRN-C004 `num2words/_build.py` is a Windows DLL named `.py`, which GRN-E002 also reports as Python that doesn't parse |
| xinference | 2.6.0, 2.6.1, 2.6.2 | warn | GRN-C003 `subprocess` at import in `xinference/__init__.py`; GRN-T004 no tag |
| mistralai | 2.4.6 | warn | GRN-C003 `subprocess` reached at import in `mistralai/client/__init__.py`; GRN-T004 no tag |
| guardrails-ai | 0.10.1 | warn | GRN-C003 `urllib.request`, `subprocess.run` at import in `guardrails/__init__.py` |
| durabletask | 1.4.1, 1.4.2, 1.4.3 | warn | GRN-C003 `urllib.request.urlretrieve`, `subprocess.Popen` at import in `durabletask/__init__.py`; GRN-T004 no tag |
| memoryos | 2.0.34 | warn | GRN-C002 build backend changed to an in-tree `sckit_poetry_build`; GRN-C003 `subprocess.Popen` in `memos/_stage0.py`, reached at import through the package's own modules; GRN-C004 six `sckit` executables for three systems, where 2.0.33 shipped no native code |
| gpsea, pyphetools, ppkt2synergy | 0.9.14, 0.9.120, 0.1.1 | warn | GRN-C001 new `.pth` file that downloads and runs Bun; gpsea also GRN-T004 |
| embiggen | 0.11.97 | warn | GRN-C001 new `embiggen-setup.pth`, found by comparing the wheel with the trusted sdist |
| cmd2func, coolbox, executor-engine, executor-http, funcdesc, mrbios, okite, uprobe | 0.2.2, 0.4.1, 0.3.4, 0.1.3, 0.2.2, 0.1.1, 0.0.7, 0.1.3 | warn | GRN-C001 new `<name>-setup.pth` (the same Hades payload); GRN-T004 no tag |
| mem8, phenopacket-store-toolkit | 6.0.1, 0.1.7 | warn | GRN-C001 new `<name>-setup.pth`; GRN-T004 no tag |
| bramin, dreamgen, ensmallen, magique, magique-ai, napari-ufish, nucbox, pantheon-agents, pantheon-toolsets, synago | 0.0.3, 1.8.1, 0.8.101, 0.6.9, 0.4.5, 0.0.3, 0.1.2, 0.6.1, 0.5.5, 0.1.1 | warn | GRN-C001 new `<name>-setup.pth` only; GRN-T004 had nothing to check, see the limits below |
| mrmustard | 0.7.4 | warn | GRN-C003 `subprocess.check_output`, `urllib.request.urlopen` in a thread started at import from `mrmustard/__init__.py` |
| 20 clean updates ([list](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/clean.toml)) | | 0 warn | none |
| 9,439 updates of the top 1,000 PyPI packages ([report](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/corpus-results-pypi-1000/REPORT.md)) | | 300 flagged for a look (3.2%); none makes a false claim | GRN-C003 65, GRN-C002 60, GRN-T004 48, GRN-T006 34, GRN-C008 23, GRN-T001 18, GRN-T003 16, GRN-T002 14, GRN-C009 9, GRN-C004 6, GRN-C007 5, GRN-C001 4, GRN-C012 2, GRN-C010 1 |

The same replay covers the npm account takeovers of August and September 2025, and event-stream 3.3.6 (2018), which added a dependency that later carried the payload. npm deletes the tarball of a removed version, so these use the registry facts the public write-ups recorded (provenance present or not, the `package.json` scripts and dependencies) and fetch the previous release and the repository's tags live. The malicious tarballs were not inspected.

| Release | Result | Rules that fired |
|---|---|---|
| chalk 5.6.0 → 5.6.1 | warn | GRN-T004 no tag `v5.6.1` where `v5.6.0` exists |
| debug 4.4.1 → 4.4.2 | warn | GRN-T004 no tag `4.4.2` |
| nx 21.4.1 → 21.5.0 | warn | GRN-T001 21.4.1 had provenance, 21.5.0 has none; GRN-C002 `postinstall` became `node telemetry.js`; GRN-T004 no tag |
| @ctrl/tinycolor 4.1.0 → 4.1.1 | warn | GRN-C002 new `postinstall` running `node bundle.js`; GRN-T004 no tag |
| event-stream 3.3.5 → 3.3.6 | warn | GRN-C008 new dependency `flatmap-stream`, first released 35 days earlier |
| 8,742 updates of the top 1,000 npm packages ([report](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/corpus-results-npm-1000/REPORT.md)) | 306 flagged for a look (3.5%); none makes a false claim | GRN-C008 162, GRN-T004 89, GRN-T001 48, GRN-T002 3, GRN-C002 3, GRN-T003 2, GRN-T005 1 |

Limits, stated plainly:
- **Three releases were missed by the rules as first written, and the replay is why they aren't now.** ultralytics 8.3.42 was built and published by the project's own release workflow, with valid attestations and its usual git tag, after a GitHub Actions cache-poisoning attack, and its miner runs when a model is downloaded, not at import; no trust or import-time rule sees it. GRN-C007 was written for it: it compares the wheel's Python files with the repository at the release's tag and reports the two that differ. embiggen 0.11.97 was missed because the trusted release shipped only an sdist and the malicious one only a wheel, so content rules had no pair to compare and passed silently; they now compare across kinds. mrmustard 0.7.4 was missed because its payload sits in a function defined inside the function `__init__.py` calls at import, one step past where GRN-C003 stopped following; it follows that step now. Each fix was checked against the clean corpus before it landed.
- **24 of the 47 releases carry the same June 2026 Hades `<name>-setup.pth` payload**, one release in each of 24 packages. They are 24 instances of one technique, mostly in small projects: four of those packages had a single earlier release, and bramin's trusted release dates from 2020. Counted by technique, the set covers five: a `.pth` startup hook, code that runs at import, a swapped build backend, a DLL named `.py`, and a payload that runs on use rather than at import.
- GRN-T001 (lost provenance) fired only for ultralytics 8.3.45 and 8.3.46. ultralytics is the only one of these projects that attested its releases before the attack. PyPI no longer serves provenance for removed releases, so the replay records ultralytics' missing attestations from [PyPI's analysis](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/).
- When the attacker controls the project's CI (elementary-data, ultralytics 8.3.41/8.3.42, memoryos), provenance looks normal, and content rules carry the result. memoryos' payload hides behind a logging setup function in another module, and num2words' loads a DLL through `getattr(ctypes, "CDLL")`; GRN-C003 now follows both, and GRN-C004 (new binary) reports num2words' DLL and memoryos' executables themselves.
- GRN-T004 uses the git tags as they stood when each release was uploaded, recorded with evidence in [incidents.toml](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/incidents.toml). Against today's tags it would also report elementary-data 0.23.3 and ultralytics 8.3.42 (both tags were deleted later; GRN-C007 needs the tag, so on today's tags it is GRN-T004 that reports ultralytics 8.3.42), and miss telnyx 4.87.1, gpsea 0.9.14 and uprobe 0.1.3 (all three projects later tagged a real release with that number). It couldn't fire for litellm, embiggen and bramin, which don't tag plain version numbers or don't tag at all; for the nine packages whose metadata links no repository (ensmallen, guardrails-ai, magique, magique-ai, mrmustard, napari-ufish, nucbox, pantheon-toolsets, synago) and ppkt2synergy, whose repository has no tags; or for pyphetools and dreamgen, whose repositories are no longer public (reported as GRN-E001). pantheon-agents has a `v0.6.1` tag today that points at a commit from eleven days before the upload; a lightweight tag carries no date of its own, so the replay treats it as already there and the rule stays quiet.
- ensmallen's `datasets/` modules are larger than Garnet's parse limit in both releases. It reported that as GRN-E003 and still found the `.pth`.
- In telnyx 4.87.1 a typo stopped the payload from running. GRN-C003 reads code; it reports what the module calls at import, not whether the call would succeed.
- The content rules recognize a sensitive call by the name it is called under. A listed function handed to another call that runs it later (`Thread(target=os.system)`), or given a harmless-looking name first (`json.dumps = subprocess.Popen`), isn't reported yet; [#91](https://github.com/orca-solutions/garnet-guard/issues/91) tracks the check.
- The litellm 1.82.7 sdist isn't replayed, because no public source gives its URL. Its wheel is, and content rules compare wheels.
- chalk and debug are reported by the missing tag alone: they never used provenance, and the one changed file, `index.js`, is gone from the registry. GRN-C011 now reads the JavaScript an npm package loads and lists, at `info`, a new process, network or eval use or obfuscated names; it can't run on these two replays, because there is no file to read.
- The 20 clean updates in `clean.toml` are a smoke test. The clean-corpus backtests cover 18,181 updates, the last 11 releases of the top 1,000 PyPI packages (9,439) and of the top 1,000 npm packages (8,742): 606 are flagged for a look (3.3%), every warning states something true, but none of those updates is malicious, so each is a false alarm a reviewer has to dismiss. Some show a release doing what the trusted one did, a new way: a `setup.py` that runs the same command with `subprocess.run` instead of `Popen`, or entry points renamed with the same targets. The [PyPI report](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/corpus-results-pypi-1000/REPORT.md#accurate-but-nothing-new-runs) lists the ones the triage found.

Reproduce it with `uv run python -m backtest`. Incident sources: [Snyk on lightning](https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer), [CSA on elementary-data](https://labs.cloudsecurityalliance.org/research/csa-research-note-pypi-elementarydata-supply-chain-20260429/), [PyPI's incident report on litellm and telnyx](https://blog.pypi.org/posts/2026-04-02-incident-report-litellm-telnyx-supply-chain-attack/), [PyPI's analysis of ultralytics](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/), [The Hacker News on the Hades campaign](https://thehackernews.com/2026/06/hades-pypi-attack-19-packages-poisoned.html), [StepSecurity on mrmustard](https://www.stepsecurity.io/blog/compromised-pypi-mrmustard-0-7-4-credential-stealer), the OSV advisory named on each entry in incidents.toml, the PyPI snapshots in DataDog's malicious-software-packages dataset, and the file hashes in [ossf/malicious-packages](https://github.com/ossf/malicious-packages).

## Try it today

`garnet diff` compares two releases of one PyPI or npm package, and `garnet check` compares two lockfiles:

```sh
pip install garnet-guard   # or run it without installing: uvx garnet-guard check --git-base main
garnet diff requests 2.32.4 2.32.5
garnet diff pypi:lightning 2.6.4 2.6.5 --format json
garnet diff npm:chalk 5.6.0 5.6.2
garnet check --git-base main   # every lockfile here, against the same files on main
garnet check --base old/uv.lock --head uv.lock
garnet policy check            # validate garnet.toml and list its ignores
garnet explain GRN-C003
```

The replays run from a checkout of this repository:

```sh
uv sync
uv run python -m backtest      # replay 52 malicious releases and the clean corpus
```

`garnet check` reads uv.lock, poetry.lock, pylock.toml and requirements files. Lines it can't check (not pinned with `==`, or from git, a path or a private index) are listed as [GRN-E004](https://garnetguard.dev/rules/GRN-E004) or [GRN-E005](https://garnetguard.dev/rules/GRN-E005), never skipped. `garnet --help` lists every option.

The exit code is 0 below `--fail-on` (default: the policy's `fail_on`, else `block`), 1 for warn, 2 for block and 3 if Garnet Guard itself failed.

## Ecosystems

Python first (uv.lock, poetry.lock, pylock.toml, pinned requirements.txt). npm is checked by `garnet diff npm:<name> <old> <new>` (provenance, tags, install scripts, OSV); the npm lockfile parsers (package-lock, pnpm-lock, yarn.lock) follow.

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
