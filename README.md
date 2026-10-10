<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/lockup/lockup-horizontal-reverse.svg">
    <img src="docs/brand/lockup/lockup-horizontal.svg" alt="Garnet Guard" width="360">
  </picture>
</p>

# Garnet Guard

<!-- Badges, once the repo and first release exist:
[![PyPI](https://img.shields.io/pypi/v/garnet-guard)](https://pypi.org/project/garnet-guard/)
[![CI](https://github.com/orca-solutions/garnet-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/orca-solutions/garnet-guard/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/orca-solutions/garnet-guard/badge)](https://scorecard.dev/viewer/?uri=github.com/orca-solutions/garnet-guard)
[![Dependencies checked by Garnet Guard](docs/brand/badge/checked-by-garnet-guard.svg)](https://github.com/orca-solutions/garnet-guard)
-->

**Garnet Guard checks every dependency update against the last release you trusted, and tells you when it looks different in ways that matter.**

*Trust the last release. Check the next.*

> Status: pre-alpha. Nothing is published yet. This README describes what the first release will do.

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

**On Dependabot and Renovate PRs (first release).** Add the Garnet Action and it posts one comment per dependency PR:

```text
Garnet Guard: 1 of 3 updates needs a look

  ⚠ examplelib 2.6.1 → 2.6.2   WARN
    GRN-T001  2.6.1 had a PyPI provenance attestation from
              github.com/example/examplelib (release.yml). 2.6.2 has none.
    GRN-T004  No git tag v2.6.2 exists in github.com/example/examplelib.
    GRN-C003  New import-time code in examplelib/__init__.py:12
              (subprocess call at module level).

  ✓ requests 2.32.4 → 2.32.5   pass
  ✓ idna 3.10 → 3.11           pass
```

**Locally and in agent hooks (planned).** `garnet check` compares two lockfiles, and a pre-install hook stops Claude Code or Codex from quietly adding a risky dependency.

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
