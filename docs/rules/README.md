# Garnet Guard rules

Each finding in a Garnet Guard report carries a rule ID. This page lists every rule; each
rule's page says what it checks, why it matters, an example finding, and how to resolve or
allowlist it. The normative definitions are in [SPEC §6](../SPEC-v1.md#6-rules).

Most rules are **diff rules**: they compare the new version with the version you already
trust, and fire only on what changed. A project that never used attestations isn't
penalized for not using them. **Absolute rules** fire on the new version alone.

Severities: `block` and `warn` set the verdict; `info` is reported but counts as a pass.
A warning is a reason to look, not a finding that the release is malicious.

The trust rules, GRN-C002, GRN-C008 and GRN-K001 apply to PyPI and npm releases. GRN-C001,
GRN-C003 and GRN-C007 read Python code, so they apply to PyPI only.

## Trust

How the release was published: attestations, publisher, workflow, tags, hashes.

| ID | Name | Kind | Default | Status |
|---|---|---|---|---|
| [GRN-T001](GRN-T001.md) | lost-provenance | diff | `warn` | 0.1 |
| [GRN-T002](GRN-T002.md) | publisher-changed | diff | `warn` | 0.1 |
| [GRN-T003](GRN-T003.md) | workflow-changed | diff | `warn` | 0.1 |
| [GRN-T004](GRN-T004.md) | no-matching-tag | diff | `warn` | 0.1 |
| [GRN-T005](GRN-T005.md) | outside-trusted-publishing | diff | `warn` | 0.1 |
| [GRN-T006](GRN-T006.md) | files-uploaded-late | absolute | `warn` | planned |
| [GRN-T007](GRN-T007.md) | invalid-attestation | absolute | `block` | 0.1 |
| [GRN-T008](GRN-T008.md) | hash-mismatch | absolute | `block` | 0.1 |

## Content

What the release contains that the trusted version didn't.

| ID | Name | Kind | Default | Status |
|---|---|---|---|---|
| [GRN-C001](GRN-C001.md) | new-pth-file | diff | `warn` | 0.1 |
| [GRN-C002](GRN-C002.md) | new-build-hook | diff | `warn` | 0.1 |
| [GRN-C003](GRN-C003.md) | new-import-time-exec | diff | `warn` (`info` in test files) | 0.1 |
| [GRN-C004](GRN-C004.md) | new-binary | diff | `warn` | planned |
| [GRN-C005](GRN-C005.md) | obfuscated-blob | diff | `warn` | planned |
| [GRN-C006](GRN-C006.md) | sdist-wheel-mismatch | diff | `warn` | planned |
| [GRN-C007](GRN-C007.md) | code-not-in-source | diff | `warn` | 0.1 |
| [GRN-C008](GRN-C008.md) | new-dependency | diff | `warn` (`info` for an established dependency) | 0.2 |

## Known bad

Matches against published malware advisories.

| ID | Name | Kind | Default | Status |
|---|---|---|---|---|
| [GRN-K001](GRN-K001.md) | known-malicious | absolute | `block` | 0.1 |

## Couldn't check

What Garnet Guard couldn't evaluate, said out loud instead of passed.

| ID | Name | Kind | Default | Status |
|---|---|---|---|---|
| [GRN-E001](GRN-E001.md) | fetch-failed | absolute | `warn` | 0.1 |
| [GRN-E002](GRN-E002.md) | parse-failed | absolute | `warn` | 0.1 |
| [GRN-E003](GRN-E003.md) | budget-exceeded | absolute | `warn` | 0.1 |
| [GRN-E004](GRN-E004.md) | unpinned-requirement | absolute | `info` | 0.1 |
| [GRN-E005](GRN-E005.md) | unsupported-source | absolute | `info` | 0.1 |

## Replays

Example findings marked as replays come from `uv run python -m backtest`, which runs
Garnet Guard against real compromised releases listed in [backtest/incidents.toml](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/incidents.toml)
and a corpus of clean updates. In the current replay of 51 malicious releases from 40
compromised packages (47 on PyPI, 4 on npm), with git tags as they stood when each release
was uploaded, all 51 get a `warn` from trust and content rules alone. Three of them
(ultralytics 8.3.42, embiggen 0.11.97 and mrmustard 0.7.4) were missed by the rules as first
written and are caught by fixes the replay prompted (see the [README](https://github.com/orca-solutions/garnet-guard#replays-of-real-malicious-releases)). 0 of 20 clean updates got a `warn` from a detection rule. Other examples are
illustrative and say so.

## Rule IDs and links

Rule IDs are permanent: a rule is never renumbered and an ID is never reused. Each page
lives at `docs/rules/<ID>.md`, and the website serves it at `https://garnetguard.dev/rules/<ID>`.
That address is the stable link for findings, `garnet explain` and the PR comment. The site
is built from a pinned commit of this repository, so an edit here appears there once the
site's pin is moved forward.
