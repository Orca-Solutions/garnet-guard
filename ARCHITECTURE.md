# Garnet Guard architecture

This describes the engine Garnet is built around and the surfaces that use it. It is the reference for anyone, human or agent, adding code. Decisions behind it are recorded in [docs/decisions/](docs/decisions/). The exact behavior is specified in [docs/SPEC-v1.md](docs/SPEC-v1.md) and the code design in [docs/API.md](docs/API.md); where they differ from this overview, they win.

## Shape in one picture

```text
 lockfile (base)  ─┐
                   ├─► LockfileDiff ─► [ReleasePair, ...]
 lockfile (head)  ─┘                          │
                                              ▼
                              Ecosystem adapter (pypi, npm)
                         metadata · artifacts · provenance · tags
                                   (content-addressed cache)
                                              │
                                              ▼
                          ReleaseFacts(old)   ReleaseFacts(new)
                                              │
                                              ▼
                     Checks: trust · content · known-bad  ─►  [Finding, ...]
                                              │
                                              ▼
                               Policy (garnet.toml) ─► Verdict
                                              │
                                              ▼
                 Reporters: text · JSON · SARIF · PR comment markdown
                                              │
              ┌───────────────────────┬───────┴──────────────┐
              ▼                       ▼                      ▼
        GitHub Action           CLI (garnet check)     Agent / install hooks
          (month 2)               (month 1)                (month 3)
```

Every surface is a thin shell over one library call: `garnet_guard.evaluate(diff, policy) -> Report`.

## Core concepts

**ReleasePair.** One dependency changing: ecosystem, package name, `old` version (the baseline you trusted) and `new` version. A newly added dependency has no `old`; it gets only known-bad and absolute checks, not diff checks.

**Baseline.** In the open-source tool the baseline is simply the version in the base lockfile, i.e. the version this project already runs. If an update skips versions (2.6.1 → 2.6.4), Garnet diffs against 2.6.1 and also reports trust signals for each skipped release, since a compromise can hide in the middle. In v2 the engine also computes **per-package history from the registry** (how the last N releases were published), so the baseline isn't limited to one release; that stays in the free engine (ADR-0009). The hosted app adds what only a service can see: history observed across many organizations.

**ReleaseFacts.** Everything Garnet knows about one release, extracted once and cached:

- registry metadata (upload time, uploader, yanked status, files and hashes)
- provenance per file (attestation present, Sigstore identity, source repo, workflow, ref, Trusted Publishing yes/no)
- source link (repository URL, whether a matching git tag exists and which commit it points to)
- content inventory per artifact (file list, sizes, hashes, file types, `.pth` files, entry points, build backend, install scripts for npm)
- a static index of Python modules: top-level statements per module, imports, and calls to sensitive APIs

**Check.** A pure function over two `ReleaseFacts` that returns findings. Checks do no I/O; adapters fetch, checks judge. That makes every check unit-testable from fixtures.

```python
class Check(Protocol):
    id: str                      # stable rule ID, e.g. "GRN-T001"
    ecosystems: frozenset[str]   # {"pypi"}, {"npm"} or both
    def run(self, pair: ReleasePair, old: ReleaseFacts | None,
            new: ReleaseFacts) -> list[Finding]: ...
```

**Finding.** `rule_id`, `severity` (info / warn / block), `package`, `old`, `new`, `title`, `evidence` (list of file path + line, URL, or attestation field), `explanation` and `remediation`. Findings must be deterministic for the same inputs so PR comments don't churn.

**Policy.** `garnet.toml` (or `[tool.garnet]` in `pyproject.toml`) maps rules to severities and holds allow-lists:

```toml
[garnet]
default = "warn"               # warn | block

[garnet.rules]
GRN-T001 = "block"             # lost provenance
GRN-C004 = "off"               # new binaries are normal for us

[[garnet.ignore]]
package = "numpy"
rules = ["GRN-C004"]
reason = "ships compiled wheels"
until = "2027-06-30"           # ignores expire
```

**Verdict.** The worst severity across findings after policy: `pass`, `warn` or `block`. Exit codes: 0 pass, 1 warn (only when `--fail-on warn`), 2 block, 3 Garnet error.

## Ecosystem adapters

Each ecosystem implements one interface, so checks and reporters never touch registry specifics:

```python
class Ecosystem(Protocol):
    name: str
    def parse_lockfile(self, path: Path) -> dict[str, str]: ...      # name -> version
    def release_facts(self, name: str, version: str) -> ReleaseFacts: ...
```

**PyPI (month 1).** JSON API for metadata and files, the Integrity API (`/integrity/<project>/<version>/<filename>/provenance`) for PEP 740 attestations, verified with the `pypi-attestations` library. Wheels and the sdist are both inspected, because sdists carry build code. Lockfile parsers: uv.lock, poetry.lock, pylock.toml, pinned requirements.txt with hashes.

**npm (month 2).** Registry packument and tarball, npm provenance / Sigstore attestations, `scripts` and `bin` from `package.json`. Lockfile parsers: package-lock.json, pnpm-lock.yaml, yarn.lock.

**Source host.** Tag lookups go to the repository named by provenance first, falling back to project URLs in metadata. GitHub only at first, through the public API with an optional token for rate limits.

## Initial rule catalog

IDs are stable forever. A retired rule keeps its ID reserved. Exact firing conditions and default severities are in SPEC §6.

| ID | Rule | Signal |
|---|---|---|
| GRN-T001 | lost-provenance | Old release had an attestation; new one has none. |
| GRN-T002 | publisher-changed | Attested source repository changed. |
| GRN-T003 | workflow-changed | Same repo, different publishing workflow file or environment. |
| GRN-T004 | no-matching-tag | No git tag for the new version in the attested or declared repo. |
| GRN-T005 | outside-trusted-publishing | Old files came through Trusted Publishing; new ones were uploaded with a token. |
| GRN-T006 | files-uploaded-late | A file was added to a release long after the release was first published. |
| GRN-C001 | new-pth-file | A `.pth` file appears that the old release didn't have. |
| GRN-C002 | new-build-hook | New `setup.py` logic, custom build backend, or new npm install-time script. |
| GRN-C003 | new-import-time-exec | New module-level calls to `exec`, `eval`, `compile`, `subprocess`, `os.system`, `ctypes`, sockets or HTTP clients. |
| GRN-C004 | new-binary | New native binaries or executables not explained by the build (e.g. outside the platform wheel's normal extension modules). |
| GRN-C005 | obfuscated-blob | New long base64/hex/compressed literals, especially passed to exec or decode. |
| GRN-C006 | sdist-wheel-mismatch | Wheel contains files with no counterpart in the sdist. |
| GRN-T007 | invalid-attestation | An attestation exists but fails verification (blocks by default). |
| GRN-T008 | hash-mismatch | A download doesn't match the registry's published hash (blocks by default). |
| GRN-K001 | known-malicious | OSV `MAL-` advisory for this package version. |
| GRN-E001–E005 | couldn't-check | Fetch, parse or budget failures, unpinned or unsupported sources. Reported, never silently passed. |

Heuristic content rules run **only on files that changed** between the two releases. That is the main lever on false positives. GuardDog's Semgrep/YARA rules are a useful reference for patterns, with their licenses respected.

## Safety of the engine itself

Garnet handles hostile input by design. These are invariants, enforced in code review and tests:

- **No execution.** Nothing from an inspected package is ever imported, run, built or installed. Python source is parsed with `ast` only.
- **Safe extraction.** Archives are read in memory or into a private temp dir with limits on total size, file count, compression ratio and path depth. Absolute paths, `..` segments, symlinks, hard links and device files are rejected.
- **Bounded work.** Timeouts on every network call, and a per-package budget; on a budget overrun Garnet reports an error finding rather than silently passing.
- **Fail visible.** If Garnet can't fetch or verify something, it says so in the report. It never turns "couldn't check" into "pass".

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full analysis.

## Caching and determinism

Artifacts and facts are cached by content hash under the user cache dir (and `actions/cache` in CI). Facts for a given `(ecosystem, name, version)` are immutable once a release is published, except for yanks and late file uploads, which are re-checked. Outputs sort findings deterministically.

## Surfaces

**CLI.** `garnet check --base <lockfile> --head <lockfile>`, `garnet explain <rule>`, `garnet diff <pkg> <old> <new>`. Run with `uvx garnet-guard` or install with `uv tool install garnet-guard`.

**GitHub Action (month 2).** Runs on `pull_request` when a lockfile changes, compares the base and head lockfiles, and posts or updates one sticky comment plus an optional SARIF upload. Design constraints:

- Never use `pull_request_target` with a checkout of PR code.
- Least privilege: `contents: read`, and `pull-requests: write` only in the step that comments.
- Dependabot-triggered runs get a restricted token. If commenting directly isn't possible, use the two-workflow pattern: the analysis job uploads the report as an artifact, and a `workflow_run` job with write permission posts it without checking out PR code. *Verify current GitHub behavior before building.*
- The Action is pinned by commit SHA in all docs, and its own dependencies are hash-locked.

**Install wrapper and agent hooks (month 3).** `garnet pip install …` / `garnet uv sync` resolve first, run `evaluate` on the resulting change, then hand off to the real tool. Claude Code and Codex hooks call the same entry point before a dependency is added.

## Package layout

See [docs/API.md](docs/API.md) §9 for the full layout and §2 for the import rules between layers. The distribution is `garnet-guard` and the import package is `garnet_guard` (ADR-0007). The CLI command is `garnet`.

## Backtesting

`backtest/` replays known incidents (47 malicious releases of 36 compromised PyPI packages, listed in `backtest/incidents.toml`, and four npm account takeovers in `backtest/npm-incidents.toml`) and a clean corpus of recent releases of the top ~500 PyPI packages. Every rule change runs against it. Two numbers gate releases: detection on the incident set and warn rate on the clean corpus. Where an incident's malicious artifacts were removed from the registry, the replay uses recorded `ReleaseFacts` from public write-ups rather than the files.
