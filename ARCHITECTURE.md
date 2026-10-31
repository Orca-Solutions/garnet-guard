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
        (preview, 0.1)              (0.1)            (preview: pip, uv)
```

Every surface is a thin shell over one library call: `garnet_guard.evaluate(diff, policy) -> Report`.

## Core concepts

**ReleasePair.** One dependency changing: ecosystem, package name, `old` version (the baseline you trusted) and `new` version. A newly added dependency has no `old`; it gets only known-bad and absolute checks, not diff checks.

**Baseline.** In the open-source tool the baseline is simply the version in the base lockfile, i.e. the version this project already runs. If an update skips versions (2.6.1 → 2.6.4), Garnet diffs against 2.6.1 and, per SPEC §5 rule 2, also reports trust signals for each skipped release, since a compromise can hide in the middle. That second part isn't built yet: 0.1 compares the baseline and the candidate only. In v2 the engine also computes **per-package history from the registry** (how the last N releases were published), so the baseline isn't limited to one release; that stays in the free engine (ADR-0009). The hosted app adds what only a service can see: history observed across many organizations.

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

**PyPI (built in 0.1).** JSON API for metadata and files, the Integrity API (`/integrity/<project>/<version>/<filename>/provenance`) for PEP 740 attestations, verified with the `pypi-attestations` library. Wheels and the sdist are both inspected, because sdists carry build code. Lockfile parsers: uv.lock, poetry.lock, pylock.toml and requirements.txt lines pinned with `==`.

**npm (`garnet diff` in 0.1; lockfiles on main, not yet released).** Registry packument and tarball, npm provenance / Sigstore attestations, and the install-time `scripts` from `package.json`. Lockfile parsers: package-lock.json and npm-shrinkwrap.json (lockfileVersion 1 to 3), pnpm-lock.yaml (lockfileVersion 9.0 and 6.x) and yarn.lock (Yarn 1, and Yarn 2+ with `__metadata` version 4 to 8). The two YAML formats are read by `lockfiles/yamldoc.py`, which builds the document from PyYAML's parser events and refuses anchors, aliases, tags and anything YAML 1.1 and js-yaml's YAML 1.2 read differently (ADR-0016). They don't record a package's registry, so the registry keys of the .npmrc, pnpm-workspace.yaml or .yarnrc.yml beside them decide which packages come from another one (GRN-E005). Names are kept as written and checked against npm's naming rules before they can reach a URL; an alias is checked as the package it installs; a registry `resolved` URL must be that package's tarball for that version. Planned: `bin` diffs.

**Source host.** Tag lookups go to the repository named by provenance first, falling back to project URLs in metadata. GitHub only at first. Tags come from the public git ref advertisement (`github.com/<repo>.git/info/refs`, ADR-0014), which needs no token and has no REST rate limit. GRN-C007 reads the repository's files at the tag over the same git endpoint (`ecosystems/gittree.py`).

## Initial rule catalog

IDs are stable forever. A retired rule keeps its ID reserved. Exact firing conditions and default severities are in SPEC §6.

| ID | Rule | Signal |
|---|---|---|
| GRN-T001 | lost-provenance | Old release had an attestation; new one has none. |
| GRN-T002 | publisher-changed | Attested source repository changed. |
| GRN-T003 | workflow-changed | Same repo, different publishing workflow file or environment. |
| GRN-T004 | no-matching-tag | No git tag for the new version in the attested or declared repo. |
| GRN-T005 | outside-trusted-publishing | Old files came through Trusted Publishing; new ones were uploaded with a token. |
| GRN-T006 | files-uploaded-late | A file was added to a release more than 24 hours after its first file; a warning when pip would install it in place of a file uploaded on time. |
| GRN-C001 | new-pth-file | A `.pth` file appears that the old release didn't have. |
| GRN-C002 | new-build-hook | New `setup.py` logic, custom build backend, or new npm install-time script. |
| GRN-C003 | new-import-time-exec | New module-level calls to `exec`, `eval`, `compile`, `subprocess`, `os.system`, `ctypes`, sockets or HTTP clients. |
| GRN-C004 | new-binary | Native code where the trusted release had none or under a name that hides it (a DLL named `.py`, num2words 0.5.15), bytecode with no source beside it or that Python loads in place of its source, and, at info, a library in a new folder. |
| GRN-C005 | obfuscated-blob (planned) | New long base64/hex/compressed literals, especially passed to exec or decode. |
| GRN-C006 | sdist-wheel-mismatch (planned) | Wheel contains files with no counterpart in the sdist. |
| GRN-C007 | code-not-in-source | A Python file in the release isn't the one at its git tag and has sensitive calls the source lacks (code injected by the build, as in ultralytics 8.3.42). |
| GRN-C008 | new-dependency | A dependency the old release didn't declare, a warning when it is missing from the registry, less than 90 days old there, or installed from outside it, whoever owns it (event-stream 3.3.6). |
| GRN-C009 | new-entry-point | A new entry point, a warning in groups other tools load by themselves (`pytest11`, `setuptools.*`) or for a script named like a common command. |
| GRN-C010 | new-startup-file | A wheel adds `sitecustomize.py`, a script that installs as a command, or a data file installed outside the package. |
| GRN-C011 | new-js-capability | The JavaScript an npm package loads uses a process, network or eval module or global, or obfuscated names, that the old release's didn't (`info`). |
| GRN-C012 | wheels-differ | Another wheel of the release, one per platform family or uploaded late, has a Python file that differs from the wheel the content rules read and makes sensitive calls that copy doesn't (a payload in the Windows wheel only). |
| GRN-T007 | invalid-attestation | An attestation exists but fails verification (blocks by default). |
| GRN-T008 | hash-mismatch | A download doesn't match the registry's published hash (blocks by default). |
| GRN-K001 | known-malicious | OSV `MAL-` advisory for this package version. |
| GRN-E001–E005 | couldn't-check | Fetch, parse or budget failures, unpinned or unsupported sources. Reported, never silently passed. |

Heuristic content rules run **only on files that changed** between the two releases. That is the main lever on false positives. GuardDog's Semgrep/YARA rules are a useful reference for patterns, with their licenses respected.

## Safety of the engine itself

Garnet handles hostile input by design. These are invariants, enforced in code review and tests:

- **No execution.** Nothing from an inspected package is ever imported, run, built or installed. Python source is parsed with `ast` only.
- **Safe extraction.** Archives are read in memory or into a private temp dir with limits on total size, file count, compression ratio and path depth. Absolute paths, `..` segments, symlinks, hard links and device files are rejected.
- **Bounded work.** Timeouts on every network call, size, count and ratio limits on every archive, and a per-change time budget; on an overrun Garnet reports an error finding rather than silently passing. The time budget is specified (SPEC §4.4) but not yet enforced in 0.1.
- **Fail visible.** If Garnet can't fetch or verify something, it says so in the report. It never turns "couldn't check" into "pass".

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full analysis.

## Caching and determinism

Planned: artifacts and facts cached by content hash under the user cache dir (and `actions/cache` in CI). 0.1 has no cache yet; it fetches everything on each run, and `--cache-dir` and `--offline` say they aren't supported. Facts for a given `(ecosystem, name, version)` are immutable once a release is published, except for yanks and late file uploads, which are re-checked. Outputs sort findings deterministically.

## Surfaces

**CLI.** `garnet check --base <lockfile> --head <lockfile>` (or `--git-base <ref>`), `garnet diff <pkg> <old> <new>`, `garnet explain <rule>`, `garnet policy check`. Run with `uvx garnet-guard` or install with `uv tool install garnet-guard`.

**GitHub Action (preview in 0.1).** Runs on `pull_request` when a lockfile changes, compares the base and head lockfiles, and posts or updates one sticky comment plus an optional SARIF upload. Design constraints:

- Never use `pull_request_target` with a checkout of PR code.
- Least privilege: `contents: read`, plus `pull-requests: write` for the comment and `security-events: write` only with SARIF upload.
- Dependabot-triggered runs get a restricted token. If commenting directly isn't possible, use the two-workflow pattern: the analysis job uploads the report as an artifact, and a `workflow_run` job with write permission posts it without checking out PR code. Both patterns ship in `action/examples/` ([docs/action.md](docs/action.md)). Both have been run on a pull request from a fork, and the single workflow has commented on a Dependabot-opened pull request (2026-10-30).
- The Action is pinned by commit SHA in all docs, and its own dependencies are hash-locked.

**Install wrapper and agent hooks (preview).** `garnet pip install …`, `garnet uv add|remove|lock|sync …` and `garnet npm install|ci|update …` resolve the change with builds turned off (pip's dry run with `--only-binary :all:` last; uv with `--no-build` in a private copy of the project; npm with `--package-lock-only`, scripts off and git unreachable in a private copy), run `evaluate` on the difference from what is installed or committed, then install exactly what was checked: pip with hash-pinned constraints, uv with `uv sync --frozen` from the checked lockfile, npm with `npm ci --ignore-scripts` and `npm rebuild` for the packages that didn't change. A change that can't be resolved without building is reported as not checked, and nothing is installed. The Claude Code and Codex PreToolUse hooks parse the agent's shell command without running it and run the same resolve-and-check step, answering with context, a deny, or (when they can't check) an ask on Claude Code and a deny on Codex; they never install. The code is in `src/garnet_guard/install/`; [docs/install-wrapper.md](docs/install-wrapper.md) has the details.

## Package layout

See [docs/API.md](docs/API.md) §9 for the full layout and §2 for the import rules between layers. The distribution is `garnet-guard` and the import package is `garnet_guard` (ADR-0007). The CLI command is `garnet`.

## Backtesting

`backtest/` replays known incidents (47 malicious releases of 36 compromised PyPI packages, listed in `backtest/incidents.toml`, and five npm releases in `backtest/npm-incidents.toml`: four account takeovers and event-stream 3.3.6) and clean corpora of the last 11 releases of the top 1,000 PyPI and top 1,000 npm packages (18,181 updates; `python -m backtest corpus pypi|npm 1000`, with reports in `backtest/corpus-results-*-1000/`). Every rule change runs against them. Two numbers gate releases: detection on the incident set (52 of 52 warn today) and the flag rate on the clean corpus (606 of 18,181, 3.3%, none a false claim). Where an incident's malicious artifacts were removed from the registry, the replay uses recorded `ReleaseFacts` from public write-ups rather than the files.
