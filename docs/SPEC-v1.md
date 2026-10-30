# Garnet Guard v1.0 specification

- Status: Draft
- Date: 2026-10-10
- Normative for: the 1.0 release. Releases before 1.0 (0.1 to 0.x) build toward it and may differ.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Where this spec and [ARCHITECTURE.md](../ARCHITECTURE.md) disagree, this spec wins.

## 1. Scope

Garnet 1.0 compares dependency changes between two lockfiles and reports, for each changed package, whether the new release shows a trust downgrade, a risky content change or a known-bad match.

**In 1.0:**

- Ecosystems: PyPI and npm.
- Surfaces: the CLI, the GitHub Action, the install wrapper, and pre-install hooks for Claude Code and Codex.
- The rules in §6, the policy format in §7, and the outputs in §9.

**Not in 1.0:** other ecosystems, non-GitHub source hosts for tag checks, GitLab/Bitbucket CI integrations, multi-release registry history (planned for v2, see [ROADMAP.md](../ROADMAP.md)), third-party check plugins as a stable interface, any hosted service.

## 2. Terms

| Term | Meaning |
|---|---|
| **Release** | One version of one package in one ecosystem, with all of its files. |
| **Artifact** | One file of a release (a wheel, an sdist, an npm tarball). |
| **Change** | One package whose resolved version differs between base and head lockfiles, or that was added or removed. |
| **Baseline** | The release a change is compared against (§5). |
| **Candidate** | The new release being judged. |
| **Facts** | Everything Garnet extracted about a release (§4.3). |
| **Finding** | One rule firing on one change, with evidence. |
| **Verdict** | `pass`, `warn` or `block` for a change, and for the whole report. |

## 3. Inputs

### 3.1 Lockfiles

Garnet MUST accept these formats and detect them by file name and content:

| Ecosystem | Format | Notes |
|---|---|---|
| PyPI | `uv.lock` | All packages with a registry source. |
| PyPI | `poetry.lock` | Lock format 2.x. |
| PyPI | `pylock.toml` (PEP 751) | `packages` entries with `index` or archive URLs on PyPI. |
| PyPI | `requirements*.txt` | Only lines pinned with `==`. Hashes are read when present. Unpinned lines produce an info finding GRN-E004 and are skipped. |
| npm | `package-lock.json` | lockfileVersion 2 and 3. |
| npm | `pnpm-lock.yaml` | lockfile v9. |
| npm | `yarn.lock` | Yarn classic v1 and Berry. |

Packages from git, local paths, direct URLs outside the registry, or private indexes are reported with GRN-E005 (not checked) and never silently passed.

### 3.2 Computing changes

Given a base and head lockfile of the same format, Garnet computes the set of changes as `(ecosystem, normalized name, base version or none, head version or none)`. Names MUST be normalized per ecosystem (PEP 503 for PyPI). A lockfile containing the same package at several versions (common in npm) is compared per `(name, version)` set: each head version not present in base is a candidate, compared against the highest base version below it, or the highest base version if none is lower.

Removed packages produce no findings. Added packages (no base version) get only the rules marked "absolute" in §6.

### 3.3 Invocation without two lockfiles

`garnet diff <package> <old> <new>` compares two releases directly. The install wrapper and hooks compute the head lockfile by resolving without installing (§10).

## 4. Fetching and facts

### 4.1 Sources

| Data | PyPI | npm |
|---|---|---|
| Release metadata and file hashes | JSON API (`/pypi/<name>/<version>/json`) | Registry packument |
| Provenance | Integrity API (`/integrity/<name>/<version>/<file>/provenance`), verified with Sigstore | Registry attestations endpoint, verified with Sigstore |
| Artifacts | Files listed by the JSON API | Tarball |
| Tags | GitHub's public git ref advertisement (`/<repo>.git/info/refs`) for the repository named in provenance, else in project URLs | Same |
| Source files at the tag (GRN-C007) | GitHub's git protocol v2 endpoint (`/<repo>.git/git-upload-pack`), one request per tagged release | Not read |
| Known bad | OSV API (`MAL-` advisories) | OSV API |
| Owners | `ownership` in the JSON API (roles and organization, as they are today) | `maintainers` of the version document |
| New dependencies (GRN-C008) | JSON API (`/pypi/<name>/json`): first upload, releases with files, project URLs, ownership | Packument: `time.created`, versions, repository of the latest version, maintainers |

### 4.2 Artifact selection

- **Trust rules** MUST evaluate every artifact of both releases.
- **Content rules** MUST evaluate the sdist (when present) and one wheel per release. The wheel is the one pip would install on the current machine: the wheel whose most specific tag ranks highest among the tags the running interpreter supports, so a platform wheel is chosen over a pure-Python (`py3-none-any`) one; when no wheel is compatible, the first wheel in sorted file-name order. (Until 2026-10-30 a pure-Python wheel was always chosen first, which let a platform wheel added beside it go unread.) The same selection rule MUST apply to baseline and candidate. If the selected wheel tags differ between releases, Garnet MUST note it in the evidence.
- Every downloaded artifact MUST match the registry's published SHA-256 before it is inspected. A mismatch is finding GRN-T008 (block).

### 4.3 Facts

For each release Garnet extracts: upload time per file; uploader where the registry exposes it; yanked/deprecated status; per-file provenance (present, verified, Sigstore identity, source repository, workflow path, ref, environment, Trusted Publishing or not); the matching tag and its commit if any; file inventory (path, size, SHA-256, kind); declared dependencies that install without an extra (`Requires-Dist` from the wheel's `METADATA`, or from an sdist's `PKG-INFO` at metadata version 2.2 or later when `Requires-Dist` isn't `Dynamic`; for npm, `dependencies`, `optionalDependencies` and non-optional `peerDependencies`), with any npm alias or source outside the registry; `.pth` files; entry points and console scripts; build backend and build requirements; for npm, `scripts` and `bin`, and the process, network and eval uses in the JavaScript its entry points load; and a static index of each Python module's top-level statements, imports and sensitive calls.

Facts are a pure function of the release's published data and MUST be cacheable by `(ecosystem, name, version, file hashes)`. Owners on PyPI and the registry profiles of new dependencies describe the registry on the day Garnet runs; they are fetched per run and are not part of that cache key.

### 4.4 Safety requirements

Garnet MUST NOT import, execute, build or install any inspected content. Archive reading MUST reject absolute paths, `..` segments, symlinks, hard links and device entries, and MUST enforce these default limits (configurable down, not up, in policy):

| Limit | Default |
|---|---|
| Compressed artifact size | 200 MB |
| Total uncompressed size | 1 GB |
| Entries per archive | 100,000 |
| Compression ratio per entry | 100:1 |
| Single Python file parsed with `ast` | 5 MB |
| Single JavaScript file an npm package loads, scanned for GRN-C011 | 16 MB |
| Wall-clock budget per change | 120 s |

Exceeding a limit yields GRN-E003 for that change.

## 5. Baseline selection

1. The baseline for a change is its base-lockfile version.
2. If the candidate skips published versions (for example 2.6.1 → 2.6.4), trust rules MUST also run on every intermediate release that is not yanked, each against its predecessor, and findings MUST name the intermediate version. Content rules run only baseline → candidate.
3. A yanked baseline is still used, with an info note in the evidence.
4. An added package has no baseline.

## 6. Rules

### 6.1 Diff semantics

Most rules are **diff rules**: they fire only when the baseline had a property and the candidate lost it, or the candidate gained a risky property the baseline lacked. A project that never used Trusted Publishing is not penalized for not using it. **Absolute** rules fire regardless of the baseline.

### 6.2 Rule catalog

Default severities are what applies with no policy file.

| ID | Name | Kind | Fires when | Default |
|---|---|---|---|---|
| GRN-T001 | lost-provenance | diff | Every baseline artifact had a verified attestation and at least one candidate artifact has none. | warn |
| GRN-T002 | publisher-changed | diff | The verified source repository differs between baseline and candidate attestations. Repository renames that GitHub redirects MUST NOT fire. | warn |
| GRN-T003 | workflow-changed | diff | Same repository, but the workflow file path or deployment environment differs. | warn |
| GRN-T004 | no-matching-tag | diff | The baseline version had a matching git tag in the source repository and the candidate does not. Tag matching accepts `X` or `vX`, alone or after a prefix that names the package or is `release`, joined by `-`, `_`, `==` or `/`, and `@` for npm. A `/` or `==` prefix may use the end of the name, as monorepos tag by folder, when no tag uses the full name. | warn |
| GRN-T005 | outside-trusted-publishing | diff | Baseline files were published via Trusted Publishing and at least one candidate file was not. | warn |
| GRN-T006 | files-uploaded-late | absolute | A candidate file was uploaded more than 24 hours after the release's first file. `info` when no late wheel is the release's first wheel or ranks at or above an on-time wheel, in pip's order, on a machine built from the release's wheel tags. | warn |
| GRN-T007 | invalid-attestation | absolute | An attestation is present but fails verification. | block |
| GRN-T008 | hash-mismatch | absolute | A downloaded artifact doesn't match its published hash. | block |
| GRN-C001 | new-pth-file | diff | The candidate contains a `.pth` file at a path the baseline did not have, or an existing `.pth` file gained executable lines (lines starting with `import`). | warn |
| GRN-C002 | new-build-hook | diff | A new or changed `setup.py` adds calls in the §6.3 sensitive set; the build backend changed to a non-allowlisted backend or an in-tree backend; or an npm `preinstall`/`install`/`postinstall` script was added or changed. (`prepare` was dropped on 2026-10-29: npm doesn't run it for a published tarball, and every `prepare` change in the top-200 backtest was a build-tool switch.) | warn |
| GRN-C003 | new-import-time-exec | diff | A module's top level (including code reached from `__init__.py` at import) gains a call in the §6.3 sensitive set. It reports at info, as a separate finding, in three cases: in test files (`tests/`, a top-level `test/`, `test_*.py`, `conftest.py`) or reached only from one, unless a non-test module imports the file (directly or through other test modules) or an entry point names it; in sdist files outside the package (`docs/conf.py`, `examples/`) or reached only from one; and for a function import-time code only hands to a call not known to run it (`functools.partial(f)`). A call a package module reaches at import is reported once, at warn. New reads at import of an environment variable that holds a credential or says the code runs in CI, of the whole environment, or of a cloud metadata address are reported in a separate finding at info (docs/rules/GRN-C003.md). | warn (info in test files and the other two cases) |
| GRN-C004 | new-binary | diff | The candidate adds a native executable or shared library that is not a compiled extension module of a package path present in the baseline, or the release changes from pure-Python to containing binaries. | warn |
| GRN-C005 | obfuscated-blob | diff | A changed file gains a string or bytes literal over 2,048 characters with Shannon entropy over 4.5 bits per character, or any such literal passed to `exec`, `eval`, `compile`, `base64.*decode`, `zlib.decompress` or `marshal.loads`. | warn |
| GRN-C006 | sdist-wheel-mismatch | diff | The selected wheel contains a `.py` or `.pth` file with no counterpart in the sdist, when the baseline had none. | warn |
| GRN-C007 | code-not-in-source | diff | A Python file in the candidate's wheel (the sdist when there is no wheel) is not byte-identical to any file in the repository at the candidate's matched git tag (submodules hosted on GitHub included), and it has a §6.3 sensitive call that the file at the same path lacks (every sensitive call counts when there is no file at that path). Calls the baseline already carried outside its source at the same path don't count. Files under a submodule Garnet can't read are reported as GRN-E001. | warn |
| GRN-C008 | new-dependency | diff | The candidate declares a dependency the baseline didn't, or a dependency the baseline had now installs from outside the registry or (npm) installs a different package under the same name. It keeps the default severity when the dependency is not on the registry, installs from outside it, or was first released less than 90 days before the candidate's first upload (or after it), whoever owns it; otherwise it reports at info. An owner it shares with the baseline is listed in the evidence. A failed registry lookup is GRN-E001 naming GRN-C008. | warn (info for an established dependency) |
| GRN-C011 | new-js-capability | diff | npm only. In the JavaScript files the candidate's `package.json` names as entry points (`main`, defaulting to `index.js`; `module`; `browser`; `bin`; every `exports` target) and the files they load through relative `require`, `import`, `import()` or `export … from`, the candidate uses a name the baseline's loaded files didn't: one of the modules `child_process`, `cluster`, `worker_threads`, `net`, `dgram`, `dns`, `http`, `http2`, `https`, `tls`, `vm` (with or without `node:`), a call to `eval`, `Function` or `fetch`, `XMLHttpRequest` or `WebSocket`, or 20 or more `_0x`-hex names in one file. Comments, strings, template text and regular expressions are skipped; nothing is run. Each use records whether it runs when the file loads (outside any function body not called where it is defined). A loaded file over the §4.4 JavaScript limit is GRN-E003. | info |
| GRN-K001 | known-malicious | absolute | OSV lists a `MAL-` advisory affecting the candidate version. | block |
| GRN-E001 | fetch-failed | absolute | Data needed for a rule couldn't be fetched. The finding names which rules were not evaluated. | warn |
| GRN-E002 | parse-failed | absolute | An artifact or file couldn't be parsed. | warn |
| GRN-E003 | budget-exceeded | absolute | A §4.4 limit was hit. | warn |
| GRN-E004 | unpinned-requirement | absolute | A requirements line isn't pinned. | info |
| GRN-E005 | unsupported-source | absolute | A dependency comes from a source Garnet doesn't check. | info |

Rule IDs are permanent. A rule may change default severity only in a minor release with a changelog entry, and never from warn to block outside a major release.

### 6.3 Sensitive call set

For GRN-C002, GRN-C003 and GRN-C007, a call is sensitive if it resolves (through imports and simple aliasing, without executing code) to any of: `exec`, `eval`, `compile`, `__import__`, `importlib.import_module` with a non-literal argument, `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `subprocess.*`, `pty.spawn`, `ctypes.*`, `socket.*`, `urllib.request.*`, `http.client.*`, `httpx.*`, `requests.*`, `aiohttp.*`, `base64.*decode` followed by any of the above, `marshal.loads`, `pickle.loads`. The list is versioned with the rule and MUST be shown by `garnet explain`.

### 6.4 Findings

Each finding MUST carry: `rule_id`, `name`, `severity` (after policy), `default_severity`, `ecosystem`, `package`, `baseline`, `candidate`, `title` (one line), `evidence` (a list, each with `kind` of `file`, `attestation`, `tag`, `advisory`, `url` or `note`, plus kind-specific fields such as `path`, `line`, `sha256`, `identity`), `explanation`, `remediation`, and `suppressed_by` when an ignore applied.

Findings MUST be deterministic: the same inputs and cache produce byte-identical JSON output.

## 7. Policy

### 7.1 Location

Garnet reads, in order, the first that exists: `--policy <path>`, `garnet.toml` in the working directory, `[tool.garnet]` in `pyproject.toml`. With none, defaults apply.

### 7.2 Format

```toml
[garnet]
version = 1                 # required when a policy file exists
default = "warn"            # optional cap for rules at default "warn": "info" | "warn" | "block"
fail_on = "block"           # "warn" | "block" | "never"

[garnet.rules]
"GRN-T001" = "block"        # "off" | "info" | "warn" | "block"
"GRN-C004" = "off"

[[garnet.ignore]]
ecosystem = "pypi"          # optional
package = "numpy"
versions = ">=2.0"          # optional, ecosystem version specifier
rules = ["GRN-C004"]
reason = "ships compiled wheels"   # required
until = "2027-06-30"        # required; ISO date

[garnet.limits]             # may only lower §4.4 defaults
budget_seconds = 60
```

- Unknown keys MUST produce an error, not be ignored.
- An ignore past its `until` date MUST stop applying and produce an info note that it expired.
- An ignore whose `until` is more than 12 months after the day the policy is read MUST be refused as invalid (exit code 3), naming the latest date accepted.
- An ignore MUST NOT suppress GRN-T007, GRN-T008 or GRN-K001 unless it also sets `acknowledge_critical = true`.
- Suppressed findings still appear in JSON and SARIF output with `suppressed_by`.

## 8. Verdicts and exit codes

A change's verdict is the highest unsuppressed severity among its findings (`info` counts as pass). The report verdict is the highest change verdict.

| Exit code | Meaning |
|---|---|
| 0 | Verdict below `fail_on`. |
| 1 | Verdict is `warn` and `fail_on = "warn"`. |
| 2 | Verdict is `block` and `fail_on` is `warn` or `block`. |
| 3 | Garnet itself failed (bad arguments, invalid policy, internal error). |

## 9. Outputs

### 9.1 Text

Human-readable, grouped by change, worst first. Colors only on a TTY. All package-supplied strings MUST be escaped of control characters.

### 9.2 JSON

```json
{
  "schema": "https://garnetguard.dev/schema/report/v1.json",
  "garnet_version": "1.0.0",
  "verdict": "warn",
  "policy": {"source": "garnet.toml", "sha256": "…"},
  "policy_changes": [{"path": "garnet.toml", "changes": ["loosens: new ignore: examplelib GRN-C003 until 2027-06-30, reason: …"]}],
  "changes": [
    {
      "ecosystem": "pypi",
      "package": "examplelib",
      "baseline": "2.6.1",
      "candidate": "2.6.2",
      "verdict": "warn",
      "findings": [ { "rule_id": "GRN-T001", "...": "…" } ],
      "notes": ["2.6.1 has no attestation and no git tag in github.com/example/examplelib, so GRN-T001 to GRN-T005, which compare how releases were published, had nothing to compare with"]
    }
  ]
}
```

`policy_changes` is present only with `garnet check --git-base REF --policy-change PATH`, when the policy file at `PATH` differs from the one at `REF`: one entry per file, each change a line, those that loosen the policy (a new or extended ignore, a rule lowered or turned off, `fail_on` raised, a limit raised, the file deleted) first and prefixed `loosens:`. It never changes the verdict; the policy that applied is the one in `policy`.

`notes` is present only when there is something to say about what the checks could compare. Today that is one case: the baseline has no attestation and no git tag (Garnet looked and found neither), so GRN-T001 to GRN-T005 had nothing to compare with. A note never changes a verdict; the text report prints it after the change's findings and the PR comment shows it in the change's row.

The schema is published with each release. Within 1.x, fields may be added but not removed or retyped. (The URL names the schema; garnetguard.dev doesn't serve the file yet.)

### 9.3 SARIF

SARIF 2.1.0. One `run`, tool name `Garnet Guard` (GitHub shows it as the check run name and on inline alerts), one `rule` per rule ID. Results are located on the lockfile line that pins the candidate version. Severity maps `block` → `error`, `warn` → `warning`, `info` → `note`. Suppressed findings carry a SARIF `suppressions` entry.

### 9.4 PR comment

Markdown with a hidden marker (`<!-- garnet:report -->`) so the Action updates one comment instead of posting new ones. It lists changes with a non-pass verdict first, each with its findings and a link to `garnet explain` docs, then a collapsed list of passing changes. All package-supplied strings MUST be escaped for markdown and MUST NOT create links or mentions. The comment MUST stay under GitHub's 65,536-character limit, truncating passing changes first. It ends with a one-line footer linking to Garnet's docs and to each cited rule's page; the footer links only to documentation, never to anything paid, and the Action input `footer: false` removes it. The footer is on by default (accepted 2026-10-10). When the report has `policy_changes`, the comment MUST open with a callout listing them, so a policy edited beside a dependency bump is visible to the reviewer.

## 10. Surfaces

### 10.1 CLI

```text
garnet check  [--base PATH] [--head PATH] [--git-base REF] [--format text|json|sarif|markdown]
              [--output PATH] [--policy PATH] [--fail-on warn|block|never]
              [--offline] [--cache-dir PATH] [--github-token-env NAME]
garnet diff   <ecosystem>:<package> <old> <new> [same output flags]
garnet explain <RULE-ID>
garnet policy check [PATH]
garnet cache  info|clear
garnet pip install …   |  garnet uv add|sync|lock …   |  garnet npm install …
garnet hook   claude-code|codex
garnet version
```

- `--git-base REF` reads the base lockfile from a git ref, so `garnet check --git-base origin/main` works in any CI.
- `--offline` uses only the cache and reports GRN-E001 for anything missing.
- Tokens are read from the environment variable named by `--github-token-env` (default `GITHUB_TOKEN`). Tokens MUST NOT appear in output or logs.

### 10.2 GitHub Action

```yaml
- uses: orca-solutions/garnet-guard@<sha>   # pinned by commit SHA
  with:
    lockfiles: auto            # or a newline list of paths
    policy: garnet.toml        # optional
    comment: true              # post or update the PR comment
    sarif: false               # upload SARIF to code scanning
    footer: true               # end the comment with one line of docs links (§9.4)
    fail-on: block
```

Outputs: `verdict`, `report-path` (JSON), `comment-path` (the rendered comment), `sarif-path`.

The Action MUST run on `pull_request`, MUST NOT check out or execute PR code under `pull_request_target`, and MUST document the minimal permissions (`contents: read`, plus `pull-requests: write` for comments and `security-events: write` for SARIF). Where the PR's token can't comment (Dependabot's restricted token, forks), the Action MUST support the two-workflow pattern: the analysis job uploads the report artifact, and a separate `workflow_run` job posts it without checking out PR code. The repository ships both workflows as examples.

### 10.3 Install wrapper

`garnet pip install …`, `garnet uv add|sync|lock …` and `garnet npm install …` MUST resolve the change without installing (`pip install --dry-run --report`, `uv lock` into a temp copy, `npm install --package-lock-only` in a temp copy), run `check` on the result, then, if the verdict is below `fail_on`, run the real command with the same arguments. On block it exits 2 and doesn't install. `--garnet-force` skips the block after printing the findings.

### 10.4 Agent hooks

`garnet hook claude-code` prints a Claude Code hook configuration that runs a `PreToolUse` hook on shell commands. The hook detects package-adding commands (`pip install`, `uv add`, `uv pip install`, `poetry add`, `npm install <pkg>`, `pnpm add`, `yarn add`), runs the wrapper's resolve-and-check step, and denies the tool call with the findings as the reason when the verdict is `block`. For `warn` it allows the call and returns the findings as context. `garnet hook codex` does the same with whatever hook or command-approval mechanism Codex offers at 1.0. *Confirm both mechanisms against current Claude Code and Codex docs when building.*

## 11. Non-functional requirements

- **Performance.** For a Dependabot PR with up to 10 changed packages and a cold cache, the Action SHOULD finish in under 3 minutes on a standard GitHub-hosted runner; with a warm cache, under 30 seconds. Fetches run concurrently, at most 8 at a time per host.
- **Platforms.** Python 3.11 to 3.14 on Linux, macOS and Windows.
- **Network.** HTTPS only. Respect `HTTPS_PROXY` and custom CA bundles. Back off on HTTP 429.
- **Dependencies.** Runtime dependencies are listed in [docs/API.md](API.md) §8; adding one requires an ADR.
- **Privacy.** No telemetry (ADR-0008).
- **Releases.** Published with PyPI Trusted Publishing and PEP 740 attestations. Garnet's own dependency PRs are checked by Garnet.

## 12. Versioning and compatibility

Garnet follows semantic versioning from 1.0. The public interface is: CLI commands, flags and exit codes; rule IDs and names; the policy format (`version = 1`); the JSON report schema; the Action's inputs and outputs; and the Python API marked public in [docs/API.md](API.md). Anything else may change in a minor release.

## 13. Acceptance criteria for 1.0

1. Every replayed incident in the backtest corpus that Garnet targets (at minimum lightning 2.6.2 and 2.6.3, elementary-data 0.23.3, litellm 1.82.7 and 1.82.8, telnyx 4.87.1 and 4.87.2, and one npm account-takeover case) produces at least one `warn` or `block` finding from a rule other than GRN-K001.
2. On the clean corpus (the last 11 releases of each of the top 1,000 PyPI packages and the top 1,000 npm packages, from the frozen lists `backtest/top-pypi-1000.json` and `backtest/top-npm-1000.json`; criterion set 2026-10-30), the share of changes with a `warn` or higher is published per rule, and the overall rate is at or below the target set after the month-2 backtest.
3. The parser fuzzing suite runs for at least 1 CPU-hour per parser per release with no crash, hang or limit bypass.
4. Every rule has `explain` text, positive and negative fixtures, and SARIF metadata.
5. The JSON schema, policy format and Action inputs are frozen and documented.
6. The release is published with Trusted Publishing and attestations, and Garnet passes its own check.
