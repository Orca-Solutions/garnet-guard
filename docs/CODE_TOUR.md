# A tour of the Garnet Guard code

This page explains how the code in `src/garnet_guard/` fits together, as it is in the 0.1
preview. It is written for someone new to the project: a contributor about to make a first
change, or a reviewer who wants to check that the code keeps the promises in the README.
You don't need to read Python fluently to follow it.

For the design Garnet Guard is growing into, see [ARCHITECTURE.md](../ARCHITECTURE.md) and
[API.md](API.md). For exact behavior, [SPEC-v1.md](SPEC-v1.md) is the reference. Where this
page and the code disagree, the code is right and this page needs a fix.

## What the program does

When a dependency update moves a package from a version your project already runs (the
**baseline**) to a new one (the **candidate**), Garnet Guard downloads both releases,
reads them without running them, and compares them. It reports three kinds of change:

- **Trust**: the candidate was published differently. It lost its signed attestation, came
  from a different repository or workflow, or has no git tag.
- **Content**: the candidate contains code that runs on its own, which the baseline didn't
  have: a new `.pth` file, new build-time code, or new calls to `subprocess`, `exec` or the
  network that run as soon as a module is imported.
- **Known bad**: a public malware database lists the candidate.

When it can't find something out (a download failed, a file couldn't be parsed, a limit was
hit), it says so in the report. A check that didn't run is never counted as a pass.

## Five stages

Every run goes through the same five stages, whichever command started it.

```text
 1. Find what changed       workspace.py, lockfiles/        → a list of Change records
 2. Gather the facts        engine.py, ecosystems/          → ReleaseFacts for each version
        (network)             net.py: the only network code
 3. Read the files          facts/                          → what each artifact contains
        (archives)            safe_archive.py: the only archive code
 4. Judge                   checks/                         → findings (no network, no files)
 5. Write it up             engine.py, report.py, markdown.py, sarif.py → text, JSON, the PR comment, SARIF
```

1. **Find what changed.** `garnet check` reads the trusted lockfile and the updated one
   (`workspace.py` finds them, `lockfiles/` parses them) and lists every package whose
   version changed. Each one becomes a `Change`: ecosystem, package, baseline version,
   candidate version, and the lockfile line. Entries Garnet can't check (not pinned to one
   version, installed from git, a path or a private index or registry, or bundled inside
   another npm package) become GRN-E004 or GRN-E005 findings
   here, so they show up in the report instead of disappearing. `garnet diff` skips this
   stage: you name the package and both versions yourself.
2. **Gather the facts.** `engine.py` asks `ecosystems/pypi.py` or `ecosystems/npm.py` for a
   `ReleaseFacts` record for each version. The PyPI module fetches PyPI's metadata, the
   attestation for every file, the sdist and one wheel (and, for GRN-C012, one wheel per other
   platform and up to 30 late ones); the npm module fetches the registry's package document, the
   release's attestations and the tarball. Both look up
   the project's git tags (`ecosystems/github.py`) and malware advisories
   (`ecosystems/osv.py`), and verify attestations (`ecosystems/provenance.py` for PEP 740,
   `ecosystems/npm_provenance.py` for npm provenance). When a PyPI release has a matching tag,
   `ecosystems/gittree.py` reads the repository's file list at that commit over the same git
   endpoint as the tag lookup, and `ecosystems/source.py` compares the wheel's Python files
   with it, reading back and indexing only the few files that aren't in the tree. When the
   new version declares a dependency the trusted one didn't, `engine.py` asks the registry
   about that package (`package_profile()` in each ecosystem module) and attaches the answer
   to the facts for GRN-C008, so the check itself stays free of I/O. A failure in any step is
   recorded on the facts as an error naming the rules it kept from running.
3. **Read the files.** `facts/inventory.py` lists every file in an archive with its size,
   hash and kind. `facts/pyindex.py` parses each Python file with `ast` (Python's own
   parser, which reads code as a tree without running it) and records the sensitive calls
   that run at import time and the id git would give the file's bytes. `facts/npmmeta.py`
   reads an npm tarball's file list and the install-time scripts in its `package.json`, and
   `facts/jsscan.py` tokenizes the JavaScript the package loads (skipping comments, strings
   and regular expressions) to find process, network and eval uses for GRN-C011.
4. **Judge.** `checks/` holds one function per rule. Each takes the baseline facts and the
   candidate facts and returns findings. Checks do no network or file access at all, so a
   test can hand them made-up facts and know exactly what should come back.
5. **Write it up.** `engine.py` gives each finding its rule's default severity, sorts the
   findings so the same input always gives the same report, and works out the verdict.
   `report.py` writes terminal text or JSON, `markdown.py` writes the pull request
   comment for the GitHub Action, and `sarif.py` writes the report GitHub code scanning
   reads for the Security tab.

The CLI, the Action and the backtest all call the same engine functions: `compare()` for
one package and `evaluate()` for many, both in `engine.py`. That is why the backtest's
results describe what users will see.

## Where each part lives

| Module | What it does |
|---|---|
| [`cli.py`](../src/garnet_guard/cli.py) | The `garnet` command: parses arguments, runs the engine, prints the report, returns the exit code. |
| [`workspace.py`](../src/garnet_guard/workspace.py) | Finds lockfiles, reads the base version from git, refuses symlinked lockfiles, and turns lockfile differences into `Change` records. |
| [`lockfiles/`](../src/garnet_guard/lockfiles/) | One parser per lockfile format (`uv.lock`, `poetry.lock`, `pylock.toml` and `requirements*.txt` for PyPI; `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml` and `yarn.lock` from Yarn 1 and Yarn 2+ for npm) and the code that compares two lists of pins, each in its ecosystem's version order. `yamldoc.py` is the strict YAML reader the pnpm and Yarn 2+ parsers share, and `registries.py` reads the registry keys of the .npmrc, pnpm-workspace.yaml and .yarnrc.yml beside those lockfiles. |
| [`engine.py`](../src/garnet_guard/engine.py) | Runs the stages in order: fetch facts in parallel, run every check, turn errors into findings, sort, decide the verdict. |
| [`ecosystems/`](../src/garnet_guard/ecosystems/) | Everything fetched about a release: PyPI and npm registry metadata and files, attestations, git tags, the repository's files at the tag (read from a git packfile, no `git` needed), OSV advisories. |
| [`net.py`](../src/garnet_guard/net.py) | The only code that uses the network. HTTPS only, a short list of allowed hosts, size caps, timeouts and retries. |
| [`safe_archive.py`](../src/garnet_guard/safe_archive.py) | The only code that opens zip and tar archives. Reads them in memory, never extracts to disk, and rejects dangerous entries. |
| [`facts/`](../src/garnet_guard/facts/) | Describes what an archive contains, what its Python code does at import time, which npm scripts run at install, and what an npm package's JavaScript reaches for, without running anything. |
| [`models.py`](../src/garnet_guard/models.py) | The records passed between stages: `Change`, `ReleaseFacts`, `Finding` and the rest. All frozen, so no stage can change what an earlier one recorded. |
| [`checks/`](../src/garnet_guard/checks/) | One small function per rule (`trust.py`, `content.py`, and K001 in `__init__.py`), plus `docs.py` with the text `garnet explain` prints. |
| [`policy.py`](../src/garnet_guard/policy.py) | Reads `garnet.toml` (SPEC §7): rule severities, expiring ignores and lower limits. Strict on purpose: an unknown key or a missing reason is an error, not a default. |
| [`report.py`](../src/garnet_guard/report.py) | Text and JSON output. Escapes package-supplied text before it reaches a terminal. |
| [`markdown.py`](../src/garnet_guard/markdown.py) | The pull request comment. Treats the whole report as untrusted and escapes every string so a package can't add links, mentions or HTML. |
| [`sarif.py`](../src/garnet_guard/sarif.py) | The SARIF report for GitHub code scanning, rendered from the JSON report the same way. Rule metadata comes from Garnet's own rule docs, never from the report. |
| [`install/`](../src/garnet_guard/install/) | `garnet pip install`, `garnet uv add|remove|lock|sync` and the agent hooks ([install-wrapper.md](install-wrapper.md)). `pip.py` and `uv.py` read a command and the files it names and refuse what would build; `check.py` resolves with builds off, compares with what's installed or committed and calls the engine; `wrapper.py` installs exactly what was checked; `shellwords.py` reads an agent's shell command with `shlex` without running it; `gate.py` and `hooks.py` answer the hook; `runner.py` starts the user's pip, uv or git from an argument list. |
| [`console.py`](../src/garnet_guard/console.py) | The entry point of `garnet` and `garnet-guard`. `garnet hook <agent> run` goes to `install/gate.py`, which imports only the standard library; everything else goes to `cli.py`. |

Outside `src/`:

| Folder | What's there |
|---|---|
| [`action/`](../action/) and [`action.yml`](../action.yml) | The GitHub Action: shell scripts that run `garnet check` and post the comment. See [action.md](action.md). |
| [`tests/`](../tests/) | Unit tests. `tests/builders.py` builds tiny wheels, sdists and facts in memory, so tests never use the network. |
| [`backtest/`](../backtest/) | Replays of real compromised releases (`incidents.toml`, `npm-incidents.toml`) and corpora of ordinary updates, to measure what Garnet catches and how often it's wrong. Run with `uv run python -m backtest`. |
| [`docs/rules/`](rules/README.md) | One page per rule. Findings link to these pages. |

## The boundaries are enforced

The stages are kept apart by the code, not only by convention. `uv run lint-imports` reads
the contracts in [`pyproject.toml`](../pyproject.toml) and CI fails if one breaks:

- `models.py` imports nothing else from Garnet.
- `checks/` can't import the network code, the fetchers or the archive reader.
- `facts/` can't import the network code.
- Only `net.py` imports the HTTP library.
- `install/` reaches the network and release data only through `engine.py`, and nothing below the surfaces imports it.

The project's hard rules (in [AGENTS.md](../AGENTS.md)) map onto the code like this:

| Hard rule | Where it's kept |
|---|---|
| Never run package code | `facts/pyindex.py` parses with `ast`. `subprocess` runs only `git` on your own repository (`workspace.py`, and `install/hooks.py` to see whether a package manager is committed) and your own pip or uv from `install/runner.py`, with builds turned off for the resolve step. |
| All archive access through `safe_archive.py` | `zipfile` and `tarfile` are imported only there. |
| Checks are pure | Enforced by `lint-imports`, above. |
| "Couldn't check" is never "pass" | Fetch and parse failures become GRN-E001 to GRN-E003 findings; unreadable lockfiles and internal errors exit with code 3. |
| Escape package-supplied strings | `report.escape()` for the terminal, `markdown.text()` and `markdown.code()` for the PR comment. |

## The rules

Each finding has a rule ID. The letter says the family: **T** trust, **C** content, **K**
known bad, **E** couldn't check. IDs are permanent: a rule is never renumbered and an ID is
never reused. [docs/rules/README.md](rules/README.md) lists every rule and says which are
built.

Most rules are **diff rules**: they fire only when the candidate is worse than the baseline.
A project that never signed its releases isn't flagged for not signing this one, which is
what keeps Garnet quiet on ordinary updates. **Absolute rules** look at the candidate alone.

Every rule function in `checks/` has the same shape. Read one with three questions in mind:

1. **When does it stay silent?** Usually when there's no baseline, or the baseline didn't
   have the property either.
2. **When does it fire?** The condition, and the evidence it attaches.
3. **What does it do when it doesn't know?** It reports GRN-E001 or relies on an error
   recorded while fetching, rather than returning nothing.

For example, `lost_provenance` in [`checks/trust.py`](../src/garnet_guard/checks/trust.py)
(GRN-T001) is silent unless every baseline file had a verified attestation, fires when a
candidate file has none, and reports GRN-E001 when the candidate's attestations couldn't be
fetched.

A check never sets a finding's severity. It returns a `RawFinding`, and the engine adds the
rule's default severity from `checks/docs.py`. A check may lower that severity (GRN-C003
reports at `info` for test files nothing imports) but never raise it.

## Following one run

`uv run garnet diff requests 2.32.4 2.32.5` goes through the code like this:

1. `cli.main` parses the arguments and calls `_diff`, which calls `engine.compare`.
2. `compare` calls `fetch_facts`, which runs `pypi.release_facts` for both versions at once.
3. For each version, `release_facts` fetches `pypi.org/pypi/requests/<version>/json`,
   then the provenance of every file. It downloads the sdist and the selected wheel,
   checks each against PyPI's SHA-256, and hands the bytes to `inspect_artifact`. It then
   looks up the git tag and, for the candidate, the OSV advisories.
4. `inspect_artifact` opens the archive through `safe_archive.open_archive`, reads every
   file, and runs `pyindex.index_module` on each Python file.
5. Back in the engine, `run_checks` calls every function in `checks.ALL_CHECKS` with the
   two `ReleaseFacts`, adds a finding for each recorded error, and sorts the result.
6. `report` collects the result, `report.to_text` prints it, and `Report.exit_code`
   decides the exit code from `--fail-on`.

`garnet check` adds stage 1 in front (`workspace.changes_for`) and calls `engine.evaluate`,
which fetches each release once even if several lockfiles mention it.

## Running it yourself

From a checkout, with [uv](https://docs.astral.sh/uv/) installed:

```sh
uv sync                                   # install
uv run garnet --help                      # every command and option, and the exit codes
uv run garnet explain GRN-C003            # what a rule checks, and its list of sensitive calls
uv run garnet diff requests 2.32.4 2.32.5 # compare two releases
uv run garnet check --git-base main       # compare this folder's lockfiles with main's
uv run python -m backtest                 # replay the incidents and the clean updates
uv run pytest                             # the unit tests (no network)
```

A good first read is [`tests/test_safe_archive.py`](../tests/test_safe_archive.py): it
builds hostile archives (path traversal, symlinks, compression bombs) and checks that each
one is refused.

## Glossary

| Term | Meaning |
|---|---|
| Attestation (PEP 740) | A signed statement stored on PyPI that a file was built by a named repository and workflow. Garnet verifies it with Sigstore. |
| Baseline | The version your project already runs. Everything is compared with it. |
| Candidate | The version the update moves to. |
| Diff rule, absolute rule | A diff rule fires only if the candidate is worse than the baseline; an absolute rule looks at the candidate alone. |
| Finding | One thing a rule reported, with evidence a reviewer can check: a file and line, a tag, an attestation or a link. |
| Hash (SHA-256) | A fingerprint of a file. Change one byte and the hash changes. |
| Import time | The moment Python loads a module. Code at the top level of a module runs then, before any of its functions are called. |
| Lockfile | A project's exact list of packages and versions, such as `uv.lock`. |
| `.pth` file | A small file Python reads at every startup. A line in it that starts with `import` runs automatically. |
| sdist, wheel | A package's source archive, and its ready-to-install archive. Garnet reads the sdist and one wheel, and compares a few of the release's other wheels with it. |
| Severity, verdict | `block`, `warn` or `info` on each finding. The verdict is the worst severity in the report; `info` counts as a pass. |
| Trusted Publishing | PyPI's way of letting a specific CI workflow upload releases without a long-lived password. |
| OSV | A public database of vulnerabilities and malware, at [osv.dev](https://osv.dev). |
