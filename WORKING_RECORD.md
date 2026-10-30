# Garnet Guard working record

Current state, open tasks, verification and review dispositions. Newest first.

## 2026-10-30: Clean corpus grows to the top 1,000 PyPI and npm packages

**State.** `python -m backtest select|corpus [pypi|npm] [SIZE]` runs the clean corpus for up to the top 1,000 packages of each registry (lists frozen as `backtest/top-pypi-1000.json` and `top-npm-1000.json`; the old top-100 and top-200 files were their first rows), in worker processes. Defaults stay at 100 and 200 so a rule PR's backtest delta stays quick. Results, with every warning triaged:

- PyPI, 9,439 updates of 975 packages: 220 flagged for a look (2.3%), none a false claim. `backtest/corpus-results-pypi-1000/REPORT.md`. Run on main plus the rule-testing branches up to `claude/project-thread-sm89m3-claims` at `dae4777` (PR #38), so the number matches the rules about to ship; on this branch alone the content-rule counts differ.
- npm, 8,742 updates of 989 packages: 146 flagged for a look (1.7%), none a false claim. `backtest/corpus-results-npm-1000/REPORT.md`.

The wider runs found false claims, fixed here or on the rule-testing branch: GRN-T004 missed 16 tags (monorepo folders `utils/v2.8.1`, `release-v1.0.0`, `prebuilt==1.0.11`, `azure-mgmt-core_1.1.0`); GRN-T001 said "no attestation" for whatwg-url 17.1.1, whose attestation is listed but not served (HTTP 404); GRN-C003 made 13 (unimported names read as modules, a module's own `compile`, renames and unparsed files as new modules, handed functions as reached at import). A first version of the wider tag matcher took a sibling package's tag (`proxy-agent@8.0.0` for socks-proxy-agent 8.0.0); a shorter folder name now counts only after `/` or `==` and only in a repository that never tags the full name. The top-200 npm report's triage of trace-mapping, whatwg-url and uuid was wrong and now carries a correction.

**Verification.** `uv run pytest`, ruff, mypy (strict) and `lint-imports` pass. `uv run python -m backtest incidents`: all 11 caught, as on main; the 51-release replay on PR #31's branch with these tag changes gives the same result as without them. Each warning was checked independently: tags with `git ls-remote`, provenance with the registries' attestation endpoints, build hooks by reading both sdists, and every GRN-C003 evidence line read back from the release files with `ast`.

**Open tasks.** Merge after the rule-testing PRs (#32, #33, #34, #36 and #38 at `dae4777` or later) so main's rules match the published PyPI number. The rule-testing thread fixed the GRN-C003 points this run raised, the last in `dae4777` (a top-level `test/` folder counts as test files, which moved ply 3.6 to info). One stays as a known imprecision: in new copies of `six` the cited line is the Python 2 definition of `exec_`, and Python 3 runs the builtin through the same name a few lines later.

**Review dispositions.** None yet.

## 2026-10-30: SARIF tool name is "Garnet Guard"

**State.** The SARIF driver name was `garnet`, which GitHub shows as the code scanning check run's name and at the top of each inline alert ("garnet / ..."). It read like one of GitHub's own checks. It is now `Garnet Guard`. Code scanning tracks alerts by tool name, so alerts uploaded under `garnet` (one so far, #9 on PR #25's merge ref) stay under the old name and aren't matched to new ones.

**Verification.** `uv run pytest`, ruff, mypy (strict) and `lint-imports` pass. The SARIF test still validates against the 2.1.0 schema.

## 2026-10-29: npm releases

**State.** `garnet diff npm:<name> <old> <new>` checks an npm release the way `garnet diff` checks a PyPI release: `ecosystems/npm.py` reads the registry's package document, the release's attestations and the tarball; `ecosystems/npm_provenance.py` verifies npm provenance with Sigstore; `facts/npmmeta.py` reads the tarball's file list and the install-time scripts in `package.json`. The trust rules, GRN-K001 and GRN-T008 (Subresource Integrity) run on npm; GRN-C002 reports an added or changed `preinstall`, `install` or `postinstall` script; GRN-T004 also accepts `<name>@X` tags. `garnet check` doesn't read npm lockfiles yet (`workspace.changes_for` is PyPI-only), so the Action can't check npm pull requests until the package-lock, yarn.lock and pnpm-lock parsers land.

Two things the spec didn't anticipate:

- npm provenance bundles from before September 2025 carry an `intoto` Rekor entry, and the 2023 ones have no inclusion proof. sigstore-python 4.x refuses both. `npm_provenance.py` verifies them with a reduced path built on sigstore's trust root (certificate chain, Rekor's signed entry timestamp, DSSE signature, payload hash, subject digest; no Merkle proof, no SCT). Newer bundles go through `Verifier.verify_dsse` unchanged. ADR-0014 is amended for the direct `sigstore` and `rfc8785` imports; the certificate chain is validated with `cryptography`'s X.509 verifier, as sigstore 4.5.1 does (4.5.0 used pyOpenSSL, which 4.5.1 dropped, and the wheel smoke test caught the missing module).
- `prepare` is dropped from GRN-C002's npm script set (SPEC §6.2 row edited, for the maintainer's say). npm doesn't run `prepare` for a published tarball, and in the first top-200 run every one of its 18 warns was a build-tool switch.

**Verification.**
- `uv run pytest` (257 tests), ruff, mypy (strict) and `lint-imports` pass. `tests/test_npm.py` verifies three recorded real bundles offline: nx 21.4.1 (`intoto` entry), which 3.0.1 (2023, no inclusion proof) and @ctrl/tinycolor 4.2.2 (`dsse` entry), plus tampering, wrong-version and wrong-digest cases.
- `uv run python -m backtest incidents`: all seven incidents caught. The four npm ones (`backtest/npm-incidents.toml`): chalk 5.6.1 and debug 4.4.2 by GRN-T004; nx 21.5.0 by GRN-T001, GRN-T004 and GRN-C002 (`postinstall` → `node telemetry.js`); @ctrl/tinycolor 4.1.1 by GRN-C002 (new `postinstall node bundle.js`) and GRN-T004. npm deletes removed tarballs, so these replay from registry facts recorded from the cited write-ups, with the baseline fetched live; the tarballs are not inspected.
- `uv run python -m backtest corpus npm`, the last 11 releases of the 200 most downloaded npm packages (then `backtest/top-npm-200.json`, now the first 200 of `top-npm-1000.json`; 1,809 updates): 33 warned (1.8%): GRN-T004 25, GRN-T001 5, GRN-T002 2, GRN-T003 1. Triage in `backtest/corpus-results-npm/REPORT.md`. Before the two fixes above the run showed 54 (3.0%), with 18 `prepare` warns and 3 wrong GRN-T007 blocks on 2023 bundles.
- The cloud container reaches registry.npmjs.org and github.com, so both npm backtests ran there; api.osv.dev stays unreachable, which the replay doesn't need.

**Open tasks.** npm lockfile parsers (package-lock.json v2/v3, yarn.lock, pnpm-lock.yaml, the last needing `pyyaml` and an ADR); `bin` diffs; a JavaScript content rule (GRN-C005 obfuscated-blob would have had something to say about chalk's index.js); SPEC §6.2 wording for `prepare`.

**Review dispositions.** None yet.

## 2026-10-29: 0.1.0a1 prepared

**State.** The version is `0.1.0a1`, the first pre-release, cut to claim `garnet-guard` on PyPI (still unclaimed on 2026-10-29). Rule links in findings, `garnet explain` and the PR comment now go to `https://garnetguard.dev/rules/<ID>`, and the JSON report's schema URL uses garnetguard.dev instead of the unowned garnet.dev. The README uses absolute links so it renders on PyPI, and pyproject.toml sends it there with project links and classifiers.

**Open tasks.** The maintainer's one-time PyPI and GitHub settings (docs/RELEASING.md), then the tag. The site serves rule pages from the commit pinned in gg-landing's `site/upstream.toml` (2026-10-10), so the linked pages show October 10 text until that pin moves. garnetguard.dev doesn't serve the report schema file yet. For the Marketplace listing, the README still needs a real PR comment, the interest-list line and the move off "pre-alpha".

**Verification.** `uv run pytest` (225 tests after merging main, which brought the policy file, SARIF and the dogfood workflow), ruff, mypy (strict) and `lint-imports` pass. `uv build --no-sources` and `twine check --strict` pass; the wheel installs in a fresh environment and both `garnet version` and `garnet-guard version` print `garnet 0.1.0a1` (`uvx garnet-guard` needs the second script). The release workflow has not run yet.
## 2026-10-29: Garnet Guard checks its own dependency pull requests

**State.** `.github/workflows/garnet-guard.yml` runs the Action on every pull request that changes `uv.lock`, which is what Dependabot's weekly uv updates do. The Action is pinned to a commit on `main` rather than run from the pull request (`uses: ./`): from the pull request it would install Garnet Guard from that pull request's own `uv.lock`, running the updated packages before checking them. It is pinned to the merge of the policy file (`cedecde`), so the Action reads `garnet.toml` from the base commit. The pin moves forward by hand when the Action changes, and to a release commit once one is tagged. The same pull request bumps ruff 0.17.1 → 0.17.2 (the update Dependabot's 7-day cooldown allows today) so the workflow runs on it.

**Verification.** Before pushing, Dependabot's PR #13 (ruff 0.17.0 → 0.17.1) was replayed through `action/run.sh` locally with a simulated runner environment: verdict, report and comment came out as expected, apart from an OSV lookup the sandbox blocks (`GRN-E001`). actionlint and zizmor pass on the new workflow. Tests, ruff, mypy and `lint-imports` pass.

**Open.** A Dependabot-opened run (its token differs from a maintainer's), a Renovate pull request and a pull request from a fork are still to be seen on GitHub.

## 2026-10-29: policy file and ignores

**State.** The SPEC §7 policy is built in `src/garnet_guard/policy.py` and applied by the engine:

- `garnet.toml`, or `[tool.garnet]` in `pyproject.toml`, with `version = 1`, `default`, `fail_on`, `[garnet.rules]`, `[[garnet.ignore]]` and `[garnet.limits]`. Unknown keys, unknown rules, raised limits and ignores without `reason` or `until` are errors (exit 3).
- `garnet check` and `garnet diff` read it (`--policy PATH`, `--no-policy`); `--fail-on` now defaults to the policy's `fail_on`, else `block`. `garnet policy check [PATH]` validates one and lists its ignores.
- An ignored finding keeps its severity and stays in every output (`suppressed_by` in JSON, `ignored` in text, "ignored by the policy" in the comment) but doesn't count toward the verdict. An ignore applies through its `until` date; afterwards the finding counts again with a note, and the report lists expired ignores (`policy.expired` in JSON, a line in the comment).
- GRN-T007, T008 and K001 can't be lowered in `[garnet.rules]` and need `acknowledge_critical = true` in an ignore. GRN-E001 to E005 can't go below their default in `[garnet.rules]` or via `default`, so a check that didn't run never passes quietly; a per-package ignore still can.
- The Action gained a `policy` input (`auto`, or a path). `action/run.sh` reads it from the base commit with `git show`, so a pull request can't relax its own policy, and passes `--no-policy` when the base has none. The `fail-on` input default is now empty (the policy's `fail_on`, else `block`).
- `docs/policy.md` is the user guide; the 20 rule pages link to it instead of saying 0.1 doesn't read policies.

**Verification.** `uv run pytest` (198 tests, 65 of them in `tests/test_policy.py` and 8 new Action tests), ruff, mypy (strict) and `lint-imports` (a new contract keeps `policy.py` off the network and archives) pass. `uv run python -m backtest`: unchanged, the three incidents are caught (lightning 2.6.2 and 2.6.3 by GRN-C003 and T004, elementary-data 0.23.3 by GRN-C001 and T004) and 0 of 20 clean updates warn.

**Decisions to confirm.**
- `versions` in an ignore is PEP 440 only. For npm changes an ignore with `versions` never matches; semver ranges arrive with npm support.
- Policies may name rules the SPEC lists but 0.1 doesn't build (GRN-T006, C004 to C006).
- In the Action's JSON report, `policy.source` is the path of the copy read from the base commit under `RUNNER_TEMP`, not the repository path.

## 2026-10-27: GitHub Action re-landed on main

**State.** PR #5 (the Action) was merged into `lockfiles/garnet-check` after PR #6 had already merged, so `action.yml`, `action/` and `garnet_guard.markdown` never reached `main`. This entry's PR replays #5's three commits onto `main` unchanged; the files match #5's final version. The Action runs `garnet check`, which is now on `main`.

**Verification.** `uv run pytest` (110 tests), ruff, mypy (strict), `lint-imports`, shellcheck and zizmor (offline) pass. The Action itself has not run on GitHub yet.

## 2026-10-10: GitHub Action preview

**State.** The Action and its comment are built on top of `garnet check` (PR #6):

- `action.yml` at the repository root (Marketplace needs it there; API.md §9 shows `action/`), with scripts in `action/`.
- `action/comment/`: the `workflow_run` comment job for forks.
- `action/examples/`: the single workflow, plus the two-workflow pair for forks.
- `garnet_guard.markdown`: the SPEC §9.4 comment, rendered from the JSON report.
- `docs/action.md` (usage) and `docs/marketplace.md` (listing steps).

**Verification.**
- `uv run pytest`: unit tests pass with no network. `tests/test_action.py` runs the shell scripts against a local git repository, with `uv` and `gh` stubbed.
- ruff, mypy (strict), `lint-imports`, shellcheck, actionlint and zizmor all pass. zizmor's only findings are the `<release-commit-sha>` placeholders in the examples.
- The Action itself has not run on GitHub yet.
- Independent review found six issues, all fixed: the renderer could import a module from the pull request checkout (`python -m` puts the working directory on `sys.path`); a bad report in the fork comment job left the old comment up; a stale report could be reused; long SHAs could still autolink; fork comments looked independent; the git auth header was on argv. A symlinked lockfile is now refused too.
- No `policy` input: `garnet check` doesn't read policy files in this preview.

**Open questions.**
- The comment's passing-update column says "no findings" where the mock shows "provenance ✓ · tag ✓ · content ✓". A report doesn't record which checks ran clean, so the mock's wording would claim more than Garnet Guard knows.
- Rule links point to `docs/rules/<ID>.md` in the repository, not garnet-guard.dev, until a domain is registered.

## 2026-10-10: CI and release pipeline

**State.** `.github/workflows/` has CI (`ci.yml`), the OpenSSF Scorecard (`scorecard.yml`) and a tag-triggered release (`release.yml`) that publishes with Trusted Publishing and PEP 740 attestations, then verifies them from PyPI. Dependabot watches GitHub Actions and the uv lockfile with a 7-day cooldown. All actions are pinned by commit SHA and every job declares minimal permissions.

**Open tasks.** The one-time PyPI and GitHub settings in docs/RELEASING.md (pending trusted publisher, `pypi` environment, tag and branch rulesets). Nothing can publish until they exist. CI runs on Linux only; macOS and Windows (SPEC §11) are a follow-up once the tests are checked there.

**Verification.** actionlint and zizmor pass on the workflows (zizmor: one low "self-repository" note, kept as `./` syntax). The CI commands pass locally, including tests on Python 3.14, `uv build --no-sources` and the wheel smoke test. The workflows themselves first run on this PR.

## 2026-10-10: repository seeded, `garnet diff` preview

**State.** The repository is seeded from the founding documents and contains the 0.1 preview engine:

- `garnet diff <pkg> <old> <new>` for PyPI
- `garnet explain` and `garnet version`
- text and JSON reports

**Rules implemented:**
- GRN-T001 to T005, T007, T008
- GRN-C001 to C003
- GRN-K001
- GRN-E001 to E003

**Verification.**
- `uv run pytest`: 38 unit tests pass with no network.
- `uv run ruff check .`, `ruff format --check .`, `mypy src` (strict) and `lint-imports` all pass.
- `uv run python -m backtest`:
  - Replays lightning 2.6.2 and 2.6.3, each caught by GRN-C003 and GRN-T004.
  - Replays elementary-data 0.23.3, caught by GRN-C001. GRN-T004 fires only against today's tags: the attacker's `v0.23.3` tag existed on the day and was deleted later.
  - Replays litellm 1.82.7 (GRN-C003) and 1.82.8 (GRN-C001, GRN-C003), and telnyx 4.87.1 and 4.87.2 (GRN-C003, GRN-T004).
  - Replays the deleted malicious files by URL and hash from files.pythonhosted.org.
  - The 20 clean updates in `backtest/clean.toml` produce no warnings from detection rules.
- Known-bad lookups are off in the backtest on purpose, to show what Garnet Guard catches before any feed lists a release.

**Caveats.**
- GRN-T001 can't fire on these incidents, because neither project attested releases before the attack.
- GRN-T004 is evaluated against the tags as they stood at upload: today's tags with the changes recorded in `backtest/incidents.toml` (`tags_on_the_day`). Tag changes nobody recorded aren't modelled.

**Open tasks (month 1, see ROADMAP.md):**
- lockfile parsers and `garnet check`
- policy file
- cache
- intermediate versions (SPEC §5 rule 2)
- SARIF output
- per-change time budget
- fuzz tests for `safe_archive.py`
- CI workflow with pinned Actions
- approach-check notes

**Review dispositions.** None yet.
