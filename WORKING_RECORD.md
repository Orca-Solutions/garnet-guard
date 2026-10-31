# Garnet Guard working record

Current state, open tasks, verification and review dispositions. Newest first.

## 2026-10-30: npm lockfiles for `garnet check`, part 1 (package-lock.json, yarn.lock)

**State.** `garnet check`, and the Action with `lockfiles: auto`, read package-lock.json and npm-shrinkwrap.json (lockfileVersion 1, 2 and 3) and Yarn 1 yarn.lock. The parsers are `lockfiles/package_lock.py` and `lockfiles/yarn.py`, with npm's name rules, SemVer order and source checks in `lockfiles/npm.py`; no dependency was added.

- Pins carry their ecosystem (`Pin.ecosystem`, `PinChange.ecosystem`, default `"pypi"`), and `workspace.changes_for` and `dedupe` key on it. A checkable pin's `source` is `"registry"` (it was `"pypi"`). `diff_pins` matches (ecosystem, package) and orders npm versions by SemVer 2.0 precedence, build metadata ignored, versions that don't parse first; ties sort by the version string, so the baseline doesn't depend on set order.
- npm names are kept as written and checked against npm's rules (optional `@scope/`, URL-safe characters, at most 214, no leading `.` or `_`, no `..`, no other slash). `ecosystems/npm.normalize` now uses the same check, so a name a parser passes is one the registry adapter accepts; it was stricter (first character a letter or digit, no `~!*'()`), so a valid legacy name from a lockfile would have raised inside `evaluate`. `registry_url` already percent-encodes the name into one path segment. An invalid name is GRN-E005 "not a valid npm package name" under `(invalid name)`, with the raw name kept only in `Pin.origin`, which is compared and never shown.
- Aliases are checked as the package they install (`name` in a package-lock entry, `alias@npm:real@range` in yarn.lock). A registry `resolved` URL (registry.npmjs.org or registry.yarnpkg.com) must be `/<name>/-/<unscoped>-<version>.tgz` for the entry's own name and version, else GRN-E005 "resolved URL isn't this package's registry tarball": otherwise a lockfile could name one package and install another, and Garnet would check the wrong one. An entry with a SemVer version and an integrity but no `resolved` counts as the default registry. Git, `file:`, `http://`, other tarball URLs and private registries are GRN-E005; details never quote the URL, which can carry a token. `Pin.origin` records the URL, so a git dependency moved to another commit at the same version is reported again.
- Skipped, like uv's virtual and editable entries: the root, workspace folders, `link: true` entries and link targets (`../lib`); packages installed under a link target's `node_modules` are checked. `inBundle` entries under another package are GRN-E005 "bundled in <parent>, checked only as part of it"; the project's own `bundleDependencies` install from the registry and are checked. Every package counts, dev, optional and peer included.
- Each pin's line is its package-lock key (found by following the JSON tokens, since `json` has no positions) or its yarn `version` line. Errors name the lockfile and a position, never the file's text, and say "(in the base version)" for the base. Deep nesting, non-object values, `node_modules/../x` keys, wrong field types, invalid UTF-8 and files over 64 MiB (a new cap, for every format) are `LockfileError`, exit 3.
- `discover` adds package-lock.json, npm-shrinkwrap.json and yarn.lock after the Python files, and leaves out a yarn.lock that starts like Yarn Berry (`__metadata:`); pnpm-lock.yaml isn't looked for. Either one passed with `--head` is a `LockfileError`. `action/run.sh`'s auto list, which it checks for symlinks, gained the same three names; nothing else under `action/` changed, and a test now checks the list against `discover`'s names.
- Policy: ignores already matched npm names exactly. `--policy-change` compared ignore names PEP 503 normalized for every ecosystem, so moving an npm ignore from `foo_bar` to `foo-bar` went unlisted; only `ecosystem = "pypi"` ignores are normalized there now. `versions` stays PEP 440 only and never matches an npm change.
- Rendering: markdown.py, sarif.py and report.py had no PyPI-only text or links. GRN-E005's explanation said Garnet compares releases on PyPI; it now says PyPI and npm.

**Decisions to confirm.**
- The registry URL check above, which reports a mismatched `resolved` URL instead of checking the named package.
- `npm.normalize` widened to npm's own rules (and narrowed by `..`), which also changes which GRN-C008 dependency names are looked up.
- `Pin.source` `"pypi"` renamed `"registry"`; the 64 MiB lockfile cap applies to the Python formats too.

**Open tasks.** Part 2: pnpm-lock.yaml (v9) and Yarn Berry, which need PyYAML and an ADR. npm semver ranges for an ignore's `versions`. The example workflows' `paths` filters (README, docs/action.md, action/examples) list only Python lockfiles, and they pin v0.1.0a1, which doesn't read npm ones; add `**/package-lock.json`, `**/npm-shrinkwrap.json` and `**/yarn.lock` with the release that does. The PR comment and text report don't name the ecosystem, so a repository with the same name on PyPI and npm gets two rows with that name (SARIF points at different lockfiles). uv.lock git sources don't record an origin, so a uv git dependency moved to another commit at the same version is still not reported. The lockfile's `integrity` isn't compared with the registry's; npm compares it at install.

**Verification.**
- `uv run pytest` (929 tests; 124 in the new `tests/test_npm_lockfiles.py`), ruff, ruff format, mypy (strict) and `lint-imports` pass. shellcheck isn't installed in this container, so `action/run.sh` wasn't linted; the change adds three quoted paths to an array.
- Fixtures in `tests/fixtures/npm/`: package-lock files written by npm 10.9.4 (`npm install --package-lock-only --ignore-scripts`, lockfileVersion 3 and 2, a workspace with git, `file:` and link entries, and `--omit-lockfile-registry-resolved`), lockfileVersion 1 by npm 6, and yarn.lock by yarn 1.22.22 (`yarn import` from npm 6's lockfile, which wrote only `node_modules/.yarn-integrity`). They cover a scoped package, aliases to plain and scoped packages, two versions of ms, a multi-pattern yarn key and a bump. pnpm-lock.yaml was written by pnpm 10 (`--lockfile-only`); yarn-berry.lock is hand-written in Yarn 4's format, since corepack couldn't download Yarn here. Bundled, private-registry and invalid-name entries are built inline in the tests.
- End to end, with network: a scratch git repository committed a package-lock.json (debug 4.3.6, `my-ms` → ms 2.1.2, @isaacs/string-locale-compare, is-number as a dev dependency), then `npm install --package-lock-only --ignore-scripts debug@4.3.7`. `garnet check --git-base HEAD` reported `debug 4.3.6 → 4.3.7` and `ms 2.1.2 → 2.1.3`, each WARN with only GRN-E001 for the OSV lookup this container can't reach (api.osv.dev, as before); no tag, provenance or content finding. `--format markdown` rendered "2 of 2 updates need a look" with both blocks, and `--format sarif` placed them at package-lock.json lines 25 and 52, the entries' keys. The same run on the yarn fixtures reported debug 2.6.9 → 4.3.7 (from the `debug4@npm:debug@4.3.7` alias) and ms 2.1.2 → 2.1.3; `--head yarn-berry.lock` exited 3 with the Berry message.
- No rule changed, so the backtest wasn't rerun.

**Review dispositions.** None yet.

## 2026-10-30: A Dependabot-opened pull request checked; "checked by" badge on

**State.** Every pending uv update was inside Dependabot's 7-day cooldown, so a run would have opened nothing. #86 exempted ruff from the cooldown for one run; merging it started a Dependabot run, which opened #87 (ruff 0.17.2 → 0.17.3 in the dev group, `uv.lock`) at 20:54 UTC. The dogfood workflow, `.github/workflows/garnet-guard.yml` with the Action pinned at `69c8e01`, ran on it under Dependabot's token with the job's `permissions` block: github-actions[bot] posted "1 update, nothing worth a look" (`ruff` 0.17.2 → 0.17.3, no findings), the SARIF upload reached code scanning, and the job passed in about 20 seconds. The merge also started the github-actions update job, which opened #88 (the actions group); it doesn't touch `uv.lock`, so the workflow didn't run on it.

The README now shows the "checked by" badge, linked to the workflow's runs, as decided on 2026-10-30. The ruff exemption is removed, so every uv update waits 7 days again.

**Open tasks.** Delete the test repository and its fork once the maintainer has looked at them. Move the example pins forward with each release (docs/marketplace.md, step 6).

**Verification.** Documentation and Dependabot configuration only. `uv run pytest`, ruff, mypy (strict) and `lint-imports` pass.

**Review dispositions.** None yet.

## 2026-10-30: The Action on Renovate and fork pull requests; examples pin v0.1.0a1

**State.** The Action at the `v0.1.0a1` commit (`42547f6`) was run on real pull requests in a throwaway public test repository, `orca-solutions/garnet-guard-action-test`, with the examples from `action/examples/` copied unchanged apart from the pin:

- Single workflow, SARIF on. Renovate's pluggy 1.6.0 → 1.7.0 pull request (`requirements.txt`) got "1 of 1 update needs a look" with GRN-T003 (publishing workflow `main.yml` → `deploy.yml`) and an inline code scanning alert on the changed line. Renovate's requests 2.32.3 → 2.34.2 pull request (`pyproject.toml` and `uv.lock`, with Renovate's lockfile `revision = 5`) got "1 update, nothing worth a look". The setup pull request, where every package was new, got a table of six "new at" rows. Each run took about 20 to 50 seconds and passed.
- Single workflow, pull request from a fork (`jfricano/garnet-guard-action-test-fork`). The read-only token's comment POST got HTTP 403, which the comment step reported as a warning; the SARIF upload was skipped with its fork notice; the report went to the job summary; the step passed on the verdict. This is what docs/action.md describes.
- Two-workflow pattern, the same fork pull request after main switched to `garnet-guard-fork.yml` and `garnet-guard-comment.yml`. The `workflow_run` job found the pull request, rendered the uploaded report and posted the comment, ending with the line that the report came from the fork's own workflow run.

No bug turned up, so nothing in the Action changed. The README, docs/action.md and the three examples now pin the `v0.1.0a1` commit instead of the `<release-commit-sha>` placeholder (the maintainer's decision, 2026-10-30).

**Open tasks.** A Dependabot-opened run is still to be seen; the dogfood workflow on this repository gets Dependabot's first weekly pull request around 2026-11-03. The "checked by" badge stays hidden until then. Delete the test repository and its fork once the maintainer has looked at them. Move the example pins forward with each release (docs/marketplace.md, step 6).

**Verification.** Documentation and example pins only. `uv run pytest`, ruff, mypy (strict) and `lint-imports` pass.

**Review dispositions.** None yet.

## 2026-10-30: 0.1.0a1 published; documentation refreshed

**State.** 0.1.0a1 is on PyPI (wheel and sdist uploaded 10:59 UTC, with PEP 740 attestations from `release.yml`) and tagged `v0.1.0a1` at `42547f6`, the merge of #41. It claims the `garnet-guard` name. It includes everything merged through #41: GRN-C007, npm `garnet diff`, the policy file, SARIF, the Action preview and the rule fixes from the replays and the top-1,000 corpora. The replay on that commit warns on all 51 malicious releases (47 PyPI, 4 npm) with the tags of the day; the clean corpora flag 366 of 18,181 updates for a look (2.0%), none a false claim. #42 refreshed the README, its Limits list, the rule pages and the expert brief for those numbers, and #43 fixed the badges PyPI shows.

A documentation review against `main` at `b317d6d` then corrected what still described the repository mid-sprint: the changelog (its "Unreleased" entries had shipped in 0.1.0a1), GRN-C007's status (0.1, not 0.2), the rule coverage page (written while #31 to #38 were open, with the 974-update corpus), ARCHITECTURE (tag source, planned rules, cache, time budget, corpus size), DEVOPS (garnetguard.dev), RELEASING, CONTRIBUTING (Discussions are off), the SPEC's tag source and Action inputs, and the docs index. ROADMAP.md and THREAT_MODEL.md are left to the gap-plan pull request, which edits both.

**Open tasks.** A Dependabot-opened, a Renovate and a fork run of the Action are still to be seen. GRN-C007 has not run on the top-1,000 corpora.

**Maintainer decisions (2026-10-30).** The Action examples keep the `<release-commit-sha>` placeholder until 0.2.0. ADR-0014 is accepted. SPEC §13.2's 1.0 clean corpus is the last 11 releases of the top 1,000 PyPI and top 1,000 npm packages, the corpus the published numbers come from. The "checked by" badge goes live once a Dependabot-opened run of the dogfood workflow has been seen.

**Verification.** Documentation only. `uv run pytest`, ruff, mypy (strict) and `lint-imports` pass. Every number was read from the replay output on `42547f6` and the corpus `summary.json` files.

**Review dispositions.** None yet.

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
  - 2026-10-30: adds 19 more malicious releases from 11 packages (ultralytics, num2words, xinference, mistralai, guardrails-ai, durabletask, memoryos and four Hades-campaign packages). 24 of the 26 releases warn on the day. ultralytics 8.3.42 (attested and tagged by the project's own hijacked workflow, payload not at import) and embiggen 0.11.97 (sdist-only baseline, wheel-only release, so content rules found nothing to compare and passed silently) get nothing. ultralytics 8.3.45/8.3.46 are the first replays where GRN-T001 fires, using `attested = false` recorded from PyPI's analysis.
  - 2026-10-30, second pass: adds 21 more releases from 21 packages whose files come from the `package_integrity` hashes in ossf/malicious-packages (no PyPI snapshot, so no `uploaded_at`): 20 Hades-campaign packages and mrmustard 0.7.4. 44 of the 47 PyPI releases warn on the day; mrmustard 0.7.4 is a third miss (GRN-C003 doesn't follow a nested function handed to `threading.Thread`). Nine packages link no repository in their metadata, so `source_repo` is absent and GRN-T004 can't run for them. With the four npm takeovers, 48 of 51 warn.
  - 2026-10-30, after #32–#36, #38 and #41 (GRN-C007) merged: all 51 warn on the day's facts. ultralytics 8.3.42 is reported by GRN-C007 (two files differ from the `v8.3.42` tree), embiggen 0.11.97 by GRN-C001, mrmustard 0.7.4, num2words and memoryos by GRN-C003. `python -m backtest` exits 0 again.
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
