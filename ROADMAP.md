# Garnet Guard roadmap

Months count from the repository going live. Version numbers are targets, not promises. Funding sequencing, go/no-go gates, outreach, grants, the fiscal host and the LLC come from the maintainer's planning documents, which are not in this repository. The PyCon US 2027 talk adds two dated milestones (Nov 15 and Dec 1, 2026) and a Dec 15 proposal submission, and the public launch is set for the week of Dec 8, 2026 (DECISIONS 40), just before that submission. Those dates assume the repo goes live in mid-October 2026 and slip with it. The normative 1.0 behavior is in [docs/SPEC-v1.md](docs/SPEC-v1.md).

| Release | When | Theme |
|---|---|---|
| 0.1 | end of month 1 | Engine and PyPI checks, CLI |
| 0.2 | end of month 2 (launch week from Tue Dec 8, 2026) | Public launch: GitHub Action, policy, docs, replay write-up |
| 0.3 | month 3 (January 2027) | Second beat: install wrapper, agent hooks, full backtest |
| **1.0** | months 4–6 | Stable interfaces, acceptance criteria met |
| **2.x** | months 6–12 | History and depth: richer baselines, new signals, plugins |
| **3.x** | year 2 | Breadth and upstream: more ecosystems, native adoption |

---

## Month 0: repo creation

- [x] Create `orca-solutions/garnet-guard` **public from day one** (ADR-0011) and seed it from the founding documents
- [x] Turn on GitHub private vulnerability reporting
- [ ] Branch protection and required signed commits
- [x] Reserve `garnet-guard` on PyPI with Trusted Publishing configured (ADR-0007); 0.1.0a1 is published
- [ ] GitHub Sponsors and `.github/FUNDING.yml`
- [ ] Enable GitHub Discussions as the community space (off for now; questions go to issues)

## Month 1 → 0.1: engine and PyPI

- [x] Repo skeleton: uv project, ruff, mypy (strict on `src/`), pytest, import-linter, CI, `uv.lock`, pinned Actions
- [x] Models and the public API in [docs/API.md](docs/API.md) §3
- [x] `safe_archive.py` and `net.py` with limits and their unit tests, before any check reads an archive
- [ ] Fuzz tests for `safe_archive.py` and `net.py`
- [x] Lockfile parsers: uv.lock, poetry.lock, pylock.toml, pinned requirements.txt
- [x] PyPI adapter: JSON API, Integrity API, attestation verification, cache
- [x] GitHub tag lookup; OSV lookup
- [x] Rules GRN-T001–T005, T007, T008, C001–C003, K001, E001–E005, and GRN-C007 code-not-in-source
- [x] Reporters: text, JSON, SARIF
- [x] First incident replays: lightning 2.6.2/2.6.3, elementary-data 0.23.3, litellm 1.82.7/1.82.8, telnyx 4.87.1/4.87.2, ultralytics, num2words, xinference, mistralai, guardrails-ai, durabletask, memoryos, mrmustard and the Hades packages (47 releases), reproducible from one command **by Nov 15, 2026** (PyCon proposal dependency); four npm replays (chalk, debug, nx, @ctrl/tinycolor) were added
- [x] **Reduced clean-corpus backtest by Dec 1, 2026:** top 100 PyPI packages × last 10 releases, warn rate per rule. Pulled forward from month 2 so the PyCon US 2027 proposal can cite a real false-positive number. Done as the 974-update corpus (the last 11 releases of the top 100), then widened to the last 11 releases of the top 1,000 PyPI and npm packages (18,181 updates)
- [ ] Approach-check notes to three to five packaging and security experts on reading the Integrity API (outreach Draft A)

**Exit:** both incidents produce a `warn` from rules that would have fired before any feed listed them; unit tests have no network access.

## Month 2 → 0.2: launch (week of Tue Dec 8, 2026)

Launch means the replay write-up plus a working GitHub Action. The bar doesn't move: the replays are caught and the clean-corpus warn rate is met, using the Dec 1 reduced backtest as the launch number. If the bar isn't met, the launch slips, not the bar.

- [x] GitHub Action with a sticky PR comment and optional SARIF upload
- [x] Ship single-job and two-workflow examples
- [ ] Verify Dependabot token behavior on a Dependabot-opened run
- [x] Policy file with expiring ignores (SPEC §7)
- [x] Dogfood on Garnet's own repo
- [ ] Dogfood on 5–10 friendly repos (outreach Draft B)
- [ ] Opt-in interest list link in the README (not telemetry)
- [ ] Docs site: quickstart, one page per rule, policy guide, comparison page
- [ ] GitHub Marketplace listing for the Action
- [ ] Launch write-up "We replayed the 2025–26 supply-chain attacks against Garnet Guard", then Show HN, Python Discourse, r/Python, Mastodon and Bluesky, newsletters (marketing owns the launch)
- [ ] In launch week: apply to the GitHub Secure Open Source Fund (if a cohort is open) and to Open Source Collective as fiscal host (needs an org-owned repo, which `orca-solutions` satisfies, and a second admin by early December)
- [ ] *Stretch, not a launch requirement:* npm adapter (package-lock, pnpm-lock, yarn.lock; npm provenance; lifecycle-script and `bin` diffs). `garnet diff npm:…`, provenance, tags and lifecycle-script diffs are built and backtested; the lockfile parsers and `bin` diffs are open.

**Exit:** the launch success criteria in [VISION.md](VISION.md); the Action runs on real Dependabot and Renovate PRs.

## Closing the evasion gaps

A red-team pass over the rules on 2026-10-30 listed the ways a malicious release could still get past Garnet; [THREAT_MODEL.md](THREAT_MODEL.md#known-gaps-and-the-plan) has the condensed map. Every gap with a feasible check has an issue, sorted below (DECISIONS 81–84). Small, quiet checks go first. Each check lands as its own draft PR with fixtures, `garnet explain` text, and the 974-update clean corpus and incident replays before and after (plus the npm corpus for npm rules); a check that the corpus shows to be noisy ships at `info`. The PR closes its issue and ticks its line here.

**Launch (0.2):**

- [x] GRN-C008 new-dependency: a dependency the trusted release didn't declare, a warning when it is new to the registry [#44](https://github.com/orca-solutions/garnet-guard/issues/44)
- [x] GRN-T006 files-uploaded-late, and content rules read the wheel pip would install (pulled forward from 0.3) [#45](https://github.com/orca-solutions/garnet-guard/issues/45)
- [x] GRN-C012 wheels-differ: a wheel whose Python files differ from the release's other wheels [#45](https://github.com/orca-solutions/garnet-guard/issues/45)
- [x] Widen the sensitive call set to process, loader and network APIs it doesn't list (set 2026-10-c) [#46](https://github.com/orca-solutions/garnet-guard/issues/46)
- [x] GRN-C009 new-entry-point: a new entry point, warning for groups other tools load automatically [#47](https://github.com/orca-solutions/garnet-guard/issues/47)
- [x] GRN-C004 new-binary, including sourceless `.pyc` files (pulled forward from 0.3) [#48](https://github.com/orca-solutions/garnet-guard/issues/48)
- [x] New startup files beyond `.pth` (GRN-C010): `sitecustomize.py`, `usercustomize.py`, `.data/` files [#49](https://github.com/orca-solutions/garnet-guard/issues/49)
- [x] Evidence notes: "only content rules apply", credential reads at import, release-notes wording [#50](https://github.com/orca-solutions/garnet-guard/issues/50)
- [x] Policy guardrails: cap an ignore's expiry, note a policy edit in the same PR (high-risk path) [#51](https://github.com/orca-solutions/garnet-guard/issues/51)
- [x] JavaScript content rule for npm (GRN-C011, at `info`; a dependency-free scan) [#52](https://github.com/orca-solutions/garnet-guard/issues/52)
- [x] Package-level capability signal: measured on the corpus and replays, and not built, since it added no detection and misses ultralytics 8.3.42 [#53](https://github.com/orca-solutions/garnet-guard/issues/53)

**After launch (0.3 to 1.0):**

- [ ] GRN-C005 obfuscation and indirect lookups of sensitive APIs [#54](https://github.com/orca-solutions/garnet-guard/issues/54)
- [ ] A listed call reached by reference: passed to another call (`Thread(target=os.system)`) or assigned to another name (`json.dumps = subprocess.Popen`) [#91](https://github.com/orca-solutions/garnet-guard/issues/91)
- [ ] Measure exception and value classes under the sensitive set's network prefixes (`httpx.TooManyRedirects`, `socket.error`) [#92](https://github.com/orca-solutions/garnet-guard/issues/92)
- [ ] Import-time hook installation (`sys.meta_path`, `settrace`, `builtins`, metaclasses) [#55](https://github.com/orca-solutions/garnet-guard/issues/55)
- [ ] A release published from a different ref or trigger than the trusted one [#56](https://github.com/orca-solutions/garnet-guard/issues/56)
- [ ] Release workflow changed between the two attested commits (`info`) [#57](https://github.com/orca-solutions/garnet-guard/issues/57)
- [ ] First look for newly added packages (`info`) [#58](https://github.com/orca-solutions/garnet-guard/issues/58)
- [ ] Model loaders fed a bundled file, changed serialized files [#59](https://github.com/orca-solutions/garnet-guard/issues/59)
- [ ] GRN-C006 sdist-wheel-mismatch [#60](https://github.com/orca-solutions/garnet-guard/issues/60)
- [ ] Tag sanity: tagged commit on the default branch, tag older than the upload [#61](https://github.com/orca-solutions/garnet-guard/issues/61)
- [ ] Trust rules on skipped intermediate releases, as SPEC §5.2 requires for 1.0 [#62](https://github.com/orca-solutions/garnet-guard/issues/62)
- [ ] A scheduled check of a deployed environment, for updates that never reach a lockfile [#63](https://github.com/orca-solutions/garnet-guard/issues/63)

**v2:**

- [ ] Per-package release history: when each risky property first appeared [#64](https://github.com/orca-solutions/garnet-guard/issues/64)
- [ ] Changed inputs to existing sensitive calls (new hosts, URLs, commands) [#65](https://github.com/orca-solutions/garnet-guard/issues/65)

## PyCon US 2027 proposal

- [ ] Jason submits the talk proposal by Dec 15, 2026 (the CFP is expected to close around Dec 18; inferred). It links the launch write-up and cites launch numbers.

## Month 3 → 0.3: second beat (January 2027)

- [x] Install wrapper: `garnet pip install …`, `garnet uv add|remove|lock|sync` (preview; [docs/install-wrapper.md](docs/install-wrapper.md))
- [ ] Install wrapper for npm, pnpm and yarn: waits on the npm lockfile parsers (package-lock, pnpm-lock, yarn.lock)
- [ ] Pre-install hooks for Claude Code and Codex (SPEC §10.4), announced as the second beat
- [ ] Rules GRN-C005 and C006 ([#54](https://github.com/orca-solutions/garnet-guard/issues/54), [#60](https://github.com/orca-solutions/garnet-guard/issues/60)); GRN-T006 and C004 moved to the launch list in [Closing the evasion gaps](#closing-the-evasion-gaps)
- [ ] npm adapter, if it didn't make the launch
- [ ] Full backtest on the 1.0 clean corpus (SPEC §13.2: the last 11 releases of the top 1,000 PyPI and top 1,000 npm packages) with the 0.3 rules (January–February); publish warn rate per rule and set the 1.0 target. These numbers feed the PyCon talk.

**Exit:** the wrapper and hooks ship; the full backtest is published.

## Months 4–6 → 1.0: stabilize

- [ ] Meet every acceptance criterion in SPEC §13
- [ ] Freeze the JSON schema, policy `version = 1`, Action inputs and the public Python API
- [ ] Long-run fuzzing for every parser; an external security review of `safe_archive.py`, `net.py` and the Action if a grant or volunteer allows
- [ ] Respond to launch feedback: false-positive fixes take priority over new rules
- [ ] OpenSSF Alpha-Omega application in its first window after launch data (target April 2027)
- [ ] **Gate A (month 4):** is the Garnet Guard App worth building? Pass if ≥15 interest-list orgs, ≥5 with 20+ repos, and ≥2 verbally agree to a paid pilot. Fail means grants and sponsors only.
- [ ] **Gate B (end of month 6):** pass if ≥2 orgs paid and ≥1 would renew at list price. Fail means stop hosted work; Garnet continues as a grant- and sponsor-funded project.

The gates were accepted on 2026-10-10 (ADR-0010). Money work stays under ~20% of Jason's time until Gate B passes, and pauses first if open-source quality slips.

## v2: history and depth (months 6–12)

The theme is seeing more than two releases and more kinds of change, while keeping every detection free.

- **Per-package registry history baseline.** Compute "how this package has been published" from the last N releases on the registry, not just the previous one, so a one-off publisher change after 40 consistent releases stands out and a project that always varies doesn't. *Free in the engine (ADR-0009).*
- **New signals:**
  - *Source mismatch:* the sdist or tarball contains files that aren't in the tagged git tree (the xz-utils pattern). Static comparison of the archive with the tag, no build. GRN-C007 (0.2) does this for the wheel's Python files; non-Python files and the sdist remain.
  - *New dependency added:* moved to launch as GRN-C008 ([#44](https://github.com/orca-solutions/garnet-guard/issues/44)).
  - *Ownership change:* maintainers, collaborators or organization roles changed between releases, where the registry exposes it.
  - *Entry-point and console-script changes:* moved to launch ([#47](https://github.com/orca-solutions/garnet-guard/issues/47)).
- **Stable plugin API.** Entry-point groups for third-party checks and ecosystems, with a compatibility promise.
- **Shareable policy.** `extends` a policy file from another path or repository, so a team can reuse one policy across its own repos without the Garnet Guard App.
- **More CI.** Documented recipes for GitLab CI, Buildkite and pre-commit; a container image.
- **pylock.toml attestations.** Write the attestation table when tools still don't.
- **Garnet Guard App** (hosted, separate, paid, only if Gate B passed): org-wide policy, exceptions, cross-org observed history, alerts and an audit trail, with SSO, audit export and compliance reports in an optional Premium add-on. See [OPEN_CORE.md](OPEN_CORE.md).

## v3: breadth and upstream (year 2)

- **More ecosystems,** in order of how much provenance data they publish: crates.io (Trusted Publishing), RubyGems (Trusted Publishing), Maven Central (Sigstore signatures), then Go modules (a different trust model built on the checksum database).
- **More source hosts** for tag and source checks: GitLab and Codeberg.
- **Upstream the checks.** Propose a trust-downgrade policy for uv and pip, modeled on pnpm's `trustPolicy`, with Garnet's backtest data as evidence. Offer the rule set to registries as publish-time warnings to maintainers.
- **Open dataset.** Publish the release-trust history Garnet's backtests collect as an open dataset for researchers.
- **Sovereign Tech Agency** application, once Garnet shows prevalence (its minimum is €50k).
- **Governance.** At least two maintainers from different organizations, and an OpenSSF sandbox application.

## Beyond

- A common, documented format for "release trust diffs" so other tools can produce and consume the same findings.
- As native package managers adopt these checks, Garnet retires its overlapping rules and becomes the policy, explanation and history layer above them. Retiring a rule because it went native counts as a win.
- Incubation in a neutral foundation, with Garnet run by its community rather than by one person.

## Not planned

A malware feed of our own, dynamic analysis or sandboxing, and closed-source detection of any kind.
