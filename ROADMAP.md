# Garnet Guard roadmap

Months count from the repository going live. Version numbers are targets, not promises. Funding sequencing and go/no-go gates come from [plans/monetization.md](../plans/monetization.md); outreach steps from [plans/outreach.md](../plans/outreach.md). Grants, the fiscal host and the LLC are planned in [plans/funding.md](../plans/funding.md). The PyCon US 2027 talk adds two dated milestones (Nov 15 and Dec 1, 2026) and a Dec 15 proposal submission, and the public launch is set for the week of Dec 8, 2026 (DECISIONS 40), just before that submission; see [plans/pycon-2027.md](../plans/pycon-2027.md). Those dates assume the repo goes live in mid-October 2026 and slip with it. The normative 1.0 behavior is in [docs/SPEC-v1.md](docs/SPEC-v1.md).

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

- [ ] Create `orca-solutions/garnet-guard` **public from day one** (ADR-0011) and seed it from the founding documents
- [ ] Turn on GitHub private vulnerability reporting, branch protection, signed commits
- [ ] Reserve `garnet-guard` on PyPI with Trusted Publishing configured (ADR-0007)
- [ ] GitHub Sponsors and `.github/FUNDING.yml` (per plans/funding.md)
- [ ] Enable GitHub Discussions as the community space

## Month 1 → 0.1: engine and PyPI

- [ ] Repo skeleton: uv project, ruff, mypy (strict on `src/`), pytest, import-linter, CI, `uv.lock`, pinned Actions
- [ ] Models and the public API in [docs/API.md](docs/API.md) §3
- [ ] `safe_archive.py` and `net.py` with limits and fuzz tests, before any check reads an archive
- [ ] Lockfile parsers: uv.lock, poetry.lock, pylock.toml, pinned requirements.txt
- [ ] PyPI adapter: JSON API, Integrity API, attestation verification, cache
- [ ] GitHub tag lookup; OSV lookup
- [ ] Rules GRN-T001–T005, T007, T008, C001–C003, K001, E001–E005
- [ ] Reporters: text, JSON, SARIF
- [ ] First incident replays: lightning 2.6.2/2.6.3, elementary-data 0.23.3, reproducible from one command **by Nov 15, 2026** (PyCon proposal dependency)
- [ ] **Reduced clean-corpus backtest by Dec 1, 2026:** top 100 PyPI packages × last 10 releases, warn rate per rule. Pulled forward from month 2 so the PyCon US 2027 proposal can cite a real false-positive number
- [ ] Approach-check notes to three to five packaging and security experts on reading the Integrity API (outreach Draft A)

**Exit:** both incidents produce a `warn` from rules that would have fired before any feed listed them; unit tests have no network access.

## Month 2 → 0.2: launch (week of Tue Dec 8, 2026)

Launch means the replay write-up plus a working GitHub Action. The bar doesn't move: the replays are caught and the clean-corpus warn rate is met, using the Dec 1 reduced backtest as the launch number. If the bar isn't met, the launch slips, not the bar.

- [ ] GitHub Action with a sticky PR comment and optional SARIF upload
- [ ] Verify Dependabot token behavior; ship single-job and two-workflow examples
- [ ] Policy file with expiring ignores (SPEC §7)
- [ ] Dogfood on Garnet's own repo and 5–10 friendly repos (outreach Draft B)
- [ ] Opt-in interest list link in the README (not telemetry)
- [ ] Docs site: quickstart, one page per rule, policy guide, comparison page
- [ ] GitHub Marketplace listing for the Action
- [ ] Launch write-up "We replayed the 2025–26 supply-chain attacks against Garnet Guard", then Show HN, Python Discourse, r/Python, Mastodon and Bluesky, newsletters (marketing owns the launch; see plans/marketing.md)
- [ ] In launch week: apply to the GitHub Secure Open Source Fund (if a cohort is open) and to Open Source Collective as fiscal host (needs an org-owned repo, which `orca-solutions` satisfies, and a second admin by early December)
- [ ] *Stretch, not a launch requirement:* npm adapter (package-lock, pnpm-lock, yarn.lock; npm provenance; lifecycle-script and `bin` diffs). `garnet diff npm:…`, provenance, tags and lifecycle-script diffs are built and backtested; the lockfile parsers and `bin` diffs are open.

**Exit:** the launch success criteria in [VISION.md](VISION.md); the Action runs on real Dependabot and Renovate PRs.

## PyCon US 2027 proposal

- [ ] Jason submits the talk proposal by Dec 15, 2026 (the CFP is expected to close around Dec 18; inferred). It links the launch write-up and cites launch numbers.

## Month 3 → 0.3: second beat (January 2027)

- [ ] Install wrapper: `garnet pip install …`, `garnet uv add|sync|lock`, `garnet npm install …`
- [ ] Pre-install hooks for Claude Code and Codex (SPEC §10.4), announced as the second beat
- [ ] Rules GRN-T006, C004–C006
- [ ] npm adapter, if it didn't make the launch
- [ ] Full backtest over the last ~20 releases of the top ~500 PyPI packages (January–February), extending the Dec 1 reduced run, plus the npm corpus; publish warn rate per rule and set the 1.0 target. These numbers feed the PyCon talk.

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
  - *Source mismatch:* the sdist or tarball contains files that aren't in the tagged git tree (the xz-utils pattern). Static comparison of the archive with the tag, no build.
  - *New dependency added:* a release suddenly depends on a new package, especially one that is young or has no provenance (the event-stream / flatmap-stream pattern).
  - *Ownership change:* maintainers, collaborators or organization roles changed between releases, where the registry exposes it.
  - *Entry-point and console-script changes* that shadow common commands.
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
