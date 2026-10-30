# npm clean-corpus backtest, top 1,000 packages, 2026-10-30

The last 11 final, non-deprecated releases of the 1,000 most downloaded npm packages
([top-npm-1000.json](../top-npm-1000.json), from wooorm/npm-high-impact 1.13.0; its first
200 are the list the [top-200 run](../corpus-results-npm/REPORT.md) used), each compared
with the release before it, the way a Dependabot or Renovate update would be: 989 packages
with at least two releases, 8,742 updates. Known-bad lookups (GRN-K001) were off.

```
uv run python -m backtest select npm 1000   # writes corpus-npm-1000.json
uv run python -m backtest corpus npm 1000   # writes this folder's summary.json and updates.json
```

The run used main (`255946a`) with the rule-testing branches stacked on it, up to
`claude/project-thread-sm89m3-claims` at `935d188` (PRs #32, #33, #34 and #36 plus that
branch, now PR #38), and this PR's commits. Those branches change only Python checks, and
PR #38's later commits only GRN-C003, so for npm the result is the same on this PR alone
and on the rules as they are about to ship.

## Result

**146 of 8,742 updates were flagged for a look (1.7%), in 131 packages. Each of the 146
was checked on its own against the registry and GitHub, and none made a false claim.**

| Rule | Updates | Packages |
|---|---|---|
| GRN-T004 no-matching-tag | 89 | 78 |
| GRN-T001 lost-provenance | 48 | 47 |
| GRN-T002 publisher-changed | 3 | 3 |
| GRN-C002 new-build-hook | 3 | 2 |
| GRN-T003 workflow-changed | 2 | 2 |
| GRN-T005 outside-trusted-publishing | 1 | 1 |

30 updates (0.3%) carry a couldn't-check finding and no warning: 26 GRN-E001, where
github.com answers HTTP 401 for the git refs of a repository under a deleted or renamed
account (`substack/*`, `humanwhocodes/retrier` and five others), and 4 GRN-E002, where a
tarball lists `package/dist/index.js` twice (agent-base 7.0.0, data-uri-to-buffer 5.0.0)
and `safe_archive.py` refuses it.

"None made a false claim" means every finding states something true about the release.
It does not mean no warning was a false alarm: none of these 8,742 updates is known to be
malicious, so from a user's point of view every one of the 146 is a false alarm, a true
observation about a legitimate release that a reviewer has to look at and dismiss.

**The first pass found 8 false claims, now fixed.** The same corpus first ran on main plus
the rule-testing branches: 153 updates warned, and 8 of the claims were wrong.

- GRN-T004 said 7 releases had no git tag, but their monorepos tag by folder:
  `api/v1.4.1` (@opentelemetry/api 1.4.1), `resolvers/node/v0.3.3`
  (eslint-import-resolver-node 0.3.3), `utils/v2.8.1`, `utils/v2.11.1` and `utils/v2.12.1`
  (eslint-module-utils), `sourcemap-codec/1.5.1` and `trace-mapping/0.3.26` (jridgewell/sourcemaps).
  `<dir>/X` and `<dir>/vX` now match when the folder names the package
  ([GRN-T004](../../docs/rules/GRN-T004.md)).
- GRN-T001 said whatwg-url 17.1.1 has no attestation. Its version document lists one, but
  the registry's attestations endpoint answers HTTP 404 for it. Nothing can be verified, so
  it still warns, but the finding now says "no attestation served" and gives the 404
  ([GRN-T001](../../docs/rules/GRN-T001.md)).

Re-run with both fixes: exactly those 7 GRN-T004 warnings went away, whatwg-url's text
changed, and nothing else moved.

**A re-run also caught a mistake in a later fix.** The PyPI corpus needed more tag forms
(`release-v1.0.0`, `prebuilt==1.0.11`), and for a while a shorter name matched after any
separator. On npm that took a sibling package's tag: socks-proxy-agent 8.0.0 matched
`proxy-agent@8.0.0` in TooTallNate/proxy-agents, which has no tag for socks-proxy-agent
8.0.0, so a true warning went quiet. Now a `-`, `_` or `@` prefix must be the full name,
and a shorter folder name counts only in a repository that never tags the package by its
full name. The final run is identical, update for update, to the checked run above, and
the only tags matched by a shorter name are eslint-plugin-import's `resolvers/node/vX` and
`utils/vX`.

## Triage

Every warning is listed with its check in [triage.json](triage.json).

**GRN-T004 (89).** Each was checked with `git ls-remote --tags` against every repository
the finding names: no tag names the candidate version, in any form. 35 are releases from
before 2020 of small packages that tagged sporadically (`inherits` 1.0.2, `progress` 1.1.3,
`through` 2.3.8); the corpus takes a package's last 11 versions, which for a package with
a dozen versions reaches back a decade. 29 are from 2025 or 2026, releases a maintainer
didn't tag (`fastq` 1.20.0, `cosmiconfig` 9.0.2, `@swc/helpers` 0.5.18, the lightningcss
binaries). Four follow a move into a monorepo that doesn't tag the moved package
(agent-base, http-proxy-agent and socks-proxy-agent into TooTallNate/proxy-agents,
merge-descriptors to sindresorhus). For bser 2.1.1, fb-watchman 1.9.1 and 2.0.1 and
fill-range 7.0.1 the trusted version matched a short tag (`v2.1`, `v1.9`, `7.0`) by version
comparison; the finding names that tag, so a reviewer can see it.

**GRN-T001 (48).** For each, the registry's version document lists an attestation for the
trusted version and none for the new one (except whatwg-url, above). 32 are one event:
on 2026-08-15 GitHub Actions published 32 @smithy packages without provenance, and each
was republished with provenance about an hour later. Five compare an older major with a
newer maintenance release that gained provenance after it (@tootallnate/once 2.0.1 → 3.0.0,
body-parser 1.20.9 → 2.0.0, express 4.22.3 → 5.0.0, uuid 11.1.1 → 12.0.0 and
12.0.1 → 13.0.0): true, and the reason is visible in the dates. The rest are
releases a maintainer published by hand after CI releases with provenance (`chokidar`
4.0.2, `fastq` 1.20.2, `serialize-javascript` 7.0.3, `protobufjs` 8.6.2). nx 21.5.0 looked
exactly like these.

**GRN-T002 (3) and GRN-T003 (2).** Confirmed from the attestations: eslint-scope 8.1.0 and
eslint-visitor-keys 4.1.0 moved into eslint/js, @rolldown/pluginutils 1.0.1 moved to
rolldown/plugins; proc-log 4.1.0 and readdirp 4.1.0 were published by a renamed workflow.

**GRN-T005 (1).** @pkgr/core 0.3.0 is attested from un-ts/pkgr's release workflow, but
was published by a maintainer's account rather than through Trusted Publishing, which
0.2.10 used. This is the first time GRN-T005 has fired on a real release in a Garnet
Guard backtest. (0.2.10 was published after 0.3.0, as a maintenance release.)

**GRN-C002 (3).** loupe 3.0.0 added `postinstall: npx playwright install`, which downloads
browsers on every install of the package; 3.0.1 removed it two weeks later. sharp 0.34.3
changed its install script from `node install/check` to `node install/check.js`, and
0.34.5 added `|| npm run build`. All three are what the rule is for: a reviewer sees the
exact command that will run at install.

## Compared with the top-200 run

The first 200 packages are the same list, with versions picked again on 2026-10-30, so
some recent releases replace older ones. The [top-200 run](../corpus-results-npm/REPORT.md)
reported 33 of 1,809 (1.8%). Its report said @jridgewell/trace-mapping's monorepo "doesn't
tag per package" and that whatwg-url 17.1.1 and uuid 12.0.0 and 13.0.0 "look like manual
publishes". All three readings were wrong: trace-mapping is tagged by folder, whatwg-url's
attestation is listed but not served, and uuid's trusted versions are maintenance releases
published later, with provenance. That report now carries a correction.

## Limits

- Tags are checked as they exist today, not as they stood on the release day.
- The content check for npm reads `package.json` install scripts only; there is no
  JavaScript equivalent of GRN-C003 yet.
- The list is ordered by downloads, which over-represents small, old utility packages
  with few releases.
- Run in the cloud container: registry.npmjs.org and github.com git refs are reachable,
  api.osv.dev is not (the run doesn't need it). About 20 minutes cold with 2 or 3 worker
  processes.
