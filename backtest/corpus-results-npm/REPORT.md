# npm clean-corpus backtest, 2026-10-29

The last 11 final, non-deprecated releases of the 200 most downloaded npm packages
([top-npm-200.json](../top-npm-200.json), from wooorm/npm-high-impact 1.13.0), each
compared with the release before it, the way a Dependabot or Renovate update would be:
200 packages, 1,809 updates. Known-bad lookups (GRN-K001) were off. Run with
`uv run python -m backtest select npm && uv run python -m backtest corpus npm`;
`summary.json` and `updates.json` are this run's output.

## Result

**33 of 1,809 updates warned (1.8%)**, in 31 packages. Every warning is a true statement
about the release; the question for each is whether a reviewer would want to see it.

| Rule | Updates | Packages | What it was |
|---|---|---|---|
| GRN-T004 no-matching-tag | 25 | 24 | The release has no git tag where the previous one had. |
| GRN-T001 lost-provenance | 5 | 4 | A release published without provenance after releases with it. |
| GRN-T002 publisher-changed | 2 | 2 | The attested repository changed. |
| GRN-T003 workflow-changed | 1 | 1 | The attested workflow file changed. |

14 updates (0.8%) carry a couldn't-check finding (GRN-E001 or GRN-E002) and no warning.

## Triage

**GRN-T004 (25).** Most are old releases of small packages that tag sporadically
(`inherits` 1.0.2, `is-glob` 1.1.2, `object-assign` 2.1.1, `string_decoder` 0.10.31): the
corpus takes a package's last 11 versions, which for a package with a dozen versions
reaches back a decade. Four are moves into a monorepo that doesn't tag per package
(`agent-base` and `http-proxy-agent` into TooTallNate/proxy-agents, `@jridgewell/trace-mapping`
into jridgewell/sourcemaps). The rest are recent releases a maintainer didn't tag
(`fastq` 1.20.0, `lodash` 4.17.17, `@esbuild/linux-x64` 0.27.6, `color-name` 2.0.2). The
rule says exactly what it found and where it looked, and it is the one rule that reports
chalk 5.6.1 and debug 4.4.2 in the incident replay, so it stays as is. The clean PyPI
corpus shows the same profile.

**GRN-T001 (5).** `chokidar` 4.0.2, `fastq` 1.20.2, `uuid` 12.0.0 and 13.0.0, and
`whatwg-url` 17.1.1 were each published without provenance after the previous release had
it. These look like manual publishes by the maintainers, and that is the point: a
reviewer can see the publish path changed and ask. nx 21.5.0 looked exactly like this.

**GRN-T002 (2) and GRN-T003 (1).** `eslint-scope` 8.1.0 and `eslint-visitor-keys` 4.1.0
moved into the eslint/js monorepo; `readdirp` 4.1.0 was published by a renamed workflow.
True, and worth one look each.

**GRN-C002 (0).** The first run of this corpus reported 18 updates in 13 packages, every
one a change to the `prepare` script (`tsc` → `tshy`, `husky` → `lefthook`). npm does not
run `prepare` when it installs a published tarball, so the script was dropped from the
rule's npm set; see [GRN-C002](../../docs/rules/GRN-C002.md). No `preinstall`, `install` or
`postinstall` script changed in 1,809 updates of the top 200 packages.

**GRN-T007 (0).** The first run blocked `which` 3.0.1 and `eslint-visitor-keys` 3.4.2 and
3.4.3 as "invalid attestation". Those are npm's first provenance bundles (April 2023),
which carry an inclusion promise but no inclusion proof; sigstore-python refuses to load
them. They now verify through the reduced path in `ecosystems/npm_provenance.py`, and a
recorded copy of `which` 3.0.1's bundle is a unit-test fixture.

**Couldn't check (14).** `minimist` (8 updates), `concat-map` (2) and `hasown` 2.0.0:
github.com answers HTTP 401 for the git refs of repositories under a deleted account
(`substack/*`, `radubrehar/hasown`), so GRN-T004 was not evaluated and the report says so.
`agent-base` 7.0.0: the tarball lists `package/dist/index.js` twice, which
`safe_archive.py` refuses, so its contents were not read (GRN-E002).

## Limits

- The corpus is the top 200 by downloads, which over-represents tiny, old utility packages
  with a handful of releases. The 1.0 target in SPEC §13 is set after a wider run.
- Tags are checked as they exist today, not as they stood on the release day.
- The content check for npm reads `package.json` scripts only; there is no JavaScript
  equivalent of GRN-C003 yet.
