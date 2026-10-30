# Clean-corpus backtest, 2026-10-10

> **Current result:** with the rule tuning from PR #8 (now merged), 12 of 974 clean updates warn (1.2%), and none of those warnings makes a false claim. Confirmed on main on 2026-10-29; see [Re-run on main](#re-run-on-main-2026-10-29). The sections before it describe the first run, which led to that tuning. The incident replay mentioned below covered three releases at the time; it now covers seven malicious releases from four attacks (lightning, elementary-data, litellm, telnyx), and all seven get a warning (PR #24).

The PyCon plan needed this number by Dec 1. Garnet `0.1.0.dev0` (the draft PR #1 engine) was run over the top 100 PyPI packages and the update between each pair of consecutive releases among their last 11 releases.

## Headline

**Verdict: a good first result.** About 1 in 57 routine updates of popular packages gets a warning, and the same rules still catch all three real attacks. A quarter of the warnings come from four bugs with known fixes. The rest are true observations that a reviewer can dismiss in seconds.

- **17 of 974 clean updates warned (1.7%)**, in 16 of 100 packages.
- 18 warnings in all. 13 state a true fact about a legitimate release. **5 are wrong** (the claim itself is false), and those 5 fall in 4 updates (**0.4%**).
- None of the 974 updates is malicious, so every warning here is a false alarm from a user's point of view. The 13 accurate ones are the rule doing its job on a benign change.
- 33 updates (3.4%) had a coverage gap (GRN-E). In 30 of them, a symlink inside an sdist made Garnet skip that sdist's content checks.

## Corpus

- Packages: the top 100 by 30-day downloads in hugovk/top-pypi-packages (snapshot of 2026-10-01). The list is frozen as the first 100 of `backtest/top-pypi-1000.json`.
- Releases: the last 11 final releases of each package by version, that still have a non-yanked file. Pre-releases and dev releases are skipped, as Dependabot does by default. Each package gives 10 updates, except 7 packages that have fewer releases, which is why the total is 974 and not 1,000. The chosen versions are in `backtest/corpus.json`.
- Settings: same as the incident replay. Known-bad lookup (K001) is off, tags are evaluated as they exist today, and default severities apply. A "warn" is any finding at warn or above from a detection rule (T, C). E-findings are counted separately as coverage gaps.

## Warnings by rule

| Rule | Updates | Packages | Accurate | Wrong |
|---|---|---|---|---|
| GRN-C003 new import-time exec | 7 | 6 | 4 | 3 |
| GRN-C002 new build hook | 5 | 5 | 5 | 0 |
| GRN-T001 lost provenance | 3 | 3 | 3 | 0 |
| GRN-T004 no matching tag | 3 | 3 | 1 | 2 |

C003 and T004 are the noisiest rules, and they are the two rules that caught the lightning incident. C002 never makes a wrong claim, but every hit was an in-tree build backend or a setup.py version read.

## Every warning, triaged

The full notes are in [triage.csv](triage.csv) and [triage.json](triage.json).

| Update | Rule | Claim | Why |
|---|---|---|---|
| annotated-doc 0.0.4 → 0.0.5 | T001 | accurate | The 0.0.5 files have no attestations. Earlier releases were attested from fastapi/annotated-doc. |
| certifi 2025.11.12 → 2026.1.4 | T004 | **wrong** | The tag `2026.01.04` exists. Garnet doesn't normalize zero-padded tag names. |
| charset-normalizer 3.4.2 → 3.4.3 | C002 | accurate | New in-tree build backend. |
| frozenlist 1.4.0 → 1.4.1 | C002 | accurate | New in-tree backend (aio-libs' Cython backend). |
| pillow 11.2.1 → 11.3.0 | T001 | accurate | 20 of 106 files are unattested. The other 86, and all 12.x files, are attested. |
| pip 26.1.2 → 26.2 | C003 | **wrong** | In vendored platformdirs, a function is returned at import, not called. The analyzer counts a reference as a call (`facts/pyindex.py:176`). |
| pyarrow 23.0.1 → 24.0.0 | C002 | accurate | New in-tree build backend. |
| pyyaml 6.0.1 → 6.0.2 | C002 | accurate | New in-tree backend `_pyyaml_pep517`. |
| requests 2.31.0 → 2.32.2 | C003 | accurate | `import_module` over the literal names `chardet` and `charset_normalizer`, called at import. |
| s3fs 2026.4.0 → 2026.6.0 | T004 | accurate | fsspec/s3fs really has no 2026.6.0 tag. |
| scipy 1.16.3 → 1.17.0 | C003 | accurate | The call is in a test module, from a module-level `@pytest.mark.parametrize`. |
| scipy 1.17.1 → 1.18.0 | C003 | **wrong** | Vendored array_api_compat moved from `_lib/` to `_external/`, byte-identical, and Garnet reported it as new code. |
| scipy 1.17.1 → 1.18.0 | T004 | **wrong** | The first attested release names scipy/scipy-release, so the tag was looked up there. `v1.18.0` exists in scipy/scipy. The message also names the wrong repo for 1.17.1's tag. |
| setuptools 80.9.0 → 80.10.1 | C003 | **wrong** | `tests/fixtures.py`: the subprocess call runs only inside pytest fixtures, not at import. This is probably the same reference-as-call issue (inferred). |
| sniffio 0.0.0 → 1.0.0 | C002 | accurate | setup.py execs `_version.py` to read `__version__`. |
| typing-inspection 0.0.0 → 0.1.0 | C003 | accurate | It compiles helper functions with `exec` at import. |
| watchfiles 1.0.4 → 1.0.5 | T001 | accurate | Attestations stopped at 1.0.5 and never came back. |
| wheel 0.44.0 → 0.45.0 | C003 | accurate | `__import__("setuptools.logging")` with a literal name. |

## Findings that suggest rule tuning

These are for the prototype thread. The rules were not changed here.

1. **T004: normalize versions when matching tags.** Compare the tag as a PEP 440 version (`2026.01.04` = `2026.1.4`) instead of the raw string. That fixes certifi. Cost: tiny.
2. **T004: look up the candidate's tag in the same repo as the baseline's.** When the attested repo differs from the baseline's repo, check both, or fall back to the baseline repo before warning. Fix the message so it names the repo each tag came from. That fixes scipy. It also matters for T002: here a new publisher repo surfaced as a tag warning.
3. **C003 reachability: count calls, not references.** `pyindex.py:176` treats any `Name` that refers to a local function as reached. Following only `ast.Call` targets, plus decorators, would remove the pip FP and probably setuptools. Re-run the incident replay after this change, because the lightning payload reaches `Popen` through a thread target, which is a reference passed to `Thread(target=...)`.
4. **C002/C003: diff by content, not only by path.** If a "new" module has the same hash, or the same call sites, as a module in the baseline at another path, it was moved, not added. That fixes the scipy `_external` move. Vendored-library moves like this are common.
5. **C003: `__import__` / `import_module` with a literal string argument** is the same as an import statement (wheel, requests). Consider dropping it from the sensitive set when every argument is a constant. Keep it when the name is computed.
6. **C003 in test code** (`*/tests/*`, `test_*.py`, conftest): not imported in normal use (scipy 1.17.0). Lowering it to info would make sense, but attackers could hide code there, so it is a policy call for Jason.
7. **C002 in-tree backend** (4 of 5 C002 hits): the claim is true and the change is benign every time. The prototype thread could show the backend module's sensitive calls as evidence, so a reviewer can tell `pep517_backend.hooks` from a payload, rather than lowering the severity.
8. **T001 fires once, then goes quiet** (watchfiles): after a provenance loss, the unattested release becomes the next baseline. That matches the spec, but per-package history (attested at any time in the last N releases) would keep the signal. It ties into the "history" feature.
9. **Coverage gap, safe_archive symlinks:** beautifulsoup4, pyparsing, referencing and tenacity ship sdists with an in-archive symlink, and Garnet then skips that sdist's content entirely (30 updates). Skipping the one link member with a note, instead of the whole artifact, would recover coverage. `safe_archive.py` is a high-risk path, so this needs the maintainer's review.
10. Minor gaps:
    - pyyaml 5.x has unparsable py2 files. That's correct behavior.
    - pyarrow 26.0.0's sdist has a duplicate `LICENSE.txt` entry.
    - annotated-doc 0.0.1's old repo URL (tiangolo/…) returns 401 from GitHub.

If fixes 1–4 land with no new noise, the corpus would drop to 13 warned updates (1.3%), and every remaining warning would be an accurate claim. That figure is a projection, not a run.

## Reproduce

```
uv run python -m backtest select     # re-pick versions (changes corpus.json)
uv run python -m backtest corpus     # about 15 min cold on 4 cores, <1 s from the fact cache
```

The fact cache defaults to `~/.cache/garnet-guard/backtest`. Set `GARNET_BACKTEST_CACHE` to move it and `GARNET_BACKTEST_WORKERS` to set parallelism (default 4).

## Files

- [summary.json](summary.json): the headline numbers of the latest run (main, 2026-10-29: 12 of 974).
- [updates.json](updates.json): every update with every finding, from the same run.
- [triage.csv](triage.csv) and [triage.json](triage.json): one row per warning of the first run (2026-10-10: 17 of 974). The 12 warnings of the latest run are all rows marked accurate there.

## Re-run on PR #8, 2026-10-10

**At PR #8's current head (`09bcd75`, which adds C003 at info in test files): 12 of 974 clean updates warned (1.2%).** The only change from `e14015f` is scipy 1.17.0, whose C003 finding is now info. All three incidents are still caught.

At `e14015f` (fixes 1–4 only), with a fresh fact cache each time:

- **13 of 974 clean updates warned (1.3%)**, down from 17. That matches the projection.
- Exactly four updates changed, and they are the four that had wrong claims: certifi 2026.1.4, pip 26.2, scipy 1.18.0 and setuptools 80.10.1. No other update gained or lost a warning, and the 13 accurate warnings all still fire.
- By rule: C002 5, C003 4, T001 3, T004 1.
- Coverage gaps are unchanged at 33.
- The incident replay still catches all three incidents.

The results at `09bcd75` are in [after-pr8/summary.json](after-pr8/summary.json) and [after-pr8/updates.json](after-pr8/updates.json).

## Re-run on main, 2026-10-29

**On main at `ce133f4`: 12 of 974 clean updates warned (1.23%), in 12 of 100 packages, and none of the 12 makes a false claim.** [summary.json](summary.json) and [updates.json](updates.json) now hold this run.

- By rule: C002 5, C003 3, T001 3, T004 1. Coverage gaps are unchanged at 33 (E002 32, E001 1).
- Compared with the first run, the same 974 updates were checked and exactly five changed, all from warn to pass: certifi 2025.11.12 → 2026.1.4 (T004), pip 26.1.2 → 26.2 (C003), scipy 1.16.3 → 1.17.0 (C003, now info in a test file), scipy 1.17.1 → 1.18.0 (C003 and T004) and setuptools 80.9.0 → 80.10.1 (C003). No update gained a warning.
- The 12 that still warn are annotated-doc 0.0.5, charset-normalizer 3.4.3, frozenlist 1.4.1, pillow 11.3.0, pyarrow 24.0.0, pyyaml 6.0.2, requests 2.32.2, s3fs 2026.6.0, sniffio 1.0.0, typing-inspection 0.1.0, watchfiles 1.0.5 and wheel 0.45.0. Each is marked accurate in the [triage](triage.json).
- The incident replay on the same commit still warns on all three incidents, and 0 of the 20 clean incident-neighbour updates warn.
- `summary.json` is byte-identical to [after-pr8/summary.json](after-pr8/summary.json). `updates.json` differs from the after-PR-#8 file in a single evidence line: scipy 1.17.0's info-level C003 finding no longer notes that the two wheels it compared had different platform tags.
- Run on the maintainer's machine with the repository's locked dependencies (`httpx` 0.28.1, `packaging` 26.3, `pypi-attestations` 0.0.30), in about 21 minutes with a cold cache and no GitHub token.
