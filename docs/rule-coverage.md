# Rule coverage: how each rule is proven

What stands behind each rule ID, as of 2026-10-30 on `main`. Three kinds of evidence:

- **Crafted releases** (`tests/test_rule_matrix.py`): tiny wheels and sdists built in memory,
  one that makes the rule fire and one that keeps it quiet (54 rows today), run for every
  ecosystem the rule is registered for. No real malware is stored in the
  repository. `test_every_built_rule_has_rows` fails when a rule is registered without both.
- **Real attacks** (`python -m backtest`): the compromised releases in
  [backtest/incidents.toml](../backtest/incidents.toml), fetched by URL and hash from
  files.pythonhosted.org, which still serves files PyPI has removed (11 releases on `main`
  today; #31 brings it to 26 releases of 15 packages).
- **Real routine updates**: the 974-update clean corpus
  ([backtest/corpus-results/REPORT.md](../backtest/corpus-results/REPORT.md)), the repository's
  own dependency bumps (the dogfood workflow), and a scan of the last 20 releases of the top 600
  PyPI packages (10,886 releases) for publisher, workflow and attestation changes, run for this
  page. The releases that confirmed a rule are in `tests/test_real_releases.py`, which fetches
  them live (`uv run pytest -m network tests/test_real_releases.py`).

A rule that has only crafted evidence is working as designed but has not met the real thing.
That is said in the table, not hidden.

## The matrix

| Rule | Crafted: fires / quiet | Real attacks it reported | Real routine updates | Clean corpus (974) | Not yet proven |
|---|---|---|---|---|---|
| GRN-T001 lost-provenance | yes / yes | ultralytics 8.3.45 and 8.3.46 (Dec 2024), uploaded with a leftover API token and carrying no attestation after attested releases (#31; PyPI no longer serves provenance for removed files, so the replay records that fact) | 20 of 600 packages dropped attestations between two releases (pillow 11.3.0, watchfiles 1.0.5, tomli 2.4.0, stripe 15.0.0, llvmlite 0.48.0, google-api-core 2.30.1, …), all legitimate | 3 warns, all accurate | a real attack seen live, not from a recorded fact |
| GRN-T002 publisher-changed | yes / yes (a renamed repository keeps its id) | none | 8 publisher changes in 10,886 releases. Fires, accurately: scikit-learn 1.9.1 and matplotlib 3.10.8 (moved to `*-release` repositories), langsmith 0.14.10 (`langsmith-sdk` → `langsmith-python`), mcp-types 2.0.0 (`kludex/mcp` → `modelcontextprotocol/python-sdk`). Quiet, correctly: msgspec 0.22.0, authlib 1.6.0 and propcache 0.2.0, transferred to an organization, which keeps the repository id | 0 | a real attack |
| GRN-T003 workflow-changed | yes / yes | ultralytics 8.3.47, the fix release, added a `release - pypi` environment (benign, accurate) | pluggy 1.7.0 `main.yml → deploy.yml` (reported live on this repository's PR #25), tornado 6.6, pymysql 1.2.0, cssselect2 0.10.0 and weasyprint 68.1 added an environment, cuda-pathfinder 1.8.4 renamed its workflow file | 0 | a real attack |
| GRN-T004 no-matching-tag | yes / yes | lightning 2.6.2 and 2.6.3, telnyx 4.87.1 and 4.87.2 (also with the tags of the day), elementary-data 0.23.3 and ultralytics 8.3.41–8.3.46 (today's tags only); in #31, with the tags of the day, ultralytics 8.3.41, 8.3.45 and 8.3.46, num2words 0.5.15 and 0.5.16, xinference 2.6.0–2.6.2, mistralai 2.4.6, durabletask 1.4.1–1.4.3 and gpsea 0.9.14 | s3fs 2026.6.0 (accurate: no tag) | 1 warn, accurate | — |
| GRN-T005 outside-trusted-publishing | yes / yes | none | none | 0 | **Cannot fire on PyPI**: PyPI accepts attestations only through Trusted Publishing, so a file without one is GRN-T001. The rule exists for registries that separate the two; on npm it never fired across 1,809 updates of the top 200 packages |
| GRN-T007 invalid-attestation | yes / yes | none | none | 0 | a real forged or broken attestation has not been seen. The verifier itself (Sigstore, via pypi-attestations) has no unit test and is exercised by every corpus run: every attested release in the corpus verified |
| GRN-T008 hash-mismatch | yes / yes | none | none | 0 | a real mismatch has not been seen; every download in the corpus matched the registry |
| GRN-C001 new-pth-file | yes / yes | elementary-data 0.23.3, litellm 1.82.8; in #31 gpsea 0.9.14, pyphetools 0.9.120 and ppkt2synergy 0.1.1 (the Hades campaign), and embiggen 0.11.97 once #33 lands | none (no top-100 release added a `.pth`) | 0 | — |
| GRN-C002 new-build-hook | yes / yes (PyPI: `setup.py` and the build backend; npm: install scripts) | memoryos 2.0.34 (#31); nx 21.5.0 and @ctrl/tinycolor 4.1.1 on npm, through install scripts | 5 in the corpus, every one an in-tree build backend or a version read in `setup.py` (accurate) | 5 warns, accurate; 7 with #33 (pycparser 2.19 and multidict 7.1.0 each added a build-time subprocess call, accurate) | a real PyPI attack through a `cmdclass` install hook, the classic shape |
| GRN-C003 new-import-time-exec | yes / yes | lightning 2.6.2 and 2.6.3, litellm 1.82.7 and 1.82.8, telnyx 4.87.1 and 4.87.2, ultralytics 8.3.45 and 8.3.46; in #31 xinference 2.6.0–2.6.2, mistralai 2.4.6, guardrails-ai 0.10.1 and durabletask 1.4.1–1.4.3, and with #34 num2words 0.5.15 and 0.5.16 and memoryos 2.0.34 | requests 2.32.2, typing-inspection 0.1.0, wheel 0.45.0 (accurate) | 3 warns, accurate (unchanged by #32) | — |
| GRN-K001 known-malicious | yes / yes | off in the backtest by design (the question is what Garnet catches before a feed lists a release) | none | n/a | the live OSV lookup has not been exercised in any recorded run; the cloud sandbox cannot reach api.osv.dev. Run `garnet diff` on a listed release from a machine that can |
| GRN-E001 fetch-failed | yes / yes | the replays (provenance of a removed release is unknown) | 1 in the corpus (a tag lookup) | 1 | — |
| GRN-E002 parse-failed | yes / yes | none | 32 in the corpus, 30 of them an sdist with a symlink, which `safe_archive` refuses | 32 | — |
| GRN-E003 budget-exceeded | yes / yes | none | none hit a limit | 0 | the 120 s wall-clock budget is not enforced in 0.1 (documented on the rule page); the size, count and ratio limits are tested on crafted archive bombs in `tests/test_safe_archive.py` |
| GRN-E004 unpinned-requirement | yes / yes (`tests/test_lockfiles.py`, `tests/test_cli_and_report.py`) | n/a | reported on real lockfiles in the Action's tests | n/a | — |
| GRN-E005 unsupported-source | yes / yes (`tests/test_lockfiles.py`) | n/a | n/a | n/a | — |
| GRN-T006, GRN-C004, GRN-C005, GRN-C006 | — | — | — | — | **not built** (planned; `checks/docs.py` lists them as such) |

Before this page, four built rules had no test at all: T005, T008, E003 and C002. They have
rows now.

## What crafted releases got past the rules

Probing each rule with releases shaped like known attacks found seven evasions and one false
alarm on `main` at `df8c6a2`. Each is fixed in a draft pull request with a regression test and
the backtest delta: #32 for the five C003 shapes, #33 for `setup.py`, the sdist cases and the
`.pth` false alarm. Two more shapes came from the real attacks below and are fixed in #34.

| Shape | Rule | What happened | Fix |
|---|---|---|---|
| `cmdclass={'install': PostInstall}` whose `run()` calls `os.system` (the classic PyPI install hook) | C002 | invisible: only import-time calls in `setup.py` were indexed | `setup.py` is read whole; the evidence names the function |
| A release that drops its wheel and ships only an sdist, after a wheel-only trusted version | C001, C002, C003 | nothing compared, nothing said | the two kinds are compared with each other, with a note |
| A release that adds an sdist with a hooked `setup.py` to a wheel-only package | C002 | silent: no trusted sdist to compare with | a trusted version without an sdist had no build code, so every call is new |
| `(lambda: os.system(...))()`, `atexit.register(lambda: ...)` | C003 | lambda bodies were never followed | followed when the lambda is called or passed |
| `class Boot: def __init__(self): os.system(...)` then `Boot()` at import | C003 | only module-level functions were followed | instantiation runs `__init__`/`__new__`; `Boot.method()` is followed too |
| `from subprocess import *` then `run([...])` | C003 | the bare name resolved to nothing | resolved against star-imported modules, skipping builtins and the module's own names |
| `getattr(os, "sys" + "tem")(...)`, `__import__("os").system(...)` | C003 | not resolved | literal names are folded and resolved; a name built at runtime still is not |
| `exec(base64.b64decode(...))` in a module that already used `exec` | C003 | same call name as before, so not new, although the rule page promised it | the decode feeding a sensitive call is its own entry: `base64.b64decode → exec` |
| A `.pth` shipped under `<name>-<version>.data/purelib/` | C001 | **false alarm on every release**: the folder carries the version, so the path was always new | compared by where the file lands in site-packages; a renamed `.pth` with the same lines is not new |

## What the real attacks show

Twenty-six malicious releases of fifteen packages are replayed in #31 (lightning,
elementary-data, litellm, telnyx, ultralytics, num2words, xinference, mistralai, guardrails-ai,
durabletask, memoryos, gpsea, pyphetools, ppkt2synergy and embiggen), each against the facts of
its day. On `main` 24 of the 26 get a warning; with #32, #33 and #34, 25 do. Three of them
showed a content rule seeing less than it should, with a trust rule or nothing carrying the
result:

- **embiggen 0.11.97** is missed on `main`. The trusted 0.11.96 is an sdist and the malicious
  release a wheel, so the content rules compared nothing and the new `embiggen-setup.pth` went
  unreported. #33 compares the two kinds with each other and reports the file on GRN-C001.
- **num2words 0.5.15 and 0.5.16** warn on `main` only through GRN-T004. The payload reaches
  `ctypes` through `getattr(sys.modules[__name__], "ctypes")`, a lookup GRN-C003 did not
  resolve. #34 resolves it: `num2words/__init__.py:121 calls ctypes.CDLL`.
- **memoryos 2.0.34** warns on `main` only through GRN-C002. Its import-time chain passes
  through the package's own modules before `_stage0.trigger()` starts a bundled binary, and
  GRN-C003 stopped at the first module. #34 follows the chain: `memos/_stage0.py:22 calls
  subprocess.Popen (in trigger(), reached at import from memos/api/client.py)`.

The one that no rule sees:

**ultralytics 8.3.42** (Dec 5, 2024) was published by the project's own release workflow after
a GitHub Actions cache-poisoning injection. Its attestation is valid, from the usual repository
and workflow; a `v8.3.42` tag existed that day (deleted since); and the payload sits in
`YOLO.__init__`, so it runs when a model is created, not when the package is imported. No
current rule looks at that. A rule that reports a changed module gaining a sensitive call
anywhere, not only at import, would have seen `subprocess.Popen` arrive in
`utils/downloads.py`; whether it stays quiet enough on routine updates is a measurement to
make before adding it. Until then the honest line is: a payload that waits to be called is
caught by the trust rules or not at all.

The other round of the same attack, 8.3.45 and 8.3.46, was uploaded with a leftover API token:
no attestation, no tag, and four `os.system` lines at module level. Garnet reports those three
things.

## Keeping this page true

- A new rule needs a firing and a quiet row in `tests/test_rule_matrix.py`, or the suite fails.
- A rule change includes the before/after warn rate from `python -m backtest` in its PR.
- When the replays are re-run, update the "real attacks" column and the counts above, and the
  website's replay page.
