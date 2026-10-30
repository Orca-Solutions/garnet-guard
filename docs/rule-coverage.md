# Rule coverage: how each rule is proven

What stands behind each rule ID, as of 2026-10-30 on `main`. Three kinds of evidence:

- **Crafted releases** (`tests/test_rule_matrix.py`): tiny wheels and sdists built in memory,
  one that makes the rule fire and one that keeps it quiet (68 rows today), run for every
  ecosystem the rule is registered for. No real malware is stored in the
  repository. `test_every_built_rule_has_rows` fails when a rule is registered without both.
- **Real attacks** (`python -m backtest`): 52 malicious releases. The 47 PyPI releases in
  [backtest/incidents.toml](../backtest/incidents.toml) (36 packages, December 2024 to
  September 2026) are fetched by URL and hash from files.pythonhosted.org, which still serves
  files PyPI has removed. The 5 npm releases in
  [backtest/npm-incidents.toml](../backtest/npm-incidents.toml) replay from recorded registry
  facts, because npm deletes removed tarballs. All 52 warn on `main`, with git tags as they
  stood on the day of each upload.
- **Real routine updates**: the clean corpora, the last 11 releases of the top 1,000 PyPI
  packages (9,439 updates, [report](../backtest/corpus-results-pypi-1000/REPORT.md)) and of
  the top 1,000 npm packages (8,742 updates,
  [report](../backtest/corpus-results-npm-1000/REPORT.md)), every warning triaged; the earlier
  974-update top-100 PyPI corpus ([report](../backtest/corpus-results/REPORT.md)), which is
  the only clean measurement of GRN-C007 so far, because the top-1,000 runs predate it; the
  repository's own dependency bumps (the dogfood workflow); and a scan of the last 20 releases
  of the top 600 PyPI packages (10,886 releases) for publisher, workflow and attestation
  changes, run for this page. The releases that confirmed a rule are in
  `tests/test_real_releases.py`, which fetches them live
  (`uv run pytest -m network tests/test_real_releases.py`).

A rule that has only crafted evidence is working as designed but has not met the real thing.
That is said in the table, not hidden.

## The matrix

"Clean corpora" counts updates the rule warned on in the top-1,000 runs, PyPI then npm. Every
one of those warnings states something true about a legitimate release; none of the updates is
known to be malicious, so each is a false alarm a reviewer has to dismiss.

| Rule | Crafted: fires / quiet | Real attacks it reported | Real routine updates | Clean corpora (PyPI 9,439 / npm 8,742) | Not yet proven |
|---|---|---|---|---|---|
| GRN-T001 lost-provenance | yes / yes | ultralytics 8.3.45 and 8.3.46 (Dec 2024), uploaded with a leftover API token and carrying no attestation after attested releases (PyPI no longer serves provenance for removed files, so the replay records that fact); nx 21.5.0 on npm | 20 of 600 packages dropped attestations between two releases (pillow 11.3.0, watchfiles 1.0.5, tomli 2.4.0, stripe 15.0.0, llvmlite 0.48.0, google-api-core 2.30.1, …), all legitimate | 18 / 48 | a real attack seen live, not from a recorded fact |
| GRN-T002 publisher-changed | yes / yes (a renamed repository keeps its id) | none | 8 publisher changes in 10,886 releases. Fires, accurately: scikit-learn 1.9.1 and matplotlib 3.10.8 (moved to `*-release` repositories), langsmith 0.14.10 (`langsmith-sdk` → `langsmith-python`), mcp-types 2.0.0 (`kludex/mcp` → `modelcontextprotocol/python-sdk`). Quiet, correctly: msgspec 0.22.0, authlib 1.6.0 and propcache 0.2.0, transferred to an organization, which keeps the repository id | 14 / 3 | a real attack |
| GRN-T003 workflow-changed | yes / yes | ultralytics 8.3.47, the fix release, added a `release - pypi` environment (benign, accurate) | pluggy 1.7.0 `main.yml → deploy.yml` (reported live on this repository's PR #25), tornado 6.6, pymysql 1.2.0, cssselect2 0.10.0 and weasyprint 68.1 added an environment, cuda-pathfinder 1.8.4 renamed its workflow file | 16 / 2 | a real attack |
| GRN-T004 no-matching-tag | yes / yes | 31 of the 51 with the tags of the day: lightning 2.6.2 and 2.6.3, telnyx 4.87.1 and 4.87.2, ultralytics 8.3.41, 8.3.45 and 8.3.46, num2words 0.5.15 and 0.5.16, xinference 2.6.0–2.6.2, mistralai 2.4.6, durabletask 1.4.1–1.4.3, eleven Hades-campaign releases (gpsea 0.9.14, cmd2func 0.2.2, …), and all four npm releases (chalk 5.6.1, debug 4.4.2, nx 21.5.0, @ctrl/tinycolor 4.1.1); with today's tags also elementary-data 0.23.3 and ultralytics 8.3.42 | s3fs 2026.6.0 (accurate: no tag) | 49 / 89 | — |
| GRN-T005 outside-trusted-publishing | yes / yes | none | @pkgr/core 0.3.0 on npm: attested from the project's release workflow but published from a maintainer's account, where 0.2.10 used Trusted Publishing (accurate) | 0 / 1 | **Cannot fire on PyPI**: PyPI accepts attestations only through Trusted Publishing, so a file without one is GRN-T001. The rule exists for registries that separate the two, and has fired once on npm; no real attack yet |
| GRN-T006 files-uploaded-late | yes / yes (a late first wheel, and late wheels that rank above, tie with or out-build an on-time one; a backfill at `info`) | none: each replayed malicious release was a whole new version | on the 974-update top-100 PyPI corpus, 2 warnings, each true: cffi 1.14.5 (aarch64 wheels uploaded again 96 days later with the same tags as on-time ones) and iniconfig 1.1.1 (its only wheel arrived two days after the sdist); 11 backfills of new Python versions and platforms at `info` (lxml 5.4.0, 6.0.0 and 6.1.1, markupsafe 2.1.3, pillow 11.3.0, pyyaml 5.3.1, 5.4.1, 6.0, 6.0.1 and 6.0.3, cffi 1.14.6) | not yet run (2 of 974 on the top-100 corpus) | the top-1,000 corpus; a real attack through a file added to a released version |
| GRN-T007 invalid-attestation | yes / yes | none | none | 0 / 0 | a real forged or broken attestation has not been seen. Every attested release in the corpora verified; the npm verifier is unit-tested on recorded real bundles (`tests/test_npm.py`), the PyPI one (Sigstore, via pypi-attestations) only through the corpus runs |
| GRN-T008 hash-mismatch | yes / yes | none | none | 0 / 0 | a real mismatch has not been seen; every download in the corpora matched the registry |
| GRN-C001 new-pth-file | yes / yes | 26 of the 51: elementary-data 0.23.3, litellm 1.82.8 and all 24 Hades-campaign releases (gpsea 0.9.14, pyphetools 0.9.120, embiggen 0.11.97, …) | amazon-ion 0.13.0, grpc-google-iam-v1 0.12.7 and zope-event 5.1 added a setuptools namespace-package `-nspkg.pth` (accurate) | 3 / n/a | — |
| GRN-C002 new-build-hook | yes / yes (PyPI: `setup.py` and the build backend; npm: install scripts) | memoryos 2.0.34; nx 21.5.0 and @ctrl/tinycolor 4.1.1 on npm, through install scripts | on PyPI, 33 setup.py files gained build-time calls and 24 build backends changed (12 to an in-tree backend); on npm, loupe 3.0.0 added `postinstall: npx playwright install` (all accurate) | 57 / 3 | a real PyPI attack through a `cmdclass` install hook, the classic shape |
| GRN-C003 new-import-time-exec | yes / yes | 20 of the 51: lightning 2.6.2 and 2.6.3, litellm 1.82.7 and 1.82.8, telnyx 4.87.1 and 4.87.2, ultralytics 8.3.45 and 8.3.46, num2words 0.5.15 and 0.5.16, xinference 2.6.0–2.6.2, mistralai 2.4.6, guardrails-ai 0.10.1, durabletask 1.4.1–1.4.3, memoryos 2.0.34 and mrmustard 0.7.4 | requests 2.32.2, typing-inspection 0.1.0, wheel 0.45.0 (accurate). New reads of credentials or CI settings at import are listed at `info`: tqdm 4.68.2 on the 974-update corpus (`os.environ` in `envwrap()`), and mistralai 2.4.6, memoryos 2.0.34 and mrmustard 0.7.4 among the replayed malicious releases, each also reported by a warning | 65 / n/a, plus 46 PyPI findings at `info` | — |
| GRN-C007 code-not-in-source | yes / yes | ultralytics 8.3.42 (Dec 2024) with the tags of the day: `ultralytics/utils/downloads.py:292 calls subprocess.Popen (in safe_run()); the source differs from ultralytics/utils/downloads.py at v8.3.42` (with today's tags the tag is gone, so GRN-T004 reports it); telnyx 4.87.1 with today's tags, which point at a clean commit | none: 158 of the 974 top-100 updates ship a Python file that isn't the one at the tag (a generated `_version.py`, Cython output, scipy's relocated submodule files), none with a sensitive call the source file lacks | not yet run (0 of 974 on the top-100 corpus) | the top-1,000 corpora; a build-injected payload seen live; a repository off GitHub, which the rule can't read (a release there has no tag lookup either, so nothing is compared and nothing is claimed) |
| GRN-C008 new-dependency | yes / yes, on PyPI and npm (a new dependency young, missing from the registry or installed from git, including one owned by the trusted package's owner; an established one; an npm alias) | event-stream 3.3.6 (Sep 2018, npm), which added `flatmap-stream`, first released 35 days earlier; no other rule reports it | on the 974-update top-100 PyPI corpus, 18 new dependencies at `info`, all established packages (`typing-extensions` 9 times, `importlib-metadata` 3 times, `anyio`, `pygments`, `packaging`, `tomlkit`, …); on the 1,809-update top-200 npm corpus, 19 warnings, each true. 14 are a helper the trusted package's own maintainer published the same day or within weeks (sindresorhus 6, ljharb 4, isaacs 2, tootallnate 2), kept at `warn` because an attacker holding a maintainer's account could do the same. The other 5: `verkit` 53 days old in @babel/core 8.0.5 and @babel/helper-compilation-targets 8.0.5, `fastest-levenshtein` in fast-levenshtein 3.0.0 and `path-dirname` in glob-parent 3.0.1 (each first released the same day), `@aashutoshrathi/word-wrap` 73 days old in optionator 0.9.2. 49 more at `info` | not yet run (0 of 974 PyPI, 19 of 1,809 npm on the smaller corpora) | the top-1,000 corpora; a PyPI attack through a new dependency |
| GRN-C010 new-startup-file | yes / yes (a new `sitecustomize.py`, a script named like a common command, a data file at `info`; the same script as before, a `sitecustomize.py` inside the package folder) | none: no replayed malicious release ships one of these files | on the 974-update top-100 PyPI corpus, 1 update at `info`: jmespath 0.9.2 added its `jp` command as a script | not yet run (0 of 974 on the top-100 corpus) | the top-1,000 corpus; a real attack through a startup file other than `.pth` |
| GRN-C011 new-js-capability | yes / yes (a new `child_process` at load, obfuscated `_0x` names shaped like chalk 5.6.1's line, a use moved between files, files nothing loads, a method named `fetch`, a loaded file over the limit) | none: the npm replays carry no tarball (npm removed the files), so chalk 5.6.1 and debug 4.4.2, whose payload was in `index.js`, stay GRN-T004 only | on the 1,809-update top-200 npm corpus, 5 updates at `info`, each a real new use: agent-base 7.1.1 `require("net")`, dotenv 18.0.0 `child_process` inside a function, function-bind 1.0.0 and json5 2.0.1 `Function(…)`, source-map 0.7.0 `fetch` to load its wasm. No warning, no GRN-E003 | not yet run (0 of 1,809 npm on the smaller corpus) | the top-1,000 npm corpus; a real attack whose JavaScript is still on the registry |
| GRN-K001 known-malicious | yes / yes | off in the backtest by design (the question is what Garnet catches before a feed lists a release) | none | off | the live OSV lookup has not been exercised in any recorded run; the cloud sandbox cannot reach api.osv.dev. Run `garnet diff` on a listed release from a machine that can |
| GRN-E001 fetch-failed | yes / yes | ultralytics 8.3.41 and 8.3.42, pyphetools 0.9.120 and dreamgen 1.8.1 (a removed release's provenance, or a repository that is no longer public) | files over the download cap (CUDA libraries, torch), repositories that answer HTTP 401 | 141 / 26 | — |
| GRN-E002 parse-failed | yes / yes | num2words 0.5.15 and 0.5.16 (a Windows DLL named `.py`) | sdists containing a link, which `safe_archive` refuses; Python 2 files | 143 / 4 | — |
| GRN-E003 budget-exceeded | yes / yes | ensmallen 0.8.101 (`datasets/` modules over the parse limit) | 11 PyPI updates hit a limit | 11 / 0 | the 120 s wall-clock budget is not enforced in 0.1 (documented on the rule page); the size, count and ratio limits are tested on crafted archive bombs in `tests/test_safe_archive.py` |
| GRN-E004 unpinned-requirement | yes / yes (`tests/test_lockfiles.py`, `tests/test_cli_and_report.py`) | n/a | reported on real lockfiles in the Action's tests | n/a | — |
| GRN-E005 unsupported-source | yes / yes (`tests/test_lockfiles.py`) | n/a | n/a | n/a | — |
| GRN-C004, GRN-C005, GRN-C006 | — | — | — | — | **not built** (planned; `checks/docs.py` lists them as such) |

Before this page, four built rules had no test at all: T005, T008, E003 and C002. They have
rows now.

## What crafted releases got past the rules

Probing each rule with releases shaped like known attacks found seven evasions and one false
alarm on `main` at `df8c6a2`. All are fixed on `main`, each with a regression test and the
backtest delta: #32 for the five C003 shapes, #33 for `setup.py`, the sdist cases and the
`.pth` false alarm. Three more shapes came from the real attacks below and were fixed in #34
and #36. The top-1,000 PyPI corpus (9,439 updates) then showed four false GRN-C003 claims (a
local list called `requests`, a package's own `compile()`, a file renamed with a leading
underscore, a trusted copy that couldn't be parsed) and three kinds of warning a reviewer
cannot act on (a function handed to a call that may never run it, a chain that starts in a
test file, sdist files outside the package); #38 fixed the four and moved the three to
`info`. On the 974-update corpus #38 changed no verdict (18 → 18). With #38, the top-1,000
PyPI corpus has 220 of 9,439 updates flagged for a look (2.3%), 65 of them GRN-C003, each
read line by line with none false, and 46 GRN-C003 findings at `info`.

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

The replay runs real malicious releases against the facts of their day. When it first ran
(26 releases of 15 packages, in #31), `main` warned on 24 of them, and four releases showed a
content rule seeing less than it should, with a trust rule or nothing carrying the result.
All four are fixed on `main` now, and with GRN-C007 all 51 releases in today's replay warn:

- **embiggen 0.11.97** was missed. The trusted 0.11.96 is an sdist and the malicious release
  a wheel, so the content rules compared nothing and the new `embiggen-setup.pth` went
  unreported. #33 compares the two kinds with each other and reports the file on GRN-C001.
- **num2words 0.5.15 and 0.5.16** warned only through GRN-T004. The payload reaches `ctypes`
  through `getattr(sys.modules[__name__], "ctypes")`, a lookup GRN-C003 did not resolve. #34
  resolves it: `num2words/__init__.py:121 calls ctypes.CDLL`.
- **memoryos 2.0.34** warned only through GRN-C002. Its import-time chain passes through the
  package's own modules before `_stage0.trigger()` starts a bundled binary, and GRN-C003
  stopped at the first module. #34 follows the chain: `memos/_stage0.py:22 calls
  subprocess.Popen (in trigger(), reached at import from memos/api/client.py)`.
- **mrmustard 0.7.4** (added to the replay later) was missed: the package links no
  repository, so GRN-T004 has nothing to check, and the payload is a `_run()` defined inside
  the function called at import, which GRN-C003 could not see. #36 follows it:
  `mrmustard/__init__.py:227 calls subprocess.check_output (in _run(), reached at import)`.

The one that only GRN-C007 sees:

**ultralytics 8.3.42** (Dec 5, 2024) was published by the project's own release workflow after
a GitHub Actions cache-poisoning injection. Its attestation is valid, from the usual repository
and workflow; a `v8.3.42` tag existed that day (deleted since); and the payload sits in
`YOLO.__init__`, so it runs when a model is created, not when the package is imported. The trust
rules and GRN-C003 are quiet. GRN-C007 asks a different question: is every Python file in the
wheel the file at the tag? Two aren't, and only the published copy of `utils/downloads.py` calls
`subprocess.Popen`; that is the report, with a link to the file at the tag. The rule weighed
first, a changed module gaining a sensitive call anywhere, not only at import, warned on 87 of
the 974 routine updates (8.9%) and was not built. GRN-C007 warned on none of them: the twelve
warnings of the corpus report are the same twelve, from the same rules. It has not yet been
run on the top-1,000 corpora, which predate it.

The other round of the same attack, 8.3.45 and 8.3.46, was uploaded with a leftover API token:
no attestation, no tag, and four `os.system` lines at module level. Garnet reports those three
things.

## Keeping this page true

- A new rule needs a firing and a quiet row in `tests/test_rule_matrix.py`, or the suite fails.
- A rule change includes the before/after warn rate from `python -m backtest` in its PR.
- When the replays are re-run, update the "real attacks" column and the counts above, and the
  website's results page (`site/replays/results.toml` in gg-landing).
