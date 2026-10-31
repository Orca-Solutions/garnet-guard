# PyPI clean-corpus backtest, top 1,000 packages, 2026-10-31

The last 11 final, non-yanked releases of the 1,000 most downloaded PyPI packages
([top-pypi-1000.json](../top-pypi-1000.json), hugovk/top-pypi-packages, snapshot of
2026-10-01; its first 100 are the list the [top-100 run](../corpus-results/REPORT.md) used),
each compared with the release before it, the way a Dependabot or Renovate update would be:
975 packages with at least two releases, 9,439 updates. Known-bad lookups (GRN-K001) were
off, tags were evaluated as they exist today, and default severities applied.

```
uv run python -m backtest select pypi 1000   # writes corpus-pypi-1000.json
uv run python -m backtest corpus pypi 1000   # writes this folder's summary.json and updates.json
```

The run used the rules as they ship in 0.2.0: main at `17b8cd1`, which has every launch
check, the GRN-C007 fix (PR #85) and the sensitive call set without the subprocess names
that start nothing (PR #90), plus PR #96 (`9314359`), which changes which wheel is read for
a release with no wheel for this Python. #96 changes the facts of 391 releases in 71
packages; those were fetched again, and the facts of the other 9,876 releases were reused
from the `17b8cd1` run's cache (7 reused releases fetched fresh gave identical facts). A
second pass retried everything the first couldn't fetch.

## Result

**300 of 9,439 updates were flagged for a look (3.2%), in 235 packages. Each of the 300
was checked on its own against PyPI, GitHub and the release files, and none made a false
claim.**

| Rule | Updates | Packages |
|---|---|---|
| GRN-C003 new-import-time-exec | 65 | 52 |
| GRN-C002 new-build-hook | 60 | 53 |
| GRN-T004 no-matching-tag | 48 | 38 |
| GRN-T006 files-uploaded-late | 34 | 30 |
| GRN-C008 new-dependency | 23 | 23 |
| GRN-T001 lost-provenance | 18 | 18 |
| GRN-T003 workflow-changed | 16 | 14 |
| GRN-T002 publisher-changed | 14 | 13 |
| GRN-C009 new-entry-point | 9 | 8 |
| GRN-C004 new-binary | 6 | 6 |
| GRN-C007 code-not-in-source | 5 | 4 |
| GRN-C001 new-pth-file | 4 | 3 |
| GRN-C012 wheels-differ | 2 | 2 |
| GRN-C010 new-startup-file | 1 | 1 |

Five updates carry two rules, so the rows add up to 305.

The [first top-1,000 run](https://github.com/orca-solutions/garnet-guard/pull/39) flagged
220. All 220 still warn, and 80 more do: 76 through the rules added since (GRN-T006 33,
GRN-C008 22, GRN-C009 8, GRN-C004 6, GRN-C007 5, GRN-C012 1, GRN-C010 1), 3 through the
wider sensitive call set (GRN-C002 on glom 23.4.0, hiredis 3.3.1 and pywavelets 1.2.0), and
1 because a release that is the first to ship a wheel is now read through it (GRN-C001 on
amazon-ion 0.11.3). One GRN-T004 warning is gone: grimp has tagged `v3.18` since.

"None made a false claim" means every finding states something true about the release.
It does not mean no warning was a false alarm: none of these 9,439 updates is known to be
malicious, so from a user's point of view every one of the 300 is a false alarm, a true
observation about a legitimate release that a reviewer has to look at and dismiss.

More findings were reported at `info`, not warn: 282 GRN-C008 (established new
dependencies), 125 GRN-T006 (late wheels that only add a platform or a Python version), 70
GRN-C009, 66 GRN-C003, 62 GRN-C010 (new scripts and data files) and 8 GRN-C004.

304 updates (3.2%) carry a couldn't-check finding (GRN-E), which names what wasn't
checked. Some carry more than one kind:

| Why | Updates | Packages |
|---|---|---|
| An sdist contains a link, which `safe_archive.py` refuses (GRN-E002) | 117 | 15 |
| A file is larger than the download cap (GRN-E001): CUDA libraries, torch, triton, xgboost, pyspark | 111 | 16 |
| github.com answers HTTP 401 for the tags of a repository that is private, renamed or gone (GRN-E001) | 34 | 8 |
| Python 2 files that don't parse as Python 3 (GRN-E002) | 24 | 14 |
| A file over the parser's size limit, or more late wheels than GRN-C012 compares (GRN-E003): av, brotli, google-re2, grimp, lazy-object-proxy, pillow, pymssql | 16 | 7 |
| A duplicate entry in an archive (GRN-E002) | 6 | 3 |

## What the first passes got wrong

**On `5227dd1`, 4 GRN-C007 claims were false**, fixed by PR #85 before this run:

- sympy/sympy tags 1.12.1 twice, as `1.12.1` and `sympy-1.12.1`, at different commits, and
  the wheel was built from the second.
- multiprocess 0.70.12.1 ships only Windows wheels, whose files have CRLF line endings.
- pycryptodomex 3.17 and 3.19.1 publish pycryptodome's `lib/Crypto/` as `Cryptodome/`.

GRN-C007 now reads CRLF as LF, compares a package published under another name with the
folder it came from, and tries every tag that names the version.

**On `17b8cd1`, 1 GRN-C004 claim was false**, fixed by PR #96. It said pendulum 2.0.5 adds
two compiled files that 2.0.4 didn't have, but 2.0.4's Python 3 wheels have the same two
files. Neither release has a wheel for Python 3.13, and Garnet read each through its first
wheel by name: for 2.0.4 a Python 2 build with no compiled code, for 2.0.5 a Python 3.4
build. pendulum 3.0.0 warned for the same reason, though 2.1.2 already shipped compiled
code. Garnet now reads such a release through its newest CPython build for this platform.
With #96, both warnings are gone, and PyYAML's 4 GRN-E002 gaps and 2 GRN-C012 `info`
findings went with them: its releases are now read through Python 3 builds that parse.

### Before PR #39

The same corpus first ran on main plus the rule-testing branches up to PR #34 (`-reach`):
242 updates warned. 22 of them rested on a false claim (9 GRN-T004, 13
GRN-C003), and 5 more were true but are now reported at info.

- **GRN-T004 said 9 releases had no tag, and they did.** explosion's packages tag
  `release-v1.0.0` (confection 1.0.0, cymem 2.0.10, murmurhash 1.0.11, preshed 3.0.10,
  srsly 2.5.0, thinc 9.1.0, weasel 0.4.2), langgraph tags `prebuilt==1.0.11`
  (langgraph-prebuilt) and the Azure SDK tags `azure-mgmt-core_1.1.0`. GRN-T004 now reads
  `X` or `vX` after a prefix that names the package or says `release`, joined by `-`, `_`,
  `==` or `/` ([GRN-T004](../../docs/rules/GRN-T004.md)).
- **GRN-C003 made 13 false claims**, in four kinds: a local name read as a module
  (curl-cffi 0.15.0's list named `requests`), a module's own function read as the builtin
  (nltk 3.10.4's `def compile`), "new module" for a renamed file (html5lib 0.99999999), and
  "reached at import" for a function only handed to another call (huggingface-hub 1.32.0,
  modal 1.6.0, partd 1.3.0 and five others). Those are fixed, and the last kind is `info`
  and says "handed to X() at import".

## Accurate, but nothing new runs

The triage checked that each finding is true. In some, a reviewer who opens the release
finds nothing new running: it does what the trusted release did, in a new way, or the new
code runs only under Python 2. These are the ones the triage found; it didn't look for
them in every warning.

- **mako 1.3.12 → 1.4.1 (GRN-C009).** The `pygments.lexers` names `css+mako`,
  `html+mako`, `js+mako` and `xml+mako` became `css_mako` and so on, with the same classes.
  pygments loads every lexer by class, not by name. GRN-C009 compares targets name by name,
  so each renamed name reads as new.
- **amazon-ion 0.11.2 → 0.11.3 (GRN-C001).** 0.11.3 is the first release with wheels, and
  each holds the `-nspkg.pth` file setuptools writes for a namespace package. 0.11.2 shipped
  only an sdist, and building it writes the same kind of file. GRN-C001 reports this case
  on purpose, with a note that a wheel was compared with an sdist
  ([GRN-C001](../../docs/rules/GRN-C001.md)), because Garnet doesn't run a build to see what
  it would write.
- **mpmath 0.17 → 0.18 (GRN-C003).** 0.18 adds a copy of `six` whose `exec` runs at import
  only under Python 2: line 333, in six's Python 2 branch, calls the `exec_` defined at line
  320, which calls `exec`. Under Python 3 neither line runs. The second evidence line names
  the callee `builtins.exec`, the value `exec_` gets in the Python 3 branch at line 307:
  Garnet reads a module's names without following `if` and `else`.
- **GRN-C002 calls that replace a call.** In 17 of the 38 GRN-C002 warnings that add a
  setup.py call, the trusted setup.py already made a call from the sensitive set. GRN-C002
  compares calls by name, so a new name is a new call even when it does the old job. Six
  were read closely, and each runs what the trusted release ran: pycparser 2.19 runs
  `_build_tables.py` with `check_call` where 2.18 used `call`, psycopg2 and psycopg2-binary
  2.9.7 run `pg_config` with `subprocess.run` where 2.9.6 used `Popen`, and glom 23.4.0,
  hiredis 3.3.1 and pywavelets 1.2.0 load their own version file with a different
  `importlib` or `runpy` call than before. The other 11 weren't read for this.

## Triage

Every warning is listed with its check in [triage.json](triage.json).

**GRN-C003 (65).** Each evidence line was read back from the release files with `ast`: the
call is on the cited line (16 of them through a local alias such as `_DWORD`,
`_find_library` or `_PyCapsule_New`), the name's head is imported, no builtin is shadowed
by the module's own function, "new module" matches the trusted release, and each function
named in "(in f(), reached at import)" is called in the package. By kind of call:

- 28 load or describe native code with `ctypes` at import: libraries (lightgbm, pypdfium2,
  python-magic, send2trash, soundfile, xgboost), Windows and macOS system APIs (fire,
  locket, progressbar2, pywin32, shellingham, oscrypto), and type definitions and sizes
  (numba, sympy, llvmlite, dill).
- 18 import a module by a computed name: optional dependencies and plugins (requests
  2.32.2 picking `chardet` or `charset_normalizer`, polars, snowflake-connector-python,
  triton's backends, huey's Django integration, wheel's `__import__("setuptools.logging")`).
- 12 generate code with `exec`, `eval` or `compile`: typing-inspection, anyio's lazy-import
  map, patsy, scipy's and scikit-learn's vendored array-api-compat, and two new copies of
  `six` (awscli 1.46.0, mpmath 0.18).
- 5 use network APIs at import: altair builds a URL opener, google-genai builds `httpx`
  timeouts and limits, reportlab and weasyprint build URL fetchers, and twisted's test
  utilities create a socket to check for IPv6.
- 2 run a subprocess: scikit-image 0.25.0 runs `git log` to add the commit to its
  version string, and pymupdf 2.0's `get_tessdata()`, reached from pymupdf4llm's OCR
  module, runs one to find Tesseract's data.

Two need a word. multiprocess 0.70.12.2's trusted wheel is Python 2 code that doesn't
parse, so the calls can't be compared; the finding warns and its title says the trusted
copy couldn't be parsed, since Garnet doesn't treat "couldn't compare" as a pass. In
awscli's copy of `six`, the cited line is the Python 2 definition of `exec_`; on Python 3
the module runs the builtin `exec` through the same name at line 746, to define
`raise_from`. mpmath's older copy is under [Accurate, but nothing new
runs](#accurate-but-nothing-new-runs).

**GRN-C002 (60).** The sdists were read for each: the cited setup.py line has the call
and the trusted setup.py doesn't, or the build backend in pyproject.toml changed as
stated. 36 add calls to setup.py that run when the sdist is built (`subprocess` 30 times,
`exec` 12, `runpy` and `__import__` 3 each, and a few others, counting evidence lines), 22
change the build backend, and 2 do both. Of the 24 backend changes, 12 are to an in-tree
backend, 5 to `flit.buildapi` and 3 to `poetry.masonry.api`. 7 compare against a trusted
version that shipped no sdist, so every build-time call is new, and the finding says so.
reportlab 5.1.0's setup.py builds and installs a URL opener. 3 are new since the first
run, through calls the sensitive set added (glom 23.4.0, hiredis 3.3.1, pywavelets 1.2.0).

**GRN-T004 (48).** Each was checked with `git ls-remote --tags` against every repository
the finding names: no tag names the candidate version, in any form. 12 are releases from
before 2020; 18 are from 2025 or 2026, releases a maintainer didn't tag (s3fs 2026.6.0,
tiktoken 0.10.0, four swebench releases). Six are post-releases (`2.0.0.post1`,
`0.7.post0`, `3.0.0.1`) of a tagged release, which the rule counts as their own version.

**GRN-T006 (34).** Checked against the upload times in PyPI's JSON API: the count of files
uploaded more than 24 hours after the release's first file matches, and so does each listed
file's upload time. In 17 the late file is the release's first wheel, which pip installs
before the sdist that was there on time. In 7 it has the same tags as a wheel uploaded on
time, so pip may install either (NVIDIA CUDA wheels, brotli 1.0.7, cffi 1.14.5, and grimp
3.18, whose aarch64 wheels gained a second copy with the tags in the other order on
2026-10-30). In 8 pip ranks it above an on-time wheel, 3 of them through a build number
(torch 2.10.0's macOS wheels `2.10.0-2`, google-re2 1.0 and 1.1), and in 2 the late files
do both.

**GRN-C008 (23).** Each dependency line was checked against PyPI's JSON API: the first
upload date, the days before the candidate's first file and the release count match, and
the trusted version's `requires_dist` doesn't list the dependency (for service-identity
1.0.0, whose JSON lists none, against the wheel's `METADATA`). 24 of the 32 lines are
dependencies first released less than 90 days before the candidate. In 16 of the 23, an
account that owns the package owns every young dependency too (griffe's `griffelib` and
`griffecli`, ghapi's and fastspec's `fasttransport`, dbt-core's experimental parser): the
rule keeps those at `warn` and says so, because an attacker who holds a maintainer's
account can publish both ([GRN-C008](../../docs/rules/GRN-C008.md)).

**GRN-T001 (18).** For each, PyPI's Integrity API serves an attestation for every file of
the trusted version and for none of the new one's (for pillow 11.3.0, 20 of 106 lack one).
Three compare a maintenance release that gained provenance with an older release on a
newer line
(thinc 8.3.14 → 9.0.0, tomli 2.3.2 → 2.4.0, google-resumable-media 2.8.1 → 2.8.2): true,
and the dates show why.

**GRN-T002 (14) and GRN-T003 (16).** Confirmed from the attestations. Nine explosion
packages (spacy, thinc, srsly, cymem and others) moved their publishing to
explosion/wheelmonger; matplotlib and scikit-learn publish from a separate `-release`
repository; langsmith and mcp-types moved repositories. The workflow changes are renames
(gcsfs, pluggy, holidays) and a new deployment environment (`pypi`, `release`, `publish`).

**GRN-C009 (9).** Read from `entry_points.txt` in both wheels. Five change a setuptools or
`distutils` target (babel 2.14.0, incremental 24.7.1, pbr 7.0.2, setuptools-scm 10.3.3) or
add one (pbr 7.1.3): code setuptools can load while it builds any package. pytest-html 4.0.0 and pytest-metadata 2.0.1 add a `pytest11` plugin, which every
pytest run loads; opentelemetry-sdk 1.43.0 adds a resource detector its own code always
loads. mako 1.4.1 is under [Accurate, but nothing new runs](#accurate-but-nothing-new-runs).

**GRN-C004 (6).** isort 9.0.0 (45 files), pytokens 0.4.0 (3) and tomli 2.2.1 (5) are now
built with mypyc, and the cp313 Linux wheel has ELF `.so` files where the trusted release
had only a pure-Python wheel. wcwidth 0.9.0 adds a C extension, magika 0.6.1 a 30 MB ELF
executable in its scripts, and pysocks 1.6.6's sdist a test binary, `test/bin/3proxy`.
The files were counted and identified from the archive members, read as bytes.

**GRN-C007 (5).** Each file's git blob id was compared with every tag that names the
version: daff 1.3.45 and 1.4.2's generated Haxe output (1.3.45's adds a call that opens a web
browser), the node-gyp Python files nodejs-wheel-binaries 24.19.0 takes from Node's
distribution, shellingham 1.2.8's `posix/_default.py`, and tensorboard 2.20.0's vendored
`html5lib`. None is in the repository at the tag.

**GRN-C001 (4).** amazon-ion 0.13.0, grpc-google-iam-v1 0.12.7 and zope-event 5.1 each
added a setuptools namespace-package `-nspkg.pth` file: one executable line that runs at
every Python startup. True, and the kind of file the rule is for. amazon-ion 0.11.3 is under
[Accurate, but nothing new runs](#accurate-but-nothing-new-runs).

**GRN-C012 (2).** multiprocess 0.70.12.2's cp27 macOS and Linux wheels call `os.popen` in
`cpu_count()`, which the py39 wheel Garnet read doesn't; pyproj 3.4.0's cp311 Windows wheel
calls `ctypes.WinDLL` in the loader delvewheel adds for bundled DLLs, which 3.3.1's Windows
wheels didn't have.

**GRN-C010 (1).** notebook-shim 0.2.2's wheel adds a Jupyter server config file under
`etc/jupyter/jupyter_server_config.d/` that turns the extension on.

## Compared with the top-100 run

Within this run, the top 100 packages give 22 of 974 updates (2.3%) and the next 900 give
278 of 8,465 (3.3%). The [top-100 run](../corpus-results/REPORT.md) on main reported 12 of
974 (1.2%), on versions picked three weeks earlier. Most of the difference is the
rule-testing branches: GRN-C003 now follows import-time code through the package's own
modules (lazy imports and code generation in anyio 4.15.0, charset-normalizer 3.4.6, scipy
1.17.0 and 1.18.0), and GRN-C002 reads all of setup.py (multidict 7.1.0 added a build-time
subprocess call). 2 of the 22 warn only through rules added since the first top-1,000 run
(GRN-T006 on cffi 1.14.5 and iniconfig 1.1.1).

## Limits

- Tags are checked as they exist today, not as they stood on the release day.
- GRN-C003 reads code; it reports what a module calls at import, not whether a branch
  around the call runs on the reader's platform or Python version.
- 111 updates of 16 very large packages (CUDA libraries, torch, triton, xgboost, pyspark)
  weren't fully content-checked, because a file exceeds the download cap. Each says so in a
  GRN-E001 finding.
- The corpus takes each package's last 11 releases, so a package that releases weekly
  contributes a few months of updates and one that releases yearly contributes a decade.
- Run in the cloud container: pypi.org, files.pythonhosted.org and github.com git refs are
  reachable, api.osv.dev is not (the run doesn't need it). The `17b8cd1` run took about
  4 hours from an empty cache, with 4 worker processes and the npm run sharing the machine;
  the #96 run fetched its 391 releases again in under 10 minutes. Two passes gave the same
  result.
