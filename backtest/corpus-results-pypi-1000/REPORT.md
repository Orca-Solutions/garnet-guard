# PyPI clean-corpus backtest, top 1,000 packages, 2026-10-30

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

The run used main (`255946a`) with the rule-testing branches stacked on it, up to
`claude/project-thread-sm89m3-claims` at `1063252` (PRs #32, #33, #34, #36 and #38), and
this PR's commits: the rules as they are about to ship. On this PR alone the content-rule
numbers would differ; the trust rules would not. The full run was on `935d188`; `1063252`
changes how GRN-C003 grades and attributes the call sites it finds, not which sites exist,
so the 105 updates with any GRN-C003 finding were re-run on it from fresh facts, and
nothing else could change.

## Result

**221 of 9,439 updates were flagged for a look (2.3%), in 173 packages. Each of the 221
was checked on its own against PyPI, GitHub and the release files, and none made a false
claim.**

| Rule | Updates | Packages |
|---|---|---|
| GRN-C003 new-import-time-exec | 66 | 53 |
| GRN-C002 new-build-hook | 57 | 51 |
| GRN-T004 no-matching-tag | 49 | 39 |
| GRN-T001 lost-provenance | 18 | 18 |
| GRN-T003 workflow-changed | 16 | 14 |
| GRN-T002 publisher-changed | 14 | 13 |
| GRN-C001 new-pth-file | 3 | 3 |

Two updates carry two rules, so the rows add up to 223.

"None made a false claim" means every finding states something true about the release.
It does not mean no warning was a false alarm: none of these 9,439 updates is known to be
malicious, so from a user's point of view every one of the 221 is a false alarm, a true
observation about a legitimate release that a reviewer has to look at and dismiss.

44 more GRN-C003 findings were reported at info, not warn: 25 where a function is only
handed to another call that isn't known to run it (`functools.partial`, `map`, a wrapper),
17 in test files nothing else imports, and 2 in sdist files outside the package (`docs/`,
`demo/`).

291 updates (3.1%) carry a couldn't-check finding (GRN-E), which names what wasn't
checked. Some carry more than one kind:

| Why | Updates | Packages |
|---|---|---|
| An sdist contains a link, which `safe_archive.py` refuses (GRN-E002) | 117 | 15 |
| A file is larger than the download cap (GRN-E001): CUDA libraries, torch, triton, xgboost, pyspark | 107 | 15 |
| github.com answers HTTP 401 for the tags of a repository that is private, renamed or gone (GRN-E001) | 34 | 8 |
| Python 2 files that don't parse as Python 3 (GRN-E002) | 23 | 14 |
| A file over the parser's size limit (GRN-E003): kubernetes, av, pillow, pymssql | 11 | 4 |
| A duplicate entry in an sdist (GRN-E002) | 3 | 2 |

## What the first pass got wrong

The same corpus first ran on main plus the rule-testing branches up to PR #34 (`-reach`):
242 updates warned. 22 of them rested on a false claim (9 GRN-T004, 13
GRN-C003), and 4 more were true but are now reported at info.

- **GRN-T004 said 9 releases had no tag, and they did.** explosion's packages tag
  `release-v1.0.0` (confection 1.0.0, cymem 2.0.10, murmurhash 1.0.11, preshed 3.0.10,
  srsly 2.5.0, thinc 9.1.0, weasel 0.4.2), langgraph tags `prebuilt==1.0.11`
  (langgraph-prebuilt) and the Azure SDK tags `azure-mgmt-core_1.1.0`. GRN-T004 now reads
  `X` or `vX` after a prefix that names the package or says `release`, joined by `-`, `_`,
  `==` or `/` ([GRN-T004](../../docs/rules/GRN-T004.md)). One true warning appeared with
  it: ordered-set tags `release/3.1` and has no tag for 3.1.1.
- **GRN-C003 made 13 false claims**, in four kinds, fixed on the rule-testing branch:
  - A local name read as a module: curl-cffi 0.15.0's list named `requests`
    (`requests.append`), oscrypto 0.17.3's `socket` argument beside `import socket as
    socket_`. A dotted name now resolves only when its head is an imported module.
  - A module's own function read as the builtin: nltk 3.10.4's `def compile`.
  - "New module" for a file that was renamed (html5lib 0.99999999's `inputstream.py` to
    `_inputstream.py`) or that the trusted release had but Garnet couldn't parse
    (multiprocess 0.70.12.2's Python 2 wheel). The rename is now a move; the unparsed case
    still warns, since Garnet couldn't compare, but says why.
  - "Reached at import" for a function that is only handed to another call: huggingface-hub
    1.32.0, jaraco-context 5.2.0 (`_compose(pushd, tarball)`), joblib 1.6.0, litellm
    1.106.0, mock 4.0.0, modal 1.6.0 (`synchronize_api(...)`), partd 1.3.0
    (`partial(Encode, ...)`) and pydantic-ai-slim 2.54.0. These are now info and say
    "handed to X() at import", unless the call is one known to run it (`threading.Thread`,
    `atexit.register` and the like).
  - Two kinds of true finding moved to info for the same reason test files are: a chain that
    starts in a test file nothing imports (passlib 1.6, skops 0.8.0) and sdist files
    outside the package (flask-login 0.5.0's `docs/conf.py`, mpmath 1.2.1's `demo/`).

Three GRN-C003 warnings are new in the final run: triton 3.4.0 (its download timed out in
the first pass), and awscli 1.46.0 and mpmath 0.18, each of which added a copy of `six`,
whose module body runs `exec` through `six.exec_`.

## Triage

Every warning is listed with its check in [triage.json](triage.json).

**GRN-C003 (66).** Each evidence line was read back from the release files with `ast`: the
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
- 13 generate code with `exec`, `eval` or `compile`: typing-inspection, anyio's lazy-import
  map, patsy, scipy's and scikit-learn's vendored array-api-compat, and two new copies of
  `six` (awscli 1.46.0, mpmath 0.18).
- 5 use network APIs at import: altair builds a URL opener, google-genai builds `httpx`
  timeouts and limits, reportlab and weasyprint build URL fetchers, and twisted's test
  utilities create a socket to check for IPv6.
- 2 run a subprocess: scikit-image 0.25.0 runs `git log` to add the commit to its
  version string, and pymupdf 2.0's `get_tessdata()`, reached from pymupdf4llm's OCR
  module, runs one to find Tesseract's data.

Three need a word. multiprocess 0.70.12.2's trusted wheel is Python 2 code that doesn't
parse, so the calls can't be compared; the finding warns and its title says the trusted
copy couldn't be parsed, since Garnet doesn't treat "couldn't compare" as a pass. ply
3.6's calls are in `ply/lex.py` and `ply/yacc.py`, and the chains that reach them start in
the sdist's `test/` folder (`test/calclex.py`): the rule lowers chains from `tests/`
folders and `test_*.py` files to info, and `test/` is neither. In the six copies, the
cited line is the Python 2 definition of `exec_`; on Python 3 the module runs the builtin
`exec` through the same name a few lines later.

**GRN-C002 (57).** Both sdists were read for each: the cited setup.py line has the call
and the trusted setup.py doesn't, or the build backend in pyproject.toml changed as
stated. 33 add calls to setup.py that run when the sdist is built (`subprocess` 31 times,
`exec` 12, `__import__` 3, and a few others, counting evidence lines), 22 change the
build backend, and 2 do both. Of the 24 backend changes, 12 are to an in-tree backend, 5
to `flit.buildapi` and 3 to `poetry.masonry.api`. 7
compare against a trusted version that shipped no sdist, so every build-time call is new,
and the finding says so. reportlab 5.1.0's setup.py builds and installs a URL opener.

**GRN-T004 (49).** Each was checked with `git ls-remote --tags` against every repository
the finding names: no tag names the candidate version, in any form. 12 are releases from
before 2020; 19 are from 2025 or 2026, releases a maintainer didn't tag (s3fs 2026.6.0,
tiktoken 0.10.0, four swebench releases). Six are post-releases (`2.0.0.post1`,
`0.7.post0`, `3.0.0.1`) of a tagged release, which the rule counts as their own version.

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

**GRN-C001 (3).** amazon-ion 0.13.0, grpc-google-iam-v1 0.12.7 and zope-event 5.1 each
added a setuptools namespace-package `-nspkg.pth` file: one executable line that runs at
every Python startup. True, and the kind of file the rule is for.

## Compared with the top-100 run

Within this run, the top 100 packages give 20 of 974 updates (2.1%) and the next 900 give
201 of 8,465 (2.4%). The [top-100 run](../corpus-results/REPORT.md) on main reported 12 of
974 (1.2%), on versions picked three weeks earlier. Most of the difference is the
rule-testing branches: GRN-C003 now follows import-time code through the package's own
modules (lazy imports and code generation in anyio 4.15.0, charset-normalizer 3.4.6, scipy
1.17.0 and 1.18.0), and GRN-C002 reads all of setup.py (multidict 7.1.0 and pycparser 2.19
really added a build-time subprocess call).

## Limits

- Tags are checked as they exist today, not as they stood on the release day.
- GRN-C003 reads code; it reports what a module calls at import, not whether a branch
  around the call runs on the reader's platform or Python version.
- 107 updates of 15 very large packages (CUDA libraries, torch, triton, xgboost, pyspark)
  weren't content-checked, because their files exceed the download cap.
- The corpus takes each package's last 11 releases, so a package that releases weekly
  contributes a few months of updates and one that releases yearly contributes a decade.
- Run in the cloud container: pypi.org, files.pythonhosted.org and github.com git refs are
  reachable, api.osv.dev is not (the run doesn't need it). About 4 hours cold with 3
  worker processes sharing the machine with other runs. Downloads that timed out were
  retried from the fact cache until none was left.
