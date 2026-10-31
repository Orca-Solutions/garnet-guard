# Garnet Guard v1.0 specification

- Status: Draft
- Date: 2026-10-10
- Normative for: the 1.0 release. Releases before 1.0 (0.1 to 0.x) build toward it and may differ.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Where this spec and [ARCHITECTURE.md](../ARCHITECTURE.md) disagree, this spec wins.

## 1. Scope

Garnet 1.0 compares dependency changes between two lockfiles and reports, for each changed package, whether the new release shows a trust downgrade, a risky content change or a known-bad match.

**In 1.0:**

- Ecosystems: PyPI and npm.
- Surfaces: the CLI, the GitHub Action, the install wrapper, and pre-install hooks for Claude Code and Codex.
- The rules in §6, the policy format in §7, and the outputs in §9.

**Not in 1.0:** other ecosystems, non-GitHub source hosts for tag checks, GitLab/Bitbucket CI integrations, multi-release registry history (planned for v2, see [ROADMAP.md](../ROADMAP.md)), third-party check plugins as a stable interface, any hosted service.

## 2. Terms

| Term | Meaning |
|---|---|
| **Release** | One version of one package in one ecosystem, with all of its files. |
| **Artifact** | One file of a release (a wheel, an sdist, an npm tarball). |
| **Change** | One package whose resolved version differs between base and head lockfiles, or that was added or removed. |
| **Baseline** | The release a change is compared against (§5). |
| **Candidate** | The new release being judged. |
| **Facts** | Everything Garnet extracted about a release (§4.3). |
| **Finding** | One rule firing on one change, with evidence. |
| **Verdict** | `pass`, `warn` or `block` for a change, and for the whole report. |

## 3. Inputs

### 3.1 Lockfiles

Garnet MUST accept these formats and detect them by file name and content:

| Ecosystem | Format | Notes |
|---|---|---|
| PyPI | `uv.lock` | All packages with a registry source. |
| PyPI | `poetry.lock` | Lock format 2.x. |
| PyPI | `pylock.toml` (PEP 751) | `packages` entries with `index` or archive URLs on PyPI. |
| PyPI | `requirements*.txt` | Only lines pinned with `==`. Hashes are read when present. Unpinned lines produce an info finding GRN-E004 and are skipped. |
| npm | `package-lock.json` | lockfileVersion 2 and 3. |
| npm | `pnpm-lock.yaml` | lockfile v9. |
| npm | `yarn.lock` | Yarn classic v1 and Berry. |

Packages from git, local paths, direct URLs outside the registry, or private indexes are reported with GRN-E005 (not checked) and never silently passed.

### 3.2 Computing changes

Given a base and head lockfile of the same format, Garnet computes the set of changes as `(ecosystem, normalized name, base version or none, head version or none)`. Names MUST be normalized per ecosystem (PEP 503 for PyPI). A lockfile containing the same package at several versions (common in npm) is compared per `(name, version)` set: each head version not present in base is a candidate, compared against the highest base version below it, or the highest base version if none is lower.

Removed packages produce no findings. Added packages (no base version) get only the rules marked "absolute" in §6.

### 3.3 Invocation without two lockfiles

`garnet diff <package> <old> <new>` compares two releases directly. The install wrapper and hooks compute the head lockfile by resolving without installing (§10).

## 4. Fetching and facts

### 4.1 Sources

| Data | PyPI | npm |
|---|---|---|
| Release metadata and file hashes | JSON API (`/pypi/<name>/<version>/json`) | Registry packument |
| Provenance | Integrity API (`/integrity/<name>/<version>/<file>/provenance`), verified with Sigstore | Registry attestations endpoint, verified with Sigstore |
| Artifacts | Files listed by the JSON API | Tarball |
| Tags | GitHub's public git ref advertisement (`/<repo>.git/info/refs`) for the repository named in provenance, else in project URLs | Same |
| Source files at the tag (GRN-C007) | GitHub's git protocol v2 endpoint (`/<repo>.git/git-upload-pack`), one request per tagged release | Not read |
| Known bad | OSV API (`MAL-` advisories) | OSV API |
| Owners | `ownership` in the JSON API (roles and organization, as they are today) | `maintainers` of the version document |
| Other wheels of the release (GRN-C012) | Files listed by the JSON API: one wheel per other platform family and up to 30 wheels uploaded late | Not read |
| New dependencies (GRN-C008) | JSON API (`/pypi/<name>/json`): first upload, releases with files, project URLs, ownership; for a young dependency with a shared owner, the files and Requires-Python of each release GRN-C008 reads (§6.2), each wheel's file list and each file's Integrity API provenance | Packument: `time.created`, versions, repository of the latest version, maintainers; for a young dependency with a shared owner, each release GRN-C008 reads: attestations, tarball `package.json` and root `binding.gyp` |

### 4.2 Artifact selection

- **Trust rules** MUST evaluate every artifact of both releases.
- **Content rules** MUST evaluate the sdist (when present) and one wheel per release. The wheel is the one pip would install on the current machine: the wheel whose most specific tag ranks highest among the tags the running interpreter supports, so a platform wheel is chosen over a pure-Python (`py3-none-any`) one; when no wheel is compatible, the wheel for the current machine's platform family (Linux, macOS, Windows) if there is one, built for the newest CPython, then for x86-64, then the first in sorted file-name order. (Until 2026-10-30 a pure-Python wheel was always chosen first, which let a platform wheel added beside it go unread. Until 2026-10-31 an incompatible release was read through its first wheel by file name, which could be a Python 2 build of one release and a Python 3 build of the next.) The same selection rule MUST apply to baseline and candidate. If the selected wheel tags differ between releases, Garnet MUST note it in the evidence. Content rules compare the two wheels when both releases have one, else the two sdists, else whatever each release has. When the candidate is the first to ship a wheel beside its sdist, content rules MUST compare each of the two with the baseline's sdist (pip installs the wheel where it fits and builds the sdist elsewhere) and report a finding the two comparisons share once. An sdist's `src/` folder is not part of a file's installed path. A comparison across kinds MUST be noted in the evidence.
- **GRN-C012** additionally downloads, from each release, one wheel for each platform family other than the selected wheel's (Windows, macOS, Linux, `any`, and the first part of any other platform tag), taking within a family the newest CPython build, then x86-64, then the first file name; and every wheel uploaded more than 24 hours after the release's first file, up to 30 in file-name order. Late wheels past the 30th are not compared: that is GRN-E003 naming GRN-C012, which MUST list them (§6.2). These wheels are read only for GRN-C012.
- Every downloaded artifact MUST match the registry's published SHA-256 before it is inspected. A mismatch is finding GRN-T008 (block).

### 4.3 Facts

For each release Garnet extracts: upload time per file; uploader where the registry exposes it; yanked/deprecated status; per-file provenance (present, verified, Sigstore identity, source repository, workflow path, ref, environment, Trusted Publishing or not); the matching tag and its commit if any; file inventory (path, size, SHA-256, kind); declared dependencies that install without an extra (`Requires-Dist` from the wheel's `METADATA`, or from an sdist's `PKG-INFO` at metadata version 2.2 or later when `Requires-Dist` isn't `Dynamic`; for npm, `dependencies`, `optionalDependencies` and non-optional `peerDependencies`), with any npm alias or source outside the registry; `.pth` files; entry points and console scripts (for a wheel, the group, name and target of every line of the `entry_points.txt` in each `.dist-info` or `.egg-info` folder at its root or under `<name>.data/purelib/` or `platlib/`; for an sdist, the modules named by `pyproject.toml`'s `[project]` `scripts`, `gui-scripts` and `entry-points`); build backend and build requirements; for npm, `scripts` and `bin`, and the process, network and eval uses in the JavaScript its entry points load; and a static index of each Python module's top-level statements, imports and sensitive calls.

Facts are a pure function of the release's published data and MUST be cacheable by `(ecosystem, name, version, file hashes)`. Owners on PyPI and the registry profiles of new dependencies describe the registry on the day Garnet runs; they are fetched per run and are not part of that cache key.

### 4.4 Safety requirements

Garnet MUST NOT import, execute, build or install any inspected content. Archive reading MUST reject absolute paths, `..` segments, symlinks, hard links and device entries, and MUST enforce these default limits (configurable down, not up, in policy):

| Limit | Default |
|---|---|
| Compressed artifact size | 200 MB |
| Total uncompressed size | 1 GB |
| Entries per archive | 100,000 |
| Compression ratio per entry | 100:1 |
| Single Python file parsed with `ast` | 5 MB |
| Single JavaScript file an npm package loads, scanned for GRN-C011 | 16 MB |
| Wall-clock budget per change | 120 s |

Exceeding a limit yields GRN-E003 for that change.

## 5. Baseline selection

1. The baseline for a change is its base-lockfile version.
2. If the candidate skips published versions (for example 2.6.1 → 2.6.4), trust rules MUST also run on every intermediate release that is not yanked, each against its predecessor, and findings MUST name the intermediate version. Content rules run only baseline → candidate.
3. A yanked baseline is still used, with an info note in the evidence.
4. An added package has no baseline.

## 6. Rules

### 6.1 Diff semantics

Most rules are **diff rules**: they fire only when the baseline had a property and the candidate lost it, or the candidate gained a risky property the baseline lacked. A project that never used Trusted Publishing is not penalized for not using it. **Absolute** rules fire regardless of the baseline.

### 6.2 Rule catalog

Default severities are what applies with no policy file.

| ID | Name | Kind | Fires when | Default |
|---|---|---|---|---|
| GRN-T001 | lost-provenance | diff | Every baseline artifact had a verified attestation and at least one candidate artifact has none. | warn |
| GRN-T002 | publisher-changed | diff | The verified source repository differs between baseline and candidate attestations. Repository renames that GitHub redirects MUST NOT fire. | warn |
| GRN-T003 | workflow-changed | diff | Same repository, but the workflow file path or deployment environment differs. | warn |
| GRN-T004 | no-matching-tag | diff | The baseline version had a matching git tag in the source repository and the candidate does not. Tag matching accepts `X` or `vX`, alone or after a prefix that names the package or is `release`, joined by `-`, `_`, `==` or `/`, and `@` for npm. A `/` or `==` prefix may use the end of the name, as monorepos tag by folder, when no tag uses the full name. | warn |
| GRN-T005 | outside-trusted-publishing | diff | Baseline files were published via Trusted Publishing and at least one candidate file was not. | warn |
| GRN-T006 | files-uploaded-late | absolute | A candidate file was uploaded more than 24 hours after the release's first file. `info` when no late wheel is the release's first wheel or ranks at or above an on-time wheel, in pip's order, on a machine built from the release's wheel tags. | warn |
| GRN-T007 | invalid-attestation | absolute | An attestation is present but fails verification. | block |
| GRN-T008 | hash-mismatch | absolute | A downloaded artifact doesn't match its published hash. | block |
| GRN-C001 | new-pth-file | diff | The candidate contains a `.pth` file at a path the baseline did not have, or an existing `.pth` file gained executable lines (lines starting with `import`). | warn |
| GRN-C002 | new-build-hook | diff | A new or changed `setup.py` adds calls in the §6.3 sensitive set; the build backend changed to a non-allowlisted backend or an in-tree backend; or an npm `preinstall`/`install`/`postinstall` script was added or changed. (`prepare` was dropped on 2026-10-29: npm doesn't run it for a published tarball, and every `prepare` change in the top-200 backtest was a build-tool switch.) | warn |
| GRN-C003 | new-import-time-exec | diff | A module's top level (including code reached from `__init__.py` at import) gains a call in the §6.3 sensitive set. It reports at info, as a separate finding, in three cases: in test files (`tests/`, a top-level `test/`, `test_*.py`, `conftest.py`) or reached only from one, unless a non-test module imports the file (directly or through other test modules) or an entry point names it; in sdist files outside the package (`docs/conf.py`, `examples/`) or reached only from one; and for a function import-time code only hands to a call not known to run it (`functools.partial(f)`). A call a package module reaches at import is reported once, at warn. New reads at import of an environment variable that holds a credential or says the code runs in CI, of the whole environment, or of a cloud metadata address are reported in a separate finding at info (docs/rules/GRN-C003.md). | warn (info in test files and the other two cases) |
| GRN-C004 | new-binary | diff | Files are classified by their extension and their first bytes: ELF, Mach-O and PE (an `MZ` header that names a `PE` header) are native code whatever the file is called. Paths are compared by where they install (the `<name>-<version>.data/<scheme>/` folder without its name and version, `<name>.libs/` with its name normalized). Warn: a native file whose last extension isn't a native one (`.so`, `.pyd`, `.dylib`, `.dll`, `.exe`, GPU code objects such as `.cubin` and `.hsaco`, `.node` and the like; a version at the end doesn't count: each last part that starts with a digit and is all digits, follows a part that is, is digits with an `a`, `b`, `rc`, `t`, `post` or `dev` suffix and optional digits after it, or holds a character that isn't a letter or digit (`so.3`, `so.1.0.2k`, `3.13t`, `2.0rc1`, `25.1-linux-x86_64`), while `.7z` and `.3gp` after a name are extensions; and `.debug` or `.dbg` after a native extension is native), new or changed; a native file when the baseline shipped none, new or at a path where the baseline's file wasn't native; a `.pyc` named `name.pyc` with no other dot, in `__pycache__` or out of it, when no file that every Python the wheel installs on tries first for that module is beside it, and the `.pyc` is new or the baseline had `name.py`. The path finder tries, in order, `name/__init__` plus `.py`, `.pyc` or an extension suffix, then `name` plus an extension suffix, then `name.py` (and `name.pyw` in a Windows wheel); no other name counts, matched case for case. An extension suffix counts only when every tag of the wheel has it. A tag on a Linux or macOS platform has `.so`, and `.abi3.so` when its ABI is `abi3` or a `cp3NN` one without `t` (free-threaded); one on Windows has `.pyd`. A tag whose ABI is `cp3NN` plus any flags `<f>` (`t`, `d`, `m`) also has `.cpython-3NN<f>-<triplet>.so` on a manylinux platform, with the triplet as CPython spells it (`x86_64-linux-gnu`; `i386-linux-gnu` for `i686`, `arm-linux-gnueabihf` for `armv7l`, `powerpc64le-linux-gnu` for `ppc64le`), `.cpython-3NN<f>-darwin.so` on macOS, and `.cp3NN-<platform>.pyd`, with `t` after `3NN` when free-threaded, on Windows. A tag for `any` (a pure-Python wheel, and an sdist) or another platform has none, and a musllinux one no tagged suffix; a new or changed `.pyc` in `__pycache__` whose PEP 552 flags say hash-based, checked or not, beside its source (magic numbers from Python 3.7 on; before that the flags word was a timestamp). Info: a new native file other than an extension module (`name.<tag>.so`, `name[.tag].pyd`) in a folder that held none, when the baseline shipped native code. When the baseline's artifact can't show what native code it shipped (a pure-Python wheel compared with a compiled one while the baseline release had compiled wheels, a wheel for another operating system, or a different kind of artifact), only the name and bytecode cases apply. PyPI only. | warn (info for the folder case) |
| GRN-C005 | obfuscated-blob | diff | A changed file gains a string or bytes literal over 2,048 characters with Shannon entropy over 4.5 bits per character, or any such literal passed to `exec`, `eval`, `compile`, `base64.*decode`, `zlib.decompress` or `marshal.loads`. | warn |
| GRN-C006 | sdist-wheel-mismatch | diff | The selected wheel contains a `.py` or `.pth` file with no counterpart in the sdist, when the baseline had none. | warn |
| GRN-C007 | code-not-in-source | diff | A Python file in the candidate's wheel (the sdist when there is no wheel) is not byte-identical to any file in the repository at the candidate's matched git tag (submodules hosted on GitHub included; CRLF line endings read as LF), and it has a §6.3 sensitive call that the file at the same path lacks (every sensitive call counts when there is no file at that path). A top-level package with no directory of its name at the tag is compared with the directory most of its files are under, when that holds at least half of them. When more than one tag names the version and the first leaves a sensitive call unexplained, the tag whose tree matches the most files is used. Calls the baseline already carried outside its source at the same path don't count. Files under a submodule Garnet can't read are reported as GRN-E001. | warn |
| GRN-C008 | new-dependency | diff | The candidate declares a dependency the baseline didn't, or a dependency the baseline had now installs from outside the registry or (npm) installs a different package under the same name. It keeps the default severity when the dependency is not on the registry, installs from outside it, is declared a second time to install another registry package (npm alias), a URL, a repository or a path (also for a dependency the baseline had, when that second declaration is new; what it installs is not looked up), or was first released less than 90 days before the candidate's first upload (or after it); otherwise it reports at info. An owner it shares with the baseline is listed in the evidence. A young dependency with an owner it shares with the baseline, declared once (a `Requires-Dist` line that needs an extra counts as a second declaration) and without an environment marker, not in npm `bundleDependencies`/`bundledDependencies` (or either `true`), and with no other requirement of the candidate installing the same registry package (an npm alias target, compared lowercased), reports at info only when every release Garnet reads has no install-time hook and every file of each has verified provenance from a repository, or github.com repository id, that the baseline's verified provenance names. Those releases are the versions pinned without an environment marker in every head lockfile the change comes from (`garnet check`), else every version the registry lists that matches the candidate's range, whenever published, up to the lookup (npm by node-semver rules, and every version, prereleases included, for `*`, `x`, an empty range or `latest`, which install the `latest` dist-tag; PyPI by the requirement's specifier over every version with a file, prereleases and yanked releases included), at most 5. Garnet doesn't model which of them an installer picks. A change from a requirements file with `--extra-index-url`, `--find-links`/`-f`, `--no-index` or a non-PyPI `--index-url`/`-i` anywhere in it reads nothing and keeps the default severity. An install-time hook is, on npm, a `preinstall`, `install` or `postinstall` script in the tarball's or the registry's `package.json`, or a root `binding.gyp` in any case unless `gypfile` is `false`, and a tarball whose entries don't share one top-level folder is not read; on PyPI, a release without a `py3-none-any` wheel, a Requires-Python that leaves out a supported CPython (3.11 to 3.15, tested at every patch level 0 to 50), or a wheel that installs a `.pth` file at the top of site-packages or anything whose first path part there, up to the first dot and in any case, is `sitecustomize` or `usercustomize` (module, package, `.pyc`, extension module), also under `<name>.data/purelib/` and `platlib/`, or any of those anywhere under `<name>.data/data/`. A baseline without verified provenance, more releases than the cap, a lookup or response that failed, provenance that couldn't be verified or a release that couldn't be read keeps the default severity, and the evidence MUST say which condition decided. On npm the first release is `time.created`; versions in `time` that are older and no longer in `versions` MUST be named in the evidence, which then calls the date the earliest version still published. A failed registry lookup is GRN-E001 naming GRN-C008. | warn (info for an established dependency) |
| GRN-C009 | new-entry-point | diff | The candidate's wheel lists a target for an entry point (a group and a name) that the baseline's wheel didn't list for it, or a line runs that didn't: for a `console_scripts` or `gui_scripts` name, a change in the last line in the wheel's own `*.dist-info/entry_points.txt`, which installers make the command from; for a group whose tool loads every line (`setuptools.*`, `distutils.setup_keywords`, `egg_info.writers`, `flake8.extension`, `flake8.report`, `keyring.backends`, `pydantic`, `pdm`, `poetry.plugin`, `poetry.application.plugin`, `virtualenv.*`, `opentelemetry_instrumentor`, `opentelemetry_pre_instrument`, `opentelemetry_post_instrument`), never, as each line already ran, nor for `pygments.lexers`, which pygments matches by the class a line loads rather than the line's name; for any other group, a target that is the first line of an `entry_points.txt` in the candidate and of none in the baseline (pluggy, which pytest, tox and hatch use, registers a name from the first line it reads, and a lookup by name, such as pygments' for a style, filter or formatter, returns the first that matches), with the evidence saying the line runs if its folder is read first when more than one folder lists the name. Lines removed, repeated or reordered with no such change are not reported. Entry points are read from every `entry_points.txt`, its name matched ignoring case, in a folder at the wheel's root or under `<name>.data/purelib/` or `platlib/` (which install at the top of site-packages) whose name ends in `.dist-info` or `.egg-info`, ignoring case, with `importlib.metadata`'s grammar: lines are stripped, a blank line or one starting with `#` is skipped, a line starting with `[` and ending with `]` names the group with the brackets stripped (and then whitespace), lines before the first group and lines without `=` are skipped, and any other line is a name (which may be empty) and a target split at the first `=`. Every line is kept, a repeated name too. It keeps the default severity for groups another tool loads by itself (`pytest11`, `setuptools.*`, `distutils.*`, `egg_info.writers`, `flake8.extension`, `flake8.report`, `keyring.backends`, `pygments.*`, `virtualenv.*`, `opentelemetry_*`, `pydantic`, `tox`, `hatch`, `pdm`, `poetry.plugin`, `poetry.application.plugin`) and for a `console_scripts` or `gui_scripts` name that the candidate's own `*.dist-info/entry_points.txt` declares and the baseline's own file didn't and that, ignoring case, is one of the common commands GRN-C010 uses (listed on the rule page), unless it is the package's own normalized name; otherwise, including a script whose target changed, it reports at info. The evidence lists the entry points that keep the default severity first and counts those past the evidence limit; each entry point's line names at most its first two targets, its last and its first new one, and is clipped to 1,000 characters. Wheels only, each read to the end: a wheel whose reading stopped is not compared, and its GRN-E002 or GRN-E003 names GRN-C009. | warn (info outside those groups and command names) |
| GRN-C010 | new-startup-file | diff | The candidate's wheel adds, at a path the baseline's wheel did not have: `sitecustomize.py` or `usercustomize.py` at the top of site-packages (after stripping `<name>.data/purelib/` or `platlib/`), a file under `<name>.data/scripts/`, or a file under `<name>.data/data/`. Reported at info, except for the two startup modules, a script whose name, ignoring case and a `.exe`, `.cmd`, `.bat` or `.com` suffix, is a common command, and a data file under `etc/`. Wheels only. | warn |
| GRN-C011 | new-js-capability | diff | npm only. In the JavaScript files the candidate's `package.json` names as entry points (`main`, defaulting to `index.js`; `module`; `browser`; `bin`; every `exports` target) and the files they load through relative `require`, `import`, `import()` or `export … from`, the candidate uses a name the baseline's loaded files didn't: one of the modules `child_process`, `cluster`, `worker_threads`, `net`, `dgram`, `dns`, `http`, `http2`, `https`, `tls`, `vm` (with or without `node:`), a call to `eval`, `Function` or `fetch`, `XMLHttpRequest` or `WebSocket`, or 20 or more `_0x`-hex names in one file. Comments, strings, template text and regular expressions are skipped; nothing is run. Each use records whether it runs when the file loads (outside any function body not called where it is defined). A loaded file over the §4.4 JavaScript limit is GRN-E003. | info |
| GRN-C012 | wheels-differ | diff | A wheel §4.2 selects for GRN-C012 has a `.py` file that is not byte-identical to the file at the same install path in the content rules' wheel, or that wheel has no such file, and it has a §6.3 sensitive call anywhere in the file that the content rules' copy lacks. Calls into the release's own top-level packages, as the content rules' wheel names them, are not sensitive; a standard-library module name, a builtin name, and the first name of a §6.3 entry (such as `requests`) are never among them. Calls that any baseline wheel of the same platform family made at the same path don't count: the baseline's content-rules wheel, each wheel GRN-C012 compared, and a file such a wheel shared byte for byte with the content-rules wheel. When the baseline had no wheel of that family, the evidence MUST say so; when Garnet couldn't read the baseline's files, it MUST say that, not that the baseline had no such wheel. When the content rules' copy of a file doesn't parse, every call in the other wheel's copy counts and the evidence says the read copy couldn't be parsed; when Garnet read the baseline's wheel of that family and its copy parsed, the evidence says that wheel didn't make the call. Such a line reports at info only when the baseline gives no such comparison and GRN-E002 reports the content rules' copy as new or changed. A compared wheel that can't be downloaded, or is over the §4.4 download size, is GRN-E001; one that can't be opened is GRN-E002; one past another §4.4 limit while it is read is GRN-E003. A `.py` file in it that would be parsed and doesn't parse is GRN-E002 naming GRN-C012, one finding per wheel, unless a baseline wheel of the same platform family had the same bytes at that install path; when Garnet has no such baseline copy to compare with (no baseline, baseline files Garnet couldn't read, no baseline wheel of that family, or one Garnet didn't read), the evidence MUST say so. One over the §4.4 parse limit is GRN-E003 naming GRN-C012. Late wheels past the 30th (§4.2) are GRN-E003 naming GRN-C012, with the wheels listed in file-name order, at most 25 and a count of the rest. When the content rules' wheel can't be downloaded or read to the end, nothing is compared, and its GRN-E001, GRN-E002 or GRN-E003 names GRN-C012. | warn (info when GRN-E002 already warns for the read copy and nothing else could be compared) |
| GRN-K001 | known-malicious | absolute | OSV lists a `MAL-` advisory affecting the candidate version. | block |
| GRN-E001 | fetch-failed | absolute | Data needed for a rule couldn't be fetched. The finding names which rules were not evaluated. | warn |
| GRN-E002 | parse-failed | absolute | An artifact or file couldn't be parsed. | warn |
| GRN-E003 | budget-exceeded | absolute | A §4.4 limit was hit, or a release has more late wheels than GRN-C012 compares (§4.2). | warn |
| GRN-E004 | unpinned-requirement | absolute | A requirements line isn't pinned. | info |
| GRN-E005 | unsupported-source | absolute | A dependency comes from a source Garnet doesn't check. | info |

Rule IDs are permanent. A rule may change default severity only in a minor release with a changelog entry, and never from warn to block outside a major release.

### 6.3 Sensitive call set

For GRN-C002, GRN-C003, GRN-C007 and GRN-C012, a call is sensitive if it resolves (through imports and simple aliasing, without executing code) to any of: `exec`, `eval`, `compile`, `__import__`, `importlib.__import__`, `importlib.import_module` with a non-literal argument, `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `os.posix_spawn*`, `os.fork`, `os.forkpty`, `os.startfile`, `subprocess.*` (except `subprocess.CalledProcessError`, `CompletedProcess`, `SubprocessError`, `TimeoutExpired` and `list2cmdline`, which build a value and start nothing), `_posixsubprocess.*`, `asyncio.create_subprocess_exec`, `asyncio.create_subprocess_shell`, `multiprocessing.Process`, `multiprocessing.context.SpawnProcess`, `multiprocessing.context.ForkProcess`, `multiprocessing.context.ForkServerProcess`, `_winapi.CreateProcess`, `distutils.spawn.spawn`, `distutils.util.spawn`, `distutils.ccompiler.spawn`, `distutils.archive_util.spawn`, `pydoc.pipepager`, `pydoc.tempfilepager`, `pty.spawn`, `pty.fork`, `runpy.*`, `zipimport.*`, `importlib.util.spec_from_file_location`, `importlib.util.spec_from_loader`, `importlib.machinery.SourceFileLoader*`, `importlib.machinery.SourcelessFileLoader*`, `importlib.machinery.ExtensionFileLoader*`, `imp.load_source`, `imp.load_compiled`, `imp.load_dynamic`, `imp.load_module`, `imp.load_package`, `types.FunctionType`, `types.LambdaType`, `types.CodeType`, `ctypes.*`, `socket.*`, `asyncio.open_connection`, `asyncio.open_unix_connection`, `asyncio.start_server`, `asyncio.start_unix_server`, `ssl.create_connection`, `ssl.socket`, `urllib.request.*`, `http.client.*`, `httpx.*`, `requests.*`, `aiohttp.*`, `urllib3.PoolManager`, `urllib3.ProxyManager`, `urllib3.HTTPConnectionPool`, `urllib3.HTTPSConnectionPool`, `urllib3.connection_from_url`, `urllib3.proxy_from_url`, `urllib3.request`, `urllib3.connection.HTTPConnection`, `urllib3.connection.HTTPSConnection`, `urllib3.connection.VerifiedHTTPSConnection`, `urllib3.contrib.socks.SOCKSProxyManager`, `ftplib.*`, `smtplib.*`, `poplib.*`, `imaplib.*`, `telnetlib.*`, `xmlrpc.client.*`, `webbrowser.*`, `base64.*decode` followed by any of the above, `marshal.loads`, `pickle.loads`. A name under a module that holds the same object as a listed name, because it defines it or imports it, counts as the listed name, and is reported as written: `builtins.<name>` as the bare `<name>` (and `__builtins__.<name>`, the same module in a script), `posix.<name>` and `nt.<name>` as `os.<name>`, `_socket.<name>` as `socket.<name>`, `_ctypes.<name>` as `ctypes.<name>`, `_pickle.<name>` as `pickle.<name>`, `asyncio.subprocess.<name>` and `asyncio.streams.<name>` as `asyncio.<name>`, `multiprocessing.context.<name>` as `multiprocessing.<name>`, `importlib._bootstrap.<name>` and `_frozen_importlib.<name>` as `importlib.<name>` or `importlib.util.<name>`, `importlib._bootstrap_external.<name>` and `_frozen_importlib_external.<name>` as `importlib.util.<name>` or `importlib.machinery.<name>`, `setuptools._distutils.<name>` as `distutils.<name>`, `urllib3.poolmanager.<name>` as `urllib3.<name>`, and `urllib3.connectionpool.<name>` as `urllib3.<name>` or `urllib3.connection.<name>`. For GRN-C003 and GRN-C007, a call under one of the release's own top-level packages is not sensitive when the release is the PyPI project of that name (`requests`, `httpx`, `aiohttp`, `urllib3` or `setuptools`, read from the artifact's filename): the `requests` project calling its own `requests.adapters`. Otherwise a top-level module or package that a release ships under a name in this list, such as an `os.py`, `requests.py` or `builtins.py` beside its own package, doesn't change what a call to that name counts as. The list is versioned with the rule (set `2026-10-c` today) and MUST be shown by `garnet explain`.

### 6.4 Findings

Each finding MUST carry: `rule_id`, `name`, `severity` (after policy), `default_severity`, `ecosystem`, `package`, `baseline`, `candidate`, `title` (one line), `evidence` (a list, each with `kind` of `file`, `attestation`, `tag`, `advisory`, `url` or `note`, plus kind-specific fields such as `path`, `line`, `sha256`, `identity`), `explanation`, `remediation`, and `suppressed_by` when an ignore applied.

Findings MUST be deterministic: the same inputs and cache produce byte-identical JSON output.

## 7. Policy

### 7.1 Location

Garnet reads, in order, the first that exists: `--policy <path>`, `garnet.toml` in the working directory, `[tool.garnet]` in `pyproject.toml`. With none, defaults apply.

### 7.2 Format

```toml
[garnet]
version = 1                 # required when a policy file exists
default = "warn"            # optional cap for rules at default "warn": "info" | "warn" | "block"
fail_on = "block"           # "warn" | "block" | "never"

[garnet.rules]
"GRN-T001" = "block"        # "off" | "info" | "warn" | "block"
"GRN-C004" = "off"

[[garnet.ignore]]
ecosystem = "pypi"          # optional
package = "numpy"
versions = ">=2.0"          # optional, ecosystem version specifier
rules = ["GRN-C004"]
reason = "ships compiled wheels"   # required
until = "2027-06-30"        # required; ISO date

[garnet.limits]             # may only lower §4.4 defaults
budget_seconds = 60
```

- Unknown keys MUST produce an error, not be ignored.
- An ignore past its `until` date MUST stop applying and produce an info note that it expired.
- An ignore whose `until` is more than 12 months after the day the policy is read MUST be refused as invalid (exit code 3), naming the latest date accepted.
- An ignore MUST NOT suppress GRN-T007, GRN-T008 or GRN-K001 unless it also sets `acknowledge_critical = true`.
- Suppressed findings still appear in JSON and SARIF output with `suppressed_by`.

## 8. Verdicts and exit codes

A change's verdict is the highest unsuppressed severity among its findings (`info` counts as pass). The report verdict is the highest change verdict.

| Exit code | Meaning |
|---|---|
| 0 | Verdict below `fail_on`. |
| 1 | Verdict is `warn` and `fail_on = "warn"`. |
| 2 | Verdict is `block` and `fail_on` is `warn` or `block`. |
| 3 | Garnet itself failed (bad arguments, invalid policy, internal error). |

## 9. Outputs

### 9.1 Text

Human-readable, grouped by change, worst first. Colors only on a TTY. All package-supplied strings MUST be escaped of control characters.

### 9.2 JSON

```json
{
  "schema": "https://garnetguard.dev/schema/report/v1.json",
  "garnet_version": "1.0.0",
  "verdict": "warn",
  "policy": {"source": "garnet.toml", "sha256": "…"},
  "policy_changes": [{"path": "garnet.toml", "changes": ["loosens: new ignore: examplelib GRN-C003 until 2027-06-30, reason: …"]}],
  "changes": [
    {
      "ecosystem": "pypi",
      "package": "examplelib",
      "baseline": "2.6.1",
      "candidate": "2.6.2",
      "verdict": "warn",
      "findings": [ { "rule_id": "GRN-T001", "...": "…" } ],
      "notes": ["2.6.1 has no attestation and no git tag in github.com/example/examplelib, so GRN-T001 to GRN-T005, which compare how releases were published, had nothing to compare with"]
    }
  ]
}
```

`policy_changes` is present only with `garnet check --git-base REF --policy-change PATH`, when the policy file at `PATH` differs from the one at `REF`: one entry per file, each change a line, those that loosen the policy (a new or extended ignore, a rule lowered or turned off, `fail_on` raised, a limit raised, the file deleted) first and prefixed `loosens:`. It never changes the verdict; the policy that applied is the one in `policy`.

`notes` is present only when there is something to say about what the checks could compare. Today that is one case: the baseline has no attestation and no git tag (Garnet looked and found neither), so GRN-T001 to GRN-T005 had nothing to compare with. A note never changes a verdict; the text report prints it after the change's findings and the PR comment shows it in the change's row.

The schema is published with each release. Within 1.x, fields may be added but not removed or retyped. (The URL names the schema; garnetguard.dev doesn't serve the file yet.)

### 9.3 SARIF

SARIF 2.1.0. One `run`, tool name `Garnet Guard` (GitHub shows it as the check run name and on inline alerts), one `rule` per rule ID. Results are located on the lockfile line that pins the candidate version. Severity maps `block` → `error`, `warn` → `warning`, `info` → `note`. Suppressed findings carry a SARIF `suppressions` entry.

### 9.4 PR comment

Markdown with a hidden marker (`<!-- garnet:report -->`) so the Action updates one comment instead of posting new ones. It lists changes with a non-pass verdict first, each with its findings and a link to `garnet explain` docs, then a collapsed list of passing changes. All package-supplied strings MUST be escaped for markdown and MUST NOT create links or mentions. The comment MUST stay under GitHub's 65,536-character limit, truncating passing changes first. It ends with a one-line footer linking to Garnet's docs and to each cited rule's page; the footer links only to documentation, never to anything paid, and the Action input `footer: false` removes it. The footer is on by default (accepted 2026-10-10). When the report has `policy_changes`, the comment MUST open with a callout listing them, so a policy edited beside a dependency bump is visible to the reviewer.

## 10. Surfaces

### 10.1 CLI

```text
garnet check  [--base PATH] [--head PATH] [--git-base REF] [--format text|json|sarif|markdown]
              [--output PATH] [--policy PATH] [--fail-on warn|block|never]
              [--offline] [--cache-dir PATH] [--github-token-env NAME]
garnet diff   <ecosystem>:<package> <old> <new> [same output flags]
garnet explain <RULE-ID>
garnet policy check [PATH]
garnet cache  info|clear
garnet pip install …   |  garnet uv add|sync|lock …   |  garnet npm install …
garnet hook   claude-code|codex
garnet version
```

- `--git-base REF` reads the base lockfile from a git ref, so `garnet check --git-base origin/main` works in any CI.
- `--offline` uses only the cache and reports GRN-E001 for anything missing.
- Tokens are read from the environment variable named by `--github-token-env` (default `GITHUB_TOKEN`). Tokens MUST NOT appear in output or logs.

### 10.2 GitHub Action

```yaml
- uses: orca-solutions/garnet-guard@<sha>   # pinned by commit SHA
  with:
    lockfiles: auto            # or a newline list of paths
    policy: garnet.toml        # optional
    comment: true              # post or update the PR comment
    sarif: false               # upload SARIF to code scanning
    footer: true               # end the comment with one line of docs links (§9.4)
    fail-on: block
```

Outputs: `verdict`, `report-path` (JSON), `comment-path` (the rendered comment), `sarif-path`.

The Action MUST run on `pull_request`, MUST NOT check out or execute PR code under `pull_request_target`, and MUST document the minimal permissions (`contents: read`, plus `pull-requests: write` for comments and `security-events: write` for SARIF). Where the PR's token can't comment (Dependabot's restricted token, forks), the Action MUST support the two-workflow pattern: the analysis job uploads the report artifact, and a separate `workflow_run` job posts it without checking out PR code. The repository ships both workflows as examples.

### 10.3 Install wrapper

`garnet pip install …`, `garnet uv add|sync|lock …` and `garnet npm install …` MUST resolve the change without installing (`pip install --dry-run --report`, `uv lock` into a temp copy, `npm install --package-lock-only` in a temp copy), run `check` on the result, then, if the verdict is below `fail_on`, run the real command with the same arguments. On block it exits 2 and doesn't install. `--garnet-force` skips the block after printing the findings.

### 10.4 Agent hooks

`garnet hook claude-code` prints a Claude Code hook configuration that runs a `PreToolUse` hook on shell commands. The hook detects package-adding commands (`pip install`, `uv add`, `uv pip install`, `poetry add`, `npm install <pkg>`, `pnpm add`, `yarn add`), runs the wrapper's resolve-and-check step, and denies the tool call with the findings as the reason when the verdict is `block`. For `warn` it allows the call and returns the findings as context. `garnet hook codex` does the same with whatever hook or command-approval mechanism Codex offers at 1.0. *Confirm both mechanisms against current Claude Code and Codex docs when building.*

## 11. Non-functional requirements

- **Performance.** For a Dependabot PR with up to 10 changed packages and a cold cache, the Action SHOULD finish in under 3 minutes on a standard GitHub-hosted runner; with a warm cache, under 30 seconds. Fetches run concurrently, at most 8 at a time per host.
- **Platforms.** Python 3.11 to 3.14 on Linux, macOS and Windows.
- **Network.** HTTPS only. Respect `HTTPS_PROXY` and custom CA bundles. Back off on HTTP 429.
- **Dependencies.** Runtime dependencies are listed in [docs/API.md](API.md) §8; adding one requires an ADR.
- **Privacy.** No telemetry (ADR-0008).
- **Releases.** Published with PyPI Trusted Publishing and PEP 740 attestations. Garnet's own dependency PRs are checked by Garnet.

## 12. Versioning and compatibility

Garnet follows semantic versioning from 1.0. The public interface is: CLI commands, flags and exit codes; rule IDs and names; the policy format (`version = 1`); the JSON report schema; the Action's inputs and outputs; and the Python API marked public in [docs/API.md](API.md). Anything else may change in a minor release.

## 13. Acceptance criteria for 1.0

1. Every replayed incident in the backtest corpus that Garnet targets (at minimum lightning 2.6.2 and 2.6.3, elementary-data 0.23.3, litellm 1.82.7 and 1.82.8, telnyx 4.87.1 and 4.87.2, and one npm account-takeover case) produces at least one `warn` or `block` finding from a rule other than GRN-K001.
2. On the clean corpus (the last 11 releases of each of the top 1,000 PyPI packages and the top 1,000 npm packages, from the frozen lists `backtest/top-pypi-1000.json` and `backtest/top-npm-1000.json`; criterion set 2026-10-30), the share of changes with a `warn` or higher is published per rule, and the overall rate is at or below the target set after the month-2 backtest.
3. The parser fuzzing suite runs for at least 1 CPU-hour per parser per release with no crash, hang or limit bypass.
4. Every rule has `explain` text, positive and negative fixtures, and SARIF metadata.
5. The JSON schema, policy format and Action inputs are frozen and documented.
6. The release is published with Trusted Publishing and attestations, and Garnet passes its own check.
