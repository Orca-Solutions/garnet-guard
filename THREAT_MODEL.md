# Garnet Guard threat model

Garnet is a security tool that downloads hostile files and runs with write access to pull requests. This document says what Garnet defends against, what it doesn't, and how Garnet keeps from becoming the attack vector.

## Part 1: what Garnet detects

### Attacker we target

Someone who gains the ability to publish a new version of a **legitimate, already-trusted package**, by any of:

| Path | Example | Garnet signals |
|---|---|---|
| Stolen or leaked long-lived publish token | lightning 2.6.2/2.6.3, litellm 1.82.7/1.82.8, telnyx 4.87.1/4.87.2, ultralytics 8.3.45/8.3.46, xinference 2.6.0–2.6.2, durabletask 1.4.1–1.4.3 | Lost provenance (T001), outside Trusted Publishing (T005), no matching tag (T004) |
| Hijacked maintainer account (phishing, session theft) | num2words 0.5.15/0.5.16, July 2025; chalk/debug, Sept 2025 | No matching tag (T004) for all four; new import-time exec (C003) for num2words. Lost provenance (T001) and a new install script (C002) cover the same path when the trusted release was attested or the payload is an install script |
| Compromised CI of the real project (script injection, poisoned action or cache, pushed release tag) | elementary-data 0.23.3, ultralytics 8.3.41/8.3.42, memoryos 2.0.34 | Provenance looks valid, so content rules carry it: new `.pth` (C001), changed build backend (C002), new import-time exec (C003), code that isn't at the tag (C007, ultralytics 8.3.42) |
| Moved publishing to a fork or new repo | repo-jacking variants | Publisher changed (T002), workflow changed (T003) |
| Known-bad release already listed | any feed-confirmed case | OSV `MAL-` match (K001) |

The design bet: an attacker can fake a lot, but it is hard to fake *both* "same publisher identity as last time" *and* "content changes that look like a normal release".

### Out of scope

- **Malicious first versions** of new packages, typosquats and slopsquats. Cooldowns and malware feeds cover these; Garnet can still report K001 if a feed has it.
- **Long-standing malicious code** that was already in the baseline. Garnet trusts the baseline by definition.
- **A compromise that changes nothing Garnet looks at:** a valid attestation from the real workflow, a matching tag, and a malicious change that reads like normal code in a non-import-time path. Garnet lowers risk; it does not prove safety. Reports must never say "safe".
- **Registry or Sigstore compromise.** Garnet relies on PyPI, npm and Sigstore being honest about what they serve and sign.
- **Runtime behavior.** No sandbox, no dynamic analysis.

### Evasion

Rules are public, so attackers can read them. Responses:

- Lean on trust signals that require control of the real publisher identity, not on content patterns alone.
- Rules run on *changes*, so hiding a payload means making it look like an ordinary diff, which raises the cost.
- Novel bypasses are reported privately (see [SECURITY.md](SECURITY.md)) and land with a backtest fixture.

### Known gaps and the plan

A red-team pass on 2026-10-30 listed the ways a malicious release could still get past the rules. This is the condensed map: what each gap is, what Garnet sees of it today, and the issue that closes it. The order and phase of each fix are in [ROADMAP.md](ROADMAP.md#closing-the-evasion-gaps). Ideas already public are tracked here and in ordinary issues; a bypass nobody has published yet still goes through private reporting.

| Gap | What Garnet sees today | Planned |
|---|---|---|
| A trusted package adds a dependency that carries the payload (event-stream 3.3.6 added flatmap-stream) | GRN-C008 new-dependency warns when the added dependency is missing from the registry, was first released there less than 90 days before, or installs from git, a URL or a path, and lists an established one at `info`. The added package's own code isn't read | A first look at added packages [#58](https://github.com/orca-solutions/garnet-guard/issues/58) |
| The payload runs when a feature is used, not at import (ultralytics 8.3.42) | GRN-C007, when the build injected code that isn't at the tag; nothing when the payload is in the tagged source | Package-level capability signal, measured on the corpus first [#53](https://github.com/orca-solutions/garnet-guard/issues/53) |
| The payload calls an API the §6.3 sensitive list doesn't name, or reaches a listed one indirectly | The 2026-10-c set adds processes started without `subprocess` (`os.fork`, `os.startfile`, `asyncio.create_subprocess_*`, `multiprocessing.Process` and its context classes, `_winapi.CreateProcess`, `distutils.spawn.spawn`), code loaded from files or code objects (`runpy`, `zipimport`, the `importlib` and `imp` file loaders, `types.FunctionType`, `types.CodeType`), more network clients (`asyncio` streams, `urllib3`'s pool managers, connection pools and connections, `ftplib`, `smtplib`, `xmlrpc.client`, `webbrowser` and others), and the same names under the modules that define or import them (`builtins.exec`, `posix.system`, `ssl.create_connection`, `asyncio.subprocess`, `urllib3.poolmanager`, `_frozen_importlib_external` and others). A top-level module a release ships under a name in the set (an empty `os.py`, `requests.py` or `builtins.py`) doesn't hide calls to that name; only the `requests` project itself, named by its wheel or sdist filename, counts as calling its own `requests` code, and the same for `httpx`, `aiohttp`, `urllib3` and `setuptools`. An API still off the list is missed, including `pickle.load`, `multiprocessing.Pool` and `ProcessPoolExecutor`, which wait for a corpus measurement. Literal `getattr` and `__import__` lookups of a listed one are followed; computed names aren't, nor is a listed function passed to another call without being called (`atexit.register(os.system, cmd)`, `Thread(target=os.system)`) or a listed name reached through what a call returns (`multiprocessing.get_context("spawn").Process`) or looked up by subscript (`__builtins__["exec"]`) | Widened in [#46](https://github.com/orca-solutions/garnet-guard/issues/46); GRN-C005 indirection and obfuscation [#54](https://github.com/orca-solutions/garnet-guard/issues/54); changed inputs to listed calls, v2 [#65](https://github.com/orca-solutions/garnet-guard/issues/65) |
| The payload isn't Python source: a native binary, a sourceless `.pyc`, or JavaScript in an npm package | On PyPI, GRN-C004 new-binary warns for native code where the trusted release had none or under a name that hides it (judged by its bytes), for a `.pyc` that Python imports with no source beside it, and for a hash-based `.pyc` that Python loads in place of its source without comparing its code; a library in a new folder is reported at `info`. A rebuilt binary, a new library or executable in a folder that already held native code, or a new extension module in a release that already shipped some, isn't reported, and what a binary does isn't read. On npm, install scripts (GRN-C002), and GRN-C011 at `info` for a new process, network or eval use, or obfuscated names, in the JavaScript the package loads; a name built at run time isn't resolved, and npm binaries aren't reported | Done for PyPI: [#48](https://github.com/orca-solutions/garnet-guard/issues/48); JavaScript done at `info`: [#52](https://github.com/orca-solutions/garnet-guard/issues/52) |
| An extra wheel for one platform, uploaded after the others | GRN-T006 files-uploaded-late warns when a late wheel would be installed in place of an on-time file on some machine, and reports backfills at `info`. GRN-C012 wheels-differ compares one wheel per other platform family, and up to 30 late wheels, with the wheel the content rules read, and warns when one has Python code with sensitive calls that wheel lacks and the trusted version's wheels for that platform didn't make; a differing file it can't parse is GRN-E002, one over the parse limit GRN-E003, and late wheels past the 30th, which it doesn't read, GRN-E003 too. A payload in a second wheel of a family Garnet already compared, such as Linux aarch64 beside Linux x86-64, or in a non-Python file, is still not seen | Done for Python files: [#45](https://github.com/orca-solutions/garnet-guard/issues/45); GRN-C006 sdist-wheel-mismatch [#60](https://github.com/orca-solutions/garnet-guard/issues/60) |
| An entry point that another tool loads on its own (pytest plugins, setuptools hooks) | GRN-C009 new-entry-point warns for a new or retargeted entry point in a group another tool loads by itself (`pytest11`, `setuptools.*`, `flake8.extension`, `keyring.backends` and others) and for a new console script with a common command's name, and lists other new entry points at `info`. A group Garnet doesn't know is `info`. Entry points are read as `importlib.metadata` reads them, `;` lines, empty names, `[[group]]` headers and repeated names included, from the `entry_points.txt` of each `.dist-info` or `.egg-info` folder at the wheel's root or under `.data/purelib/` or `platlib/`. A metadata folder installed through `.data/data/`, or in a folder a `.pth` file adds to `sys.path`, isn't read: GRN-C010 lists the `.data/data/` file at `info`, and GRN-C001 warns for a new `.pth`. Wheels only, each read to the end: a wheel Garnet couldn't read to the end is not compared, and GRN-E002 or GRN-E003 says so | Done: [#47](https://github.com/orca-solutions/garnet-guard/issues/47) |
| A startup file other than `.pth`: `sitecustomize.py`, `usercustomize.py`, files under `.data/` | GRN-C010 new-startup-file warns for a new `sitecustomize.py` or `usercustomize.py`, a script named like a common command and a file installed under `etc/`, and lists other new scripts and data files at `info`. Wheels only: what an sdist installs is up to its build | Done: [#49](https://github.com/orca-solutions/garnet-guard/issues/49) |
| An import hook installed at import (`sys.meta_path`, `settrace`, `builtins`, metaclasses) | Only when the call is on the sensitive list | Hook installation [#55](https://github.com/orca-solutions/garnet-guard/issues/55) |
| The real release workflow, run from a different branch, ref or trigger | Provenance looks normal; the ref and trigger aren't compared | Different ref or trigger [#56](https://github.com/orca-solutions/garnet-guard/issues/56); release-workflow diff at `info` [#57](https://github.com/orca-solutions/garnet-guard/issues/57) |
| The attacker also pushes a matching tag | GRN-T004 is satisfied | Tag sanity checks [#61](https://github.com/orca-solutions/garnet-guard/issues/61) |
| The bad release is between the trusted version and the candidate | Trust rules compare the two ends only | Intermediate releases, SPEC §5.2 [#62](https://github.com/orca-solutions/garnet-guard/issues/62) |
| The payload sits in a model or data file a loader runs (pickle) | Nothing | Model loaders [#59](https://github.com/orca-solutions/garnet-guard/issues/59) |
| An ignore added to the policy in the same PR as the update | The Action checks the pull request with the base commit's policy, so the new ignore doesn't apply to it, and the comment lists the edit, loosening changes first. After the merge it applies to every later pull request, for at most 12 months | Done: policy guardrails [#51](https://github.com/orca-solutions/garnet-guard/issues/51) |
| An update that never reaches a lockfile (installed by hand, or in an image) | Nothing: Garnet checks lockfile diffs | A scheduled check of a deployed environment [#63](https://github.com/orca-solutions/garnet-guard/issues/63) |
| A risky property added slowly, one small step per release | Each step is compared only with the release before | Per-package history, v2 [#64](https://github.com/orca-solutions/garnet-guard/issues/64) |

Smaller notes that help a reviewer without a new rule are done ([#50](https://github.com/orca-solutions/garnet-guard/issues/50)): a change whose trusted release has no attestation and no git tag says that GRN-T001 to GRN-T005 had nothing to compare with, GRN-C003 lists new reads of credentials and CI settings at import at `info`, and the remediation text points at the repository before the release notes, which whoever published the release also wrote.

## Part 2: protecting Garnet itself

### Assets

- The CI environments and developer machines that run Garnet.
- The `GITHUB_TOKEN` and any tokens the Action receives.
- The integrity of Garnet's verdicts. A forged "pass" is the worst outcome.
- Garnet's own release pipeline on PyPI and the Action's repository.

### Threats and mitigations

| Threat | Mitigation |
|---|---|
| A hostile package exploits Garnet's parser (zip bomb, path traversal, symlink, huge file, pathological AST) | All archive access goes through `safe_archive.py` with size, ratio, count and depth limits. No links or device files. `ast` parsing has size and time limits. The git packfile reader (`ecosystems/gittree.py`) caps the response, each object and their total, verifies the pack checksum and bounds every delta. Fuzz tests on the archive and lockfile parsers. |
| Garnet executes package code by accident (importing a module, running a build backend to get metadata) | Hard invariant: no execution. Metadata comes from the registry and static files (`METADATA`, `pyproject.toml`, `package.json`). A test asserts no subprocess or import of inspected content. |
| A malicious PR abuses the Action (pwn request) | No `pull_request_target` with PR checkout. Least-privilege tokens. Comments are posted from a job that never executes PR content. Report text from packages is escaped in markdown. |
| Markdown or terminal injection via package names, file names or metadata | Every string from a package is escaped before rendering in comments, SARIF and terminals. |
| Network attacker tampers with downloads | HTTPS only. Downloaded files are checked against the registry's published hashes before inspection. |
| Garnet's own dependencies are compromised | Small dependency set. Hash-pinned lock (`uv.lock`) in CI and releases. Garnet runs Garnet on its own dependency PRs. New runtime dependencies require an ADR. |
| Garnet's release is hijacked | PyPI Trusted Publishing from a protected environment with required reviewer, PEP 740 attestations on every file, signed tags, 2FA and hardware keys on maintainer accounts, no long-lived publish tokens. |
| The Action repo is tampered with | Users pin by commit SHA in docs. Branch protection and signed commits on main. Release tags are immutable. |
| AI agents introduce a subtle weakness | Agents never merge. Changes to `safe_archive.py`, the Action, release workflows and policy defaults require a careful human review (see [AGENTS.md](AGENTS.md)). |
| An upstream outage silently weakens results | "Couldn't check" is reported as an error finding, never as pass. |

### Privacy

Garnet sends only what it needs to public registries and GitHub (package names, versions, file names). It has no telemetry. The hosted app, when it exists, will document exactly what it stores.
