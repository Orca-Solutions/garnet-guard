# Garnet Guard code design and API

- Status: Draft
- Date: 2026-10-10
- Companion to: [SPEC-v1.md](SPEC-v1.md) (what Garnet does) and [ARCHITECTURE.md](../ARCHITECTURE.md) (the overview). This document says how the code is organized and what the Python API looks like.

> **This is the 1.0 design; 0.1 builds part of it.** The layers and import rules in §2 are enforced today. Of the API in §3, 0.1 exports `compare`, `report`, `explain`, `Options`, `Report` and the models; `evaluate` and `diff_lockfiles` exist in `garnet_guard.engine` but aren't exported yet, and policy, the cache and SARIF aren't built. npm is built for `compare` and `evaluate` (`ecosystems/npm.py`, `ecosystems/npm_provenance.py`, `facts/npmmeta.py`); the npm lockfile parsers aren't. [CODE_TOUR.md](CODE_TOUR.md) describes the code as it is now, module by module.

## 1. Design goals

1. **One entry point, many surfaces.** The CLI, Action, wrapper and hooks are thin; all logic sits behind `evaluate()`.
2. **I/O at the edges, judgment in the middle.** Adapters fetch; extractors turn bytes into facts; checks are pure functions of facts. Most code is testable without a network or a filesystem.
3. **Hostile input is the normal case.** Only one module opens archives, only one module talks to the network, and both are small enough to review line by line.
4. **Boring, typed Python.** Frozen dataclasses, `Protocol`s, no metaprogramming, `mypy --strict`.

## 2. Layers and import rules

```text
 surfaces     cli.py   action/   wrapper.py   hooks/
                 │        │          │           │
                 └────────┴────┬─────┴───────────┘
 orchestration           engine.py  (evaluate, compare)
                     ┌────────┼──────────┬──────────────┐
 judgment        checks/   policy.py   report/        baseline.py
                     │        │          │
 data            models.py  (shared, imports nothing internal)
                     ▲
 extraction      facts/  (inventory.py, pyindex.py, npmmeta.py)
                     ▲
 edges           ecosystems/  lockfiles/   net.py   safe_archive.py   cache.py
```

Import rules, enforced by an `import-linter` contract in CI:

- `models` imports nothing from Garnet.
- `checks` imports only `models` (and the standard library). No `net`, no `ecosystems`, no `safe_archive`.
- `facts` may use `safe_archive` but not `net`.
- Only `net.py` imports the HTTP client. Only `safe_archive.py` imports `zipfile` and `tarfile`.
- Surfaces import only `garnet_guard` public names and `engine`.

## 3. Public Python API

Everything below is exported from `garnet_guard` and is covered by the compatibility promise in SPEC §12. Anything not listed is internal.

### 3.1 Entry points

```python
def evaluate(
    changes: Sequence[Change],
    *,
    policy: Policy | None = None,     # None means defaults
    options: Options | None = None,
) -> Report: ...

def compare(
    ecosystem: str, package: str, baseline: str | None, candidate: str,
    *, policy: Policy | None = None, options: Options | None = None,
) -> ChangeResult: ...

def diff_lockfiles(base: Path | bytes, head: Path | bytes,
                   *, format: str | None = None) -> list[Change]: ...

def load_policy(path: Path | None = None, *, cwd: Path | None = None) -> Policy: ...

def explain(rule_id: str) -> RuleDoc: ...
```

Typical use:

```python
from pathlib import Path
import garnet_guard as gg

changes = gg.diff_lockfiles(Path("base/uv.lock"), Path("uv.lock"))
report = gg.evaluate(changes, policy=gg.load_policy())
print(report.verdict)               # Verdict.WARN
print(report.to_json())
```

### 3.2 Models

```python
class Severity(IntEnum):
    OFF = 0; INFO = 1; WARN = 2; BLOCK = 3

class Verdict(StrEnum):
    PASS = "pass"; WARN = "warn"; BLOCK = "block"

@dataclass(frozen=True)
class Change:
    ecosystem: str                    # "pypi" | "npm"
    package: str                      # normalized name
    baseline: str | None              # None for an added package
    candidate: str
    lockfile: Path | None = None
    line: int | None = None           # where the candidate is pinned (for SARIF)

@dataclass(frozen=True)
class Evidence:
    kind: Literal["file", "attestation", "tag", "advisory", "url", "note"]
    summary: str
    path: str | None = None
    line: int | None = None
    sha256: str | None = None
    url: str | None = None
    identity: str | None = None       # Sigstore identity / workflow

@dataclass(frozen=True)
class Finding:
    rule_id: str
    name: str
    severity: Severity                # after policy
    default_severity: Severity
    change: Change
    title: str
    evidence: tuple[Evidence, ...]
    explanation: str
    remediation: str
    release: str | None = None        # set when about an intermediate version
    suppressed_by: Ignore | None = None

@dataclass(frozen=True)
class ChangeResult:
    change: Change
    verdict: Verdict
    findings: tuple[Finding, ...]

@dataclass(frozen=True)
class Report:
    garnet_version: str
    verdict: Verdict
    results: tuple[ChangeResult, ...]
    policy_source: str | None
    def to_json(self) -> str: ...
    def to_sarif(self) -> str: ...
    def to_markdown(self, *, max_chars: int = 60_000) -> str: ...
    def to_text(self, *, color: bool = False) -> str: ...
    def exit_code(self, fail_on: Severity) -> int: ...

@dataclass(frozen=True)
class Options:
    cache_dir: Path | None = None     # default: platformdirs user cache
    offline: bool = False
    github_token: str | None = None   # never logged or serialized
    concurrency: int = 8
    limits: Limits = Limits()
```

`Policy`, `RuleSetting`, `Ignore`, `Limits` and `RuleDoc` mirror SPEC §7 and §4.4 one-to-one.

### 3.3 Errors

```python
class GarnetError(Exception): ...          # base; CLI maps to exit code 3
class PolicyError(GarnetError): ...        # invalid or unknown policy keys
class LockfileError(GarnetError): ...      # unreadable or unsupported lockfile
class UsageError(GarnetError): ...
```

Problems *with packages* (fetch failures, parse failures, budget overruns) are never exceptions at the API boundary. They become GRN-E findings so a report is always produced.

## 4. Internal interfaces

### 4.1 Release facts

```python
@dataclass(frozen=True)
class FileProvenance:
    filename: str
    present: bool
    verified: bool
    identity: str | None              # e.g. https://github.com/o/r/.github/workflows/release.yml@refs/tags/v1
    repository: str | None            # "github.com/o/r"
    workflow: str | None              # ".github/workflows/release.yml"
    environment: str | None
    trusted_publishing: bool | None
    error: str | None = None

@dataclass(frozen=True)
class FileEntry:
    path: str
    size: int
    sha256: str
    kind: Literal["py", "pth", "native", "script", "data", "other"]

@dataclass(frozen=True)
class ModuleIndex:
    module: str
    path: str
    top_level_calls: tuple[CallSite, ...]     # resolved names + line
    imports: tuple[str, ...]
    large_literals: tuple[Literal_, ...]      # length, entropy, line, sink

@dataclass(frozen=True)
class ArtifactFacts:
    filename: str
    sha256: str
    uploaded_at: datetime
    provenance: FileProvenance
    files: tuple[FileEntry, ...]
    modules: tuple[ModuleIndex, ...]
    build_backend: str | None
    install_scripts: Mapping[str, str]        # npm lifecycle scripts

@dataclass(frozen=True)
class ReleaseFacts:
    ecosystem: str
    package: str
    version: str
    yanked: bool
    artifacts: tuple[ArtifactFacts, ...]      # all artifacts (trust rules)
    content: ContentSelection                 # sdist + selected wheel (content rules)
    source_repo: str | None
    tag: TagInfo | None
    advisories: tuple[str, ...]               # OSV MAL- ids
    errors: tuple[FactError, ...]             # become GRN-E findings
```

`ReleaseFacts` serializes to JSON. That serialized form is also the test fixture format and the cache format.

### 4.2 Ecosystem adapter

```python
class Ecosystem(Protocol):
    name: ClassVar[str]
    def normalize(self, package: str) -> str: ...
    def versions_between(self, package: str, low: str, high: str) -> list[str]: ...
    def release_facts(self, package: str, version: str, ctx: FetchContext) -> ReleaseFacts: ...
```

`FetchContext` carries the HTTP client, cache, limits and token. Adapters are registered in a module-level dict in `ecosystems/__init__.py` for 1.0. An `importlib.metadata` entry-point group (`garnet_guard.ecosystems`) is planned for v2.

### 4.3 Lockfile parser

```python
class LockfileParser(Protocol):
    ecosystem: ClassVar[str]
    def detect(self, name: str, head: bytes) -> bool: ...
    def parse(self, data: bytes) -> list[Pin]: ...   # Pin(package, version, line, source)
```

### 4.4 Check

```python
class Check(Protocol):
    id: ClassVar[str]                 # "GRN-C001"
    name: ClassVar[str]               # "new-pth-file"
    kind: ClassVar[Literal["diff", "absolute"]]
    ecosystems: ClassVar[frozenset[str]]
    default: ClassVar[Severity]
    doc: ClassVar[RuleDoc]

    def run(self, change: Change, baseline: ReleaseFacts | None,
            candidate: ReleaseFacts) -> Iterable[RawFinding]: ...
```

Checks return `RawFinding` (no severity, no suppression). The engine applies policy afterward, so checks never read policy. Checks are registered by listing them in `checks/__init__.py:ALL_CHECKS`; a test asserts IDs are unique, match the SPEC table and have docs and fixtures.

## 5. Engine flow

```text
evaluate(changes, policy, options)
  for each change (concurrently, bounded):
    eco        = ECOSYSTEMS[change.ecosystem]
    candidate  = facts(eco, change.package, change.candidate)      # cache → net → extract
    baseline   = facts(eco, change.package, change.baseline) if change.baseline
    raws       = [c.run(change, baseline, candidate) for c in checks_for(eco, kind)]
    for v in intermediates(eco, change):                           # SPEC §5 rule 2
        raws  += trust checks on (prev(v), v), tagged release=v
    raws      += error findings from candidate.errors / baseline.errors
    findings   = apply_policy(raws, policy)                        # severities, ignores, expiry
    result     = ChangeResult(change, worst(findings), sorted(findings))
  return Report(..., verdict=worst(results))
```

Concurrency uses a `ThreadPoolExecutor` sized by `Options.concurrency`, with a per-host semaphore inside `net.py`. A per-change deadline enforces the time budget; a missed deadline produces GRN-E003 and the change still appears in the report.

## 6. The two hardened modules

**`net.py`.** One `httpx.Client` with HTTP/1.1 and HTTP/2, TLS verification always on, proxy and CA settings from the environment, timeouts (connect 10 s, read 30 s), retries with backoff for 429/5xx, a response size cap, and a hosts allowlist (`pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`, `api.github.com`, `api.osv.dev`, Sigstore TUF hosts). Requests to anything else raise. Tokens are attached only to `api.github.com`.

**`safe_archive.py`.** Exposes `open_archive(data: bytes, limits: Limits) -> ArchiveReader` with `entries()` and `read(path, max_bytes)`. It never writes to disk. It rejects unsafe entries per SPEC §4.4, and counts uncompressed bytes as it reads so a lying header can't bypass limits. It is fuzzed with Atheris or Hypothesis on every CI run (short) and nightly (long).

## 7. Testing

| Layer | How it's tested |
|---|---|
| checks | Pure unit tests over `ReleaseFacts` JSON fixtures in `tests/fixtures/facts/`. Each rule has `positive/` and `negative/` pairs. |
| facts | Tiny synthetic wheels, sdists and tarballs built in-test by `tests/builders.py`, so no real malware is stored in the repo. |
| lockfiles | Real-world sample lockfiles per format and version; golden outputs. |
| report | Golden files for text, JSON, Markdown and SARIF; SARIF validated against the official schema. |
| net, adapters | Recorded HTTP responses (`respx`). Live tests under `-m network`, run nightly. |
| safe_archive | Fuzzing, plus a corpus of hostile archives (zip bomb, traversal, symlink, huge header). |
| end to end | `backtest/` replays incidents and the clean corpus; run on rule changes and nightly. |

Unit tests MUST NOT open network sockets; a pytest fixture enforces it.

## 8. Dependencies

Runtime, for 1.0. Each needs an ADR to add or swap.

| Package | Why |
|---|---|
| `httpx` | HTTP client with timeouts, proxies, HTTP/2 |
| `pypi-attestations` (brings `sigstore`) | Verify PEP 740 attestations; the reference implementation |
| `packaging` | Version parsing, specifiers, name normalization, wheel tags |
| `platformdirs` | Cache location |
| `pyyaml` (safe loader only) | pnpm-lock.yaml |

`tomllib` (standard library) covers TOML. CLI argument parsing uses `argparse` to avoid a dependency. npm Sigstore verification goes through `sigstore` directly.

Development: `pytest`, `respx`, `hypothesis`, `atheris` (Linux CI only), `ruff`, `mypy`, `import-linter`, `jsonschema`.

## 9. Repository layout

```text
src/garnet_guard/
  __init__.py            # public API (§3) and __all__
  models.py  policy.py  baseline.py  engine.py
  net.py  safe_archive.py  cache.py
  lockfiles/   uv.py poetry.py pylock.py requirements.py npm_lock.py pnpm.py yarn.py
  ecosystems/  pypi.py npm.py github.py osv.py
  facts/       inventory.py pyindex.py npmmeta.py
  checks/      trust.py content.py known_bad.py errors.py __init__.py
  report/      text.py json.py sarif.py markdown.py schema/report-v1.json
  rules/       *.md               # explain text, one file per rule
  cli.py  wrapper.py
  hooks/       claude_code.py codex.py
action/          action.yml  examples/
backtest/        incidents/  corpus.py  __main__.py
tests/           fixtures/  builders.py  ...
docs/            SPEC-v1.md  API.md  README.md  decisions/  handoffs/  brand/
```
