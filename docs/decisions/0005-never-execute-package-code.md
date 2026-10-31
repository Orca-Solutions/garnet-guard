# 0005. Static analysis only; never execute inspected code

- Status: Accepted
- Date: 2026-10-10

## Context

Garnet inspects packages that may be malicious, inside CI jobs with tokens. Running a build backend or importing a module to learn about it would hand the attacker exactly the execution Garnet exists to prevent.

## Decision

Garnet never imports, builds, installs or runs anything it downloads. Metadata comes from the registry and static files; Python code is parsed with `ast`; all archive reading goes through one hardened module.

**Amendment (2026-10-30, install wrapper).** `garnet pip install` and `garnet uv add|remove|lock|sync` run the user's own package manager, so "never installs" now reads: Garnet's own process never imports, builds or runs code it inspects, and it starts the user's pip or uv only with builds turned off for the resolve step. pip and uv both run a package's build backend while resolving a source distribution (pip during `--dry-run`, uv for dynamic metadata), so the resolve step passes `--only-binary :all:` last to pip, after reading every requirements file it names, and `--no-build` with `UV_NO_BUILD=1` to uv in a private copy of the project; anything that would turn building back on (`--no-binary`, editable installs, local paths, URLs, VCS requirements, uv's `--build`) is refused. After a passing check, the wrapper installs exactly what was checked: pip with `--only-binary :all: -c <pins with hashes>`, uv with `uv sync --frozen` from the checked lockfile. A change that can't be resolved without building is reported as not checked, never as a pass (SPEC §10.3).

## Consequences

Some facts (dynamic `setup.py` metadata, runtime behavior) are unavailable, and certain obfuscation can't be resolved. That's an accepted limit; dynamic analysis stays out of scope.

With the amendment, the wrapper's hand-off is the user's package manager doing the install the user asked for, after the check; the user's own project build (uv installs the project itself in editable mode) still runs there, as it would without Garnet. A package whose release needs a build to resolve can't go through the wrapper unchecked except with `--garnet-force`.
