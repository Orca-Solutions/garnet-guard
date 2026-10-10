# 0005. Static analysis only; never execute inspected code

- Status: Accepted
- Date: 2026-10-10

## Context

Garnet inspects packages that may be malicious, inside CI jobs with tokens. Running a build backend or importing a module to learn about it would hand the attacker exactly the execution Garnet exists to prevent.

## Decision

Garnet never imports, builds, installs or runs anything it downloads. Metadata comes from the registry and static files; Python code is parsed with `ast`; all archive reading goes through one hardened module.

## Consequences

Some facts (dynamic `setup.py` metadata, runtime behavior) are unavailable, and certain obfuscation can't be resolved. That's an accepted limit; dynamic analysis stays out of scope.
