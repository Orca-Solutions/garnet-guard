# 0002. Implement in Python, distribute with uv

- Status: Accepted
- Date: 2026-10-10

## Context

The first audience is Python developers. Useful libraries (`pypi-attestations`, `ast`, packaging tools) are Python. GuardDog's rules are Python/Semgrep. A compiled language would give a single binary and speed but would slow a solo builder.

## Decision

Python 3.11+, packaged with uv, run via `uvx garnet-guard` or `uv tool install`. Performance-critical parts can move to a compiled extension later if profiling shows a need.

## Consequences

npm users need Python available. That's acceptable for the Action (runners have it) and will be revisited for local npm use.
