# 0016. PyYAML for pnpm-lock.yaml

- Status: Proposed
- Date: 2026-10-30

## Context

SPEC §3.1 lists `pnpm-lock.yaml` among the lockfiles `garnet check` must read, and [docs/API.md](../API.md) §8 planned `pyyaml` (safe loader only) for it. ADR-0014 deferred the dependency until the pnpm parser needed it. The other npm lockfiles need nothing new: `package-lock.json` is JSON, and `yarn.lock` is read line by line because neither Yarn generation writes strict YAML.

pnpm's lockfile is real YAML: flow mappings for `resolution: {integrity: ...}`, quoted keys for scoped packages and peer suffixes, nested maps several levels deep. A hand-written reader would re-implement enough of YAML to become a bug source of its own.

## Decision

Declare `pyyaml>=6` as a runtime dependency and read `pnpm-lock.yaml` with a subclass of its safe loader that refuses aliases. The safe loader builds only plain Python values, never objects. Refusing aliases as well keeps a lockfile from a pull request from expanding into memory (`&a` and `*a` references, the "billion laughs" shape); pnpm never writes them. `lockfiles/pnpm.py` is the only module that imports `yaml`.

`types-pyyaml` joins the development dependencies for `mypy --strict`.

## Consequences

One more package in the install. The C extension is not used, so the pure-Python wheel is enough on every platform.

A YAML error is reported with its line and column, never with the file's own text, like the TOML and JSON parsers do, because the report may be posted publicly.

pnpm lockfile versions 6 and 9 are read; older ones (pnpm 7 and earlier) are refused with a message naming the version.
