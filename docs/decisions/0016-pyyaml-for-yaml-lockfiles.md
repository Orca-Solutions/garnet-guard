# 0016. PyYAML's parser for pnpm-lock.yaml and Yarn 2+ yarn.lock

- Status: Proposed
- Date: 2026-10-30

## Context

SPEC §3.1 lists `pnpm-lock.yaml` and Yarn Berry's `yarn.lock` among the lockfiles `garnet check` must read, and [docs/API.md](../API.md) §8 planned `pyyaml` (safe loader only) for them. ADR-0014 held the dependency back until a parser needed it. The npm formats read so far needed nothing new: `package-lock.json` is JSON, and Yarn 1's `yarn.lock` is its own format, read with a port of Yarn 1's parser.

pnpm (9 and 10, and 8 for lockfileVersion 6.x) and Yarn 2 and later write their lockfiles with js-yaml and read them back with it. They are real YAML: flow mappings (`resolution: {integrity: ...}`), quoted keys for scoped packages and peer suffixes, explicit `? ` keys once a key passes 1,024 characters, several levels of nesting. Yarn 2+ projects also keep their registry settings in `.yarnrc.yml`. A YAML reader written here would be a second parser to maintain, and a reader that reads a file differently from js-yaml would let a pull request show Garnet one lockfile and the package manager another.

The input is hostile: the lockfile comes from the pull request under review. A YAML reader can be made to build objects from tags (`!!python/object/apply`), to expand a small file into a huge one through anchors and aliases, or to recurse on deep nesting. PyYAML reads YAML 1.1 and js-yaml YAML 1.2, which differ on plain scalars (`yes`, `0o17`, `1:20`, `2001-01-01`), on merge keys (`<<`) and on NEL, LS and PS, which 1.1 counts as line breaks.

The options were:

- **PyYAML.** The common Python YAML library, maintained under the yaml organization. 6.0.3 has binary wheels for CPython 3.11 to 3.14 on Linux, macOS and Windows (the Linux x86_64 one used here includes libyaml), and a pure-Python parser everywhere else. Its event API (`yaml.parse`) reports each scalar, collection, anchor, alias and tag before anything is built, with its line.
- **ruamel.yaml.** Reads YAML 1.2, so closer to js-yaml, but its API has changed incompatibly between releases (0.18 removed the module-level `load` functions), and its C parser is the same libyaml, in a second package (`ruamel.yaml.clib`). Garnet would still have to refuse anchors, tags and duplicate keys itself.
- **strictyaml.** Refuses flow style, which every pnpm-lock.yaml uses.
- **A reader for the subset pnpm and Yarn write.** No dependency, but a hand-written YAML parser for hostile input, and every difference from js-yaml would be Garnet's own bug.

## Decision

Add `pyyaml>=6.0.2` as a runtime dependency, and `types-pyyaml` as a development one for `mypy --strict`. Only `lockfiles/yamldoc.py` imports `yaml`, enforced by an import-linter contract; `lockfiles/pnpm.py`, `lockfiles/berry.py` and `lockfiles/registries.py` get their documents from it.

`yamldoc` never uses a PyYAML loader or constructor. It walks `yaml.parse` events, from `CSafeLoader`'s parser when PyYAML has libyaml and `SafeLoader`'s otherwise, and builds the document itself from `dict`, `list` and `str` (with `None` and booleans in the core schema). So no tag can build an object, and an alias is refused at its event: the composer that would follow it never runs, with either parser. It refuses, with a line number:

- an alias, and an anchor, which pnpm and Yarn never write;
- a tag other than the core schema's `!!str`, `!!null`, `!!bool`, `!!int`, `!!float`, `!!map` and `!!seq` (only `!!str`, `!!map` and `!!seq` for Yarn's failsafe schema);
- a merge key in the core schema, where js-yaml merges and Garnet doesn't;
- a repeated key, including two that js-yaml makes one (`null:` and `'null':`, `1:` and `'1':`), which js-yaml refuses as well;
- a key that isn't a scalar, nesting deeper than 32 levels, and a second document;
- NEL, LS and PS anywhere in the file, and a quoted string that isn't valid text (a lone surrogate).

Plain scalars are typed the way the tool reads them: as js-yaml's default schema does for pnpm (`core`), and as text for Yarn and `.yarnrc.yml` (`failsafe`, js-yaml's `FAILSAFE_SCHEMA`, which Yarn uses). A plain scalar either YAML version reads as something other than text becomes an opaque `Scalar`, which the parsers refuse wherever they need text. Errors give a line and, from the parser, a column, never the file's text, because a report may be posted publicly and `.yarnrc.yml` can hold tokens. Lockfiles over 64 MiB are refused before parsing, as every format is, and registry settings files over 1 MiB.

The lower bound is 6.0.2, the oldest release the test suite was run against here and the first with Python 3.13 wheels; `uv.lock` pins 6.0.3, the first with 3.14 wheels. There is no upper bound: only the documented event API (`yaml.parse` and the event classes) is used.

## Consequences

One more package in the install, with no dependencies of its own.

Speed, measured on a synthetic 30 MB pnpm-lock.yaml (83,016 packages and as many snapshots, 1,162,242 lines) in the development container (4 x86_64 cores, CPython 3.13.17, PyYAML 6.0.3): libyaml's events alone take 2.6 s, `yamldoc.load` 6.1 s, and the whole pnpm parse 6.9 s. With the pure-Python parser, `yamldoc.load` takes 51.3 s. For comparison, PyYAML's own `yaml.load` with `CSafeLoader`, which would also follow aliases, takes 20.9 s. Real lockfiles are a few MB.

A file pnpm or Yarn wrote reads the same in Garnet as in the tool. A hand-edited file that YAML 1.1 and 1.2 read differently, or that uses a YAML feature the tools never write, is refused with exit code 3 instead of read one way or the other.

This amends ADR-0014, which deferred `pyyaml` to this point.
