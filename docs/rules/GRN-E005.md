---
id: GRN-E005
name: unsupported-source
kind: absolute
default_severity: info
status: implemented
---

# GRN-E005 unsupported-source

| | |
|---|---|
| Default severity | `info` |
| Kind | absolute rule: fires on the new version alone, whatever the trusted version looked like. |
| Status | Implemented in 0.1 (`garnet check`) |

## What it checks

A dependency comes from a source Garnet Guard doesn't check: a git URL, a local path, a
direct file URL, or a registry other than PyPI and npm. In an npm lockfile, a package
bundled inside another package's tarball (`inBundle`, with no `resolved` URL or integrity
of its own) and an entry whose name breaks npm's naming rules are reported the same way.

In a requirements file, pip applies `--index-url` (`-i`), `--extra-index-url`, `--find-links`
(`-f`) and `--no-index` to every requirement in the file, before or after the option's line,
and accepts any unambiguous prefix of a long option (`--extra-ind`, `--no-ind`) and a short
option's value attached (`-ihttps://…`, `-f/srv/wheels`). Garnet reads them the same way. When
a file sets an index other than PyPI, an extra index, find-links or no-index, every `==` pin
in it is reported here instead of being checked against PyPI. So is every pin in a file that
holds an option pip would refuse. The reason names the option, never its value, which can
hold credentials.

pip reads a file named with `-r` or `-c` as part of the file that names it, and applies its
index options to everything it reads. `garnet check` follows these includes as pip resolves
them, beside the file that names them, for the working tree and for the base (at
`--git-base`, or beside the `--base` file), and applies the index options of the whole
include tree to every pin in it: an index set in `base.txt` applies to the
`requirements-dev.txt` that brings it in, and one set in `requirements-dev.txt` applies to
the pins of `base.txt`. It follows them only inside the directory it checks, never through a
symlink, and at most 10 deep, reading each file once and at most 100 includes and 64 MiB
per tree. An include it can't follow (a URL, a path with a `..` part or outside that
directory, a missing file, a symlink, an environment variable, files that include each
other, more than 10 deep, a tree past those caps) leaves the pins of the file that names it,
and of the files read with it, unchecked. Lines are joined and comments stripped as pip 24.0
does it: a line ending in `\` runs on into the next with nothing between, so `--\` followed
by `index-url …` is `--index-url …`.

## Why it matters

Garnet Guard's rules are written against registry metadata. A dependency from somewhere
else isn't compared at all, and the report says so rather than leaving it out.

## Example finding

Illustrative; not from a real project. This is 0.1's output when a uv.lock entry starts
coming from a git repository.

```text
examplelib (new) → 2.6.2: PASS
  info  GRN-E005 unsupported-source: examplelib was not checked: git source
           - git source
```

The reason after "was not checked" names the source, for example `git source`,
`direct URL or path`, `editable install` or `private index`. From a requirements file it can
be `private index, set with --index-url in this file`, `extra index, set with
--extra-index-url in this file`, `--find-links in this file, so pip can install it from
elsewhere`, `--no-index in this file, so pip doesn't install it from PyPI`, `-r in this file
brings in a file Garnet can't follow (it doesn't exist), which can set another index` (or
`-c`, with the reason in brackets) or `an option Garnet can't read (<option>), so the index is
unknown`. For an option in another file of the include tree, "this file" is that file's
path, such as `private index, set with --index-url in requirements/base.txt, which this file
brings in`. From package-lock.json and
yarn.lock it can also be `private registry`, `file: source`, `tarball URL outside the npm
registry`, `bundled in <package>, checked only as part of it`, `resolved URL isn't this
package's registry tarball` or `not a valid npm package name`; an invalid name is shown as
`(invalid name)`, and the lockfile line points at it. From pnpm-lock.yaml and a Yarn 2+
yarn.lock it can also be `private registry, set in .npmrc` (or `pnpm-workspace.yaml`,
`.yarnrc.yml`), `JSR registry, pnpm's default for @jsr packages` (or `Yarn's default`),
`exec: source`, `link: outside the project`, `portal: outside the project` or `patch file
outside the project`. The JSON report also gives the file and line in the evidence.

## How to resolve it

Nothing to do if you meant it. Review changes to that dependency by hand, as you would
any vendored code. A bundled dependency changes only with the package that ships it, so
review that package's update, or the lockfile edit itself if that package didn't change.

## Allowlisting

This rule reports at `info`, which doesn't change the verdict. To hide it, turn it off
in policy:

```toml
[garnet.rules]
"GRN-E005" = "off"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## What it doesn't check

- **pip's settings outside the file.** `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`,
  `PIP_FIND_LINKS`, `PIP_NO_INDEX` and the same keys in `pip.conf` change where pip installs
  from for every file, and `garnet check` doesn't see them. `garnet pip install` doesn't read
  them either, but it checks what pip's own resolution says it will install, so a package
  from another index is reported there.
- **Several files on one command line.** `pip install -r a.txt -r b.txt` reads both files
  with one index setting, so an index set in `b.txt` applies to `a.txt`'s pins too. Garnet
  knows only the includes each file names, not how files are put together on a command line.
- **Environment variables.** pip expands `${VAR}` in a requirements file, so a line such as
  `${PIP_ARGS}` can turn into an index option. Garnet reads the line as written; an include
  path with `${` in it isn't followed.

## See also

- `garnet explain GRN-E005` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
