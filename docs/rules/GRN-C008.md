---
id: GRN-C008
name: new-dependency
kind: diff
default_severity: warn
status: implemented
---

# GRN-C008 new-dependency

| | |
|---|---|
| Default severity | `warn` for a dependency that is new to the registry, missing from it, or installed from outside it; `info` for an established one, and for a new one from the trusted package's owner when every release of it that Garnet reads (every published version its range admits, or the lockfile's pins) has no install-time hook and provenance from the trusted package's repository |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.2; the shared-owner check is new in 0.3 |

## What it checks

Garnet reads the dependencies each version declares: `Requires-Dist` in the wheel's
`METADATA` on PyPI, and `dependencies`, `optionalDependencies` and `peerDependencies` in
the tarball's `package.json` on npm. A dependency only installed with an extra, or a peer
marked optional, is left out. For every dependency the new version declares and the trusted
version didn't, Garnet asks the registry when the package was first released, how many
releases it has, which repository it names and which accounts own it.

The rule reports every new dependency. It keeps its `warn` severity when the new dependency:

- isn't on the registry at all;
- installs from outside the registry: a git repository, a URL or a local path;
- is declared a second time to install something else: another package under an npm alias
  (`"helper": "^1"` with `"helper": "npm:other@^1"` in `optionalDependencies`, which npm
  installs in its place), a repository, a URL or a path. Garnet doesn't look up what that
  second declaration installs. This applies to a dependency the trusted version had, too, when
  the second declaration is new;
- was first released less than 90 days before the new version, or after it.

On npm the first release is the date the registry created the package's record. When a name
was unpublished and created again, the registry still lists the dates of the versions that
were removed. The evidence then says "earliest version still published" and names the older
versions, and the 90 days count from the current record: a name that was taken down and came
back is no reason to look less closely.

### A young dependency from the trusted package's owner

Maintainers who split code into a helper package often publish it the same day as the release
that uses it. An attacker who holds a maintainer's account can do the same, so a shared owner
alone never lowers the finding. When an account that owns the trusted package owns the young
dependency too, Garnet reads the releases of it listed below, and reports the dependency at
`info` only when all of these hold for every one of them:

- **No install-time hook.** On npm, neither the tarball's `package.json` nor the registry's copy
  of it has a `preinstall`, `install` or `postinstall` script, and there is no `binding.gyp`, in
  any case, at the package root. With a `binding.gyp` and no `install` or `preinstall` script,
  npm runs `node-gyp rebuild` on its own (`@npmcli/run-script` and arborist's rebuild step),
  unless `package.json` sets `"gypfile": false`. A tarball whose files don't all sit under one
  top-level folder isn't read, since npm could install another `package.json` from it.
- **Nothing to build or run on PyPI.** The release has a wheel tagged `py3-none-any`
  (`py2.py3-none-any` counts), so pip installs the same wheel on every platform with Python 3.
  Otherwise pip builds the sdist where no wheel fits and runs its build code, or, with no sdist,
  installs another version there. Its Requires-Python admits every CPython release supported
  today, tested at 3.11.0 to 3.11.50 and so on for each of 3.11 to 3.15 (so `!=3.12.4` or
  `<=3.15` keeps `warn`); on a Python it leaves out, pip installs another version. No wheel
  installs anything Python reads or runs at every start: a `.pth` file at the top of
  site-packages, or anything that imports as `sitecustomize` or `usercustomize` from there,
  matched by its first path part up to the first dot, in any case: a module
  (`sitecustomize.py`), a package (`sitecustomize/__init__.py`), compiled code
  (`sitecustomize.pyc`) or an extension module
  (`sitecustomize.cpython-312-x86_64-linux-gnu.so`, `sitecustomize.abi3.so`,
  `sitecustomize.pyd`). The same goes under `<name>.data/purelib/` and `platlib/`, which install
  into site-packages, and anywhere under `<name>.data/data/`, which installs relative to the
  environment and can land there.
- **Provenance from the trusted package's repository.** Every file of the release has an
  attestation that verifies with Sigstore (npm provenance, PEP 740 on PyPI), from a repository
  the trusted version's own verified attestations name, or, on github.com, from the same GitHub
  repository id after a rename. A trusted version with no verified provenance gives nothing to
  match, so the dependency keeps `warn`.
- **One requirement.** The new version declares the dependency once, with no environment
  marker, and doesn't bundle it. A second requirement for the same name (another
  `Requires-Dist` line, one that needs an extra such as `helper>=2; extra == "x"`, which
  installs for users of `demo[x]`, or the name in both `dependencies` and
  `optionalDependencies`), a second requirement on npm that installs the
  same registry package under an alias (`"helper": "^1"` and `"h2": "npm:helper@^2"`, matched
  by the alias target, lowercased), or a marker makes the release that installs depend on how
  they combine or on the machine, so the dependency keeps `warn` without a lookup. So does a
  name in `bundleDependencies` (or `bundledDependencies`, or either set to `true`): the copy
  packed in the new version's tarball installs, not a registry release.

The releases Garnet reads are these. It doesn't work out which one an installer would pick:
that depends on dist-tags, deprecations, `engines`, yanks, resolution strategy (uv's
`lowest`) and what is already installed, so it reads every version the range admits instead.

- Under `garnet check`, when the dependency is pinned in every lockfile the change comes from,
  with no environment marker on the pin (a `;` marker in a requirements file, `marker` in
  `pylock.toml`, `resolution-markers` in `uv.lock`), the pinned versions. Pins in other
  lockfiles of the repository aren't used. npm lockfiles (package-lock.json, yarn.lock,
  pnpm-lock.yaml) aren't used for versions, since a package can sit in the tree several times,
  aliased or bundled; the range is read instead.
- Nothing is read, and the dependency keeps `warn`, when a lockfile the change comes from has
  anything that could install a package from somewhere Garnet doesn't look: in a requirements
  file, any option line but `--hash` (pip accepts abbreviated options and attached values, such
  as `--extra-ind` or `-ihttps://…`, and `-r` or `-c` bring in files) or any URL, path or
  editable requirement; in any lockfile, any entry from outside the registry (git, a URL, a
  path, another index, an npm alias whose tarball is another package, a bundled copy). Garnet
  doesn't work out which name such an entry installs under or which dependency it serves.
- `garnet pip install` reads the versions its resolution installs from PyPI files; a file from
  another index, or a package already installed (pip doesn't record which index it came from),
  keeps `warn`. `garnet uv` reads the new `uv.lock` by the same rules as `garnet check`.
- Otherwise, every version the registry lists that the requirement admits, whenever it was
  published, up to the time of the lookup. On npm the range follows node-semver's rules, with
  prereleases only when the range names one. A spec that admits any version (`*`, `x`, an
  empty range, `latest`, or a bare `npm:helper` alias) installs whatever the `latest`
  dist-tag points to, even a prerelease, so every version is read, prereleases too. Any other
  dist-tag is a range Garnet can't read. On PyPI it is the
  requirement's specifier over every version with a file, prereleases and yanked releases
  included.
- More than 5 such releases aren't read, so the dependency keeps `warn`, and the evidence says
  how many there were. A helper that is less than 90 days old rarely has more.

Anything Garnet couldn't check keeps `warn`: a registry lookup or download that failed, or a
response it couldn't read (both also GRN-E001), an attestation that couldn't be verified, a range
Garnet can't read, a tarball that doesn't match its integrity hash, more than 5 releases to read,
or a release with more than 10 wheels. The files and attestations checked are the ones the
registry lists at the time of the lookup. The evidence line says which way it went and why, for
example `info: same owner, no install scripts, provenance from
github.com/TooTallNate/proxy-agents, in proxy-agent-negotiate 1.1.0, the only published
version matching proxy-agent-negotiate@1.1.0`, or
`kept at warn: httpx2 2.9.1 has provenance naming github.com/pydantic/httpx2, not
github.com/modelcontextprotocol/python-sdk like mcp 1.30.0`.

Owners are registry accounts: the owner and maintainer roles and organization on PyPI, the
maintainers on npm.

An established dependency is reported at `info`.

A dependency the trusted version already had is reported when it now installs from
somewhere else: from a git repository or URL, or, on npm, a different package under the same
name (`"lodash": "npm:other-package@1"`). An npm alias that is new is looked up under the
package it installs.

A failed registry lookup is GRN-E001, and the dependency is listed with a note that the
registry wasn't consulted. It is never passed.

## Why it matters

A dependency installs with the package that declares it, and a new one gets no comparison
of its own: Garnet has no trusted version of it to diff against. Adding a package the attacker
controls is a quiet way to carry a payload into a trusted one. The trusted package's own
diff shows one new line in its metadata, and the payload can arrive later, in a release of
the new dependency.

event-stream 3.3.6 (npm, September 2018) did this. It added `flatmap-stream`, a package
first published five weeks earlier. A month later, `flatmap-stream` 0.1.1 shipped encrypted
code that stole bitcoin from users of one wallet app. event-stream never tagged its 3.3.x
releases or used provenance, so no trust rule had anything to compare; the new dependency
was the change to see.

## Example finding

From the [replay](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/npm-incidents.toml)
of event-stream 3.3.6 ([GHSA-mh6f-8j2x-4483](https://osv.dev/vulnerability/GHSA-mh6f-8j2x-4483)):

```text
event-stream 3.3.5 → 3.3.6: WARN
  WARN  GRN-C008 new-dependency: 3.3.6 depends on 1 package(s) that 3.3.5 didn't; flatmap-stream was first released 35 day(s) before it
           - flatmap-stream@^0.1.0: first released 2018-08-05, 35 day(s) before 3.3.6; 1 release(s); github.com/hugeglass/flatmap-stream <https://www.npmjs.com/package/flatmap-stream>
```

npm removed event-stream 3.3.6, so the replay uses its `package.json` dependencies as
committed in the change that added `flatmap-stream`, and `flatmap-stream`'s registry record as
the write-ups describe it on the day. The write-ups don't name the npm account that published it,
so the replay records no owner.

## How to resolve it

1. Open the new dependency's registry page and repository; the evidence links to the page.
2. Check who publishes it, how long it has existed and why this release needs it. The
   release notes, or the commit that added the dependency, should say.
3. A package a few weeks old, with no repository, one release and owners you don't recognize,
   needs a look before the update merges. A dependency installed from a URL or a git
   repository gets none of Garnet's checks; read what it points to.
4. If it is expected, merge and add a time-limited ignore with the reason.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-C008"]
reason = "new helper package split out of examplelib by its maintainers, see the 2.6.2 notes"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-C008" = "info"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## What it doesn't check

- **The new dependency's code.** Garnet reports that it was added and what the registry says
  about it. For a young dependency from the trusted package's owner it reads those releases'
  install scripts, file lists and provenance, never their code.
- **Releases published after the check.** The lookup sees the releases that existed when it
  ran. A helper release published later, which the range also allows, installs without this
  rule having seen it unless a lockfile pins the helper. Once your lockfile pins it, moving the
  pin to a new release is an update Garnet checks, with the release pinned before as the trusted
  one. A package that is new to the lockfile has no trusted release there, so it gets only the
  rules that need none; for a young helper from the trusted package's owner, this rule reads the
  pinned version itself.
- **Which release installs.** Garnet reads every release the range admits, not the one an
  installer would choose, and doesn't read releases outside the range that a lockfile or an
  override (npm `overrides`, pip constraints) could install instead. A requirement that needs
  an extra counts only as a second declaration of a dependency the new version also requires
  without one; a dependency installed only with an extra isn't reported. A bundled copy
  (`bundleDependencies`) isn't read: the rule keeps `warn` for a young one from the trusted
  package's owner, and reports any other one as it would a registry dependency.
- **A changed version range** of a dependency the trusted version already had.
- **An sdist without fixed metadata.** When a release has no wheel, the sdist's `PKG-INFO` is
  used only from metadata version 2.2 onwards and only when `Requires-Dist` isn't listed as
  `Dynamic`. Older sdists don't record their dependencies reliably, and Garnet never runs
  `setup.py` to find out, so the rule doesn't run on them.
- **Owners are today's.** The registry says who owns a dependency now, not on the day of the
  release, so the "also owns" line in the evidence can be out of date, and so can the owner that
  lets a young dependency drop to `info`. A dependency's age is measured from its earliest file
  still on the registry.

## See also

- `garnet explain GRN-C008` prints this rule's summary in your terminal.
- [GRN-C002](GRN-C002.md), which reports new install-time scripts.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
