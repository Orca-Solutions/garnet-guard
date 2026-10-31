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
| Default severity | `warn` for a dependency that is new to the registry, missing from it, or installed from outside it; `info` for an established one, and for a new one from the trusted package's owner whose release has no install-time hook and provenance from the trusted package's repository |
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
dependency too, Garnet reads the release of it that the new version would install, and reports
the dependency at `info` only when both of these hold:

- **No install-time hook.** On npm, neither the tarball's `package.json` nor the registry's copy
  of it has a `preinstall`, `install` or `postinstall` script, and there is no `binding.gyp` at
  the package root. With a `binding.gyp` and no `install` or `preinstall` script, npm runs
  `node-gyp rebuild` on its own (`@npmcli/run-script` and arborist's rebuild step), unless
  `package.json` sets `"gypfile": false`. On PyPI, the release has a wheel that fits every
  platform (`py3-none-any` and the like), or no sdist to build: otherwise pip builds the sdist
  somewhere and runs its build code. No wheel installs a `.pth` file into site-packages, which
  Python reads at every start.
- **Provenance from the trusted package's repository.** Every file of that release has an
  attestation that verifies with Sigstore (npm provenance, PEP 740 on PyPI), from a repository
  the trusted version's own verified attestations name, or from the same GitHub repository id
  after a rename. A trusted version with no verified provenance gives nothing to match, so the
  dependency keeps `warn`.

Anything Garnet couldn't check keeps `warn`: a registry lookup or download that failed (which is
also GRN-E001), an attestation that couldn't be verified, a range Garnet can't read, a tarball
that doesn't match its integrity hash, or a release with more than 10 wheels. The evidence line
says which way it went and why, for example
`info: same owner, no install scripts in proxy-agent-negotiate 1.1.0, provenance from
github.com/TooTallNate/proxy-agents`, or `kept at warn: httpx2 2.9.1 has provenance from
github.com/pydantic/httpx2, not github.com/modelcontextprotocol/python-sdk like mcp 1.30.0`.

The release Garnet reads is the newest version that matches the new version's range for the
dependency and was published at or before the new version's first upload: on npm by
node-semver's rules, with prereleases only when the range names one, and `latest` read as the
newest release by then; on PyPI by the requirement's specifier, counting a version from its
first file. That is what an install on the day would have picked unless the npm `latest` tag
pointed elsewhere; neither registry records dist-tags or yanks as they stood then. The files
and attestations checked are the ones the registry lists now.

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
  about it. For a young dependency from the trusted package's owner it reads that release's
  install scripts, file lists and provenance, never its code. When the dependency later
  publishes a bad release, that release is checked as an update of its own if your lockfile
  pins it.
- **Later releases of a helper that dropped to `info`.** The check is of the release the new
  version would have installed on the day. A newer release that the range also allows installs
  without this rule looking at it, unless your lockfile pins it and it is checked as an update.
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
