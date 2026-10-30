---
id: GRN-C011
name: new-js-capability
kind: diff
default_severity: info
status: implemented
---

# GRN-C011 new-js-capability

| | |
|---|---|
| Default severity | `info` |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.2 (npm) |

## What it checks

Garnet reads the JavaScript an npm package loads and lists what it reaches for:

- **Modules** that start processes or reach the network or run code: `child_process`,
  `cluster`, `worker_threads`, `net`, `dgram`, `dns`, `http`, `http2`, `https`, `tls` and
  `vm`, with or without the `node:` prefix, through `require`, `import`, `import()` or
  `export … from`.
- **Globals**: `eval(…)` and `Function(…)`, which run a string as code, `fetch(…)`,
  `XMLHttpRequest` and `WebSocket`.
- **Obfuscated code**: 20 or more variable names of the form `_0x` and hex digits in one file,
  the names javascript-obfuscator gives.

The files are the ones a program loads: those `package.json` names in `main` (`index.js`
when it names none), `module`, `browser`, `bin` and `exports`, and every file they load
through a relative `require` or `import`, as deep as that goes. Files nothing loads, such
as build scripts and tests, aren't read.

The rule compares the new version with the trusted one by name, across the whole package,
and reports each module or global the trusted version didn't use. A call that moved from one
file to another is not new. The evidence shows one place each name is used, and says
whether that code runs when the file loads or sits in a function that waits to be called.

## Why it matters

Code added to a module runs when the package is required, by the app, its tests or a build
tool. npm install scripts (GRN-C002) don't cover it. chalk 5.6.1 and debug 4.4.2 (September
2025) changed only `index.js`, adding an obfuscated line that rewrote browser network calls.
Garnet reports both through the missing git tag (GRN-T004), and the files are gone from the
registry, so the replay can't read them; this rule reads the file itself when it is there.

## Example finding

Illustrative; not from a real release.

```text
examplelib 2.6.1 → 2.6.2: PASS
  info  GRN-C011 new-js-capability: 2.6.2's JavaScript uses child_process, which 2.6.1's didn't
           - lib/telemetry.js:3 loads child_process (when the file loads)
```

An `info` finding doesn't change the verdict; it puts the line in front of the reviewer.

## How to resolve it

1. Open the line the evidence names.
2. Find the commit that added it in the project's repository. A package that never reached the
   network or started processes rarely starts in a patch release, and obfuscated code has no
   ordinary place in a published library.
3. If the repository explains it, merge. If the repository doesn't have the code, or the code
   is obfuscated, don't merge, and tell the maintainers.

## Allowlisting

The rule reports at `info`, so it never fails a check on its own. To make it a warning
for every package:

```toml
[garnet.rules]
"GRN-C011" = "warn"   # "off" | "info" | "warn" | "block"
```

After raising it, ignore it for a package and version range you've reviewed. Every ignore
needs a reason and an expiry date; after `until` it stops applying and the report notes that
it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
ecosystem = "npm"
versions = "==2.6.2"
rules = ["GRN-C011"]
reason = "2.6.2 adds a CLI that runs git, see the commit that added lib/telemetry.js"
until = "2027-06-30"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## What it doesn't check

- **What the code does with the module.** The rule reports that `child_process` is loaded, not
  which command it runs.
- **Names built at run time.** `require("child" + "_process")`, `globalThis["ev" + "al"]` and
  similar aren't resolved. Obfuscators that don't use `_0x` names aren't recognized.
- **Exactly when code runs.** "When the file loads" is a reading of the braces: code inside a
  function body waits to be called, unless the function is called where it is defined, as in
  `(function () { … })()`. A callback passed to code that calls it straight away counts as
  waiting.
- **Files over 16 MB.** A loaded file over the limit isn't read, and the change gets
  GRN-E003 for this rule.
- **TypeScript sources and files a bundler inlined from elsewhere.** The rule reads what the
  tarball ships; a bundled dependency counts as the package's own code.
- **PyPI.** Python code is GRN-C003's.

## See also

- `garnet explain GRN-C011` prints this rule's summary in your terminal.
- [GRN-C002](GRN-C002.md), which reports npm install scripts, and [GRN-C003](GRN-C003.md), its
  Python counterpart.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
