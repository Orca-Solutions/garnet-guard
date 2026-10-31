---
id: GRN-C005
name: obfuscated-blob
kind: diff
default_severity: info
status: implemented
---

# GRN-C005 obfuscated-blob

| | |
|---|---|
| Default severity | `info` |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.3 (PyPI) |

## What it checks

Code that runs when a module is imported gains encoded data, or reaches a module or attribute
by a name the source doesn't hold. Garnet reads the same code [GRN-C003](GRN-C003.md) reads:
module top-level code and what it runs, including functions in the package's other modules,
parsed with `ast`. Nothing is imported or run. Three kinds of thing are reported:

- **Encoded literals.** A string or bytes literal with a run of more than 2,048 characters in
  one encoding's alphabet whose entropy is over that alphabet's threshold: hex over 3.0 bits
  per character, base64 (with `+/` or `-_`) over 4.5, base85 and Ascii85 over 5.5. A run
  may be wrapped at a fixed width of 32 characters or more, as base64 encoders and PEM write
  it. A bytes literal that is mostly not text (more than 10% of its bytes outside printable
  ASCII and whitespace) counts as binary, over 4.5 bits per byte. Passed to a decoder
  (`base64.*decode`, `binascii.a2b_*` and `unhexlify`, `bytes.fromhex`, `codecs.decode`,
  `zlib`, `bz2`, `lzma` and `gzip` `decompress`), directly or through a name bound to it, a
  literal counts from 256 characters.
- **Values built from literals that reach code or a name.** `exec`, `eval`, `compile`,
  `marshal.loads` or `pickle.loads` given a value made only from literals with a step that
  disguises it: a decoder, `chr()`, `bytes()`, slicing, xor, a `codecs` rot13 and the like
  (`exec(zlib.decompress(base64.b64decode(BLOB)))`); and `getattr`, `__import__`,
  `importlib.import_module` or `sys.modules` given a name made that way
  (`getattr(os, "".join(map(chr, codes)))`, `getattr(builtins, "cexe"[::-1])`). A name only
  assembled from literals, by concatenation, `%` or `format`, `join`, case changes or
  `strip`, counts when it spells a call in GRN-C003's sensitive call set or the module it
  belongs to (`getattr(os, "sys" + "tem")`, `import_module("o" + "s")`), and not otherwise
  (`import_module(PKG + ".plugins")`, `getattr(self, "_" + "x")`). Where the name is short,
  Garnet works out what it spells from the literals with a fixed set of pure operations,
  capped in size, and the evidence names it: `looks up os.system by a name built with
  map(chr) and .join()`. Decompression and formatting are never worked out.
- **Lookups on `os`, `sys`, `builtins`, `ctypes` or `importlib` by a name not written in the
  source.** `getattr(os, name)`, `vars(os)[name]`, `os.__dict__.get(name)`,
  `sys.modules[name]` and `__builtins__[name]`, on those modules and the modules that define
  what they hold (`posix`, `nt`, `_ctypes`, `importlib.util`, `importlib.machinery`,
  `_frozen_importlib` and the like). A subscript with a literal key counts when the key
  names a call in GRN-C003's [sensitive call set](GRN-C003.md#sensitive-call-set)
  (`__builtins__["exec"]`, `vars(os)["system"]`), which GRN-C003 doesn't follow, and so does
  a name bound once to such a literal (`n = "system"; getattr(os, n)`).

It reports only what the trusted version didn't have. A literal, or a value built from
literals, that any module of the trusted version had is not new, so a blob that moved to
another file is quiet and a blob whose bytes changed is reported. A lookup by a name not in
the source is compared with the same module, or the file it was moved from. A file
byte-identical to one in the trusted version is skipped.

What it leaves out, on purpose:

- **Plain literals and names from variables.** `exec("x = 1")` and `getattr(os, "system")`
  name what they run, and GRN-C003 reports them. So does `exec("x" + " = 1")`, which only
  assembles its text. `importlib.import_module(name)` with a name
  read from entry points or configuration, an f-string or `"pkg." + name` with a variable in
  it, and `getattr(module, attr)` on any module other than the five above (a dispatch table)
  are what plugin loaders do, and stay quiet here.
- **A module looking itself up.** `sys.modules[__name__]`, `sys.modules[__package__]`,
  `sys.modules[__spec__.name]` and `sys.modules[cls.__module__]`, and stores into
  `sys.modules`.
- **Certificates and keys.** A PEM block (`-----BEGIN ...-----` to `-----END ...-----`)
  doesn't count as an encoded literal, and neither does decoding one, since that is what
  certificates and keys are for. A value built from one that reaches `exec` still counts.
- **Text that isn't an encoding.** Templates, HTML, documentation, regular expressions and
  word lists have spaces, short lines or characters outside the alphabets, and stay quiet
  whatever their entropy: in Garnet's own measurement, Python's standard library and about
  200 installed packages had 83 literals over 2,048 characters and 4.5 bits per character,
  every one of them text of that kind.
- **Code that doesn't run at import**, as in GRN-C003: test files nothing else imports
  (`tests/`, a top-level `test/`, `test_*.py`, `conftest.py`), sdist files outside the
  package (`docs/conf.py`, `examples/`), a function only handed to a call not known to run
  it (`functools.partial(f)`), and code under `if __name__ == "__main__":`. A literal in a
  function nothing calls at import isn't read either; when that function decodes a
  module-level constant, the constant is.
- **A name bound more than once.** A name assigned in two places (`import builtins as m`
  and later `m = __import__(x)`) may hold either value, and Garnet can't tell which without
  running the code, so it isn't read as a module or a literal.
- **npm.** The rule reads Python. [GRN-C011](GRN-C011.md) lists, at `info`, JavaScript with
  names in the shape javascript-obfuscator writes; encoded literals and computed lookups in
  JavaScript aren't read yet.

The thresholds are those of set `2026-10-a`, and `garnet explain GRN-C005` prints them.

## Why it matters

Encoding a payload, or building the name of the call it makes, hides it from a reviewer and
from rules that match names. GRN-C003 reads `getattr(os, "system")`, but not
`getattr(os, "".join(map(chr, [115, 121, 115, 116, 101, 109])))`, and it reports
`exec(base64.b64decode(...))` by the `exec`, not by what the literal holds. Packages also
embed data (certificate bundles, fonts, compressed tables, images in templates) and look
names up in plugin loaders and compatibility shims, so this rule reports at `info`: it never
changes a verdict on its own, and next to a GRN-C003 warning it shows what the warned call
runs.

## Example finding

Illustrative; not from a real release.

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-C003 new-import-time-exec: 2.6.2 adds import-time calls to sensitive APIs in 1 module(s)
           - new module examplelib/_compat.py:4 calls exec
           - new module examplelib/_compat.py:4 calls base64.b64decode → exec
  info  GRN-C005 obfuscated-blob: 2.6.2 adds encoded literals or computed lookups at import in 1 module(s)
           - new module examplelib/_compat.py:3 has a base64 literal of 18,240 characters (6.0 bits per character)
           - new module examplelib/_compat.py:4 runs exec on a value built from literals with base64.b64decode and zlib.decompress, from a base64 literal of 18,240 characters (6.0 bits per character)
```

## How to resolve it

1. Open the line the evidence names and see what the literal is, and where the value goes.
2. Decode the literal, or work out the name, with a separate tool: never by importing the
   package or running its code.
3. Data that is only read (a certificate bundle, a table, an image) is usually fine. Code
   that is decoded and run at import, or a sensitive call reached through a built name, that
   the repository at the release's tag doesn't explain is a reason not to merge.
4. If it is expected, merge and add an ignore for this version.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-C005"]
reason = "vendored font table in _fonts.py, see example/examplelib#700"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-C005" = "warn"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## See also

- `garnet explain GRN-C005` prints this rule's summary and thresholds in your terminal.
- [GRN-C003](GRN-C003.md), which reports the sensitive calls these values and names reach.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
