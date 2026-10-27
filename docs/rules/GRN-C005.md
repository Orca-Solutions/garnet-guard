---
id: GRN-C005
name: obfuscated-blob
kind: diff
default_severity: warn
status: planned
---

# GRN-C005 obfuscated-blob

| | |
|---|---|
| Default severity | `warn` |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Specified for 1.0, not yet implemented |

## What it checks

A changed file gains a string or bytes literal over 2,048 characters with Shannon entropy over
4.5 bits per character, or any such literal is passed to `exec`, `eval`, `compile`,
`base64.*decode`, `zlib.decompress` or `marshal.loads`.

## Why it matters

Encoded payloads hide code from review. Real packages carry large literals (certificates,
lookup tables, test data), but a new high-entropy blob, especially one that is decoded and
run, is the usual shape of a hidden payload.

## Example finding

Illustrative; not from a real release. The rule is specified but not yet implemented.

```text
examplelib 2.6.1 → 2.6.2: WARN
  WARN  GRN-C005 obfuscated-blob: 2.6.2 adds 1 high-entropy literal
           - examplelib/_compat.py:3 bytes literal of 18,240 characters (5.9 bits/char) passed to base64.b64decode
```

## How to resolve it

1. Open the file and see what the literal is and where it goes.
2. Data that is only read (a certificate bundle, a table) is usually fine. Data that is
   decoded and then executed is a reason not to merge.
3. If it is expected, merge and add an ignore for this version.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-C005"]
reason = "vendored certificate bundle in _certs.py, see example/examplelib#700"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-C005" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. The policy format is in [SPEC §7](../SPEC-v1.md#7-policy); 0.1 doesn't read
policy files yet.

## See also

- `garnet explain GRN-C005` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
