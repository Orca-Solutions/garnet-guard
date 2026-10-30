---
id: GRN-T001
name: lost-provenance
kind: diff
default_severity: warn
status: implemented
---

# GRN-T001 lost-provenance

| | |
|---|---|
| Default severity | `warn` |
| Kind | diff rule: fires only when the trusted version had the property and the new version lost it, or the new version gained a risky property the trusted version lacked. |
| Status | Implemented in 0.1 |

## What it checks

Every file of the trusted version had a verified attestation (a Sigstore-signed statement
of which repository and workflow built it: PEP 740 provenance on PyPI, npm provenance on
npm), and at least one file of the new version has none.

A project that has never attested its releases is not flagged. The rule only looks for
attestations that went away.

On npm, a version document can list an attestation that the registry's attestations
endpoint doesn't serve (whatwg-url 17.1.1 answers HTTP 404). Garnet Guard can't verify an
attestation it can't fetch, so the file counts as missing one, and the finding says the
registry lists it: "have no attestation served", with the 404 on the evidence line.

## Why it matters

An attestation ties a file to the CI run that built it. When a project has been
publishing from CI with attestations and a new file arrives without one, that file was
most likely uploaded some other way, for example with a leaked or stolen API token. Token
uploads are the most common way a trusted package gets a malicious release.

## Example finding

From the [replay](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/npm-incidents.toml)
of nx 21.5.0 ([MAL-2025-41439](https://osv.dev/vulnerability/MAL-2025-41439)), uploaded with
a stolen npm token on 2025-08-26. nx had published 21.4.1 from GitHub Actions with
provenance; the registry record for 21.5.0 had none, as the
[Nx postmortem](https://nx.dev/blog/s1ngularity-postmortem) notes.

```text
nx 21.4.1 → 21.5.0: WARN
  WARN  GRN-T001 lost-provenance: 1 file(s) in 21.5.0 have no attestation; every file of 21.4.1 had one
           - nx-21.5.0.tgz: no attestation
           - 21.4.1 was attested by github.com/nrwl/nx .github/workflows/publish.yml
```

In the replay of lightning 2.6.2 and 2.6.3, also uploaded with a stolen token, this rule
could not fire: lightning had not attested releases before the incident, so there was no
provenance to lose. [GRN-T004](GRN-T004.md) and [GRN-C003](GRN-C003.md) reported those
releases instead ([replay](https://github.com/orca-solutions/garnet-guard/blob/main/backtest/incidents.toml)).

On PyPI, from the replay of ultralytics 8.3.45
([PYSEC-2024-154](https://osv.dev/vulnerability/PYSEC-2024-154)). ultralytics published 8.3.44
through Trusted Publishing with attestations; 8.3.45 was uploaded with a PyPI API token left in
CI from before Trusted Publishing. PyPI no longer serves provenance for the removed release, so
the replay records its missing attestations from
[PyPI's analysis](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/).

```text
ultralytics 8.3.44 → 8.3.45: WARN
  WARN  GRN-T001 lost-provenance: 2 file(s) in 8.3.45 have no attestation; every file of 8.3.44 had one
           - ultralytics-8.3.45-py3-none-any.whl: no attestation
           - ultralytics-8.3.45.tar.gz: no attestation
           - 8.3.44 was attested by github.com/ultralytics/ultralytics .github/workflows/publish.yml
```

The same rule reported ultralytics 8.3.46. It couldn't fire for the other replayed
token uploads (lightning, litellm, telnyx, xinference, mistralai, durabletask and others):
none of those projects attested releases before the attack, so there was no provenance to
lose. Nor could it fire for ultralytics 8.3.41 and 8.3.42, which the project's own hijacked
workflow built and attested.

## How to resolve it

1. Don't merge yet.
2. Look for a release workflow run and a git tag for the new version in the project's
   repository. A tag and a matching run point to a CI problem; neither points to a manual upload.
3. Check the project's issue tracker and security advisories.
4. If the maintainers confirm they published this version by hand, merge and add a
   time-limited ignore (below) for this version only.

## Allowlisting

Once you've reviewed a release, ignore this rule for that package and version range.
Every ignore needs a reason and an expiry date; after `until` it stops applying and the
report notes that it expired.

```toml
[[garnet.ignore]]
package = "examplelib"
versions = "==2.6.2"
rules = ["GRN-T001"]
reason = "maintainers confirmed a manual release in example/examplelib#123"
until = "2027-06-30"
```

To change the rule's severity for every package instead:

```toml
[garnet.rules]
"GRN-T001" = "block"   # "off" | "info" | "warn" | "block"
```

Suppressed findings still appear in JSON and SARIF output, marked with the ignore that
matched. How to write one is in [the policy guide](../policy.md); the format is in
[SPEC §7](../SPEC-v1.md#7-policy).

## See also

- `garnet explain GRN-T001` prints this rule's summary in your terminal.
- [SPEC §6.2](../SPEC-v1.md#62-rule-catalog), the normative rule catalog.
- [All rules](README.md)
