# Garnet Guard founding principles

These are the commitments Garnet is built on. When a decision is unclear, the answer should follow from one of them. Changing this file needs an ADR with public comment (see [GOVERNANCE.md](GOVERNANCE.md)).

## What Garnet is for

1. **Impact first.** Garnet exists to make dependency updates safer for as many projects as possible. Income is welcome when it funds that, never when it competes with it.
2. **Diff, don't scan.** Judge a release against the release it replaces. This catches attacks no feed knows yet and keeps findings few.
3. **Fill the gap, not the category.** Garnet does one thing nobody else does well: compare a new release with the last trusted one. It complements cooldowns, CVE scanners and malware feeds rather than competing with them.

## How it behaves

4. **Quiet on clean updates.** A warning nobody believes is worse than none. A false positive is a bug, fixed with the same urgency as a missed detection.
5. **Every finding explains itself.** Rule ID, evidence (a file and line, an attestation field, a missing tag), why it matters, and what to do.
6. **Never say "safe".** Garnet reports what it found and what it couldn't check. "Couldn't check" is never reported as "pass".
7. **Warn by default, block by choice.** Users decide what blocks. Only cryptographic failures and confirmed malware block by default.
8. **Never execute what we inspect.** Static analysis only, in a hardened reader, with limits on everything.

Garnet Guard's voice follows from these principles; see [brand-kit.md](https://github.com/orca-solutions/gg-landing/blob/main/brand/brand-kit.md) in the gg-landing repository.

## How it's built

9. **Hold ourselves to the bar we check.** Trusted Publishing, attestations, hash-pinned dependencies, SHA-pinned Actions, a small dependency tree, and Garnet guarding its own repo.
10. **Measure before claiming.** Every rule ships with fixtures and a backtest delta. Every public "would have caught" has a replay link.
11. **Stable interfaces.** Rule IDs are permanent. The policy format, JSON schema and Action inputs change only with deprecation.
12. **Humans are accountable.** AI agents write much of the code. A human maintainer reviews and merges every change, and owns the result.

## How it's shared

13. **Open and neutral.** Apache-2.0, no telemetry, no account, no API key, no single vendor's feed. Known-bad data comes from open sources.
14. **Detection is never paywalled.** Every rule ships in the open engine. A paid hosted service may sell coordination, history across organizations and convenience, never better detection. See [OPEN_CORE.md](OPEN_CORE.md).
15. **Disclose responsibly.** A Garnet warning is a reason to look, not proof of compromise. Unconfirmed findings about someone else's release go privately to the maintainer and registry first.
16. **Credit the work we build on.** PyPI, Sigstore, OpenSSF, OSV and the researchers who documented each incident made Garnet possible, and the docs say so.
17. **Aim upstream.** The best long-term outcome is that pip, uv and npm adopt these checks natively and Garnet becomes the policy and history layer above them.
