# Garnet Guard threat model

Garnet is a security tool that downloads hostile files and runs with write access to pull requests. This document says what Garnet defends against, what it doesn't, and how Garnet keeps from becoming the attack vector.

## Part 1: what Garnet detects

### Attacker we target

Someone who gains the ability to publish a new version of a **legitimate, already-trusted package**, by any of:

| Path | Example | Garnet signals |
|---|---|---|
| Stolen or leaked long-lived publish token | lightning 2.6.2/2.6.3 | Lost provenance (T001), outside Trusted Publishing (T005), no matching tag (T004) |
| Hijacked maintainer account (phishing, session theft) | chalk/debug, Sept 2025 | Lost provenance, new install script or obfuscated code (C002, C005) |
| Compromised CI of the real project (script injection, poisoned action) | elementary-data 0.23.3 | Provenance looks valid, so content rules carry it: new `.pth` (C001), new import-time exec (C003) |
| Moved publishing to a fork or new repo | repo-jacking variants | Publisher changed (T002), workflow changed (T003) |
| Known-bad release already listed | any feed-confirmed case | OSV `MAL-` match (K001) |

The design bet: an attacker can fake a lot, but it is hard to fake *both* "same publisher identity as last time" *and* "content changes that look like a normal release".

### Out of scope

- **Malicious first versions** of new packages, typosquats and slopsquats. Cooldowns and malware feeds cover these; Garnet can still report K001 if a feed has it.
- **Long-standing malicious code** that was already in the baseline. Garnet trusts the baseline by definition.
- **A compromise that changes nothing Garnet looks at:** a valid attestation from the real workflow, a matching tag, and a malicious change that reads like normal code in a non-import-time path. Garnet lowers risk; it does not prove safety. Reports must never say "safe".
- **Registry or Sigstore compromise.** Garnet relies on PyPI, npm and Sigstore being honest about what they serve and sign.
- **Runtime behavior.** No sandbox, no dynamic analysis.

### Evasion

Rules are public, so attackers can read them. Responses:

- Lean on trust signals that require control of the real publisher identity, not on content patterns alone.
- Rules run on *changes*, so hiding a payload means making it look like an ordinary diff, which raises the cost.
- Novel bypasses are reported privately (see [SECURITY.md](SECURITY.md)) and land with a backtest fixture.

## Part 2: protecting Garnet itself

### Assets

- The CI environments and developer machines that run Garnet.
- The `GITHUB_TOKEN` and any tokens the Action receives.
- The integrity of Garnet's verdicts. A forged "pass" is the worst outcome.
- Garnet's own release pipeline on PyPI and the Action's repository.

### Threats and mitigations

| Threat | Mitigation |
|---|---|
| A hostile package exploits Garnet's parser (zip bomb, path traversal, symlink, huge file, pathological AST) | All archive access goes through `safe_archive.py` with size, ratio, count and depth limits. No links or device files. `ast` parsing has size and time limits. Fuzz tests on the archive and lockfile parsers. |
| Garnet executes package code by accident (importing a module, running a build backend to get metadata) | Hard invariant: no execution. Metadata comes from the registry and static files (`METADATA`, `pyproject.toml`, `package.json`). A test asserts no subprocess or import of inspected content. |
| A malicious PR abuses the Action (pwn request) | No `pull_request_target` with PR checkout. Least-privilege tokens. Comments are posted from a job that never executes PR content. Report text from packages is escaped in markdown. |
| Markdown or terminal injection via package names, file names or metadata | Every string from a package is escaped before rendering in comments, SARIF and terminals. |
| Network attacker tampers with downloads | HTTPS only. Downloaded files are checked against the registry's published hashes before inspection. |
| Garnet's own dependencies are compromised | Small dependency set. Hash-pinned lock (`uv.lock`) in CI and releases. Garnet runs Garnet on its own dependency PRs. New runtime dependencies require an ADR. |
| Garnet's release is hijacked | PyPI Trusted Publishing from a protected environment with required reviewer, PEP 740 attestations on every file, signed tags, 2FA and hardware keys on maintainer accounts, no long-lived publish tokens. |
| The Action repo is tampered with | Users pin by commit SHA in docs. Branch protection and signed commits on main. Release tags are immutable. |
| AI agents introduce a subtle weakness | Agents never merge. Changes to `safe_archive.py`, the Action, release workflows and policy defaults require a careful human review (see [AGENTS.md](AGENTS.md)). |
| An upstream outage silently weakens results | "Couldn't check" is reported as an error finding, never as pass. |

### Privacy

Garnet sends only what it needs to public registries and GitHub (package names, versions, file names). It has no telemetry. The hosted app, when it exists, will document exactly what it stores.
