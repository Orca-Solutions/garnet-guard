# Garnet Guard governance

## Today

Garnet has one maintainer, Jason (GitHub: @jfricano), who has final say on design, releases and the roadmap. Development uses AI coding agents (Codex and Claude Code), which open pull requests. The maintainer reviews and merges every change; agents never merge.

## How decisions are made

- **Everyday changes** happen in pull requests.
- **Significant decisions** (new ecosystem, new runtime dependency, change to a rule's default severity, anything touching the open-core boundary, any change to this file) are written up as an Architecture Decision Record in `docs/decisions/`, opened as a PR, and left open for comment for at least 7 days once the project has outside contributors.
- **Rule IDs, the JSON report schema and the policy format** are public interfaces. After 1.0 they change only with a deprecation period.

## Becoming a maintainer

Anyone who has made sustained, high-quality contributions (code, rules, triage or reviews) over a few months can be invited as a maintainer by the existing maintainers. Maintainers get commit access and review rights, and must use 2FA with a hardware key or passkey.

## Where this is headed

The goal is neutral, community governance. Once Garnet has at least two active maintainers, preferably from different organizations, it will apply to become an OpenSSF sandbox project and adopt a multi-maintainer model with lazy consensus and maintainer votes for disputes.

## Relationship to the hosted service

The paid Garnet Guard App may be run by the maintainer or a company they control. It does not get special say over the open-source project. The commitments in [OPEN_CORE.md](OPEN_CORE.md) are part of this governance and can only be changed by an ADR with public comment.
