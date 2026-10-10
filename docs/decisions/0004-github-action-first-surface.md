# 0004. First surface is a GitHub Action on dependency PRs

- Status: Accepted
- Date: 2026-10-10

## Context

Dependency updates land in Dependabot and Renovate PRs, and cooldowns already give a check time to run there. A PR comment is visible to the whole team, which helps Garnet spread. An install wrapper changes every developer's workflow and is harder to adopt first.

## Decision

Ship the engine and CLI in month 1, the GitHub Action in month 2 as the primary way to use Garnet, and the install wrapper and agent hooks in month 3. All surfaces call the same `evaluate()`.

## Consequences

The Action's security (token scope, pwn-request avoidance, Dependabot's restricted token) is a first-class design concern. Non-GitHub CI users rely on the CLI until later.
