# Architecture decision records

Each significant decision gets a short record: context, decision, consequences. Records are never deleted; a reversed decision gets a new ADR that supersedes the old one. Copy [template.md](template.md) and take the next number.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-release-diff-guard-python-first.md) | Garnet is a release-diff guard, Python first, npm second | Accepted |
| [0002](0002-implementation-in-python.md) | Implement in Python, distribute with uv | Accepted |
| [0003](0003-apache-2-and-dco.md) | Apache-2.0 license with DCO sign-off, no CLA | Accepted |
| [0004](0004-github-action-first-surface.md) | First surface is a GitHub Action on dependency PRs | Accepted |
| [0005](0005-never-execute-package-code.md) | Static analysis only, never execute inspected code | Accepted |
| [0006](0006-open-core-boundary.md) | Open core: all detection free, hosted app sells coordination | Accepted |
| [0007](0007-distribution-name.md) | Name Garnet Guard; publish as `garnet-guard`, import as `garnet_guard` | Accepted |
| [0008](0008-no-telemetry.md) | No telemetry in the open-source tool | Accepted |
| [0009](0009-trust-history-boundary.md) | Per-package registry history free; cross-org observed history hosted | Accepted |
| [0010](0010-funding-gates.md) | Go/no-go gates for the hosted app in months 4 and 6 | Accepted |
| [0011](0011-public-from-day-one.md) | Build in public from day one | Accepted |
| [0012](0012-pricing-shape.md) | Four hosted tiers sized by active developers; Business in size bands; public repos never charged | Accepted (prices are a working draft) |
| [0013](0013-brand-identity.md) | Brand identity: pomegranate mark, palette, tagline, trademarks | Accepted |

The [v1.0 specification](../SPEC-v1.md) and [code design](../API.md) sit beside these records.
