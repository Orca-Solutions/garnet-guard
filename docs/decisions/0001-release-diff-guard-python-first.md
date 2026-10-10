# 0001. Garnet is a release-diff guard, Python first

- Status: Accepted
- Date: 2026-10-10

## Context

The first idea was an install wrapper that blocks malware and brand-new packages. By late 2026 that is covered: Socket Firewall Free and Aikido Safe Chain block known malware for free, every major package manager ships a minimum-release-age cooldown, and npm 12 disables install scripts by default. What remains open is judging a new release of an already-trusted package. pip and uv don't verify PEP 740 attestations, and only pnpm has a trust-downgrade check. The 2026 PyPI incidents (lightning, elementary-data) used import-time and `.pth` payloads that no install-script setting stops.

## Decision

Build a guard that diffs each new release against the last trusted one on trust signals and content, plus open known-bad data. Python (pip, uv, Poetry) first; npm in month 2.

## Consequences

Python's smaller audience is accepted in exchange for the biggest open gap. Diffing wheels and sdists is more work than querying an API. False-positive rate becomes the main product risk, so a backtest corpus is part of the MVP.
