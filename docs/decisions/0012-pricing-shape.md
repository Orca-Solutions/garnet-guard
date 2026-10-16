# 0012. Pricing shape for the hosted app

- Status: Accepted (tier shape); price table superseded by 0015
- Date: 2026-10-10

## Context

If the hosted app passes Gate A and Gate B (ADR-0010), it needs a pricing shape. Jason first accepted flat per-org tiers, then reshaped them the same day into four tiers sized by developers. Business was briefly priced per developer, then moved to size bands so that normal team turnover doesn't change the bill month to month. plans/monetization.md holds the detailed table and reasoning.

## Decision

| Tier | Who | Price (working draft) |
|---|---|---|
| Free | Up to 10 developers | $0, limited hosted features |
| Team | Up to 10 developers | ~$99/month, all Business features |
| Business | 11 to 250 developers | 11–25 $199, 26–50 $449, 51–100 $899, 101–250 $1,999 a month |
| Enterprise | Over 250 developers | Call us |

- "Developers" means active committers to private repositories where the app is installed, in the last 90 days. No seat admin.
- Public repositories are never counted and never charged.
- Alerts on already-merged versions that are flagged later are paid, from Team up.
- Tiers limit hosted conveniences only. The open-source engine and every rule are free on every tier (OPEN_CORE.md commitment 1).

## Consequences

Small teams and open source get the hosted app free. Band edges keep price steps predictable. Final numbers come from design-partner pilots.
