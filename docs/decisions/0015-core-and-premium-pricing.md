# 0015. Business priced per developer; Core tiers plus a Premium add-on

- Status: Accepted (prices are placeholders)
- Date: 2026-10-16

## Context

ADR-0012 set four hosted tiers sized by active developers, with Business in size bands. A business review of the plans on 2026-10-16 raised two problems. At the first band edge, one extra developer moved a bill from $199 to $449 a month. And Team and Business promised every feature, including SSO, audit export, private registries and priority support, at prices set before anyone knew what those cost one maintainer to build and support.

None of the hosted app is built yet and no customer has been quoted a price, so changing the shape now raises nobody's bill.

## Decision

Business is priced per developer above a floor. The hosted app is sold as **Core**, the features each tier includes, plus an optional **Premium** add-on for governance and audit.

| Tier | Who | Price (placeholder) |
|---|---|---|
| Free | Up to 10 developers | $0, limited hosted features |
| Team | Up to 10 developers | ~$99/month, the same Core features as Business |
| Business | 11 to 250 developers | $199/month up to 25 developers, plus $8/month for each developer above 25 ($399 at 50, $799 at 100, $1,999 at 250) |
| Enterprise | Over 250 developers, or custom needs | Call us. Premium included. |
| Premium add-on | Any tier | $49/month up to 10 developers, $99/month up to 25, then $4/month for each developer above 25 |

- **Core** covers policy per group of repos, exceptions with an owner and an expiry date, alerts on already-merged versions that are flagged later, an org-wide view, Slack, webhook and email alerts, a year of history and the audit trail of policy changes and exceptions.
- **Premium** covers SSO, audit log export and compliance reports. Each item is built when a paying pilot needs it.
- Private registry and mirror support is offered under Enterprise or as a quoted project. Response-time promises live only in Enterprise contracts; Premium promises features, not a service level.
- The developer count is set at purchase or renewal, with no true-ups during the term. ADR-0012's definition of a developer and its rule that public repositories are never counted still hold.
- Another add-on package opens only when two paying customers ask for the same thing.
- Detection stays free on every tier (OPEN_CORE.md commitment 1). Premium sells hosted governance features, never a check.

This supersedes ADR-0012's price table. ADR-0012's tier shape, developer count and public-repo rule stand.

## Consequences

The bill grows smoothly with team size instead of jumping at band edges. Core has to justify its price on its own, so pilots test it at list price and are asked separately which Premium items they need. A customer who wants everything pays about half again over Core alone (for example $148 instead of $99 for a 10-person team), and pilots will judge that total. Prices stay placeholders until pilots and a price check with qualified buyers support them.
