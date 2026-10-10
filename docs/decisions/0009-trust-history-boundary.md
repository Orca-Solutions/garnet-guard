# 0009. Trust-history boundary between the engine and the hosted app

- Status: Accepted
- Date: 2026-10-10

## Context

OPEN_CORE.md first listed a "trust-history baseline" as a paid hosted feature. But a package's publishing history on a public registry ("its last 40 PyPI releases all came from workflow X") can be computed by the engine alone from the Integrity API. Putting it behind a paywall would break the commitment that detection is never paywalled. plans/monetization.md recommended splitting the two.

## Decision

- **Per-package history from public registries** is part of the free engine (planned for v2).
- **History observed across many organizations** ("verified in 1,200 repos, this release is the first to differ"), and alerts when an already-merged version is flagged later, belong to the hosted app, because only a service running across many repos can produce them.

## Consequences

The hosted app's value rests on coordination and cross-org data, not on any detection the engine lacks. Critics can't point to a paywalled signal.
