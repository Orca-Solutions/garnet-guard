# 0013. Brand identity

- Status: Accepted
- Date: 2026-10-10

## Context

"Garnet" alone collides with other well-known projects in search, and a security tool needs a calm, recognizable identity that doesn't promise protection it can't give. The brand thread produced a kit; Jason confirmed the name and mark.

## Decision

- **Name:** Garnet Guard (ADR-0007). CLI `garnet`, rule IDs `GRN-`.
- **Mark:** a pomegranate opened by a delta (the diff symbol) to show its seeds, with one amber seed as "the tell", the one thing that differs from the last trusted release.
- **Palette:** garnet-700 `#8E1B2C` is the brand colour; amber `#E0A100` is reserved for findings and warnings; ink `#1B1F24`, slate `#5C636B`, paper `#F7F3EE`. Red is the brand, never "danger".
- **Tagline:** *Trust the last release. Check the next.*
- **Badge wording:** "checked by Garnet Guard", never "guarded by" or "protected by".
- **Where it lives:** the kit is copied to `docs/brand/` when the repo is seeded; `docs/brand/brand-kit.md` is the detail, including voice rules.
- **Trademarks:** the name and mark are project trademarks, noted in NOTICE. The code stays Apache-2.0.

## Consequences

Forks can use the code but not ship under the name and mark. User-facing text follows the kit's voice rules (AGENTS.md, CONTRIBUTING.md).
