# 0007. Name: Garnet Guard; publish as `garnet-guard`, import as `garnet_guard`

- Status: Accepted
- Date: 2026-10-10

## Context

The PyPI name `garnet` is taken by an unrelated bioinformatics project (fraenkel-lab/GarNet, version 0.5.0), so `uvx garnet` from the scoping plan can't work. `garnet-guard` was free on 2026-10-10. Shipping an import package named `garnet` would collide with that project's module, which is a poor look for a supply-chain tool.

## Decision

Distribution `garnet-guard`, import package `garnet_guard`, CLI command `garnet`. Register `garnet-guard` on PyPI (and the matching npm name, if an npm wrapper is ever published) as soon as the repo exists, with Trusted Publishing configured from the first release.

Public name: **Garnet Guard**. Short form in prose and CLI: Garnet / `garnet`. Repository: `github.com/orca-solutions/garnet-guard` (Jason, 2026-10-10 22:06). The repo may move to a dedicated, project-owned org later if Open Source Collective or OpenSSF needs one; GitHub redirects transferred repos. Confirmed by Jason on 2026-10-10.

## Consequences

Users type `uvx garnet-guard` but run `garnet`. The project name stays Garnet. Revisit if the project is renamed.
