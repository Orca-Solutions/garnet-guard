# Deployment agreement

Status: minimal. Revisit if the hosted app passes Gate A (ROADMAP.md, month 4).

| Record | Value |
| --- | --- |
| Project / repository | Garnet Guard, `github.com/orca-solutions/garnet-guard` |
| App development owner | Jason (maintainer) |
| What ships | A Python package on PyPI (`garnet-guard`), a CLI (`garnet`) and a GitHub Action. There is no server and no persistent store. |
| Release trigger | A tag pushed by the maintainer, published by PyPI Trusted Publishing with PEP 740 attestations (SPEC §11). Not configured yet. |
| Docs site | Static. Hosting is undecided between Cloudflare Pages and GitHub Pages; decide before ROADMAP month 3. |
| Secrets | None at runtime. The Action uses the workflow's `GITHUB_TOKEN`. Publishing uses Trusted Publishing, with no stored token. |
| Telemetry | None (ADR-0008). |

## Not applicable until a hosted service exists

The following are all N/A: hosting platform and runtime, persistent stores, auth and origins, resource and cost limits, backups, recovery drills and production change procedure. There is nothing deployed to operate.
