# Deployment agreement

Status: minimal. Revisit if the hosted app passes Gate A (ROADMAP.md, month 4).

| Record | Value |
| --- | --- |
| Project / repository | Garnet Guard, `github.com/orca-solutions/garnet-guard` |
| App development owner | Jason (maintainer) |
| What ships | A Python package on PyPI (`garnet-guard`), a CLI (`garnet`) and a GitHub Action. There is no server and no persistent store. |
| Release trigger | A `v*` tag pushed by the maintainer from `main`, published by PyPI Trusted Publishing with PEP 740 attestations from the `pypi` environment (SPEC §11). See [RELEASING.md](RELEASING.md). |
| Docs site | Static, built from [orca-solutions/gg-landing](https://github.com/orca-solutions/gg-landing) (`site/`), which also holds the brand kit. Cloudflare Pages, at garnetguard.orcasolutions.dev; the maintainer connects the repo and the domain. |
| Secrets | None at runtime. The Action uses the workflow's `GITHUB_TOKEN`. Publishing uses Trusted Publishing, with no stored token. |
| Telemetry | None (ADR-0008). |

## Not applicable until a hosted service exists

The following are all N/A: hosting platform and runtime, persistent stores, auth and origins, resource and cost limits, backups, recovery drills and production change procedure. There is nothing deployed to operate.
