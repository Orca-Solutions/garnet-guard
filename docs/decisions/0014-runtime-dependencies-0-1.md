# 0014. Runtime dependencies for 0.1

- Status: Proposed
- Date: 2026-10-10

## Context

AGENTS.md requires an ADR for every runtime dependency. [docs/API.md](../API.md) §8 lists the planned set. The 0.1 `garnet diff` command needs only part of it.

## Decision

0.1 depends on `httpx`, `pypi-attestations` and `packaging`. `platformdirs` and `pyyaml` wait until the cache and the pnpm parser need them.

Two modules installed by `pypi-attestations` are imported directly:

- `cryptography` reads the Fulcio certificate's source-repository id, so a repository rename doesn't fire GRN-T002.
- `pydantic` catches validation errors from malformed provenance.

Neither one adds a package to the install.

Tags come from GitHub's public git ref advertisement (`github.com/<repo>.git/info/refs`) instead of the REST API. That needs no token, avoids the 60-requests-per-hour limit, follows rename redirects and costs one request per repository. So `github.com` joins the hosts allowlist in `net.py`.

## Consequences

`sigstore` fetches its TUF trust root itself, from `tuf-repo-cdn.sigstore.dev`, outside `net.py`. Those hosts are not in the `net.py` allowlist because Garnet's own code never calls them.


The install stays small. Attestation verification falls back to the trust root that ships with `sigstore` when the Sigstore TUF repository can't be reached, and the result is the same unless Sigstore has rotated keys since that release.
