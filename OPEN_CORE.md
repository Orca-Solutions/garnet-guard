# Garnet Guard: what's free, what's paid

Garnet is open core. This page draws the line so users and contributors can trust it.

## Free forever, Apache-2.0

Everything a single repository or a single developer needs:

- the engine and **every detection rule**
- the CLI, the GitHub Action and the install and agent hooks
- local policy (`garnet.toml`), ignores and allow-lists
- all output formats (text, JSON, SARIF, PR comments)
- PyPI, npm and any future ecosystem support
- **per-package history from public registries** ("this package's last 40 releases all came from workflow X"), once it lands in v2. *(Accepted 2026-10-10, ADR-0009.)*

## The Garnet Guard App (hosted, later)

The Garnet Guard App is a hosted GitHub App for things that only make sense when someone runs a service across many repositories. The Free tier includes the basics (one org-wide policy, PR checks, email alerts); paid tiers add the rest:

- org-wide policy pushed to every repository, and policy per group of repos
- dashboards, Slack, webhook and email alerts, audit logs, SSO
- private registry and mirror support, managed caching
- longer history retention

### Two kinds of history

- **Per-package history from public registries** ("this package's last 40 releases all came from workflow X") is computed by the engine from public data, so it is **free**, in the open-source tool (ADR-0009).
- **History the Garnet Guard App observes across many organizations** ("this release was verified in 1,200 repos and is the first to differ") can only come from a service running across many repos, so it is **paid**. Alerts on a version you already merged that is flagged later are paid, from Team up; detection itself stays free, because rerunning the Action flags the same version.

### Tiers

| Tier | Who | Price |
|---|---|---|
| Free | Up to 10 developers | $0, with a limited set of hosted features |
| Team | Up to 10 developers | ~$99/month, all Business features |
| Business | 11 to 250 developers | Size bands: 11–25 $199, 26–50 $449, 51–100 $899, 101–250 $1,999 a month |
| Enterprise | Over 250 developers | Call us |

**Public repositories are never counted and never charged,** on any tier. "Developers" means active committers: someone counts only through commits to private repositories where the app is installed in the last 90 days, so there's no seat admin. Every tier, Free included, keeps the whole open-source engine, every rule, the CLI, the Action and the hooks; tiers limit only hosted conveniences.

*The tier shape is agreed; prices are a working draft, revised with pilot data.* The full tier table, features and reasoning are in [plans/monetization.md](../plans/monetization.md), along with sequencing and the go/no-go gates (ADR-0010). No paid work starts before Gate A in month 4.

## Commitments

1. **Detection is never paywalled.** A rule that ships in the Garnet Guard App ships in the open-source engine too. The Garnet Guard App's advantage is data and coordination, not secret checks.
2. **No telemetry.** The open-source tool never phones home. Any interest list or hosted signup is opt-in and separate.
3. **No crippling.** Free features won't be removed or limited to push people to the paid app.
4. **Separate code, no hooks.** The Garnet Guard App lives in its own repository and uses the engine as a normal dependency. The open-source code needs no account, key or server.
5. **License stays.** Code released under Apache-2.0 stays Apache-2.0.

Changing these commitments requires an ADR with public comment (see [GOVERNANCE.md](GOVERNANCE.md)).

## Other funding

GitHub Sponsors, the GitHub Secure Open Source Fund, foundation grants (for example OpenSSF Alpha-Omega or the Sovereign Tech Agency) and paid support are all compatible with this model and preferred where they keep Garnet neutral.
