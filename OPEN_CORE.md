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

The Garnet Guard App is a hosted GitHub App for things that only make sense when someone runs a service across many repositories. The Free tier includes the basics (one org-wide policy, PR checks, email alerts, 30 days of history). Paid tiers add the rest in two parts: **Core**, the features every paid tier includes, and **Premium**, an add-on any tier can buy.

Core, on Team and Business:

- org-wide policy pushed to every repository, and policy per group of repos
- exceptions with an owner, a reason and an expiry date
- alerts on versions you already merged that are flagged later, with the repos they're in
- an org-wide view of which versions each repo trusts, and Slack, webhook and email alerts
- a year of history, and an audit trail of policy changes and exceptions

Premium, for governance and audit:

- SSO through the company's identity provider
- audit log export, to a SIEM or as a file for auditors
- compliance reports on policy coverage, exceptions and time to fix

Enterprise or a quoted project: private registry and mirror support, managed caching, and response-time promises.

### Two kinds of history

- **Per-package history from public registries** ("this package's last 40 releases all came from workflow X") is computed by the engine from public data, so it is **free**, in the open-source tool (ADR-0009).
- **History the Garnet Guard App observes across many organizations** ("this release was verified in 1,200 repos and is the first to differ") can only come from a service running across many repos, so it is **paid**. Alerts on a version you already merged that is flagged later are paid, from Team up; detection itself stays free, because rerunning the Action flags the same version.

### Tiers

| Tier | Who | Price |
|---|---|---|
| Free | Up to 10 developers | $0, with a limited set of hosted features |
| Team | Up to 10 developers | ~$99/month, the same Core features as Business |
| Business | 11 to 250 developers | $199/month up to 25 developers, plus $8/month for each developer above 25 (for example $399 at 50, $1,999 at 250) |
| Enterprise | Over 250 developers, or custom needs | Call us. Premium included. |
| Premium add-on | Any tier | $49/month up to 10 developers, $99/month up to 25, then $4/month for each developer above 25 |

**Public repositories are never counted and never charged,** on any tier. "Developers" means active committers: someone counts only through commits to private repositories where the app is installed in the last 90 days, so there's no seat admin. The count is set at purchase or renewal, with no true-ups during the term. Every tier, Free included, keeps the whole open-source engine, every rule, the CLI, the Action and the hooks; tiers limit only hosted conveniences.

*The tier shape is agreed; prices are a working draft, revised with pilot data.* The pricing decision and its reasoning are in [ADR-0015](docs/decisions/0015-core-and-premium-pricing.md), and the go/no-go gates in [ADR-0010](docs/decisions/0010-funding-gates.md). No paid work starts before Gate A in month 4.

## Commitments

1. **Detection is never paywalled.** A rule that ships in the Garnet Guard App ships in the open-source engine too. The Garnet Guard App's advantage is data and coordination, not secret checks.
2. **No telemetry.** The open-source tool never phones home. Any interest list or hosted signup is opt-in and separate.
3. **No crippling.** Free features won't be removed or limited to push people to the paid app.
4. **Separate code, no hooks.** The Garnet Guard App lives in its own repository and uses the engine as a normal dependency. The open-source code needs no account, key or server.
5. **License stays.** Code released under Apache-2.0 stays Apache-2.0.

Changing these commitments requires an ADR with public comment (see [GOVERNANCE.md](GOVERNANCE.md)).

## Other funding

GitHub Sponsors, the GitHub Secure Open Source Fund, foundation grants (for example OpenSSF Alpha-Omega or the Sovereign Tech Agency) and paid support are all compatible with this model and preferred where they keep Garnet neutral.
