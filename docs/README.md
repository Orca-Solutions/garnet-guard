# Documentation index

- [../PROJECT_BRIEF.md](../PROJECT_BRIEF.md): approved outcome, constraints and permissions. Start here.
- [../WORKING_RECORD.md](../WORKING_RECORD.md): current state, tasks, verification and review dispositions.
- [SPEC-v1.md](SPEC-v1.md): the normative 1.0 specification. Read before changing behavior users see.
- [API.md](API.md): code design, layers, import rules and the public Python API. Read before changing code structure.
- [CODE_TOUR.md](CODE_TOUR.md): a plain-language tour of the code as it is in 0.1: the five stages, where each part lives, and how to follow one run. Start here if you're new to the code.
- [rules/](rules/README.md): one page per rule ID: what it checks, why it matters, an example finding, and how to resolve or allowlist it. Findings and the PR comment link here.
- [rule-coverage.md](rule-coverage.md): what stands behind each rule: crafted tests, real attacks replayed, real routine updates, and what is not yet proven.
- [action.md](action.md): setting up the GitHub Action, its inputs and outputs, and the two-workflow pattern for pull requests from forks.
- [policy.md](policy.md): the `garnet.toml` policy file: severities, expiring ignores and how the Action reads it.
- [vscode.md](vscode.md): Garnet Guard in VS Code today: the Action's comment through the GitHub Pull Requests extension, and the CLI's findings on the lockfile lines through the SARIF Viewer. The extension itself is planned after 0.3.
- [marketplace.md](marketplace.md): how the Action gets listed on GitHub Marketplace (maintainer steps).
- [expert-brief.md](expert-brief.md): a one-page summary for the packaging and security experts reviewing the approach before launch.
- [../ARCHITECTURE.md](../ARCHITECTURE.md) and [../THREAT_MODEL.md](../THREAT_MODEL.md): overview and security model. Read the threat model before touching anything that reads package contents or runs in CI.
- [decisions/](decisions/): architecture decision records, accepted and superseded.
- [handoffs/](handoffs/): dated implementation, review and merge handoffs.
- [brand/](brand/README.md): copies of the brand files this repository uses, including the voice rules for user-facing text. The kit itself lives in the `orca-solutions/gg-landing` repository.
- [DEVOPS.md](DEVOPS.md): deployment agreement. Garnet Guard is a CLI, an Action and a PyPI package with no server; hosting sections are N/A until the hosted app passes Gate A.
- [RELEASING.md](RELEASING.md): how a release is cut and published, and the one-time PyPI and GitHub settings it depends on.
