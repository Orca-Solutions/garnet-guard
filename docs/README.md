# Documentation index

- [../PROJECT_BRIEF.md](../PROJECT_BRIEF.md): approved outcome, constraints and permissions. Start here.
- [../WORKING_RECORD.md](../WORKING_RECORD.md): current state, tasks, verification and review dispositions.
- [SPEC-v1.md](SPEC-v1.md): the normative 1.0 specification. Read before changing behavior users see.
- [API.md](API.md): code design, layers, import rules and the public Python API. Read before changing code structure.
- [CODE_TOUR.md](CODE_TOUR.md): a plain-language tour of the code as it is in 0.1: the five stages, where each part lives, and how to follow one run. Start here if you're new to the code.
- [rules/](rules/README.md): one page per rule ID: what it checks, why it matters, an example finding, and how to resolve or allowlist it. Findings and the PR comment link here.
- [action.md](action.md): setting up the GitHub Action, its inputs and outputs, and the two-workflow pattern for pull requests from forks.
- [../ARCHITECTURE.md](../ARCHITECTURE.md) and [../THREAT_MODEL.md](../THREAT_MODEL.md): overview and security model. Read the threat model before touching anything that reads package contents or runs in CI.
- [decisions/](decisions/): architecture decision records, accepted and superseded.
- [handoffs/](handoffs/): dated implementation, review and merge handoffs.
- [brand/](brand/): the brand kit, including voice rules for user-facing text.
- [DEVOPS.md](DEVOPS.md): deployment agreement. Garnet Guard is a CLI, an Action and a PyPI package with no server; hosting sections are N/A until the hosted app passes Gate A.
- [RELEASING.md](RELEASING.md): how a release is cut and published, and the one-time PyPI and GitHub settings it depends on.
