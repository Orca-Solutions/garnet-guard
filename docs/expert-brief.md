# Garnet Guard: a one-page brief for reviewers

*For the people I've asked to check Garnet Guard's approach before launch. Numbers are from the backtest of 2026-10-10.*

**What it is.** Garnet Guard is an Apache-2.0 tool that checks each dependency update against the release a project already trusts. It asks one question: does the new release differ from the last good one in a way that matters for trust? It runs as a GitHub Action that comments on Dependabot and Renovate PRs, and as a CLI (`garnet diff`, `garnet check`). It is deterministic, has no telemetry, and never imports, builds or installs the code it inspects; it reads files as bytes and parses Python with `ast`.

**What it checks (PyPI first).**

| Signal | Rules | How it's read |
|---|---|---|
| Lost provenance | T001 | PEP 740 provenance from the Integrity API (`/integrity/<project>/<version>/<file>/provenance`), verified with `pypi-attestations`. Fires when every baseline file was attested and a candidate file isn't. |
| Publisher changed | T002, T003, T005 | Source repository, workflow path and environment from the attestation, compared across the two releases; Trusted Publishing use per file. |
| No matching tag | T004 | The baseline version had a git tag in the source repo and the candidate doesn't (`X`, `vX`, `name-X`, `name-vX`, compared as PEP 440 versions). |
| New code that runs on install or import | C001, C002, C003 | A new `.pth` file, a new build hook or in-tree backend, or a new top-level call to `exec`, `subprocess`, sockets, `ctypes` and similar. Test files report at info. |
| Known bad | K001 | OSV `MAL-` advisories. |
| Couldn't check | E001 to E005 | Reported as a finding, never as a pass. |

**Evidence so far.**
- **Replays:** 47 malicious releases of 36 compromised PyPI packages (December 2024 to September 2026), with git tags as they stood when each release was uploaded and without the known-bad feed, plus four npm account takeovers. 48 of 51 get a warning. Three get none: ultralytics 8.3.42, which the project's own hijacked workflow built, signed and tagged, with a payload that doesn't run at import; embiggen 0.11.97, where a bug skipped the content checks (fix planned); and mrmustard 0.7.4, whose import-time payload runs in a thread started from a nested function, one step past where GRN-C003 stops following (fix planned). 24 of the 47 are the June 2026 Hades campaign, one `.pth` technique across 24 mostly small packages.
- **Clean updates:** across 974 updates of the top 100 PyPI packages, 12 warned (1.2%), and each of those warnings states something true about the release. The first run warned on 17 (1.7%). Five of its warnings made a false claim, and tuning since merged removes them. It also lowers one warning from a test file to info. No other result changed.
- **Known gap:** in 33 updates (3.4%), a symlink inside an sdist made Garnet skip that sdist's content checks. It reports this as a coverage gap rather than a pass, and a fix is planned.
- The method, every warning and its triage are public: [backtest/corpus-results/REPORT.md](../backtest/corpus-results/REPORT.md).

**What it doesn't catch.** A malicious first release or typosquat; malicious code already in the trusted baseline; a compromise that keeps the real workflow, a matching tag and adds nothing at install or import time; a compromise of PyPI or Sigstore themselves. It lowers risk; it never says a release is safe.

**What I'd value from you.** Any of these, even one line:
1. Is reading the Integrity API and comparing publisher identity across consecutive releases the right way to use PEP 740 here, or is there a better signal?
2. Which of these checks would you expect to be noisy on legitimate releases?
3. Is there anything here that would cause trouble for PyPI or for maintainers (load on the API, or warnings that unfairly cast doubt on a project)?

**Links.** Design: [ARCHITECTURE.md](../ARCHITECTURE.md) · Threat model: [THREAT_MODEL.md](../THREAT_MODEL.md) · Rules: [SPEC-v1.md](SPEC-v1.md) and [docs/rules](rules/) · How agents work on it: [AGENTS.md](../AGENTS.md)
