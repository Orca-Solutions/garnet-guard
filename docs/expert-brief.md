# Garnet Guard: a one-page brief for reviewers

*For the people I've asked to check Garnet Guard's approach before launch. Clean-update numbers are from the backtest of 2026-10-30.*

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
- **Replays:** seven malicious releases from four real 2026 compromises of trusted packages (lightning 2.6.2 and 2.6.3, elementary-data 0.23.3, litellm 1.82.7 and 1.82.8, telnyx 4.87.1 and 4.87.2) each produce a warning without using the known-bad feed, with git tags as they stood when each release was uploaded.
- **Clean updates:** across 18,181 everyday updates of the top 1,000 PyPI and top 1,000 npm packages, 367 were flagged for a look (2.0%): 221 of 9,439 on PyPI (2.3%) and 146 of 8,742 on npm (1.7%). Each flagged update was checked on its own against the registry, GitHub and the release files, and none made a false claim. That is not "no false alarms": none of these updates is known to be malicious, so every flag is a true observation about a legitimate release that a reviewer has to look at and dismiss. The first wider run found 30 false claims, and they were fixed before these numbers.
- **Couldn't check:** 291 PyPI updates (3.1%) and 30 npm updates (0.3%) carry a finding that names what wasn't checked, rather than a pass. On PyPI the main causes are sdists containing a link, which the archive reader refuses (117), and files over the download cap, such as CUDA libraries and torch (107).
- The method, every warning and its triage are public: [PyPI report](../backtest/corpus-results-pypi-1000/REPORT.md) and [npm report](../backtest/corpus-results-npm-1000/REPORT.md).

**What it doesn't catch.** A malicious first release or typosquat; malicious code already in the trusted baseline; a compromise that keeps the real workflow, a matching tag and adds nothing at install or import time; a compromise of PyPI or Sigstore themselves. It lowers risk; it never says a release is safe.

**What I'd value from you.** Any of these, even one line:
1. Is reading the Integrity API and comparing publisher identity across consecutive releases the right way to use PEP 740 here, or is there a better signal?
2. Which of these checks would you expect to be noisy on legitimate releases?
3. Is there anything here that would cause trouble for PyPI or for maintainers (load on the API, or warnings that unfairly cast doubt on a project)?

**Links.** Design: [ARCHITECTURE.md](../ARCHITECTURE.md) · Threat model: [THREAT_MODEL.md](../THREAT_MODEL.md) · Rules: [SPEC-v1.md](SPEC-v1.md) and [docs/rules](rules/) · How agents work on it: [AGENTS.md](../AGENTS.md)
