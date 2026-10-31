# Garnet Guard: a one-page brief for reviewers

*For the people I've asked to check Garnet Guard's approach before launch. Clean-update numbers are from the backtest of 2026-10-30.*

**What it is.** Garnet Guard is an Apache-2.0 tool that checks each dependency update against the release a project already trusts. It asks one question: does the new release differ from the last good one in a way that matters for trust? It runs as a GitHub Action that comments on Dependabot and Renovate PRs, and as a CLI (`garnet diff`, `garnet check`). It is deterministic, has no telemetry, and never imports, builds or installs the code it inspects; it reads files as bytes and parses Python with `ast`.

**What it checks (PyPI first).**

| Signal | Rules | How it's read |
|---|---|---|
| Lost provenance | T001 | PEP 740 provenance from the Integrity API (`/integrity/<project>/<version>/<file>/provenance`), verified with `pypi-attestations`. Fires when every baseline file was attested and a candidate file isn't. |
| Publisher changed | T002, T003, T005 | Source repository, workflow path and environment from the attestation, compared across the two releases; Trusted Publishing use per file. |
| No matching tag | T004 | The baseline version had a git tag in the source repo and the candidate doesn't (`X` or `vX`, alone or after a prefix naming the package, compared as PEP 440 versions; the [rule page](rules/GRN-T004.md) lists every form). Tags are read from GitHub's public git ref advertisement, one request per repository. |
| New code that runs on install or import | C001, C002, C003 | A new `.pth` file, a new build hook or in-tree backend, or a new call to `exec`, `subprocess`, sockets, `ctypes` and similar in code that runs at import, followed through the package's own modules. Test files report at info. |
| Code that isn't in the source | C007 | A Python file in the wheel differs from the file at the release's git tag and has a sensitive call the source file lacks: code added by the build, as in ultralytics 8.3.42. |
| Known bad | K001 | OSV `MAL-` advisories. |
| Couldn't check | E001 to E005 | Reported as a finding, never as a pass. |

**Evidence so far.**
- **Replays:** 47 malicious releases of 36 compromised PyPI packages (December 2024 to September 2026), with git tags as they stood when each release was uploaded and without the known-bad feed, plus four npm account takeovers and event-stream 3.3.6. All 52 get a warning. Three of them were missed by the rules as first written and drove fixes: ultralytics 8.3.42, which the project's own hijacked workflow built, signed and tagged, with a payload that doesn't run at import (now reported by GRN-C007, which compares the wheel's files with the repository at the release's tag); embiggen 0.11.97, where a bug skipped the content checks when the two releases shipped different artifact kinds; and mrmustard 0.7.4, whose import-time payload runs in a thread started from a nested function, one step past where GRN-C003 used to stop. 24 of the 47 are the June 2026 Hades campaign, one `.pth` technique across 24 mostly small packages.
- **Clean updates:** across 18,181 everyday updates of the top 1,000 PyPI and top 1,000 npm packages, 606 were flagged for a look (3.3%), with every rule 0.2.0 ships: 300 of 9,439 on PyPI (3.2%) and 306 of 8,742 on npm (3.5%). Each flagged update was checked on its own against the registry, GitHub and the release files, and none made a false claim. That is not "no false alarms": none of these updates is known to be malicious, so every flag is a true observation about a legitimate release that a reviewer has to look at and dismiss. The first wider run found 30 false claims, and the final run's first passes 5 more (4 GRN-C007, 1 GRN-C004); all were fixed before these numbers. A few true warnings show a release doing the old thing a new way, such as a `setup.py` that swaps `subprocess.Popen` for `subprocess.run`; the PyPI report lists the ones found.
- **Couldn't check:** 304 PyPI updates (3.2%) and 30 npm updates (0.3%) carry a finding that names what wasn't checked, rather than a pass. On PyPI the main causes are sdists containing a link, which the archive reader refuses (117), and files over the download cap, such as CUDA libraries and torch (111).
- The method, every warning and its triage are public: [PyPI report](../backtest/corpus-results-pypi-1000/REPORT.md) and [npm report](../backtest/corpus-results-npm-1000/REPORT.md).

**What it doesn't catch.** A malicious first release or typosquat; malicious code already in the trusted baseline; a compromise that keeps the real workflow, a matching tag and adds nothing at install or import time; a compromise of PyPI or Sigstore themselves. It lowers risk; it never says a release is safe.

**What I'd value from you.** Any of these, even one line:
1. Is reading the Integrity API and comparing publisher identity across consecutive releases the right way to use PEP 740 here, or is there a better signal?
2. Which of these checks would you expect to be noisy on legitimate releases?
3. Is there anything here that would cause trouble for PyPI or for maintainers (load on the API, or warnings that unfairly cast doubt on a project)?

**Links.** Design: [ARCHITECTURE.md](../ARCHITECTURE.md) · Threat model: [THREAT_MODEL.md](../THREAT_MODEL.md) · Rules: [SPEC-v1.md](SPEC-v1.md) and [docs/rules](rules/) · How agents work on it: [AGENTS.md](../AGENTS.md)
