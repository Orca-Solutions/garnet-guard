# Garnet Guard project brief

The approved outcome, constraints and permissions for anyone working on Garnet Guard, human or agent. This page points to the documents that hold the detail rather than copying them.

## Outcome

- **Mission:** no project takes a dependency update on faith. See [VISION.md](VISION.md).
- **Launch success** (mid-December 2026, launch week from Tue Dec 8): the criteria in [VISION.md](VISION.md#what-success-looks-like) and the month-2 exit in [ROADMAP.md](ROADMAP.md).
- **1.0:** the acceptance criteria in [docs/SPEC-v1.md](docs/SPEC-v1.md) §13.
- **Dated milestones:** incident replays reproducible by Nov 15, 2026, and a reduced clean-corpus backtest by Dec 1, 2026 ([ROADMAP.md](ROADMAP.md), month 1). Both were met on 2026-10-30: `uv run python -m backtest` replays 51 malicious releases (47 PyPI, 4 npm), all of which get a warning, and the clean corpus covers 18,181 updates of the top 1,000 PyPI and npm packages, 366 of them flagged for a look (2.0%), none a false claim ([README](README.md#replays-of-real-malicious-releases)).

## Constraints

- Never execute inspected package code; all archive access goes through `safe_archive.py` (ADR-0005, [THREAT_MODEL.md](THREAT_MODEL.md)).
- No telemetry (ADR-0008).
- Apache-2.0 with DCO sign-off, no CLA (ADR-0003).
- Detection is never paywalled ([OPEN_CORE.md](OPEN_CORE.md), ADR-0006, ADR-0009).
- Python 3.11+, packaged with uv; distribution `garnet-guard`, import `garnet_guard`, CLI `garnet` (ADR-0002, ADR-0007).
- New runtime dependencies need an ADR ([docs/API.md](docs/API.md) §8).
- User-facing text follows the brand voice ([docs/brand/brand-kit.md](docs/brand/brand-kit.md)).

## Permissions

- Jason merges pull requests and accepts releases.
- Agents work on branches and open draft pull requests. They never merge.
- Publishing to PyPI or GitHub Marketplace, sending outreach messages, and spending money need Jason's explicit say each time.
- No standing exceptions are recorded.
