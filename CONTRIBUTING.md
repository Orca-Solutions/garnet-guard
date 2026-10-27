# Contributing to Garnet Guard

Thanks for helping. Garnet is young, so the most useful contributions right now are:

1. **False-positive reports.** If Garnet warned on an update that was fine, open a "False positive" issue with the package, versions and finding. These shape the rules more than anything else.
2. **Missed detections.** A real compromised release Garnet didn't flag, or would not have flagged.
3. **Rule ideas** backed by a real incident.
4. Code, docs and lockfile-format support.

Questions, ideas and show-and-tell go in GitHub Discussions. Bugs, false positives and missed detections go in issues.

## Development setup

```sh
git clone https://github.com/orca-solutions/garnet-guard
cd garnet-guard
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy src
uv run lint-imports              # the layer rules in docs/API.md §2
```

Unit tests never touch the network. They build tiny wheels, sdists and release facts in memory with `tests/builders.py`, so no real package (and no real malware) is stored in the repository. Tests that need the network are marked `@pytest.mark.network` and are skipped by default; run them with `uv run pytest -m network`.

New to the code? [docs/CODE_TOUR.md](docs/CODE_TOUR.md) walks through it module by module, in plain language.

## Adding or changing a rule

1. Open an issue first describing the signal and the incident or risk behind it.
2. Pick the next free ID in the right family (`GRN-T` trust, `GRN-C` content, `GRN-K` known-bad, `GRN-E` couldn't-check). IDs are never reused. Add it to the table in [docs/SPEC-v1.md](docs/SPEC-v1.md) §6.2.
3. Implement the check as a pure function in `src/garnet_guard/checks/` and register it in `ALL_CHECKS` in `checks/__init__.py`. No I/O in checks. If it needs a fact Garnet doesn't collect yet, add the field to `ReleaseFacts` or `ArtifactFacts` in `models.py` and fill it in under `facts/` or `ecosystems/`.
4. Add at least one positive and one negative test in `tests/test_checks.py`, built with `tests/builders.py`.
5. Add `garnet explain` text in `checks/docs.py`: what it means, why it matters, what to do.
6. Add the rule's page at `docs/rules/<ID>.md`, following the existing pages, and list it in [docs/rules/README.md](docs/rules/README.md).
7. Run the backtest (`uv run python -m backtest`) and include the before/after warn rate in the PR.

## User-facing text

Findings, `garnet explain` text, PR comments and CLI messages follow the voice rules in docs/brand/brand-kit.md: calm, exact, never call anything "safe", and put evidence on every line.

## Pull requests

- Keep PRs small and focused. One rule or one feature per PR.
- Fill in the PR template, including the backtest delta for rule changes.
- New runtime dependencies need a short ADR in `docs/decisions/` explaining why.
- Changes to `safe_archive.py`, `action/`, `.github/workflows/` or default policy get extra review.

## Sign-off (DCO)

Garnet uses the [Developer Certificate of Origin](https://developercertificate.org/). Sign off every commit with `git commit -s`, which adds `Signed-off-by: Your Name <you@example.com>`. By doing so you certify you have the right to submit the work under the Apache-2.0 license. There is no CLA.

## AI-assisted contributions

Garnet itself is built with AI coding agents, so AI-assisted contributions are welcome. You remain responsible for them: you must understand every line you submit, be able to explain it in review, and say in the PR description which parts were AI-generated. Low-effort generated PRs will be closed.

## Code of conduct

Everyone taking part agrees to the [Code of Conduct](CODE_OF_CONDUCT.md).
