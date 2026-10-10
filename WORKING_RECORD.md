# Garnet Guard working record

Current state, open tasks, verification and review dispositions. Newest first.

## 2026-10-10: repository seeded, `garnet diff` preview

**State.** The repository is seeded from the founding documents and contains the 0.1 preview engine:

- `garnet diff <pkg> <old> <new>` for PyPI
- `garnet explain` and `garnet version`
- text and JSON reports

**Rules implemented:**
- GRN-T001 to T005, T007, T008
- GRN-C001 to C003
- GRN-K001
- GRN-E001 to E003

**Verification.**
- `uv run pytest`: 38 unit tests pass with no network.
- `uv run ruff check .`, `ruff format --check .`, `mypy src` (strict) and `lint-imports` all pass.
- `uv run python -m backtest`:
  - Replays lightning 2.6.2 and 2.6.3, each caught by GRN-C003 and GRN-T004.
  - Replays elementary-data 0.23.3, caught by GRN-C001 and GRN-T004.
  - Replays the deleted malicious files by URL and hash from files.pythonhosted.org.
  - The 20 clean updates in `backtest/clean.toml` produce no warnings from detection rules.
- Known-bad lookups are off in the backtest on purpose, to show what Garnet Guard catches before any feed lists a release.

**Caveats.**
- GRN-T001 can't fire on these incidents, because neither project attested releases before the attack.
- GRN-T004 is evaluated against the repository tags as they are now.

**Open tasks (month 1, see ROADMAP.md):**
- lockfile parsers and `garnet check`
- policy file
- cache
- intermediate versions (SPEC §5 rule 2)
- SARIF output
- per-change time budget
- fuzz tests for `safe_archive.py`
- CI workflow with pinned Actions
- approach-check notes

**Review dispositions.** None yet.
