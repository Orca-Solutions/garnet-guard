"""Checks: pure functions from (change, baseline facts, candidate facts) to findings.

This package imports only ``garnet_guard.models`` and the standard library.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator

from ..models import Change, Evidence, RawFinding, ReleaseFacts
from . import content, trust
from .docs import DOCS

CheckFn = Callable[[Change, ReleaseFacts | None, ReleaseFacts], Iterable[RawFinding]]


def known_malicious(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    if cand.advisories:
        yield RawFinding(
            "GRN-K001",
            f"OSV lists {cand.package} {cand.version} as malicious",
            tuple(
                Evidence("advisory", a, url=f"https://osv.dev/vulnerability/{a}")
                for a in cand.advisories
            ),
        )


# (rule id, function, ecosystems). Diff rules return nothing without a baseline.
ALL_CHECKS: tuple[tuple[str, CheckFn, frozenset[str]], ...] = (
    ("GRN-T001", trust.lost_provenance, frozenset({"pypi"})),
    ("GRN-T002", trust.publisher_changed, frozenset({"pypi"})),
    ("GRN-T003", trust.workflow_changed, frozenset({"pypi"})),
    ("GRN-T004", trust.no_matching_tag, frozenset({"pypi"})),
    ("GRN-T005", trust.outside_trusted_publishing, frozenset({"pypi"})),
    ("GRN-T007", trust.invalid_attestation, frozenset({"pypi"})),
    ("GRN-T008", trust.hash_mismatch, frozenset({"pypi"})),
    ("GRN-C001", content.new_pth_file, frozenset({"pypi"})),
    ("GRN-C002", content.new_build_hook, frozenset({"pypi"})),
    ("GRN-C003", content.new_import_time_exec, frozenset({"pypi"})),
    ("GRN-K001", known_malicious, frozenset({"pypi"})),
    ("GRN-E002", content.unparsed_changed, frozenset({"pypi"})),
)

__all__ = ["ALL_CHECKS", "DOCS", "CheckFn"]
