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
    """GRN-K001: OSV lists the candidate under a ``MAL-`` advisory."""
    if cand.advisories:
        yield RawFinding(
            "GRN-K001",
            f"OSV lists {cand.package} {cand.version} as malicious",
            tuple(
                Evidence("advisory", a, url=f"https://osv.dev/vulnerability/{a}")
                for a in cand.advisories
            ),
        )


BOTH = frozenset({"pypi", "npm"})
PYPI = frozenset({"pypi"})
NPM = frozenset({"npm"})

# (rule id, function, ecosystems). Diff rules return nothing without a baseline.
ALL_CHECKS: tuple[tuple[str, CheckFn, frozenset[str]], ...] = (
    ("GRN-T001", trust.lost_provenance, BOTH),
    ("GRN-T002", trust.publisher_changed, BOTH),
    ("GRN-T003", trust.workflow_changed, BOTH),
    ("GRN-T004", trust.no_matching_tag, BOTH),
    ("GRN-T005", trust.outside_trusted_publishing, BOTH),
    ("GRN-T006", trust.files_uploaded_late, PYPI),
    ("GRN-T007", trust.invalid_attestation, BOTH),
    ("GRN-T008", trust.hash_mismatch, BOTH),
    ("GRN-C001", content.new_pth_file, PYPI),
    ("GRN-C002", content.new_build_hook, BOTH),
    ("GRN-C003", content.new_import_time_exec, PYPI),
    ("GRN-C004", content.new_binary, PYPI),
    ("GRN-C007", content.code_not_in_source, PYPI),
    ("GRN-C008", content.new_dependency, BOTH),
    ("GRN-C010", content.new_startup_file, PYPI),
    ("GRN-C011", content.new_js_use, NPM),
    ("GRN-K001", known_malicious, BOTH),
    ("GRN-E002", content.unparsed_changed, PYPI),
)

__all__ = ["ALL_CHECKS", "DOCS", "CheckFn"]
