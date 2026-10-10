"""Garnet: a release-diff guard for dependency updates."""

from __future__ import annotations

__version__ = "0.1.0.dev0"

from .engine import Options, Report, compare, report  # noqa: E402
from .models import (  # noqa: E402
    Change,
    ChangeResult,
    Evidence,
    Finding,
    Severity,
    Verdict,
)


def explain(rule_id: str) -> object:
    from .checks import DOCS

    return DOCS[rule_id.upper()]


__all__ = [
    "Change",
    "ChangeResult",
    "Evidence",
    "Finding",
    "Options",
    "Report",
    "Severity",
    "Verdict",
    "__version__",
    "compare",
    "explain",
    "report",
]
