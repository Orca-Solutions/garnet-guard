"""Garnet: a release-diff guard for dependency updates."""

from __future__ import annotations

__version__ = "0.2.0"

from .engine import Options, Report, compare, report  # noqa: E402
from .models import (  # noqa: E402
    Change,
    ChangeResult,
    Evidence,
    Finding,
    Ignore,
    Policy,
    Severity,
    Verdict,
)
from .policy import PolicyError, load_policy  # noqa: E402


def explain(rule_id: str) -> object:
    """The ``RuleDoc`` for a rule ID, as ``garnet explain`` prints it."""
    from .checks import DOCS

    return DOCS[rule_id.upper()]


__all__ = [
    "Change",
    "ChangeResult",
    "Evidence",
    "Finding",
    "Ignore",
    "Options",
    "Policy",
    "PolicyError",
    "Report",
    "Severity",
    "Verdict",
    "__version__",
    "compare",
    "explain",
    "load_policy",
    "report",
]
