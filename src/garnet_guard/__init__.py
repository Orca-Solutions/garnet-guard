"""Garnet: a release-diff guard for dependency updates.

The public names below load on first use (PEP 562), so a command that needs
none of them, such as an agent hook's fast path, starts without importing
the engine.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

__version__ = "0.2.0"

if TYPE_CHECKING:
    from .engine import Options, Report, compare, report
    from .models import (
        Change,
        ChangeResult,
        Evidence,
        Finding,
        Ignore,
        Policy,
        Severity,
        Verdict,
    )
    from .policy import PolicyError, load_policy

_LAZY = {
    "Options": "engine",
    "Report": "engine",
    "compare": "engine",
    "report": "engine",
    "Change": "models",
    "ChangeResult": "models",
    "Evidence": "models",
    "Finding": "models",
    "Ignore": "models",
    "Policy": "models",
    "Severity": "models",
    "Verdict": "models",
    "PolicyError": "policy",
    "load_policy": "policy",
}


def __getattr__(name: str) -> Any:
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(f".{module}", __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *_LAZY})


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
