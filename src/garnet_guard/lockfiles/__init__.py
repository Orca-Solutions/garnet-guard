"""Lockfile parsers and change computation (SPEC §3).

Parsers read lockfiles as data (``tomllib`` and line parsing). They never
resolve, install or run anything.
"""

from __future__ import annotations

from .base import LockfileError, Pin, detect, parse
from .diff import diff_pins

__all__ = ["LockfileError", "Pin", "detect", "diff_pins", "parse"]
