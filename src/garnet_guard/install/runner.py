"""The two things the wrapper and hooks reach outside for, behind small
interfaces so tests can replay recorded outputs: starting the user's package
manager, and reading PyPI's release lists.

Every program is started from an argv list, never through a shell, and with
a timeout when one is given. Only the user's own pip and uv are run here.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..models import ProjectReleases


@dataclass(frozen=True)
class Ran:
    """A finished program: its exit code and what it printed (when captured)."""

    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""

    def text(self) -> str:
        """stderr then stdout, decoded, for messages."""
        return (self.stderr + b"\n" + self.stdout).decode("utf-8", "replace").strip()


class TimedOut(Exception):
    """A program ran past its time budget and was stopped."""


class Runner(Protocol):
    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        capture: bool = True,
        timeout: float | None = None,
    ) -> Ran: ...


def run(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    capture: bool = True,
    timeout: float | None = None,
) -> Ran:
    """Start ``argv`` with no shell. ``capture=False`` lets it use the terminal."""
    if not argv or not os.path.isabs(argv[0]):
        raise ValueError(f"refusing to run a program without an absolute path: {argv[:1]}")
    try:
        done = subprocess.run(  # noqa: S603  (argv list, absolute program path, no shell)
            list(argv),
            cwd=cwd,
            env=dict(env),
            capture_output=capture,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL if capture else None,
        )
    except subprocess.TimeoutExpired as err:
        raise TimedOut(
            f"{os.path.basename(argv[0])} didn't finish in {timeout:.0f} seconds"
        ) from err
    return Ran(done.returncode, done.stdout or b"", done.stderr or b"")


# PyPI's release list for a project. Raises an exception the caller reports.
Registry = Callable[[str], ProjectReleases]
