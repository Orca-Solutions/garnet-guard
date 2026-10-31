from __future__ import annotations

import os
import socket
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from garnet_guard.install.hooks import WORKER as HOOK_WORKER


@pytest.fixture(autouse=True)
def _no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests must not open sockets (AGENTS.md rule 8)."""
    if request.node.get_closest_marker("network"):
        return

    def guard(*args: object, **kwargs: object) -> None:
        raise RuntimeError("unit tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket, "create_connection", guard)


@pytest.fixture(autouse=True)
def _temp_files_stay_in_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Tests leave nothing in the system temp folder.

    The temp folder of the code under test, and of the programs a test starts,
    is a folder in ``tmp_path``. A temp file or folder created anywhere else
    fails the test, and so does a hook check still running when the test ends:
    it would go on writing after this redirect is undone.
    """
    folder = tmp_path / "system-temp"
    folder.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(folder))
    for name in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.setenv(name, str(folder))

    made: list[str] = []

    def recorded(make: Any) -> Any:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            out = make(*args, **kwargs)
            made.append(out[1] if isinstance(out, tuple) else out)
            return out

        return wrapper

    monkeypatch.setattr(tempfile, "mkstemp", recorded(tempfile.mkstemp))
    monkeypatch.setattr(tempfile, "mkdtemp", recorded(tempfile.mkdtemp))
    before = set(threading.enumerate())
    yield
    running = [t for t in threading.enumerate() if t.name == HOOK_WORKER and t not in before]
    assert not running, "a hook check is still running after the test; join it before returning"
    root = os.path.realpath(tmp_path)
    outside = [p for p in made if not os.path.realpath(p).startswith(root + os.sep)]
    assert not outside, f"temp files outside tmp_path: {outside}"
