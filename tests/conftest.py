from __future__ import annotations

import socket

import pytest


@pytest.fixture(autouse=True)
def _no_network(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests must not open sockets (AGENTS.md rule 8)."""
    if request.node.get_closest_marker("network"):
        return

    def guard(*args: object, **kwargs: object) -> None:
        raise RuntimeError("unit tests must not use the network")

    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket, "create_connection", guard)
