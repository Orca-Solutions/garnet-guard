"""The entry point of the ``garnet`` and ``garnet-guard`` commands.

``garnet hook <agent> run`` runs before every shell command an agent starts.
It is answered by :mod:`garnet_guard.install.gate`, which imports only the
standard library and returns at once unless the command names a package
manager. Every other command goes to :func:`garnet_guard.cli.main`.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

_AGENTS = ("claude-code", "codex")


def main(argv: Sequence[str] | None = None) -> int:
    words = list(sys.argv[1:] if argv is None else argv)
    if len(words) == 3 and words[0] == "hook" and words[1] in _AGENTS and words[2] == "run":
        from .install import gate

        return gate.run(words[1])
    from .cli import main as cli_main

    return cli_main(words)
