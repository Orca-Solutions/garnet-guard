"""Fuzz target for the lockfile parsers (``lockfiles/``).

Run under Atheris (Linux, CPython 3.12+): ``uv run --group fuzz python -m
tests.fuzz.fuzz_lockfiles -max_total_time=60``. ``check`` is plain Python,
so the unit tests run it on the seed corpus without Atheris.

A pull request controls the lockfiles Garnet reads. The first byte picks the
file name, so every parser is reached, and the rest is the file. Any
exception other than ``LockfileError`` is a bug.
"""

from __future__ import annotations

import sys

from garnet_guard.lockfiles import LockfileError, parse

NAMES = (
    "uv.lock",
    "poetry.lock",
    "pylock.toml",
    "requirements.txt",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "unnamed",
)


def check(data: bytes) -> None:
    if not data:
        return
    name = NAMES[data[0] % len(NAMES)]
    try:
        parse(name, data[1:])
    except LockfileError:
        pass


def main() -> None:
    import atheris

    # Instrument what is already imported (Garnet and the standard library
    # parsers it calls), so the fuzzer is guided by coverage.
    atheris.instrument_all()
    atheris.Setup(sys.argv, check)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
