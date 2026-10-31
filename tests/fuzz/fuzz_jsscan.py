"""Fuzz target for the JavaScript tokenizer and scanner (``facts/jsscan.py``).

Run under Atheris (Linux, CPython 3.12+): ``uv run --group fuzz python -m
tests.fuzz.fuzz_jsscan -max_total_time=60``. ``check`` is plain Python, so
the unit tests run it on the seed corpus without Atheris.

The input is decoded as UTF-8 with replacement, the way Garnet reads a file
it scans. The scanner must return for any text: an exception or a hang is a
bug.
"""

from __future__ import annotations

import sys

from garnet_guard.facts.jsscan import scan


def check(data: bytes) -> None:
    result = scan("fuzz.js", data.decode("utf-8", errors="replace"))
    for use in result.uses:
        assert use.line >= 1, f"line number {use.line}"


def main() -> None:
    import atheris

    # Instrument what is already imported (Garnet and the standard library
    # parsers it calls), so the fuzzer is guided by coverage.
    atheris.instrument_all()
    atheris.Setup(sys.argv, check)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
