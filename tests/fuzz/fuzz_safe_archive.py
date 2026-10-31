"""Fuzz target for ``safe_archive``: hostile wheels and sdists.

Run under Atheris (Linux, CPython 3.12+): ``uv run --group fuzz python -m
tests.fuzz.fuzz_safe_archive -max_total_time=60``. ``check`` is plain
Python, so the unit tests run it on the seed corpus without Atheris.

The first byte picks the file name's suffix and the rest is the archive.
Any exception other than ``ArchiveError`` (``LimitExceeded`` included) is a
bug, and so is an entry path that is absolute or climbs out with ``..``, or
reading more bytes than the limit allows.
"""

from __future__ import annotations

import sys

from garnet_guard.models import Limits
from garnet_guard.safe_archive import ArchiveError, open_archive

SUFFIXES = (".whl", ".zip", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar")

# Small limits keep each input fast; the logic under test is the same.
LIMITS = Limits(
    max_artifact_bytes=1024 * 1024,
    max_total_uncompressed=4 * 1024 * 1024,
    max_entries=256,
)


def check(data: bytes) -> None:
    if not data:
        return
    name = "fuzz" + SUFFIXES[data[0] % len(SUFFIXES)]
    try:
        reader = open_archive(data[1:], name, LIMITS)
        total = 0
        for entry in reader.entries():
            path = entry.path
            assert path, "empty entry path"
            assert "\\" not in path and "\x00" not in path, f"unnormalized path {path!r}"
            assert not path.startswith("/") and path[1:2] != ":", f"absolute path {path!r}"
            assert ".." not in path.split("/"), f"path climbs out: {path!r}"
            content = reader.read(path)
            total += len(content)
            assert total <= LIMITS.max_total_uncompressed, "read past the uncompressed limit"
    except ArchiveError:
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
