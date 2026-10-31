"""The fuzz targets accept every seed, without Atheris.

This keeps the targets working on every Python CI runs; the fuzzing itself
runs in .github/workflows/fuzz.yml.
"""

import pytest

from tests.fuzz import fuzz_jsscan, fuzz_lockfiles, fuzz_safe_archive
from tests.fuzz.seeds import seeds

TARGETS = {
    "safe_archive": fuzz_safe_archive.check,
    "jsscan": fuzz_jsscan.check,
    "lockfiles": fuzz_lockfiles.check,
}


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_seeds_pass(target: str) -> None:
    corpus = seeds(target)
    assert corpus
    for data in corpus:
        TARGETS[target](data)


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_empty_and_junk_inputs(target: str) -> None:
    for data in (b"", b"\x00", b"\xff" * 64, bytes(range(256))):
        TARGETS[target](data)


def test_archive_seeds_are_read() -> None:
    # Every archive seed opens, so the fuzzer starts from inputs that reach
    # the entry checks rather than the format check.
    from garnet_guard.safe_archive import open_archive

    for data in seeds("safe_archive"):
        name = "seed" + fuzz_safe_archive.SUFFIXES[data[0]]
        reader = open_archive(data[1:], name, fuzz_safe_archive.LIMITS)
        assert reader.entries()
