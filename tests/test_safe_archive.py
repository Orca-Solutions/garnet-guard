import gzip
import io
import tarfile
import zipfile

import pytest

from garnet_guard.models import Limits
from garnet_guard.safe_archive import ArchiveError, LimitExceeded, open_archive
from tests.builders import sdist, wheel


def test_reads_wheel_and_sdist() -> None:
    w = open_archive(wheel({"a/__init__.py": "x=1"}), "a.whl", Limits())
    assert [e.path for e in w.entries()] == ["a/__init__.py"]
    assert w.read("a/__init__.py") == b"x=1"
    s = open_archive(sdist("a-1.0", {"setup.py": "pass"}), "a-1.0.tar.gz", Limits())
    assert [e.path for e in s.entries()] == ["a-1.0/setup.py"]


@pytest.mark.parametrize("name", ["../evil.py", "/etc/passwd", "a/../../b"])
def test_rejects_traversal(name: str) -> None:
    with pytest.raises(ArchiveError):
        open_archive(wheel({name: "x"}), "a.whl", Limits())


def test_rejects_symlink_in_tar() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("a-1/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    with pytest.raises(ArchiveError):
        open_archive(buf.getvalue(), "a.tar.gz", Limits())


def test_rejects_symlink_in_zip() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "/etc/passwd")
    with pytest.raises(ArchiveError):
        open_archive(buf.getvalue(), "a.whl", Limits())


def test_gzip_bomb_hits_limit() -> None:
    bomb = gzip.compress(b"\0" * (64 * 1024 * 1024))
    with pytest.raises(LimitExceeded):
        open_archive(bomb, "a.tar.gz", Limits())


def test_zip_entry_ratio_limit() -> None:
    data = wheel({"big.bin": b"\0" * (32 * 1024 * 1024)})
    reader = open_archive(data, "a.whl", Limits())
    with pytest.raises(LimitExceeded):
        reader.read("big.bin")


def test_entry_count_limit() -> None:
    data = wheel({f"f{i}.txt": "x" for i in range(20)})
    with pytest.raises(LimitExceeded):
        open_archive(data, "a.whl", Limits(max_entries=10))


def _tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.mark.parametrize(
    ("suffix", "compress"),
    [
        ("tar.gz", gzip.compress),
        ("tar.bz2", __import__("bz2").compress),
        ("tar.xz", __import__("lzma").compress),
    ],
)
def test_concatenated_members_are_all_read(suffix, compress) -> None:
    """A second compressed member must not hide files from inspection."""
    # The first member holds tar entries with no end-of-archive marker, so
    # tarfile (and pip) keep reading into the second member.
    info = tarfile.TarInfo("pkg-1/setup.py")
    info.size = 4
    first = info.tobuf() + b"pass".ljust(512, b"\0")
    second = _tar({"pkg-1/evil.py": b"import os"})
    with tarfile.open(fileobj=io.BytesIO(compress(first) + compress(second))) as tf:
        assert len(tf.getnames()) == 2  # what an installer sees
    data = compress(first) + compress(second)
    names = [e.path for e in open_archive(data, f"a.{suffix}", Limits()).entries()]
    assert names == ["pkg-1/evil.py", "pkg-1/setup.py"]


def test_trailing_garbage_after_stream_rejected() -> None:
    data = gzip.compress(_tar({"pkg-1/a.py": b"x"})) + b"not a gzip member"
    with pytest.raises(ArchiveError):
        open_archive(data, "a.tar.gz", Limits())


def test_zero_padding_after_stream_allowed() -> None:
    data = gzip.compress(_tar({"pkg-1/a.py": b"x"})) + b"\0" * 512
    assert [e.path for e in open_archive(data, "a.tar.gz", Limits()).entries()] == ["pkg-1/a.py"]


def test_truncated_stream_rejected() -> None:
    data = gzip.compress(_tar({"pkg-1/a.py": b"x" * 5000}))
    with pytest.raises(ArchiveError):
        open_archive(data[: len(data) // 2], "a.tar.gz", Limits())


def test_corrupt_zip_entry_is_archive_error() -> None:
    body = bytes(range(256)) * 64
    data = bytearray(wheel({"a.py": body}))
    start = data.index(b"a.py") + 4  # local header name, then the deflate body
    data[start : start + 40] = b"\xff" * 40
    reader = open_archive(bytes(data), "a.whl", Limits())
    with pytest.raises(ArchiveError):
        reader.read("a.py")


def test_sparse_tar_member_rejected() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.GNU_FORMAT) as tf:
        info = tarfile.TarInfo("pkg-1/big.py")
        info.type = tarfile.GNUTYPE_SPARSE
        info.size = 0
        tf.addfile(info)
    with pytest.raises(ArchiveError):
        open_archive(buf.getvalue(), "a.tar.gz", Limits())


def test_zip_entry_count_checked_before_parsing() -> None:
    data = wheel({f"f{i}": "" for i in range(50)})
    with pytest.raises(LimitExceeded):
        open_archive(data, "a.whl", Limits(max_entries=10))
    from garnet_guard.safe_archive import _zip_entry_count

    assert _zip_entry_count(data) == 50
