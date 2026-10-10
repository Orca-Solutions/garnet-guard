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
