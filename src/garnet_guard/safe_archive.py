"""The only module that opens archives.

Reads wheels (zip) and sdists (tar.gz, tar.bz2, tar.xz, zip) from memory.
It never writes to disk and never extracts. Unsafe entries (absolute paths,
``..`` segments, symlinks, hard links, devices) are rejected, and limits are
enforced on the bytes actually decompressed, so a lying header can't bypass
them.
"""

from __future__ import annotations

import bz2
import io
import lzma
import tarfile
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import IO, Protocol

from .models import Limits


class ArchiveError(Exception):
    """The archive is malformed or unsafe. Becomes GRN-E002."""


class LimitExceeded(ArchiveError):
    """A SPEC §4.4 limit was hit. Becomes GRN-E003."""


@dataclass(frozen=True)
class Entry:
    path: str
    size: int  # declared uncompressed size
    compressed: int


class ArchiveReader(Protocol):
    def entries(self) -> list[Entry]: ...
    def read(self, path: str, max_bytes: int | None = None) -> bytes: ...


def _check_path(name: str) -> str:
    if not name or "\x00" in name:
        raise ArchiveError("entry with empty or NUL-containing name")
    norm = name.replace("\\", "/")
    if norm.startswith("/") or (len(norm) > 1 and norm[1] == ":"):
        raise ArchiveError(f"absolute path in archive: {name!r}")
    if any(part == ".." for part in norm.split("/")):
        raise ArchiveError(f"path traversal in archive: {name!r}")
    return norm


_RATIO_FLOOR = 16 * 1024 * 1024  # ratios are only enforced past this many bytes


class _Budget:
    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.total = 0

    def add(self, n: int) -> None:
        self.total += n
        if self.total > self.limits.max_total_uncompressed:
            raise LimitExceeded("total uncompressed size limit exceeded")


def _read_stream(
    stream: IO[bytes],
    *,
    compressed: int,
    cap: int,
    limits: Limits,
    budget: _Budget,
    name: str,
    archive_compressed: int = 0,
) -> bytes:
    """Read one entry, checking limits on every chunk actually produced.

    ``compressed`` is the entry's own compressed size (zip); tar has none,
    so ``archive_compressed`` checks the whole archive's ratio as it grows.
    """
    out = bytearray()
    read = stream.read
    while True:
        chunk: bytes = read(64 * 1024)
        if not chunk:
            break
        out += chunk
        budget.add(len(chunk))
        if len(out) > cap:
            raise LimitExceeded(f"entry {name!r} larger than {cap} bytes")
        if compressed > 0 and len(out) > 1024 * 1024 and len(out) > compressed * limits.max_ratio:
            raise LimitExceeded(f"entry {name!r} exceeds compression ratio limit")
        if (
            archive_compressed > 0
            and budget.total > _RATIO_FLOOR
            and budget.total > archive_compressed * limits.max_ratio
        ):
            raise LimitExceeded("archive exceeds compression ratio limit")
    return bytes(out)


class _ZipReader:
    def __init__(self, data: bytes, limits: Limits) -> None:
        self._limits = limits
        self._budget = _Budget(limits)
        declared = _zip_entry_count(data)
        if declared is not None and declared > limits.max_entries:
            raise LimitExceeded("too many entries in archive")
        try:
            self._zf = zipfile.ZipFile(io.BytesIO(data))
            infos = self._zf.infolist()
        except Exception as err:  # zipfile raises many types on hostile input
            raise ArchiveError(f"bad zip: {err}") from err
        if len(infos) > limits.max_entries:
            raise LimitExceeded("too many entries in archive")
        self._infos: dict[str, zipfile.ZipInfo] = {}
        for info in infos:
            path = _check_path(info.filename)
            if info.is_dir():
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise ArchiveError(f"symlink in archive: {info.filename!r}")
            if mode not in (0, 0o100000):
                raise ArchiveError(f"special file in archive: {info.filename!r}")
            if path in self._infos:
                raise ArchiveError(f"duplicate entry in archive: {info.filename!r}")
            self._infos[path] = info

    def entries(self) -> list[Entry]:
        return sorted(
            (Entry(p, i.file_size, i.compress_size) for p, i in self._infos.items()),
            key=lambda e: e.path,
        )

    def read(self, path: str, max_bytes: int | None = None) -> bytes:
        info = self._infos[path]
        cap = max_bytes if max_bytes is not None else self._limits.max_total_uncompressed
        try:
            with self._zf.open(info) as fh:
                return _read_stream(
                    fh,
                    compressed=info.compress_size,
                    cap=cap,
                    limits=self._limits,
                    budget=self._budget,
                    name=path,
                )
        except ArchiveError:
            raise
        except Exception as err:  # zlib.error, LZMAError, EOFError, BadZipFile, ...
            raise ArchiveError(f"cannot read {path!r}: {err}") from err


class _TarReader:
    def __init__(self, data: bytes, limits: Limits) -> None:
        self._limits = limits
        self._budget = _Budget(limits)
        self._compressed = len(data)
        raw = _decompress(data, limits)
        try:
            self._tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
            members: list[tarfile.TarInfo] = []
            for m in self._tf:
                members.append(m)
                if len(members) > limits.max_entries:
                    raise LimitExceeded("too many entries in archive")
        except ArchiveError:
            raise
        except Exception as err:  # tarfile raises many types on hostile input
            raise ArchiveError(f"bad tar: {err}") from err
        self._members: dict[str, tarfile.TarInfo] = {}
        for m in members:
            path = _check_path(m.name)
            if m.isdir():
                continue
            if m.issym() or m.islnk():
                raise ArchiveError(f"link in archive: {m.name!r}")
            if not m.isfile() or m.issparse():
                raise ArchiveError(f"special or sparse file in archive: {m.name!r}")
            if path in self._members:
                raise ArchiveError(f"duplicate entry in archive: {m.name!r}")
            self._members[path] = m

    def entries(self) -> list[Entry]:
        # tar has no per-entry compressed size; the whole-archive ratio is
        # enforced while reading.
        return sorted((Entry(p, m.size, 0) for p, m in self._members.items()), key=lambda e: e.path)

    def read(self, path: str, max_bytes: int | None = None) -> bytes:
        member = self._members[path]
        cap = max_bytes if max_bytes is not None else self._limits.max_total_uncompressed
        try:
            fh = self._tf.extractfile(member)
            if fh is None:
                raise ArchiveError(f"cannot read {path!r}")
            with fh:
                return _read_stream(
                    fh,
                    compressed=0,
                    cap=cap,
                    limits=self._limits,
                    budget=self._budget,
                    name=path,
                    archive_compressed=max(self._compressed, 1),
                )
        except ArchiveError:
            raise
        except Exception as err:
            raise ArchiveError(f"cannot read {path!r}: {err}") from err


_GZIP_MAGIC = b"\x1f\x8b"
_BZ2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"


class _Stream(Protocol):
    @property
    def eof(self) -> bool: ...
    @property
    def unused_data(self) -> bytes: ...
    def produce(self, chunk: bytes, room: int) -> bytes: ...
    def pending(self) -> bool: ...


class _Zlib:
    def __init__(self) -> None:
        self._d = zlib.decompressobj(16 + zlib.MAX_WBITS)

    @property
    def eof(self) -> bool:
        return self._d.eof

    @property
    def unused_data(self) -> bytes:
        return self._d.unused_data

    def produce(self, chunk: bytes, room: int) -> bytes:
        return self._d.decompress(self._d.unconsumed_tail + chunk, room)

    def pending(self) -> bool:
        return bool(self._d.unconsumed_tail) and not self._d.eof


class _Buffered:
    def __init__(self, d: bz2.BZ2Decompressor | lzma.LZMADecompressor) -> None:
        self._d = d

    @property
    def eof(self) -> bool:
        return self._d.eof

    @property
    def unused_data(self) -> bytes:
        return self._d.unused_data

    def produce(self, chunk: bytes, room: int) -> bytes:
        return b"" if self._d.eof else self._d.decompress(chunk, room)

    def pending(self) -> bool:
        return not self._d.eof and not self._d.needs_input


def _new_stream(head: bytes) -> _Stream | None:
    if head.startswith(_GZIP_MAGIC):
        return _Zlib()
    if head.startswith(_BZ2_MAGIC):
        return _Buffered(bz2.BZ2Decompressor())
    if head.startswith(_XZ_MAGIC):
        return _Buffered(lzma.LZMADecompressor(format=lzma.FORMAT_XZ))
    return None


def _decompress(data: bytes, limits: Limits) -> bytes:
    """Decompress a tar stream with hard caps, before tarfile sees it.

    Every concatenated member is decoded (gzip, bz2 and xz all allow several,
    and installers read them all), so nothing hides after the first one.
    Anything after the last member other than zero padding is rejected.
    """
    first = _new_stream(data[:6])
    if first is None:
        if len(data) > limits.max_total_uncompressed:
            raise LimitExceeded("total uncompressed size limit exceeded")
        return data

    cap = limits.max_total_uncompressed
    out = bytearray()

    def check() -> None:
        if len(out) > cap:
            raise LimitExceeded("total uncompressed size limit exceeded")
        if len(out) > _RATIO_FLOOR and len(out) > len(data) * limits.max_ratio:
            raise LimitExceeded("archive exceeds compression ratio limit")

    buf = memoryview(data)
    stream: _Stream | None = first
    try:
        while stream is not None:
            pos = 0
            tail = b""
            while pos < len(buf):
                chunk = bytes(buf[pos : pos + 64 * 1024])
                pos += len(chunk)
                out += stream.produce(chunk, cap - len(out) + 1)
                check()
                while stream.pending():
                    out += stream.produce(b"", cap - len(out) + 1)
                    check()
                if stream.eof:
                    tail = stream.unused_data + bytes(buf[pos:])
                    break
            if not stream.eof:
                raise ArchiveError("truncated compressed stream")
            if not tail.strip(b"\x00"):
                break
            stream = _new_stream(tail[:6])
            if stream is None:
                raise ArchiveError("unexpected data after the compressed stream")
            buf = memoryview(tail)
    except ArchiveError:
        raise
    except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError) as err:
        raise ArchiveError(f"bad compressed stream: {err}") from err
    return bytes(out)


def _zip_entry_count(data: bytes) -> int | None:
    """Entry count from the end-of-central-directory record, before parsing.

    Lets a zip with millions of entries be refused without building them all.
    Returns None when the record can't be found (zipfile will then fail).
    """
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65_557))
    if end < 0 or end + 22 > len(data):
        return None
    count = int.from_bytes(data[end + 10 : end + 12], "little")
    if count != 0xFFFF:
        return count
    loc = end - 20
    if loc < 0 or data[loc : loc + 4] != b"PK\x06\x07":
        return None
    z64 = int.from_bytes(data[loc + 8 : loc + 16], "little")
    if data[z64 : z64 + 4] != b"PK\x06\x06":
        return None
    return int.from_bytes(data[z64 + 32 : z64 + 40], "little")


def open_archive(data: bytes, filename: str, limits: Limits) -> ArchiveReader:
    if len(data) > limits.max_artifact_bytes:
        raise LimitExceeded("artifact larger than the compressed size limit")
    lower = filename.lower()
    if lower.endswith((".whl", ".zip", ".egg")):
        return _ZipReader(data, limits)
    if lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        return _TarReader(data, limits)
    raise ArchiveError(f"unsupported archive type: {filename!r}")


def iter_files(reader: ArchiveReader) -> Iterator[Entry]:
    yield from reader.entries()
