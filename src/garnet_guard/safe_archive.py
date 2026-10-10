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
) -> bytes:
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
    return bytes(out)


class _ZipReader:
    def __init__(self, data: bytes, limits: Limits) -> None:
        self._limits = limits
        self._budget = _Budget(limits)
        try:
            self._zf = zipfile.ZipFile(io.BytesIO(data))
            infos = self._zf.infolist()
        except (zipfile.BadZipFile, OSError, ValueError) as err:
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
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError) as err:
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
        except (tarfile.TarError, OSError, EOFError, ValueError) as err:
            raise ArchiveError(f"bad tar: {err}") from err
        self._members: dict[str, tarfile.TarInfo] = {}
        for m in members:
            path = _check_path(m.name)
            if m.isdir():
                continue
            if m.issym() or m.islnk():
                raise ArchiveError(f"link in archive: {m.name!r}")
            if not m.isfile():
                raise ArchiveError(f"special file in archive: {m.name!r}")
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
        except (tarfile.TarError, OSError, EOFError) as err:
            raise ArchiveError(f"cannot read {path!r}: {err}") from err
        if fh is None:
            raise ArchiveError(f"cannot read {path!r}")
        with fh:
            data = _read_stream(
                fh, compressed=0, cap=cap, limits=self._limits, budget=self._budget, name=path
            )
        if self._budget.total > max(self._compressed, 1) * self._limits.max_ratio and (
            self._budget.total > 16 * 1024 * 1024
        ):
            raise LimitExceeded("archive exceeds compression ratio limit")
        return data


def _decompress(data: bytes, limits: Limits) -> bytes:
    """Decompress a tar stream with hard caps, before tarfile sees it."""
    if data[:2] == b"\x1f\x8b":
        zd = zlib.decompressobj(16 + zlib.MAX_WBITS)

        def step(chunk: bytes, room: int) -> bytes:
            return zd.decompress(zd.unconsumed_tail + chunk, room)

        def pending() -> bool:
            return bool(zd.unconsumed_tail)
    elif data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00":
        cd: bz2.BZ2Decompressor | lzma.LZMADecompressor = (
            bz2.BZ2Decompressor() if data[:3] == b"BZh" else lzma.LZMADecompressor()
        )

        def step(chunk: bytes, room: int) -> bytes:
            if cd.eof:
                return b""
            return cd.decompress(chunk, room)

        def pending() -> bool:
            return not cd.eof and not cd.needs_input
    else:
        if len(data) > limits.max_total_uncompressed:
            raise LimitExceeded("total uncompressed size limit exceeded")
        return data

    cap = limits.max_total_uncompressed
    ratio_floor = 16 * 1024 * 1024
    out = bytearray()

    def check() -> None:
        if len(out) > cap:
            raise LimitExceeded("total uncompressed size limit exceeded")
        if len(out) > ratio_floor and len(out) > len(data) * limits.max_ratio:
            raise LimitExceeded("archive exceeds compression ratio limit")

    try:
        for pos in range(0, len(data), 64 * 1024):
            out += step(data[pos : pos + 64 * 1024], cap - len(out) + 1)
            check()
            while pending():
                out += step(b"", cap - len(out) + 1)
                check()
    except (zlib.error, OSError, EOFError, lzma.LZMAError) as err:
        raise ArchiveError(f"bad compressed stream: {err}") from err
    return bytes(out)


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
