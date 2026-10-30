"""Read the files of a git commit from GitHub without git.

One POST to ``/<owner>/<repo>.git/git-upload-pack`` (git protocol v2 over
HTTPS, the same endpoint as the tag lookup) with ``filter blob:none`` and
``deepen 1`` returns a packfile holding the commit and its trees, a few
dozen kilobytes for most repositories. A second request for one blob
returns one file. No token, no REST rate limit, and no ``git`` binary.

The packfile is parsed here: pkt-line framing, zlib-compressed objects,
offset and reference deltas, tree entries. Every size is capped, nothing is
written to disk, and nothing is executed. GRN-C007 uses the result to ask
whether the code in a release is the code at its tag.
"""

from __future__ import annotations

import hashlib
import struct
import threading
import zlib
from collections.abc import Mapping
from dataclasses import dataclass

from ..net import Http, NetError

COMMIT, TREE, BLOB, TAG, OFS_DELTA, REF_DELTA = 1, 2, 3, 4, 6, 7
_TYPE_NAMES = {COMMIT: b"commit", TREE: b"tree", BLOB: b"blob", TAG: b"tag"}

MAX_RESPONSE_BYTES = 64 * 1024 * 1024  # the whole fetch response
MAX_OBJECT_BYTES = 16 * 1024 * 1024  # one decompressed object
MAX_TOTAL_BYTES = 256 * 1024 * 1024  # every decompressed object together
MAX_OBJECTS = 200_000
_HEADERS = {
    "Git-Protocol": "version=2",
    "Content-Type": "application/x-git-upload-pack-request",
    "Accept": "application/x-git-upload-pack-result",
}


class PackError(Exception):
    """The response wasn't a packfile Garnet can read. Becomes GRN-E001."""


def pkt_line(text: str) -> bytes:
    """One pkt-line: a four-digit hex length (including itself) and the text."""
    data = text.encode()
    return b"%04x" % (len(data) + 4) + data


def fetch_request(wants: list[str], *, trees_only: bool) -> bytes:
    """The body of a protocol v2 ``fetch`` for these objects, one commit deep."""
    parts = [pkt_line("command=fetch\n"), pkt_line("object-format=sha1\n"), b"0001"]
    parts += [pkt_line(f"want {sha}\n") for sha in wants]
    if trees_only:
        parts.append(pkt_line("filter blob:none\n"))
    parts += [pkt_line("deepen 1\n"), pkt_line("no-progress\n"), pkt_line("done\n"), b"0000"]
    return b"".join(parts)


def packfile_from_response(data: bytes) -> bytes:
    """The PACK bytes carried on sideband 1 of a v2 fetch response."""
    pack = bytearray()
    pos = 0
    in_pack = False
    while pos + 4 <= len(data):
        try:
            length = int(data[pos : pos + 4], 16)
        except ValueError as err:
            raise PackError("bad pkt-line length") from err
        if length in (0, 1):  # flush and delimiter packets
            pos += 4
            continue
        if length < 4 or pos + length > len(data):
            raise PackError("truncated pkt-line")
        line = data[pos + 4 : pos + length]
        pos += length
        if in_pack:
            band = line[:1]
            if band == b"\x01":
                pack += line[1:]
            elif band == b"\x03":
                raise PackError("server error: " + _text(line[1:]))
            # band 2 is progress, which the request turned off
        elif line.rstrip(b"\n") == b"packfile":
            in_pack = True
        elif line.startswith(b"ERR "):
            raise PackError(_text(line[4:]))
    if not pack.startswith(b"PACK"):
        raise PackError("no packfile in response")
    return bytes(pack)


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace").strip()


@dataclass(frozen=True)
class Obj:
    kind: int
    data: bytes


def _git_id(kind: bytes, data: bytes) -> str:
    """Git names objects by SHA-1; that is an identifier here, not a security check."""
    return hashlib.sha1(kind + b" %d\0" % len(data) + data).hexdigest()  # noqa: S324


def _sha(obj: Obj) -> str:
    return _git_id(_TYPE_NAMES[obj.kind], obj.data)


def _object_header(pack: bytes, pos: int) -> tuple[int, int, int]:
    """(type, declared size, next position) of the object at ``pos``."""
    c = pack[pos]
    pos += 1
    kind = (c >> 4) & 7
    size = c & 15
    shift = 4
    while c & 0x80:
        c = pack[pos]
        pos += 1
        size |= (c & 0x7F) << shift
        shift += 7
    return kind, size, pos


def _delta_size(delta: bytes, pos: int) -> tuple[int, int]:
    size = 0
    shift = 0
    while True:
        c = delta[pos]
        pos += 1
        size |= (c & 0x7F) << shift
        shift += 7
        if not c & 0x80:
            return size, pos


def apply_delta(base: bytes, delta: bytes) -> bytes:
    """Rebuild an object from its base and a git delta (copy and insert ops)."""
    src_size, pos = _delta_size(delta, 0)
    if src_size != len(base):
        raise PackError("delta base size mismatch")
    out_size, pos = _delta_size(delta, pos)
    if out_size > MAX_OBJECT_BYTES:
        raise PackError("delta result larger than the limit")
    out = bytearray()
    while pos < len(delta):
        op = delta[pos]
        pos += 1
        if op & 0x80:
            offset = 0
            size = 0
            for i in range(4):
                if op & (1 << i):
                    offset |= delta[pos] << (8 * i)
                    pos += 1
            for i in range(3):
                if op & (1 << (4 + i)):
                    size |= delta[pos] << (8 * i)
                    pos += 1
            size = size or 0x10000
            if offset + size > len(base):
                raise PackError("delta copies outside its base")
            out += base[offset : offset + size]
        elif op:
            out += delta[pos : pos + op]
            pos += op
        else:
            raise PackError("delta opcode 0")
        if len(out) > out_size:
            raise PackError("delta result size mismatch")
    if len(out) != out_size:
        raise PackError("delta result size mismatch")
    return bytes(out)


def _inflate(pack: bytes, pos: int, expect: int) -> tuple[bytes, int]:
    """Decompress one object at ``pos``, bounded; return (bytes, next position)."""
    d = zlib.decompressobj()
    out = bytearray()
    while not d.eof:
        chunk = pack[pos : pos + 65536]
        if not chunk:
            raise PackError("truncated object")
        try:
            out += d.decompress(chunk, MAX_OBJECT_BYTES + 1 - len(out))
        except zlib.error as err:
            raise PackError("corrupt object") from err
        if len(out) > MAX_OBJECT_BYTES or d.unconsumed_tail:
            raise PackError("object larger than the limit")
        pos += len(chunk) - len(d.unused_data) if d.eof else len(chunk)
    if len(out) != expect:
        raise PackError("object size mismatch")
    return bytes(out), pos


def parse_pack(pack: bytes) -> dict[str, Obj]:
    """Every object in a version 2 packfile by its id, deltas resolved."""
    if len(pack) < 32 or pack[:4] != b"PACK":
        raise PackError("not a packfile")
    version, count = struct.unpack(">II", pack[4:12])
    if version != 2 or count > MAX_OBJECTS:
        raise PackError(f"unsupported packfile (version {version}, {count} objects)")
    if hashlib.sha1(pack[:-20]).digest() != pack[-20:]:  # noqa: S324 (git's trailer)
        raise PackError("packfile checksum mismatch")
    by_offset: dict[int, Obj] = {}
    by_sha: dict[str, Obj] = {}
    # Deltas wait until their base is known: (offset, base offset, base id, delta).
    pending: list[tuple[int, int, str | None, bytes]] = []
    pos = 12
    total = 0
    try:
        for _ in range(count):
            start = pos
            kind, size, pos = _object_header(pack, pos)
            base_off = -1
            base_sha = None
            if kind == OFS_DELTA:
                c = pack[pos]
                pos += 1
                back = c & 0x7F
                while c & 0x80:
                    c = pack[pos]
                    pos += 1
                    back = ((back + 1) << 7) | (c & 0x7F)
                base_off = start - back
            elif kind == REF_DELTA:
                base_sha = pack[pos : pos + 20].hex()
                pos += 20
            elif kind not in _TYPE_NAMES:
                raise PackError(f"unknown object type {kind}")
            data, pos = _inflate(pack, pos, size)
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise PackError("packfile decompresses past the limit")
            if kind in (OFS_DELTA, REF_DELTA):
                pending.append((start, base_off, base_sha, data))
                continue
            obj = Obj(kind, data)
            by_offset[start] = obj
            by_sha[_sha(obj)] = obj
    except IndexError as err:
        raise PackError("truncated packfile") from err
    while pending:  # deltas can chain, so resolve in rounds
        rest = []
        for start, base_off, base_sha, delta in pending:
            base = by_offset.get(base_off) if base_sha is None else by_sha.get(base_sha)
            if base is None:
                rest.append((start, base_off, base_sha, delta))
                continue
            obj = Obj(base.kind, apply_delta(base.data, delta))
            by_offset[start] = obj
            by_sha[_sha(obj)] = obj
        if len(rest) == len(pending):
            raise PackError("delta base missing from packfile")
        pending = rest
    return by_sha


def parse_tree(data: bytes) -> list[tuple[str, str, str]]:
    """The (mode, name, id) entries of a tree object."""
    out = []
    pos = 0
    try:
        while pos < len(data):
            space = data.index(b" ", pos)
            nul = data.index(b"\0", space)
            if nul + 21 > len(data):
                raise PackError("truncated tree entry")
            mode = data[pos:space].decode("ascii", "replace")
            name = data[space + 1 : nul].decode("utf-8", "replace")
            out.append((mode, name, data[nul + 1 : nul + 21].hex()))
            pos = nul + 21
    except ValueError as err:
        raise PackError("malformed tree object") from err
    return out


@dataclass(frozen=True)
class CommitFiles:
    """What a commit's tree holds: regular files by blob id, and submodules by
    the commit they pin. Symlinks are left out; they aren't files in a release."""

    files: Mapping[str, str]
    submodules: Mapping[str, str]


def tree_files(objects: dict[str, Obj], commit: str) -> CommitFiles:
    """Every regular file and submodule reachable from the commit's tree."""
    head = objects.get(commit)
    if head is None or head.kind != COMMIT:
        raise PackError("commit not in packfile")
    first = head.data.split(b"\n", 1)[0]
    if not first.startswith(b"tree ") or len(first) < 45:
        raise PackError("commit without a tree")
    files: dict[str, str] = {}
    submodules: dict[str, str] = {}
    stack = [(first[5:45].decode("ascii", "replace"), "")]
    while stack:
        sha, prefix = stack.pop()
        tree = objects.get(sha)
        if tree is None or tree.kind != TREE:
            raise PackError(f"tree {sha} missing from packfile")
        for mode, name, entry in parse_tree(tree.data):
            if mode == "40000":
                stack.append((entry, f"{prefix}{name}/"))
            elif mode in ("100644", "100755"):
                files[prefix + name] = entry
            elif mode == "160000":
                submodules[prefix + name] = entry
    return CommitFiles(files, submodules)


def parse_gitmodules(data: bytes) -> dict[str, str]:
    """{path: url} from a ``.gitmodules`` file. Malformed lines are skipped."""
    out: dict[str, str] = {}
    path = url = None
    for raw in data.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if line.startswith("["):
            if path and url:
                out[path] = url
            path = url = None
        elif "=" in line:
            key, _, value = line.partition("=")
            if key.strip() == "path":
                path = value.strip()
            elif key.strip() == "url":
                url = value.strip()
    if path and url:
        out[path] = url
    return out


class TreeLookup:
    """Files at a commit, and single blobs, fetched once per run and shared.

    Raises ``NetError`` for anything the caller should report as GRN-E001:
    the request failed, or the response wasn't a packfile Garnet could read.
    """

    def __init__(self, http: Http) -> None:
        self._http = http
        self._trees: dict[tuple[str, str], CommitFiles] = {}
        self._blobs: dict[tuple[str, str], bytes] = {}
        self._lock = threading.Lock()

    def _fetch(self, repo: str, wants: list[str], *, trees_only: bool) -> dict[str, Obj]:
        url = f"https://github.com/{repo}.git/git-upload-pack"
        body = fetch_request(wants, trees_only=trees_only)
        resp = self._http.post(url, body, headers=_HEADERS, max_bytes=MAX_RESPONSE_BYTES)
        if resp.status != 200:
            raise NetError(f"git fetch from github.com/{repo} returned HTTP {resp.status}")
        try:
            return parse_pack(packfile_from_response(resp.content))
        except PackError as err:
            raise NetError(f"git fetch from github.com/{repo}: {err}") from err

    def files(self, repo: str, commit: str) -> CommitFiles:
        """The files and submodules at ``commit`` in ``owner/repo``."""
        key = (repo.lower(), commit)
        with self._lock:
            cached = self._trees.get(key)
        if cached is None:
            try:
                cached = tree_files(self._fetch(repo, [commit], trees_only=True), commit)
            except PackError as err:
                raise NetError(f"git fetch from github.com/{repo}: {err}") from err
            with self._lock:
                self._trees[key] = cached
        return cached

    def blob(self, repo: str, sha: str) -> bytes:
        """The bytes of one file by its blob id."""
        key = (repo.lower(), sha)
        with self._lock:
            cached = self._blobs.get(key)
        if cached is None:
            obj = self._fetch(repo, [sha], trees_only=False).get(sha)
            if obj is None or obj.kind != BLOB:
                raise NetError(f"git fetch from github.com/{repo}: blob {sha} not returned")
            cached = obj.data
            with self._lock:
                self._blobs[key] = cached
        return cached
