"""Packfile parsing on packs built here in pure Python. No git, no network."""

from __future__ import annotations

import hashlib
import struct
import zlib

import httpx
import pytest

from garnet_guard.ecosystems import gittree
from garnet_guard.ecosystems.gittree import (
    BLOB,
    COMMIT,
    OFS_DELTA,
    REF_DELTA,
    TREE,
    PackError,
    TreeLookup,
    apply_delta,
    fetch_request,
    packfile_from_response,
    parse_gitmodules,
    parse_pack,
    tree_files,
)
from garnet_guard.net import Http

# --- A tiny packfile builder -------------------------------------------------


def sha(kind: bytes, data: bytes) -> bytes:
    return hashlib.sha1(kind + b" %d\0" % len(data) + data).digest()


def tree(entries: list[tuple[str, str, bytes]]) -> bytes:
    """Entries are (mode, name, raw 20-byte id)."""
    return b"".join(f"{mode} {name}\0".encode() + raw for mode, name, raw in entries)


def _header(kind: int, size: int) -> bytes:
    out = bytearray([(kind << 4) | (size & 15)])
    size >>= 4
    while size:
        out[-1] |= 0x80
        out.append(size & 0x7F)
        size >>= 7
    return bytes(out)


def _ofs(back: int) -> bytes:
    """git's big-endian base-128 encoding with the +1 trick, as in pack-format.txt."""
    out = [back & 0x7F]
    back >>= 7
    while back:
        back -= 1
        out.append(0x80 | (back & 0x7F))
        back >>= 7
    return bytes(reversed(out))


def _delta_size(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def delta(base: bytes, target: bytes) -> bytes:
    """A delta that copies the common prefix of ``base`` and inserts the rest."""
    common = 0
    while common < min(len(base), len(target)) and base[common] == target[common]:
        common += 1
    ops = bytearray()
    if common:
        ops += bytes([0x80 | 0x10, common & 0xFF])  # copy from offset 0, 1 size byte
        ops[-1] = common & 0xFF
        if common > 0xFF:
            ops = bytearray([0x80 | 0x10 | 0x20, common & 0xFF, (common >> 8) & 0xFF])
    rest = target[common:]
    while rest:
        piece, rest = rest[:127], rest[127:]
        ops += bytes([len(piece)]) + piece
    return _delta_size(len(base)) + _delta_size(len(target)) + bytes(ops)


def pack(objects: list[tuple[int, bytes, bytes]]) -> bytes:
    """Objects are (kind, extra header bytes, uncompressed data)."""
    body = bytearray(b"PACK" + struct.pack(">II", 2, len(objects)))
    for kind, extra, data in objects:
        body += _header(kind, len(data)) + extra + zlib.compress(data)
    return bytes(body) + hashlib.sha1(body).digest()


def sideband(pack_bytes: bytes) -> bytes:
    """A v2 fetch response: shallow-info section, then the pack on band 1."""
    out = gittree.pkt_line("shallow-info\n") + gittree.pkt_line("shallow " + "a" * 40 + "\n")
    out += b"0001" + gittree.pkt_line("packfile\n")
    for i in range(0, len(pack_bytes), 1000):
        chunk = b"\x01" + pack_bytes[i : i + 1000]
        out += b"%04x" % (len(chunk) + 4) + chunk
    return out + b"0000"


BLOB_A = b"import os\n"
BLOB_B = b"X = 1\n"
SUBTREE = tree([("100644", "mod.py", sha(b"blob", BLOB_B)), ("120000", "link", b"\x02" * 20)])
ROOT = tree(
    [
        ("100644", "README", sha(b"blob", BLOB_A)),
        ("40000", "pkg", sha(b"tree", SUBTREE)),
        ("160000", "vendor", b"\x03" * 20),
    ]
)
COMMIT_DATA = b"tree " + sha(b"tree", ROOT).hex().encode() + b"\nauthor a <a> 0 +0000\n\nmsg\n"
COMMIT_SHA = sha(b"commit", COMMIT_DATA).hex()


def simple_pack() -> bytes:
    return pack([(COMMIT, b"", COMMIT_DATA), (TREE, b"", ROOT), (TREE, b"", SUBTREE)])


# --- Tests -------------------------------------------------------------------


def test_tree_files_walks_subtrees_and_records_submodules() -> None:
    found = tree_files(parse_pack(simple_pack()), COMMIT_SHA)
    assert found.files == {
        "README": sha(b"blob", BLOB_A).hex(),
        "pkg/mod.py": sha(b"blob", BLOB_B).hex(),
    }
    assert found.submodules == {"vendor": "03" * 20}  # the symlink is not a file


def test_parse_gitmodules() -> None:
    text = (
        b'[submodule "vendor"]\n\tpath = vendor\n\turl = https://github.com/o/vendor.git\n'
        b'[submodule "broken"]\n\tpath = broken\n'
        b'[submodule "other"]\n\turl = git@github.com:o/other.git\n\tpath = libs/other\n'
    )
    assert parse_gitmodules(text) == {
        "vendor": "https://github.com/o/vendor.git",
        "libs/other": "git@github.com:o/other.git",
    }


def test_offset_delta_resolves_against_earlier_object() -> None:
    root2 = ROOT + b""  # same bytes, so the delta is "copy everything"
    body = pack([(COMMIT, b"", COMMIT_DATA), (TREE, b"", ROOT), (TREE, b"", SUBTREE)])
    # Append an OFS_DELTA whose base is the ROOT object. Its offset is right
    # after the commit: 12 header bytes + the commit entry.
    commit_entry = _header(COMMIT, len(COMMIT_DATA)) + zlib.compress(COMMIT_DATA)
    root_offset = 12 + len(commit_entry)
    objs = [(COMMIT, b"", COMMIT_DATA), (TREE, b"", ROOT), (TREE, b"", SUBTREE)]
    raw = bytearray(b"PACK" + struct.pack(">II", 2, 4))
    for kind, extra, data in objs:
        raw += _header(kind, len(data)) + extra + zlib.compress(data)
    d = delta(ROOT, root2)
    raw += _header(OFS_DELTA, len(d)) + _ofs(len(raw) - root_offset) + zlib.compress(d)
    raw += hashlib.sha1(raw).digest()
    objects = parse_pack(bytes(raw))
    assert len(objects) == 3  # the delta rebuilt ROOT, which is already there
    assert objects[sha(b"tree", ROOT).hex()].data == ROOT
    del body


def test_ref_delta_rebuilds_a_changed_tree() -> None:
    changed = tree([("100644", "README", sha(b"blob", BLOB_B))])
    d = delta(ROOT, changed)
    objects = parse_pack(
        pack([(TREE, b"", ROOT), (REF_DELTA, sha(b"tree", ROOT), d)]),
    )
    assert objects[sha(b"tree", changed).hex()].data == changed


def test_apply_delta_rejects_copy_outside_base() -> None:
    bad = _delta_size(3) + _delta_size(5) + bytes([0x80 | 0x10, 5])  # copy 5 from a 3-byte base
    with pytest.raises(PackError):
        apply_delta(b"abc", bad)


def test_checksum_and_truncation_are_errors() -> None:
    good = simple_pack()
    with pytest.raises(PackError, match="checksum"):
        parse_pack(good[:-1] + bytes([good[-1] ^ 1]))
    with pytest.raises(PackError):
        parse_pack(good[:40] + hashlib.sha1(good[:40]).digest())
    with pytest.raises(PackError, match="not a packfile"):
        parse_pack(b"nope")


def test_missing_delta_base_is_an_error() -> None:
    d = delta(ROOT, ROOT)
    with pytest.raises(PackError, match="base missing"):
        parse_pack(pack([(COMMIT, b"", COMMIT_DATA), (REF_DELTA, b"\x09" * 20, d)]))


def test_commit_or_tree_missing_is_an_error() -> None:
    objects = parse_pack(pack([(COMMIT, b"", COMMIT_DATA)]))
    with pytest.raises(PackError, match="missing"):
        tree_files(objects, COMMIT_SHA)
    with pytest.raises(PackError, match="commit not in"):
        tree_files(objects, "0" * 40)


def test_packfile_from_response_takes_band_one_and_reports_errors() -> None:
    assert packfile_from_response(sideband(simple_pack())) == simple_pack()
    err = gittree.pkt_line("packfile\n") + gittree.pkt_line("\x03not our ref\n") + b"0000"
    with pytest.raises(PackError, match="not our ref"):
        packfile_from_response(err)
    with pytest.raises(PackError, match="not found"):
        packfile_from_response(gittree.pkt_line("ERR upload-pack: not found\n"))
    with pytest.raises(PackError):
        packfile_from_response(b"zzzz")


def test_fetch_request_is_pkt_lines() -> None:
    body = fetch_request(["a" * 40], trees_only=True)
    assert body.startswith(b"0012command=fetch\n")
    assert b"0032want " + b"a" * 40 + b"\n" in body
    assert b"filter blob:none" in body and body.endswith(b"0009done\n0000")
    assert b"filter" not in fetch_request(["b" * 40], trees_only=False)


def test_tree_lookup_posts_once_per_commit_and_fetches_blobs() -> None:
    calls: list[tuple[str, bytes]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((str(request.url), request.content))
        assert request.headers["git-protocol"] == "version=2"
        if b"filter blob:none" in request.content:
            return httpx.Response(200, stream=httpx.ByteStream(sideband(simple_pack())))
        blob = sideband(pack([(BLOB, b"", BLOB_B)]))
        return httpx.Response(200, stream=httpx.ByteStream(blob))

    with Http(transport=httpx.MockTransport(handler)) as http:
        lookup = TreeLookup(http)
        found = lookup.files("o/r", COMMIT_SHA)
        assert lookup.files("O/R", COMMIT_SHA) is found
        assert lookup.blob("o/r", found.files["pkg/mod.py"]) == BLOB_B
    assert [u for u, _ in calls] == ["https://github.com/o/r.git/git-upload-pack"] * 2
    assert b"want " + COMMIT_SHA.encode() in calls[0][1]


def test_tree_lookup_turns_bad_responses_into_net_errors() -> None:
    from garnet_guard.net import NetError

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=httpx.ByteStream(b"not a pack"))

    with Http(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(NetError, match="git fetch from github.com/o/r: bad pkt-line"):
            TreeLookup(http).files("o/r", COMMIT_SHA)
