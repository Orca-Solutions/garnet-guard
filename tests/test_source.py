"""Comparing a release's Python files with the source tree at its tag (GRN-C007 facts)."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

import pytest

from garnet_guard.ecosystems.gittree import CommitFiles
from garnet_guard.ecosystems.source import (
    find_prefix,
    find_renames,
    match_artifact,
    match_tags,
    repo_files,
)
from garnet_guard.facts.inventory import file_reader, git_blob_id
from garnet_guard.models import Limits, TagInfo
from garnet_guard.net import NetError
from tests.builders import release, sdist, wheel

INIT = "def hello():\n    return 1\n"
CLEAN_DL = "import subprocess\n\ndef run(cmd):\n    return cmd\n"
PAYLOAD_DL = "import subprocess\n\ndef run(cmd):\n    return subprocess.Popen(cmd)\n"
VERSION = "__version__ = '1.1'\n"
TAG = TagInfo(name="v1.1", sha="c" * 40, repo="o/r")


class FakeTrees:
    """Stands in for ``gittree.TreeLookup``: trees by (repo, commit), blobs by id."""

    def __init__(self, trees: dict[tuple[str, str], CommitFiles], blobs: dict[str, bytes]):
        self.trees = trees
        self.blobs = blobs
        self.blob_requests: list[str] = []

    def files(self, repo: str, commit: str) -> CommitFiles:
        try:
            return self.trees[(repo, commit)]
        except KeyError:
            raise NetError(f"git fetch from github.com/{repo} returned HTTP 404") from None

    def blob(self, repo: str, sha: str) -> bytes:
        self.blob_requests.append(sha)
        return self.blobs[sha]


def blobs(*sources: str) -> dict[str, bytes]:
    return {git_blob_id(s.encode()): s.encode() for s in sources}


def published(files: dict[str, str]) -> tuple[Callable[[str], bytes], list[str]]:
    """A ``source_of`` reader over the wheel's files that records what was read back."""
    asked: list[str] = []

    def read(path: str) -> bytes:
        asked.append(path)
        return files[path].encode()

    return read, asked


def test_git_blob_id_matches_git() -> None:
    assert git_blob_id(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    assert (
        git_blob_id(INIT.encode())
        == hashlib.sha1(b"blob %d\0" % len(INIT) + INIT.encode()).hexdigest()
    )


def test_find_prefix_votes_for_the_directory_most_files_share() -> None:
    tree = {"src/demo/__init__.py": "", "src/demo/dl.py": "", "demo/__init__.py": ""}
    assert find_prefix(["demo/__init__.py", "demo/dl.py"], tree) == "src/"
    assert find_prefix(["demo/__init__.py"], {"demo/__init__.py": ""}) == ""
    assert find_prefix(["demo/__init__.py"], {"other/x.py": ""}) == ""


def test_repo_files_expands_github_submodules_and_names_the_rest() -> None:
    gitmodules = (
        b'[submodule "vendor"]\n\tpath = vendor\n\turl = git@github.com:o/vendor.git\n'
        b'[submodule "private"]\n\tpath = private\n\turl = https://gitlab.example/x.git\n'
    )
    trees = FakeTrees(
        {
            ("o/r", "c" * 40): CommitFiles(
                {".gitmodules": "g" * 40, "demo/__init__.py": "a" * 40},
                {"vendor": "d" * 40, "private": "e" * 40, "gone": "f" * 40},
            ),
            ("o/vendor", "d" * 40): CommitFiles({"lib.py": "b" * 40}, {"nested": "1" * 40}),
        },
        {"g" * 40: gitmodules},
    )
    files, unreadable = repo_files(trees, "o/r", "c" * 40)  # type: ignore[arg-type]
    assert files == {
        ".gitmodules": ("o/r", "g" * 40),
        "demo/__init__.py": ("o/r", "a" * 40),
        "vendor/lib.py": ("o/vendor", "b" * 40),
    }
    assert unreadable == ("gone", "private", "vendor/nested")


def test_match_reports_calls_the_source_lacks_and_fetches_only_what_it_needs() -> None:
    files = {"demo/__init__.py": INIT, "demo/dl.py": PAYLOAD_DL, "demo/_version.py": VERSION}
    cand = release("1.1", files)
    source_of, asked = published(files)
    trees = FakeTrees(
        {
            ("o/r", "c" * 40): CommitFiles(
                {
                    "src/demo/__init__.py": git_blob_id(INIT.encode()),
                    "src/demo/dl.py": git_blob_id(CLEAN_DL.encode()),
                },
                {},
            )
        },
        blobs(INIT, CLEAN_DL),
    )
    match = match_artifact(trees, TAG, cand.artifacts[0], source_of)  # type: ignore[arg-type]
    assert (match.repo, match.tag, match.prefix, match.matched) == ("o/r", "v1.1", "src/", 1)
    assert [(u.path, u.in_source, [c.name for c in u.calls]) for u in match.unmatched] == [
        ("demo/_version.py", False, []),
        ("demo/dl.py", True, ["subprocess.Popen"]),
    ]
    assert match.unmatched[1].calls[0].via == "run"
    assert trees.blob_requests == [git_blob_id(CLEAN_DL.encode())]  # not the version file
    assert asked == ["demo/_version.py", "demo/dl.py"]  # the sourced file is never read back


def test_identical_file_counts_as_sourced_wherever_the_build_put_it() -> None:
    cand = release("1.1", {"demo/_vendor/x.py": PAYLOAD_DL})
    source_of, asked = published({})  # reading anything back would raise KeyError
    trees = FakeTrees(
        {
            ("o/r", "c" * 40): CommitFiles(
                {"subprojects/x/x/x.py": git_blob_id(PAYLOAD_DL.encode())}, {}
            )
        },
        {},
    )
    match = match_artifact(trees, TAG, cand.artifacts[0], source_of)  # type: ignore[arg-type]
    assert (match.matched, match.unmatched) == (1, ())


def test_match_is_quiet_when_the_source_has_the_same_call() -> None:
    files = {"demo/dl.py": PAYLOAD_DL + "\n# built\n"}
    cand = release("1.1", files)
    trees = FakeTrees(
        {("o/r", "c" * 40): CommitFiles({"demo/dl.py": git_blob_id(PAYLOAD_DL.encode())}, {})},
        blobs(PAYLOAD_DL),
    )
    match = match_artifact(trees, TAG, cand.artifacts[0], published(files)[0])  # type: ignore[arg-type]
    assert [(u.path, u.calls) for u in match.unmatched] == [("demo/dl.py", ())]


def test_a_top_level_module_named_like_a_library_hides_no_call() -> None:
    # demo ships an empty requests.py; Python imports the installed requests,
    # so the call the tagged source lacks is listed.
    post = "import requests\n\nrequests.post('https://example.invalid', data='')\n"
    files = {"demo/__init__.py": INIT + post, "requests.py": ""}
    trees = FakeTrees(
        {("o/r", "c" * 40): CommitFiles({"demo/__init__.py": git_blob_id(INIT.encode())}, {})},
        blobs(INIT),
    )
    match = match_artifact(trees, TAG, release("1.1", files).artifacts[0], published(files)[0])  # type: ignore[arg-type]
    assert [(u.path, [c.name for c in u.calls]) for u in match.unmatched] == [
        ("demo/__init__.py", ["requests.post"]),
        ("requests.py", []),
    ]
    # The requests project calling its own module is its own code.
    own = {"requests/adapters.py": "from requests.utils import where\n\nCA = where()\n"}
    trees = FakeTrees(
        {("o/r", "c" * 40): CommitFiles({"requests/adapters.py": git_blob_id(INIT.encode())}, {})},
        blobs(INIT),
    )
    art = release("1.1", own, package="requests").artifacts[0]
    match = match_artifact(trees, TAG, art, published(own)[0])  # type: ignore[arg-type]
    assert [(u.path, u.calls) for u in match.unmatched] == [("requests/adapters.py", ())]


def test_a_file_with_crlf_line_endings_is_the_source_file() -> None:
    # multiprocess 0.70.12.1 ships only Windows wheels, built from a checkout with CRLF endings.
    files = {"demo/dl.py": PAYLOAD_DL.replace("\n", "\r\n")}
    cand = release("1.1", files)
    trees = FakeTrees(
        {("o/r", "c" * 40): CommitFiles({"demo/dl.py": git_blob_id(PAYLOAD_DL.encode())}, {})}, {}
    )
    match = match_artifact(trees, TAG, cand.artifacts[0], published(files)[0])  # type: ignore[arg-type]
    assert (match.matched, match.unmatched) == (1, ())


def test_crlf_endings_on_changed_code_still_report_the_new_call() -> None:
    files = {"demo/dl.py": (PAYLOAD_DL + "import os\nos.system('x')\n").replace("\n", "\r\n")}
    cand = release("1.1", files)
    trees = FakeTrees(
        {("o/r", "c" * 40): CommitFiles({"demo/dl.py": git_blob_id(PAYLOAD_DL.encode())}, {})},
        blobs(PAYLOAD_DL),
    )
    match = match_artifact(trees, TAG, cand.artifacts[0], published(files)[0])  # type: ignore[arg-type]
    assert [(u.path, [c.name for c in u.calls]) for u in match.unmatched] == [
        ("demo/dl.py", ["os.system"])
    ]


def test_find_renames_maps_a_package_published_under_another_name() -> None:
    # pycryptodome's build publishes lib/Crypto/ as pycryptodomex's Cryptodome/.
    tree = {
        "lib/Crypto/__init__.py": "",
        "lib/Crypto/Cipher/AES.py": "",
        "lib/Crypto/Hash/MD5.py": "",
    }
    paths = ["Cryptodome/__init__.py", "Cryptodome/Cipher/AES.py", "Cryptodome/Hash/MD5.py"]
    assert find_renames(paths, tree, "") == {"Cryptodome": "lib/Crypto/"}
    # A package whose own directory is there isn't renamed, and one vote in three isn't enough.
    assert find_renames(["Crypto/Cipher/AES.py"], tree, "lib/") == {}
    odd = ["Cryptodome/Cipher/AES.py", "Cryptodome/Util/a.py", "Cryptodome/Util/b.py"]
    assert find_renames(odd, tree, "") == {}


def test_a_renamed_package_is_compared_with_the_directory_it_came_from() -> None:
    source = "import Crypto.Hash\nimport importlib\n\ndef get(n):\n    return importlib.import_module(n)\n"
    built = source.replace("Crypto", "Cryptodome")
    files = {"Cryptodome/__init__.py": INIT, "Cryptodome/SelfTest/__init__.py": built}
    cand = release("1.1", files)
    trees = FakeTrees(
        {
            ("o/r", "c" * 40): CommitFiles(
                {
                    "lib/Crypto/__init__.py": git_blob_id(INIT.encode()),
                    "lib/Crypto/SelfTest/__init__.py": git_blob_id(source.encode()),
                },
                {},
            )
        },
        blobs(source),
    )
    match = match_artifact(trees, TAG, cand.artifacts[0], published(files)[0])  # type: ignore[arg-type]
    assert [(u.path, u.in_source, u.at, u.calls) for u in match.unmatched] == [
        ("Cryptodome/SelfTest/__init__.py", True, "lib/Crypto/SelfTest/__init__.py", ())
    ]
    # A call the renamed source doesn't have is still reported.
    files = {**files, "Cryptodome/SelfTest/__init__.py": built + "import os\nos.system('x')\n"}
    cand = release("1.1", files)
    match = match_artifact(trees, TAG, cand.artifacts[0], published(files)[0])  # type: ignore[arg-type]
    assert [[c.name for c in u.calls] for u in match.unmatched] == [["os.system"]]


def test_match_tags_uses_the_tag_whose_tree_the_release_was_built_from() -> None:
    # sympy/sympy tags 1.12.1 at one commit and sympy-1.12.1 at the release's.
    files = {"demo/__init__.py": INIT, "demo/dl.py": PAYLOAD_DL}
    cand = release("1.1", files)
    other = TagInfo(name="demo-1.1", sha="d" * 40, repo="o/r")
    trees = FakeTrees(
        {
            ("o/r", "c" * 40): CommitFiles(
                {"demo/__init__.py": git_blob_id(INIT.encode()), "demo/dl.py": git_blob_id(b"x")},
                {},
            ),
            ("o/r", "d" * 40): CommitFiles(
                {
                    "demo/__init__.py": git_blob_id(INIT.encode()),
                    "demo/dl.py": git_blob_id(PAYLOAD_DL.encode()),
                },
                {},
            ),
        },
        {git_blob_id(b"x"): b"x"},
    )
    source_of = published(files)[0]
    match = match_tags(trees, [TAG, other], cand.artifacts[0], source_of)  # type: ignore[arg-type]
    assert (match.tag, match.commit, match.matched, match.unmatched) == (
        "demo-1.1",
        "d" * 40,
        2,
        (),
    )
    # A second tag whose tree can't be read leaves the first tag's answer.
    missing = TagInfo(name="demo-1.1", sha="e" * 40, repo="o/r")
    match = match_tags(trees, [TAG, missing], cand.artifacts[0], source_of)  # type: ignore[arg-type]
    assert match.tag == "v1.1" and [u.path for u in match.unmatched] == ["demo/dl.py"]
    with pytest.raises(NetError):
        match_tags(trees, [missing, TAG], cand.artifacts[0], source_of)  # type: ignore[arg-type]


def test_match_tags_reads_no_other_tree_when_the_first_explains_every_call() -> None:
    files = {"demo/__init__.py": INIT, "demo/_version.py": VERSION}
    cand = release("1.1", files)
    trees = FakeTrees(
        {("o/r", "c" * 40): CommitFiles({"demo/__init__.py": git_blob_id(INIT.encode())}, {})}, {}
    )
    other = TagInfo(name="demo-1.1", sha="d" * 40, repo="o/r")  # its tree would raise NetError
    match = match_tags(trees, [TAG, other], cand.artifacts[0], published(files)[0])  # type: ignore[arg-type]
    assert match.tag == "v1.1" and [u.path for u in match.unmatched] == ["demo/_version.py"]


def test_files_under_an_unreadable_submodule_are_unchecked_not_passed() -> None:
    files = {"demo/__init__.py": INIT, "demo/vendored/x.py": PAYLOAD_DL}
    cand = release("1.1", files)
    trees = FakeTrees(
        {
            ("o/r", "c" * 40): CommitFiles(
                {"demo/__init__.py": git_blob_id(INIT.encode())}, {"demo/vendored": "d" * 40}
            )
        },
        {},
    )
    match = match_artifact(trees, TAG, cand.artifacts[0], published(files)[0])  # type: ignore[arg-type]
    assert match.unchecked == ("demo/vendored/x.py",)
    assert match.unmatched == ()


def test_tree_fetch_failure_propagates_as_net_error() -> None:
    cand = release("1.1", {"demo/__init__.py": INIT})
    with pytest.raises(NetError):
        match_artifact(FakeTrees({}, {}), TAG, cand.artifacts[0], published({})[0])  # type: ignore[arg-type]


def test_file_reader_reads_recorded_paths_back_from_wheels_and_sdists() -> None:
    files = {"demo/__init__.py": INIT, "demo/dl.py": PAYLOAD_DL}
    read = file_reader("demo-1.1-py3-none-any.whl", wheel(files), Limits(), sdist=False)
    assert read("demo/dl.py") == PAYLOAD_DL.encode()
    read = file_reader("demo-1.1.tar.gz", sdist("demo-1.1", files), Limits(), sdist=True)
    assert read("demo/dl.py") == PAYLOAD_DL.encode()  # the name-version/ prefix is implied
