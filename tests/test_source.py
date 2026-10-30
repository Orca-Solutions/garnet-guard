"""Comparing a release's Python files with the source tree at its tag (GRN-C007 facts)."""

from __future__ import annotations

import hashlib

import pytest

from garnet_guard.ecosystems.gittree import CommitFiles
from garnet_guard.ecosystems.source import find_prefix, match_artifact, repo_files
from garnet_guard.facts.inventory import git_blob_id
from garnet_guard.models import TagInfo
from garnet_guard.net import NetError
from tests.builders import release

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
    cand = release(
        "1.1",
        {"demo/__init__.py": INIT, "demo/dl.py": PAYLOAD_DL, "demo/_version.py": VERSION},
    )
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
    match = match_artifact(trees, TAG, cand.artifacts[0])  # type: ignore[arg-type]
    assert (match.repo, match.tag, match.prefix, match.matched) == ("o/r", "v1.1", "src/", 1)
    assert [(u.path, u.in_source, [c.name for c in u.calls]) for u in match.unmatched] == [
        ("demo/_version.py", False, []),
        ("demo/dl.py", True, ["subprocess.Popen"]),
    ]
    assert match.unmatched[1].calls[0].via == "run"
    assert trees.blob_requests == [git_blob_id(CLEAN_DL.encode())]  # not the version file


def test_match_is_quiet_when_the_source_has_the_same_call() -> None:
    cand = release("1.1", {"demo/dl.py": PAYLOAD_DL + "\n# built\n"})
    trees = FakeTrees(
        {("o/r", "c" * 40): CommitFiles({"demo/dl.py": git_blob_id(PAYLOAD_DL.encode())}, {})},
        blobs(PAYLOAD_DL),
    )
    match = match_artifact(trees, TAG, cand.artifacts[0])  # type: ignore[arg-type]
    assert [(u.path, u.calls) for u in match.unmatched] == [("demo/dl.py", ())]


def test_files_under_an_unreadable_submodule_are_unchecked_not_passed() -> None:
    cand = release("1.1", {"demo/__init__.py": INIT, "demo/vendored/x.py": PAYLOAD_DL})
    trees = FakeTrees(
        {
            ("o/r", "c" * 40): CommitFiles(
                {"demo/__init__.py": git_blob_id(INIT.encode())}, {"demo/vendored": "d" * 40}
            )
        },
        {},
    )
    match = match_artifact(trees, TAG, cand.artifacts[0])  # type: ignore[arg-type]
    assert match.unchecked == ("demo/vendored/x.py",)
    assert match.unmatched == ()


def test_tree_fetch_failure_propagates_as_net_error() -> None:
    cand = release("1.1", {"demo/__init__.py": INIT})
    with pytest.raises(NetError):
        match_artifact(FakeTrees({}, {}), TAG, cand.artifacts[0])  # type: ignore[arg-type]
