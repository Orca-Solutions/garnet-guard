"""Compare a release's Python files with its repository at the release's tag.

The facts for GRN-C007. A wheel is supposed to be built from the tagged
source, so every ``.py`` file in it should be byte-identical to a file in the
repository at that commit. Files that differ are common and mostly harmless
(a generated ``_version.py``, Cython output), so each one is also asked
whether it has sensitive calls the source file doesn't. The answer is
recorded; the rule in ``checks.content`` decides what to report.

Reading the repository goes through ``gittree`` (GitHub's git protocol over
HTTPS). Nothing is executed.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping

from ..facts.pyindex import sensitive_calls
from ..models import ArtifactFacts, SourceMatch, TagInfo, UnsourcedFile
from ..net import NetError
from . import github
from .gittree import TreeLookup, parse_gitmodules


def _submodule_repo(url: str) -> str | None:
    """``owner/repo`` for a GitHub submodule URL, in either the https or ssh form."""
    if url.startswith("git@github.com:"):
        url = "https://github.com/" + url[len("git@github.com:") :]
    return github.parse_repo(url)


def repo_files(
    trees: TreeLookup, repo: str, commit: str
) -> tuple[dict[str, tuple[str, str]], tuple[str, ...]]:
    """{path: (repo, blob id)} at the commit, with GitHub-hosted submodules
    expanded one level, plus the paths of submodules that couldn't be read."""
    found = trees.files(repo, commit)
    files = {path: (repo, sha) for path, sha in found.files.items()}
    unreadable: list[str] = []
    if found.submodules:
        urls: Mapping[str, str] = {}
        gitmodules = found.files.get(".gitmodules")
        if gitmodules is not None:
            urls = parse_gitmodules(trees.blob(repo, gitmodules))
        for path, sub_commit in sorted(found.submodules.items()):
            sub_repo = _submodule_repo(urls.get(path, ""))
            if sub_repo is None:
                unreadable.append(path)
                continue
            try:
                sub = trees.files(sub_repo, sub_commit)
            except NetError:
                unreadable.append(path)
                continue
            files.update({f"{path}/{p}": (sub_repo, sha) for p, sha in sub.files.items()})
            unreadable += [f"{path}/{p}" for p in sub.submodules]  # nested: one level only
    return files, tuple(unreadable)


def find_prefix(paths: Iterable[str], files: Mapping[str, object]) -> str:
    """The repository directory the artifact's files live under.

    ``""`` for a package at the repository root, ``src/`` for a src layout,
    ``python/`` and the like for mixed-language repositories, chosen by the
    directory under which most of the artifact's paths are found.
    """
    by_name: dict[str, list[str]] = {}
    for path in files:
        by_name.setdefault(path.rsplit("/", 1)[-1], []).append(path)
    votes: Counter[str] = Counter()
    for p in paths:
        for t in by_name.get(p.rsplit("/", 1)[-1], ()):
            if t == p:
                votes[""] += 1
            elif t.endswith("/" + p):
                votes[t[: -len(p)]] += 1
    if not votes:
        return ""
    return max(votes, key=lambda k: (votes[k], -len(k), k))


def match_artifact(trees: TreeLookup, tag: TagInfo, art: ArtifactFacts) -> SourceMatch:
    """Compare the artifact's parsed Python files with the tag's source tree.

    A published file counts as sourced when its exact bytes are anywhere in
    the tree (submodules included). Otherwise it is compared with the file at
    the same path under ``prefix``, when there is one. Raises ``NetError``
    when the tree or a needed file can't be read. Source files are fetched
    only for published files that have sensitive calls.
    """
    assert tag.sha is not None and tag.repo is not None
    files, unreadable = repo_files(trees, tag.repo, tag.sha)
    modules = sorted((m for m in art.modules if m.blob_sha1), key=lambda m: m.path)
    prefix = find_prefix([m.path for m in modules], files)
    own = frozenset(m.module.split(".")[0] for m in modules)
    # A file with the same bytes anywhere in the tree is sourced, wherever the
    # build put it: scipy copies a submodule's inner package up two levels.
    in_tree = {sha for _, sha in files.values()}
    matched = 0
    unmatched: list[UnsourcedFile] = []
    unchecked: list[str] = []
    for m in modules:
        if m.blob_sha1 in in_tree:
            matched += 1
            continue
        full = prefix + m.path
        source = files.get(full)
        if source is None and any(full.startswith(u + "/") for u in unreadable):
            unchecked.append(m.path)
            continue
        calls = m.sensitive_calls
        if calls and source is not None:
            repo, sha = source
            try:
                in_source = {
                    c.name for c in sensitive_calls(trees.blob(repo, sha), path=full, own=own)
                }
            except (SyntaxError, ValueError, RecursionError):
                in_source = set()  # unreadable source explains nothing
            calls = tuple(c for c in calls if c.name not in in_source)
        unmatched.append(UnsourcedFile(m.path, source is not None, calls))
    return SourceMatch(
        repo=tag.repo,
        tag=tag.name,
        commit=tag.sha,
        prefix=prefix,
        matched=matched,
        unmatched=tuple(unmatched),
        unchecked=tuple(unchecked),
    )
