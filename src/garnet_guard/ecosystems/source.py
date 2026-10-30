"""Compare a release's Python files with its repository at the release's tag.

The facts for GRN-C007. A wheel is supposed to be built from the tagged
source, so every ``.py`` file in it should be byte-identical to a file in the
repository at that commit. Files that differ are common and mostly harmless
(a generated ``_version.py``, Cython output), so each one is also asked
whether it has sensitive calls the source file doesn't. The answer is
recorded; the rule in ``checks.content`` decides what to report.

Three build habits make a file look unsourced when it isn't, and each is
allowed for: a Windows build writes CRLF line endings, a build can publish
a package under another name (pycryptodome's ``lib/Crypto/`` is
pycryptodomex's ``Cryptodome/``), and a repository can tag one release
twice at different commits.

Reading the repository goes through ``gittree`` (GitHub's git protocol over
HTTPS). Nothing is executed.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence

from ..facts.inventory import git_blob_id, project_name
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


def find_renames(paths: Iterable[str], files: Mapping[str, object], prefix: str) -> dict[str, str]:
    """Top-level packages published under another name: {name: repository directory}.

    pycryptodome's build publishes ``lib/Crypto/`` as pycryptodomex's
    ``Cryptodome/``. A top-level package with no directory of its name under
    ``prefix`` maps to the directory under which most of its files' paths
    below the top level are found, if that is at least half of them.
    """
    below: dict[str, list[str]] = {}
    for p in paths:
        top, _, rest = p.partition("/")
        if "/" in rest:
            below.setdefault(top, []).append(rest)
    missing = [t for t in sorted(below) if not any(f.startswith(f"{prefix}{t}/") for f in files)]
    if not missing:
        return {}
    dirs: dict[str, list[str]] = {}  # "Cipher/AES.py": ["lib/Crypto/"]
    for f in files:
        parts = f.split("/")
        for i in range(1, len(parts) - 1):
            dirs.setdefault("/".join(parts[i:]), []).append("/".join(parts[:i]) + "/")
    renames: dict[str, str] = {}
    for top in missing:
        votes = Counter(d for rest in below[top] for d in dirs.get(rest, ()))
        if votes:
            best = max(votes, key=lambda k: (votes[k], -len(k), k))
            if 2 * votes[best] >= len(below[top]):
                renames[top] = best
    return renames


def match_artifact(
    trees: TreeLookup, tag: TagInfo, art: ArtifactFacts, source_of: Callable[[str], bytes]
) -> SourceMatch:
    """Compare the artifact's parsed Python files with the tag's source tree.

    A published file counts as sourced when its exact bytes are anywhere in
    the tree (submodules included). Otherwise ``source_of`` reads it back
    from the artifact, its sensitive calls are indexed, and it is compared
    with the file at the same path under ``prefix``, when there is one.
    Raises ``NetError`` when the tree or a needed file can't be read. Only
    the files that differ are read back and parsed again, and source files
    are fetched only for those that have sensitive calls. A file that matches
    once CRLF line endings are read as LF is sourced; a package published
    under another name is compared with the directory it came from.
    """
    assert tag.sha is not None and tag.repo is not None
    files, unreadable = repo_files(trees, tag.repo, tag.sha)
    modules = sorted((m for m in art.modules if m.blob_sha1), key=lambda m: m.path)
    paths = [m.path for m in modules]
    prefix = find_prefix(paths, files)
    renames = find_renames(paths, files, prefix)
    own = frozenset(m.module.split(".")[0] for m in modules)
    project = project_name(art.filename)
    # The source's own packages go by their names in the repository.
    own_there = own | {d.rstrip("/").rpartition("/")[2] for d in renames.values()}
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
        top, _, rest = m.path.partition("/")
        full = renames[top] + rest if top in renames else prefix + m.path
        source = files.get(full)
        if source is None and any(full.startswith(u + "/") for u in unreadable):
            unchecked.append(m.path)
            continue
        data = source_of(m.path)
        if b"\r\n" in data and git_blob_id(data.replace(b"\r\n", b"\n")) in in_tree:
            matched += 1  # built on Windows: the same file with CRLF line endings
            continue
        try:
            calls = sensitive_calls(data, path=m.path, own=own, project=project)
        except (SyntaxError, ValueError, RecursionError):
            calls = ()  # inventory parsed it once; nothing more can be said
        if calls and source is not None:
            repo, sha = source
            try:
                blob = trees.blob(repo, sha)
                in_source = {
                    c.name for c in sensitive_calls(blob, path=full, own=own_there, project=project)
                }
            except (SyntaxError, ValueError, RecursionError):
                in_source = set()  # unreadable source explains nothing
            calls = tuple(c for c in calls if c.name not in in_source)
        unmatched.append(UnsourcedFile(m.path, source is not None, calls, at=full))
    return SourceMatch(
        repo=tag.repo,
        tag=tag.name,
        commit=tag.sha,
        prefix=prefix,
        matched=matched,
        unmatched=tuple(unmatched),
        unchecked=tuple(unchecked),
    )


def match_tags(
    trees: TreeLookup,
    tags: Sequence[TagInfo],
    art: ArtifactFacts,
    source_of: Callable[[str], bytes],
) -> SourceMatch:
    """``match_artifact`` at the first tag, and at the others naming the same
    version while sensitive calls are left unexplained. The tree that matches
    the most files is the one the release was built from; the first tag wins
    a tie. Raises ``NetError`` only for the first tag: another tag whose tree
    can't be read leaves the first tag's answer standing.
    """
    best = match_artifact(trees, tags[0], art, source_of)
    seen = {tags[0].sha}
    for tag in tags[1:]:
        if not any(u.calls for u in best.unmatched):
            break
        if tag.sha is None or tag.repo is None or tag.sha in seen:
            continue
        seen.add(tag.sha)
        try:
            other = match_artifact(trees, tag, art, source_of)
        except NetError:
            continue
        if other.matched > best.matched:
            best = other
    return best
