"""Tag lookup for GitHub repositories.

Reads the public git ref advertisement over HTTPS
(``/<owner>/<repo>.git/info/refs?service=git-upload-pack``). That needs no
token, has no REST rate limit, and follows GitHub's redirects for renamed
repositories. One request per repository covers every version.
"""

from __future__ import annotations

import re
from collections.abc import Container, Iterator, Mapping

from packaging.version import InvalidVersion, Version

from ..models import TagInfo
from ..net import Http, NetError

_REPO_RE = re.compile(r"^(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")


def parse_repo(url: str) -> str | None:
    """Return ``owner/repo`` for a GitHub URL, else None."""
    m = _REPO_RE.match(url.strip())
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not repo or repo in (".", ".."):
        return None
    return f"{owner}/{repo}"


def parse_ref_advertisement(data: bytes) -> dict[str, str]:
    """Parse pkt-line output into {tag name: commit sha} (peeled where given)."""
    tags: dict[str, str] = {}
    pos = 0
    while pos + 4 <= len(data):
        try:
            length = int(data[pos : pos + 4], 16)
        except ValueError:
            break
        if length == 0:
            pos += 4
            continue
        line = data[pos + 4 : pos + length].rstrip(b"\n")
        pos += length
        line = line.split(b"\x00", 1)[0]
        if b" " not in line:
            continue
        sha, ref = line.split(b" ", 1)
        name = ref.decode("utf-8", "replace")
        if not name.startswith("refs/tags/"):
            continue
        tag = name[len("refs/tags/") :]
        if tag.endswith("^{}"):
            tags[tag[:-3]] = sha.decode()  # peeled: the commit an annotated tag points to
        else:
            tags.setdefault(tag, sha.decode())
    return tags


class TagLookup:
    """Tags per repository, fetched once per run and shared between releases.

    ``overrides`` maps ``owner/repo`` to {tag name: sha or None} and is laid
    over the fetched tags: a sha adds or replaces a tag, None removes it. The
    incident replay uses it to see the tags as they stood on the day.
    """

    def __init__(
        self, http: Http, overrides: Mapping[str, Mapping[str, str | None]] | None = None
    ) -> None:
        self._http = http
        self._cache: dict[str, dict[str, str]] = {}
        self._overrides = {k.lower(): v for k, v in (overrides or {}).items()}

    def tags(self, repo: str) -> dict[str, str]:
        """{tag name: commit sha} for ``owner/repo``. Raises ``NetError``."""
        if repo not in self._cache:
            url = f"https://github.com/{repo}.git/info/refs?service=git-upload-pack"
            resp = self._http.get(url, max_bytes=64 * 1024 * 1024)
            if resp.status != 200:
                raise NetError(f"tag lookup for github.com/{repo} returned HTTP {resp.status}")
            tags = parse_ref_advertisement(resp.content)
            for name, sha in self._overrides.get(repo.lower(), {}).items():
                if sha is None:
                    tags.pop(name, None)
                else:
                    tags[name] = sha
            self._cache[repo] = tags
        return self._cache[repo]


# Separators between a tag's prefix and its version: ``lightning-2.6.1``,
# ``azure-mgmt-core_1.1.0``, ``prebuilt==1.0.11``, ``api/v1.4.1`` and, for npm,
# ``@ctrl/tinycolor@4.2.2``.
_SEPARATORS = ("-", "_", "==", "/")
# Prefixes that name a release rather than a package: ``release-v1.0.0``.
_RELEASE_WORDS = frozenset({"release"})


def _norm(name: str) -> str:
    return name.lower().replace("_", "-")


def _package_names(package: str) -> tuple[str, set[str]]:
    """The package's name without its npm scope, and its shorter folder names.

    Both lowercased, ``_`` as ``-``. The shorter names are the runs of its
    trailing hyphenated words, since monorepos tag a package by its folder:
    ``eslint-module-utils`` is tagged ``utils/v2.8.1``,
    ``eslint-import-resolver-node`` ``resolvers/node/v0.3.3`` and
    ``langgraph-prebuilt`` ``prebuilt==1.0.11``.
    """
    words = _norm(package.rpartition("/")[2]).split("-")
    return "-".join(words), {"-".join(words[i:]) for i in range(1, len(words)) if words[i]}


def _readings(name: str, *, npm: bool) -> Iterator[tuple[str, str, str]]:
    """Each (prefix, separator, rest) split of a tag name, and ("", "", name)."""
    yield "", "", name
    for sep in (*_SEPARATORS, *(("@",) if npm else ())):
        start = name.find(sep, 1)
        while start != -1:
            yield name[:start], sep, name[start + len(sep) :]
            start = name.find(sep, start + 1)


def _names_package(prefix: str, sep: str, full: str, short: Container[str]) -> bool:
    """Does a tag prefix name this package (or a release)?

    ``-``, ``_`` and ``@`` prefixes must use the full name (``@`` may keep
    the npm scope); a folder (``/``) or ``==`` prefix may use a shorter
    name from ``short``.
    """
    if not prefix:
        return True
    if sep == "@":
        return _norm(prefix).rpartition("/")[2] == full
    last = _norm(prefix.rpartition("/")[2])
    if last == full or last in _RELEASE_WORDS:
        return True
    return sep in ("/", "==") and last in short


def _as_version(text: str) -> Version | None:
    try:
        return Version(text)
    except InvalidVersion:
        return None


def match_tag(
    tags: dict[str, str],
    package: str,
    version: str,
    repo: str | None = None,
    *,
    npm: bool = False,
) -> TagInfo | None:
    """SPEC GRN-T004: a tag whose name is the version, alone or after a prefix.

    The version is ``X`` or ``vX``. The prefix, before a ``-``, ``_``, ``==``
    or ``/`` (and ``@`` for npm), must name the package or be ``release``
    (see ``_names_package``): ``2.6.1``, ``v1.18.0``, ``lightning-2.6.1``,
    ``release-v1.0.0``, ``api/v1.4.1``. A shorter folder name counts only if
    no tag uses the full name. ``X`` alone wins, then an exact name, in
    sorted order; otherwise X is compared as a PEP 440 version, so tag
    ``2026.01.04`` matches release ``2026.1.4``.
    """
    found = matching_tags(tags, package, version, repo, npm=npm)
    return found[0] if found else None


def matching_tags(
    tags: dict[str, str],
    package: str,
    version: str,
    repo: str | None = None,
    *,
    npm: bool = False,
) -> list[TagInfo]:
    """Every tag ``match_tag`` accepts for the version, its choice first.

    A repository can tag one release twice at different commits: sympy/sympy
    has ``1.12.1`` and ``sympy-1.12.1``. GRN-C007 compares the release with
    each of them when the first doesn't explain its files.
    """
    full, short = _package_names(package)
    found = [name for name in (version, f"v{version}") if name in tags]
    # A repository that tags the package by its full name tags other packages
    # by the shorter ones: TooTallNate/proxy-agents has socks-proxy-agent@8.0.1
    # and proxy-agent@8.0.1.
    if any(
        p and _norm(p.rpartition("/")[2]) == full and rest.lstrip("vV")[:1].isdigit()
        for name in tags
        for p, _, rest in _readings(name, npm=npm)
    ):
        short = set()
    wanted = _as_version(version)
    loose: str | None = None
    for name in sorted(tags):
        if name in found:
            continue
        for prefix, sep, rest in _readings(name, npm=npm):
            if not _names_package(prefix, sep, full, short):
                continue
            rest = rest[1:] if rest[:1] in ("v", "V") else rest
            if rest == version:
                found.append(name)
                break
            if loose is None and wanted is not None and rest[:1].isdigit():
                if _as_version(rest) == wanted:
                    loose = name
    if not found and loose is not None:
        found.append(loose)
    return [TagInfo(name=name, sha=tags[name], repo=repo) for name in found]
