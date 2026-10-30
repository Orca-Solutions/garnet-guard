"""Tag lookup for GitHub repositories.

Reads the public git ref advertisement over HTTPS
(``/<owner>/<repo>.git/info/refs?service=git-upload-pack``). That needs no
token, has no REST rate limit, and follows GitHub's redirects for renamed
repositories. One request per repository covers every version.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

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


def _prefixes(package: str, *, npm: bool = False) -> list[str]:
    """Tag prefixes to try: none, then ``<name>-`` in each spelling of the name.

    npm monorepos tag ``<name>@X`` (lerna, changesets), with or without the
    ``@scope/``, so those forms are added for npm packages.
    """
    out = [""]
    names = {package, package.replace("-", "_"), package.replace("_", "-")}
    if npm and "/" in package:
        names.add(package.rpartition("/")[2])
    for n in sorted(names):
        out.append(f"{n}-")
        if npm:
            out.append(f"{n}@")
    return out


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
    """SPEC GRN-T004: accept X, vX, <name>-X and <name>-vX (and <name>@X for npm).

    An exact name wins. Otherwise X is compared as a PEP 440 version, so
    tag ``2026.01.04`` matches release ``2026.1.4``.
    """
    prefixes = _prefixes(package, npm=npm)
    for p in prefixes:
        for name in (f"{p}{version}", f"{p}v{version}"):
            if name in tags:
                return TagInfo(name=name, sha=tags[name], repo=repo)
    wanted = _as_version(version)
    if wanted is None:
        return None
    for name in sorted(tags):
        for p in prefixes:
            if not name.startswith(p):
                continue
            rest = name[len(p) :]
            rest = rest[1:] if rest[:1] in ("v", "V") else rest
            if rest and rest[0].isdigit() and _as_version(rest) == wanted:
                return TagInfo(name=name, sha=tags[name], repo=repo)
    return None
