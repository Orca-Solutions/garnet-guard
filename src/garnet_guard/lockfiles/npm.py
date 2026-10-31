"""npm names, versions and sources, shared by the package-lock.json and yarn.lock parsers.

Pure string handling: nothing here fetches, resolves or installs.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, urlsplit

# Tarball hosts Garnet checks. registry.yarnpkg.com serves npm's registry.
REGISTRY_HOSTS = ("https://registry.npmjs.org/", "https://registry.yarnpkg.com/")
MAX_NAME = 214
INVALID_NAME = "(invalid name)"

# The characters encodeURIComponent leaves alone, which is what npm means by a
# URL-safe name. No slash, whitespace, control character or non-ASCII letter.
_URL_SAFE = re.compile(r"[A-Za-z0-9\-_.!~*'()]+")


def _part_ok(part: str) -> bool:
    return bool(_URL_SAFE.fullmatch(part)) and not part.startswith((".", "_"))


def valid_name(name: str) -> bool:
    """True if ``name`` follows npm's package name rules.

    An optional ``@scope/``, then a name of URL-safe characters; at most 214
    characters in all, no part starting with ``.`` or ``_``, no ``..`` and no
    other slash. Uppercase is allowed, as older packages use it. Only a name
    that passes is ever put in a registry URL.
    """
    if not name or len(name) > MAX_NAME or ".." in name:
        return False
    if name.startswith("@"):
        scope, slash, rest = name[1:].partition("/")
        return bool(slash) and _part_ok(scope) and _part_ok(rest)
    return _part_ok(name)


def split_spec(spec: str) -> tuple[str, str]:
    """``name@range`` as (name, range); a scoped name keeps its leading ``@``."""
    at = spec.find("@", 1)
    if at < 0:
        return spec, ""
    return spec[:at], spec[at + 1 :]


def alias_target(spec_range: str) -> tuple[str, str] | None:
    """(package, range) for an ``npm:<package>@<range>`` alias, else None."""
    if not spec_range.startswith("npm:"):
        return None
    return split_spec(spec_range[4:])


# --- SemVer 2.0 precedence ------------------------------------------------------

_NUM = r"0|[1-9]\d*"
_PRE_ID = r"0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*"
_SEMVER = re.compile(
    rf"({_NUM})\.({_NUM})\.({_NUM})"
    rf"(?:-((?:{_PRE_ID})(?:\.(?:{_PRE_ID}))*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_MAX_VERSION = 256  # far longer than any real version; keeps int() cheap


def is_semver(version: str) -> bool:
    return len(version) <= _MAX_VERSION and bool(_SEMVER.fullmatch(version))


def semver_key(version: str) -> tuple[int, Any]:
    """Sort key in SemVer 2.0 precedence, with versions that don't parse first.

    A pre-release sorts below its release; pre-release identifiers compare
    numerically when both are numbers, a number below text, and text in ASCII
    order; a longer list of identifiers sorts higher when the shorter is a
    prefix of it. Build metadata is ignored.
    """
    m = _SEMVER.fullmatch(version) if len(version) <= _MAX_VERSION else None
    if m is None:
        return (0, version)
    pre: tuple[Any, ...]
    if m[4] is None:
        pre = (1,)
    else:
        pre = (0, tuple((0, int(p)) if p.isdigit() else (1, p) for p in m[4].split(".")))
    return (1, (int(m[1]), int(m[2]), int(m[3]), pre))


# --- Sources --------------------------------------------------------------------

_GIT_PREFIXES = ("git+", "git:", "git@", "ssh:", "github:", "gitlab:", "bitbucket:", "gist:")
_GITHUB_SHORTHAND = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:#.*)?")


def _git_url(url: str) -> bool:
    lower = url.lower()
    return lower.startswith(_GIT_PREFIXES) or lower.endswith(".git") or ".git#" in lower


def looks_like_git(spec: str) -> bool:
    """True for a dependency range that installs from a git repository,
    including GitHub's ``owner/repo`` shorthand."""
    return _git_url(spec) or bool(_GITHUB_SHORTHAND.fullmatch(spec))


def tarball_path(name: str, version: str) -> str:
    """The registry's tarball path for a release: ``/<name>/-/<unscoped>-<version>.tgz``."""
    return f"/{name}/-/{name.rpartition('/')[2]}-{version}.tgz"


def source_problem(url: str, name: str, version: str | None) -> str | None:
    """None when ``url`` is ``name``'s tarball for ``version`` on the public
    registry, else a short reason for the GRN-E005 finding.

    The reason never quotes the URL, which can carry credentials.
    """
    lower = url.lower()
    if lower.startswith(REGISTRY_HOSTS):
        try:
            parts = urlsplit(url)
        except ValueError:
            return "unsupported source"
        # yarn adds the tarball's SHA-1 as a fragment; anything else is unusual.
        if parts.query or version is None or unquote(parts.path) != tarball_path(name, version):
            return "resolved URL isn't this package's registry tarball"
        return None
    if _git_url(url):
        return "git source"
    if lower.startswith("file:"):
        return "file: source"
    if lower.startswith("http://"):
        return "plain HTTP URL"
    if lower.startswith("https://"):
        try:
            path = urlsplit(url).path
        except ValueError:
            return "unsupported source"
        if re.search(r"/-/[^/]+\.tgz$", path):
            return "private registry"
        return "tarball URL outside the npm registry"
    return "unsupported source"
