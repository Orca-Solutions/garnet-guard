"""yarn.lock from Yarn 2 and later (Berry), ``__metadata`` versions 4 to 8.

Read with the strict YAML reader in ``yamldoc`` (ADR-0016) in its failsafe
schema, where every scalar is text, as Yarn reads it (js-yaml's
``FAILSAFE_SCHEMA``). Each entry's ``resolution`` is the locator Yarn
fetches: ``name@npm:<version>`` is that release from the registry
``.yarnrc.yml`` names for it, and is checked. An alias
(``alias@npm:real@range`` in the key) resolves to the real package, so it
is checked as that package.

- ``workspace:`` is the project's own package and is skipped, and so are
  ``link:`` and ``portal:`` folders inside the project: a path from a
  workspace that stays in the folder holding yarn.lock. Any other
  ``link:`` or ``portal:`` is GRN-E005.
- ``file:``, git, ``exec:`` and other tarball URLs are GRN-E005; a tarball
  URL that is the package's own registry tarball is checked.
- ``patch:`` is checked as the release it patches. Yarn fetches that
  release and applies patch files that are either in the project (``~/``,
  or a path from a workspace) or built into Yarn (``builtin<compat/...>``,
  which Yarn applies to typescript, resolve and fsevents); a patch file
  anywhere else is GRN-E005, whatever it patches. Yarn 4 (``__metadata``
  7 and 8) writes an optional patch as ``optional!builtin<...>``, Yarn 2
  and 3 (4 to 6) as ``~builtin<...>``, and only Yarn 4 reads ``~/`` as
  the project's folder.
- A ``@jsr/`` package is GRN-E005 in a Yarn 4 lockfile unless
  ``.yarnrc.yml`` configures the ``jsr`` scope: Yarn 4 fetches it from
  npm.jsr.io by default; Yarn 2 and 3 have no such default.

Yarn 1 and Berry are told apart by ``yarn.is_berry``, which counts a file
as Berry only in the shape Yarn 1 ignores.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, unquote

from .base import LockfileError, Pin
from .npm import INVALID_NAME, inside, is_semver, looks_like_git, source_problem, valid_name
from .registries import NONE, Registries
from .yamldoc import Mapping, load

METADATA_VERSIONS = range(4, 9)
YARN4_METADATA = 7  # Yarn 4 writes 7 (its release candidates) and 8

# Yarn's structUtils: a strict locator, and a range split into protocol,
# source, selector and ::params.
_LOCATOR = re.compile(r"(?:@([^/]+?)/)?([^@/]+?)@(.+)", re.DOTALL)
_RANGE = re.compile(r"([^#:]*:)?((?:(?!::)[^#])*)(?:#((?:(?!::).)*))?(?:::(.*))?", re.DOTALL)
_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_BUILTIN_PATCH = re.compile(r"builtin<[^>]+>")
_GIT_PROTOCOLS = ("git:", "git+", "ssh:", "github:", "gitlab:", "bitbucket:", "git@")
# ASCII digits only: int() refuses some characters str.isdigit() accepts.
_METADATA_VERSION = re.compile("[0-9]{1,8}")


def _decode(text: str, line: int) -> str:
    """decodeURIComponent, which throws on a malformed escape."""
    if _BAD_ESCAPE.search(text):
        raise LockfileError(f"line {line}: a resolution Yarn can't read")
    return unquote(text, errors="strict")


class _Range:
    def __init__(self, reference: str, line: int) -> None:
        m = _RANGE.fullmatch(reference)
        if m is None:
            raise LockfileError(f"line {line}: a resolution Yarn can't read")
        self.protocol = m[1]
        try:
            if m[3] is not None:
                self.source: str | None = _decode(m[2], line)
                self.selector = _decode(m[3], line)
            else:
                self.source = None
                self.selector = _decode(m[2], line)
        except UnicodeDecodeError as err:
            raise LockfileError(f"line {line}: a resolution Yarn can't read") from err
        self.params: dict[str, list[str]] | None = (
            parse_qs(m[4], keep_blank_values=True) if m[4] is not None else None
        )

    def param(self, name: str) -> str | None:
        values = (self.params or {}).get(name)
        return values[-1] if values else None


def _locator(text: str, line: int) -> tuple[str, str]:
    """(package, reference) from ``name@reference`` or ``@scope/name@reference``."""
    m = _LOCATOR.fullmatch(text)
    if m is None:
        raise LockfileError(f"line {line}: a resolution that isn't name@reference")
    name = f"@{m[1]}/{m[2]}" if m[1] is not None else m[2]
    return name, m[3]


def _workspace_folder(parent: str | None, line: int) -> str | None:
    """The folder of a ``::locator=`` parent that is a workspace, else None."""
    if parent is None:
        return None
    _, reference = _locator(parent, line)
    if not reference.startswith("workspace:"):
        return None
    return reference.removeprefix("workspace:")


def _patch_inside(path: str, parent: str | None, line: int, yarn4: bool) -> bool:
    """True for a patch file Yarn reads from the project or from itself.

    Yarn 4 writes flags before the last ``!`` (``optional!``) and a path
    from the project's folder as ``~/``. Yarn 2 and 3 mark an optional
    patch with a leading ``~`` and have no project paths: their ``~/x`` is
    the absolute path ``/x``.
    """
    path = path[path.rfind("!") + 1 :] if yarn4 else path.removeprefix("~")
    if _BUILTIN_PATCH.fullmatch(path):
        return True
    if yarn4 and path.startswith("~/"):
        return inside(".", path[2:])
    folder = _workspace_folder(parent, line)
    return folder is not None and inside(folder, path)


# A pin's package, version, source, detail; None for the project's own code.
Judged = tuple[str, str | None, str, str | None] | None


def _registry_problem(name: str, registries: Registries, yarn4: bool) -> str | None:
    """Why a package fetched by name and version isn't checked: .yarnrc.yml
    sends it to another registry, or it is a JSR package, which Yarn 4
    fetches from npm.jsr.io unless the ``jsr`` scope is configured."""
    where = registries.other_registry(name)
    if where is not None:
        return f"private registry, set in {where}"
    if yarn4 and name.startswith("@jsr/") and "@jsr" not in registries.scopes:
        return "JSR registry, Yarn's default for @jsr packages"
    return None


def _judge(
    name: str, reference: str, version: str | None, line: int, registries: Registries, yarn4: bool
) -> Judged:
    """What Yarn fetches for ``name@reference``. ``yarn4`` is True for a
    lockfile Yarn 4 wrote."""
    if not valid_name(name):
        return (INVALID_NAME, version if version and is_semver(version) else None, "", None)
    lower = reference.lower()
    if lower.startswith("npm:"):
        rng = _Range(reference, line)
        if rng.source is None and is_semver(rng.selector):
            if version != rng.selector:
                raise LockfileError(f"line {line}: a version that doesn't match its resolution")
            if reference == f"npm:{rng.selector}":
                why = _registry_problem(name, registries, yarn4)
                return (name, version, "registry" if why is None else "unsupported", why)
            archive = rng.param("__archiveUrl")
            if archive is not None and set(rng.params or {}) == {"__archiveUrl"}:
                # Yarn fetches this URL instead of the registry's usual one.
                why = source_problem(archive, name, version)
                return (name, version, "registry" if why is None else "unsupported", why)
        return (name, version, "unsupported", "unsupported source")
    if lower.startswith("workspace:"):
        return None
    if lower.startswith(("link:", "portal:")):
        rng = _Range(reference, line)
        protocol = "link:" if lower.startswith("link:") else "portal:"
        folder = _workspace_folder(rng.param("locator"), line)
        if folder is not None and inside(folder, rng.selector):
            return None
        return (name, version, "unsupported", f"{protocol} outside the project")
    if lower.startswith("patch:"):
        rng = _Range(reference, line)
        if rng.source is None:
            raise LockfileError(f"line {line}: a patch: resolution with no source")
        paths = rng.selector.split("&") if rng.selector else []
        parent = rng.param("locator")
        source_name, source_reference = _locator(rng.source, line)
        if source_reference.lower().startswith("patch:"):
            raise LockfileError(f"line {line}: a patch: resolution of a patch: resolution")
        judged = _judge(source_name, source_reference, version, line, registries, yarn4)
        if all(_patch_inside(p, parent, line, yarn4) for p in paths):
            return judged
        # Even a patch of the project's own code installs a file the diff
        # doesn't show.
        package, shown = (name, version) if judged is None else judged[:2]
        return (package, shown, "unsupported", "patch file outside the project")
    if lower.startswith("file:"):
        return (name, version, "unsupported", "file: source")
    if lower.startswith("exec:"):
        return (name, version, "unsupported", "exec: source")
    if lower.startswith(_GIT_PROTOCOLS) or looks_like_git(reference):
        return (name, version, "unsupported", "git source")
    if lower.startswith(("https://", "http://")):
        why = source_problem(reference, name, version)
        if why is None and version is not None:
            return (name, version, "registry", None)
        return (name, version, "unsupported", why or "no version")
    if lower.startswith("virtual:"):
        raise LockfileError(f"line {line}: a virtual: resolution, which Yarn doesn't write")
    return (name, version, "unsupported", "unsupported source")


def _pin(key: object, entry: Any, line: int, registries: Registries, yarn4: bool) -> Pin | None:
    if not isinstance(key, str) or not isinstance(entry, Mapping):
        raise LockfileError(f"line {line}: an entry that isn't 'descriptor: fields'")
    resolution = entry.get("resolution")
    if not isinstance(resolution, str):
        raise LockfileError(f"line {line}: an entry with no resolution")
    version = entry.get("version")
    if version is not None and not isinstance(version, str):
        raise LockfileError(f"line {line}: a version that isn't text")
    checksum = entry.get("checksum")
    if checksum is not None and not isinstance(checksum, str):
        raise LockfileError(f"line {line}: a checksum that isn't text")
    name, reference = _locator(resolution, line)
    judged = _judge(name, reference, version, line, registries, yarn4)
    if judged is None:
        return None
    package, shown, source, detail = judged
    if package == INVALID_NAME:
        source, detail = "unsupported", "not a valid npm package name"
    if source == "registry" and shown is not None:
        return Pin(package, shown, line, ecosystem="npm")
    origin = " ".join(v for v in (resolution, checksum) if v)
    return Pin(package, shown, line, "unsupported", detail, "npm", origin)


def parse(text: str, registries: Registries = NONE) -> list[Pin]:
    """Pins from a Yarn 2+ yarn.lock, one per entry, at its key's line.

    Every entry counts, dev and optional dependencies too. ``registries``
    is what the project's .yarnrc.yml says about registries.
    """
    doc = load(text.removeprefix("﻿"), schema="failsafe")
    if not isinstance(doc, Mapping) or not isinstance(doc.get("__metadata"), Mapping):
        raise LockfileError("no __metadata entry, so it isn't a Yarn 2 or later lockfile")
    metadata = doc["__metadata"]
    version = metadata.get("version")
    digits = isinstance(version, str) and _METADATA_VERSION.fullmatch(version) is not None
    if not (digits and int(version) in METADATA_VERSIONS):
        shown = f"version {version}" if digits and len(version) < 4 else "a version"
        raise LockfileError(
            f"line {doc.lines['__metadata']}: __metadata {shown} isn't one Garnet reads (4 to 8)"
        )
    yarn4 = int(version) >= YARN4_METADATA
    pins = []
    for key, entry in doc.items():
        if key == "__metadata":
            continue
        pin = _pin(key, entry, doc.lines[key], registries, yarn4)
        if pin is not None:
            pins.append(pin)
    return sorted(pins, key=lambda p: p.line)
