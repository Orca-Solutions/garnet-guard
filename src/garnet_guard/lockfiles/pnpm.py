"""pnpm-lock.yaml: lockfileVersion 9.0 (pnpm 9 and 10) and 6.x (pnpm 8).

Read with the strict YAML reader in ``yamldoc`` (ADR-0016), the way pnpm
reads it. In version 9.0 pnpm installs one package for each ``snapshots``
key, with the fields of the ``packages`` entry its key names once the peer
and patch suffixes are removed (``Object.assign`` in pnpm 10's
``convertToLockfileObject``); in 6.x it installs each ``packages`` key.
The package is the name in the key, and the version is the key's (for a
git, tarball or directory entry, its ``version`` field). With no
``tarball`` and no ``type`` in its ``resolution``, pnpm fetches that name
and version from the registry .npmrc or pnpm-workspace.yaml names for it;
a ``tarball`` URL must be that package's registry tarball for that
version, as a package-lock.json ``resolved`` URL must. Git, directory and
other tarball sources are GRN-E005. ``link:`` and workspace dependencies are the project's own code
and have no ``packages`` entry, so nothing is reported for them. A
patched dependency (``patchedDependencies``) is checked as the release it
patches when its patch file, at the ``path`` the lockfile records (which
a frozen install requires to match the project's settings), is inside the
folder that holds pnpm-lock.yaml; otherwise every release its key names
(``name@version``, or every version for a bare name or a range) is GRN-E005
"patch file outside the project".

A shape pnpm doesn't write and might read some other way is refused: a
snapshot with its own resolution or version, a snapshot with no
``packages`` entry, a ``version`` that disagrees with its key, a key with no
version.
"""

from __future__ import annotations

import re
from typing import Any

from .base import LockfileError, Pin
from .npm import INVALID_NAME, inside, is_semver, source_problem, valid_name
from .registries import NONE, Registries
from .yamldoc import Mapping, Scalar, load

_V9 = ("9.0",)
_V6 = ("6.0", "6.1")
_SHOWN_VERSION = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3})?")
# ASCII digits only: int() refuses some characters str.isdigit() accepts.
_MAJOR = re.compile("[0-9]{1,8}")
# Snapshot fields that would change what pnpm fetches if the packages
# entry didn't set them. pnpm 9 and 10 write only dependencies,
# optionalDependencies, transitivePeerDependencies, optional and id there.
_FETCH_FIELDS = ("resolution", "version", "name")
_GIT_TARBALL_HOSTS = (
    "https://codeload.github.com/",
    "https://bitbucket.org/",
    "https://gitlab.com/",
)


def _lockfile_version(doc: Mapping) -> str:
    value = doc.get("lockfileVersion")
    text = value.text if isinstance(value, Scalar) else value
    if not isinstance(text, str):
        raise LockfileError("no lockfileVersion; Garnet reads lockfileVersion 9.0 and 6.x")
    if text in _V9 or text in _V6:
        return text
    shown = f"lockfileVersion {text}" if _SHOWN_VERSION.fullmatch(text) else "a lockfileVersion"
    major = text.partition(".")[0]
    if _MAJOR.fullmatch(major) and int(major) <= 5:
        raise LockfileError(
            f"{shown} is from pnpm 7 or earlier, which Garnet doesn't read; regenerate the "
            "lockfile with pnpm 8 or later"
        )
    raise LockfileError(f"{shown} isn't one Garnet reads (9.0 or 6.x)")


def _section(doc: Mapping, name: str) -> Mapping:
    value = doc.get(name)
    if value is None:
        return Mapping(0)
    if not isinstance(value, Mapping):
        raise LockfileError(f"line {doc.lines[name]}: {name} isn't a mapping")
    return value


def _text(entry: Mapping, name: str, line: int) -> str | None:
    value = entry.get(name)
    if value is None or isinstance(value, str):
        return value
    raise LockfileError(f"line {line}: a {name} that isn't text")


# --- Dependency paths (pnpm's @pnpm/dependency-path) ----------------------------------


def _suffix(dep_path: str) -> int:
    """Where the peer and patch suffixes start, or -1. A port of pnpm 10's
    ``indexOfDepPathSuffix``: scanning back from the closing ``)``, the first
    character outside parentheses ends the version."""
    if not dep_path.endswith(")"):
        return -1
    depth = 1
    for i in range(len(dep_path) - 2, -1, -1):
        c = dep_path[i]
        if c == "(":
            depth -= 1
        elif c == ")":
            depth += 1
        elif not depth:
            return i + 1
    return -1


def remove_suffix(dep_path: str) -> str:
    """``react-dom@18.3.1`` from ``react-dom@18.3.1(react@18.3.1)`` and
    ``lodash@4.17.21`` from ``lodash@4.17.21(patch_hash=...)``."""
    at = _suffix(dep_path)
    return dep_path if at < 0 else dep_path[:at]


def split_key(key: str) -> tuple[str, str] | None:
    """(name, version) from ``name@version``; a scoped name keeps its ``@``.
    None for a key with no ``@`` after the first character."""
    at = key.find("@", 1)
    if at < 0:
        return None
    return key[:at], key[at + 1 :]


# --- Entries ------------------------------------------------------------------------


def _origin(key: str, resolution: Mapping) -> str:
    """The key and every text field of the resolution, so a new commit, URL,
    folder or integrity counts as a change."""
    fields = sorted((str(k), v) for k, v in resolution.items() if isinstance(v, str))
    return " ".join([key, *(f"{k}={v}" for k, v in fields)])


def _source(resolution: Mapping, line: int) -> tuple[str, str | None] | None:
    """None for a registry fetch by name and version; else ("tarball", URL)
    for a tarball pnpm fetches as written, or ("unsupported", why)."""
    kind = resolution.get("type")
    if kind is not None:
        if not isinstance(kind, str) or not kind:
            raise LockfileError(f"line {line}: a resolution type that isn't text")
        if kind == "git":
            return ("unsupported", "git source")
        if kind == "directory":
            return ("unsupported", "file: source")
        return ("unsupported", "unsupported source")
    tarball = _text(resolution, "tarball", line)
    _text(resolution, "integrity", line)
    if tarball is None:
        return None
    if tarball.startswith("file:"):
        return ("unsupported", "file: source")
    if tarball.startswith(_GIT_TARBALL_HOSTS) and "tar.gz" in tarball:
        return ("unsupported", "git source")
    if tarball.lower().startswith(("https://", "http://")):
        return ("tarball", tarball)
    # pnpm resolves anything else against the registry URL; it never writes one.
    return ("unsupported", "unsupported source")


def _pin(key: str, entry: Any, line: int, registries: Registries, *, v6: bool = False) -> Pin:
    if not isinstance(entry, Mapping):
        raise LockfileError(f"line {line}: a packages entry that isn't a mapping")
    resolution = entry.get("resolution")
    if not isinstance(resolution, Mapping):
        raise LockfileError(f"line {line}: an entry with no resolution mapping")
    written = _text(entry, "version", line)
    named = _text(entry, "name", line)
    origin = _origin(key, resolution)
    parsed = _parse_v6_key(key, line) if v6 else split_key(key)
    if parsed is None:
        raise LockfileError(f"line {line}: a packages key that isn't name@version")
    name, key_version = parsed
    if v6 and named is not None and not key.startswith("/"):
        name = named  # pnpm 8 writes the name for git, tarball and directory entries
    semver = is_semver(key_version)
    if semver and ((written is not None and written != key_version) or named not in (None, name)):
        raise LockfileError(f"line {line}: a name or version that doesn't match its key")
    version = key_version if semver else written
    if not valid_name(name):
        shown = version if version and is_semver(version) else None
        return Pin(
            INVALID_NAME, shown, line, "unsupported", "not a valid npm package name", "npm", origin
        )
    source = _source(resolution, line)
    if source is None:
        if not semver:
            raise LockfileError(f"line {line}: a registry entry whose key has no SemVer version")
        why = _registry_problem(name, registries)
        if why is None:
            return Pin(name, version, line, ecosystem="npm")
        return Pin(name, version, line, "unsupported", why, "npm", origin)
    kind, value = source
    if kind == "tarball" and value is not None:
        why = source_problem(value, name, version)
        if why is None and version:
            return Pin(name, version, line, ecosystem="npm")
        return Pin(name, version, line, "unsupported", why or "no version", "npm", origin)
    return Pin(name, version, line, "unsupported", value, "npm", origin)


def _registry_problem(name: str, registries: Registries) -> str | None:
    """Why a package fetched by name and version isn't checked: the project's
    settings send it to another registry, or it is a JSR package, which pnpm
    fetches from npm.jsr.io unless they name npm's public registry for it."""
    source = registries.other_registry(name)
    if source is not None:
        return f"private registry, set in {source}"
    if name.startswith("@jsr/") and not registries.public_scope("@jsr"):
        return "JSR registry, pnpm's default for @jsr packages"
    return None


# --- patchedDependencies -------------------------------------------------------------

OUTSIDE_PATCH = "patch file outside the project"


def _outside_patches(doc: Mapping) -> dict[tuple[str, str | None], str]:
    """The releases ``patchedDependencies`` patches from a file outside the
    lockfile's folder, as (name, version), with None for every version of
    the name, each with that patch's path and hash."""
    patched = _section(doc, "patchedDependencies")
    outside: dict[tuple[str, str | None], str] = {}
    for key, entry in patched.items():
        line = patched.lines[key]
        if not isinstance(key, str) or not isinstance(entry, Mapping):
            raise LockfileError(f"line {line}: a patchedDependencies entry pnpm doesn't write")
        path = _text(entry, "path", line)
        if path is None:
            raise LockfileError(f"line {line}: a patchedDependencies entry with no path")
        if inside(".", path):
            continue
        parsed = split_key(key)
        if parsed is not None and is_semver(parsed[1]):
            release: tuple[str, str | None] = parsed
        else:  # a bare name, or a range, which pnpm matches against every version
            release = (key if parsed is None else parsed[0], None)
        outside[release] = f"patch={path} hash={_text(entry, 'hash', line)}"
    return outside


def _patch_outside(pin: Pin, outside: dict[tuple[str, str | None], str]) -> Pin:
    patch = outside.get((pin.package, pin.version)) or outside.get((pin.package, None))
    if patch is None:
        return pin
    origin = f"{pin.origin or f'{pin.package}@{pin.version}'} {patch}"
    return Pin(pin.package, pin.version, pin.line, "unsupported", OUTSIDE_PATCH, "npm", origin)


# --- lockfileVersion 9.0 -----------------------------------------------------------


def _v9(doc: Mapping, registries: Registries) -> list[Pin]:
    packages = _section(doc, "packages")
    snapshots = _section(doc, "snapshots")
    for key in packages:
        if not isinstance(key, str):
            raise LockfileError(f"line {packages.lines[key]}: a packages key that isn't text")
        if remove_suffix(key) != key:
            raise LockfileError(
                f"line {packages.lines[key]}: a packages key with a peer or patch suffix, which "
                "pnpm doesn't write"
            )
    for key, snapshot in snapshots.items():
        line = snapshots.lines[key]
        if not isinstance(key, str):
            raise LockfileError(f"line {line}: a snapshots key that isn't text")
        if snapshot is not None and not isinstance(snapshot, Mapping):
            raise LockfileError(f"line {line}: a snapshot that isn't a mapping")
        for name in _FETCH_FIELDS:
            if snapshot is not None and name in snapshot:
                raise LockfileError(
                    f"line {line}: a snapshot with its own {name}, which pnpm doesn't write"
                )
        if remove_suffix(key) not in packages:
            raise LockfileError(f"line {line}: a snapshot with no packages entry")
    return [_pin(k, e, packages.lines[k], registries) for k, e in packages.items()]


# --- lockfileVersion 6.x -----------------------------------------------------------


def _parse_v6_key(key: str, line: int) -> tuple[str, str] | None:
    """(name, version) from a pnpm 8 key: ``/name@version``, then an optional
    ``(peer@x)`` or ``_peer@x`` suffix. Other keys (``file:``, a git host)
    have no version in them; their name and version are in the entry."""
    if not key.startswith("/"):
        name = key  # replaced by the entry's name field
        return name, ""
    rest = key[1:]
    at = rest.find("@", rest.find("/") + 1 if rest.startswith("@") else 1)
    if at <= 0:
        return None
    name, version = rest[:at], rest[at + 1 :]
    if "(" in version and version.endswith(")"):
        version = version[: version.index("(")]
    elif "_" in version:
        version = version[: version.index("_")]
    return name, version


def _v6(doc: Mapping, registries: Registries) -> list[Pin]:
    packages = _section(doc, "packages")
    pins: list[Pin] = []
    seen: set[tuple[str, str | None, str, str | None, str | None]] = set()
    for key, entry in packages.items():
        line = packages.lines[key]
        if not isinstance(key, str):
            raise LockfileError(f"line {line}: a packages key that isn't text")
        pin = _pin(key, entry, line, registries, v6=True)
        # One package with different peers has one key for each; keep the first.
        ident = (pin.package, pin.version, pin.source, pin.detail, _strip_key(pin.origin))
        if ident not in seen:
            seen.add(ident)
            pins.append(pin)
    return pins


def _strip_key(origin: str | None) -> str | None:
    return origin.partition(" ")[2] if origin else origin


def parse(text: str, registries: Registries = NONE) -> list[Pin]:
    """Pins from a pnpm-lock.yaml, one per package and version, at the line
    of its ``packages`` key.

    Every package counts, dev and optional dependencies too. ``registries``
    is what the project's .npmrc and pnpm-workspace.yaml say about registries.
    """
    doc = load(text.removeprefix("﻿"), schema="core")
    if not isinstance(doc, Mapping):
        raise LockfileError("the top level isn't a mapping")
    version = _lockfile_version(doc)
    _section(doc, "importers")
    outside = _outside_patches(doc)
    pins = _v9(doc, registries) if version in _V9 else _v6(doc, registries)
    return sorted((_patch_outside(p, outside) for p in pins), key=lambda p: p.line)
