"""package-lock.json and npm-shrinkwrap.json (lockfileVersion 1, 2 and 3)."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from .base import LockfileError, Pin
from .npm import INVALID_NAME, alias_target, is_semver, source_problem, valid_name

KeyPath = tuple[str, ...]

# A JSON string token (unrolled, so it can't backtrack badly) or a structural
# character. Numbers and literals aren't needed to follow the nesting.
_TOKEN = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|[{}\[\]:]')
_NOT_A_KEY = "\x00"  # stands for the top level or an array on a key path


def _load(text: str) -> dict[str, Any]:
    """The parsed document. Errors name a position, never the file's text."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as err:
        raise LockfileError(f"invalid JSON at line {err.lineno}, column {err.colno}") from err
    except RecursionError as err:
        raise LockfileError("JSON nested too deeply to read") from err
    except ValueError as err:  # an integer too long to convert, for one
        raise LockfileError("invalid JSON") from err
    if not isinstance(doc, dict):
        raise LockfileError("the top level isn't a JSON object")
    return doc


def key_lines(text: str, want: Callable[[KeyPath], bool]) -> dict[KeyPath, int]:
    """The 1-based line of each object key whose path ``want`` accepts.

    JSON has no positions, so this follows the document's tokens: a key is a
    string followed by ``:``, and its path is the keys of the objects around
    it. ``text`` must already have parsed as JSON. A key repeated in one object
    keeps its last line, as ``json.loads`` keeps its last value.
    """
    out: dict[KeyPath, int] = {}
    stack: list[str] = []
    key: str | None = None
    last: re.Match[str] | None = None
    line, pos = 1, 0
    for m in _TOKEN.finditer(text):
        c = m.group()[0]
        if c == '"':
            last = m
        elif c == ":" and last is not None:
            raw = last.group()
            key = raw[1:-1] if "\\" not in raw else str(json.loads(raw))
            path = (*stack[1:], key)
            if want(path):
                line += text.count("\n", pos, last.start())
                pos = last.start()
                out[path] = line
        elif c in "{[":
            stack.append(key if key is not None and c == "{" else _NOT_A_KEY)
            key = None
        else:
            if stack:
                stack.pop()
            key = None
    return out


def _string(entry: dict[str, Any], field: str, line: int) -> str | None:
    value = entry.get(field)
    if value is None or isinstance(value, str):
        return value
    raise LockfileError(f"the entry at line {line} has a {field} that isn't a string")


def _flag(entry: dict[str, Any], field: str, line: int) -> bool:
    value = entry.get(field, False)
    if isinstance(value, bool):
        return value
    raise LockfileError(f"the entry at line {line} has a {field} that isn't true or false")


def _invalid(version: str | None, line: int, origin: str) -> Pin:
    """An entry whose name breaks npm's rules: reported, never looked up, never echoed."""
    shown = version if version and is_semver(version) else None
    return Pin(
        INVALID_NAME, shown, line, "unsupported", "not a valid npm package name", "npm", origin
    )


def _pin(
    name: str, version: str | None, resolved: str | None, integrity: str | None, line: int
) -> Pin:
    """A registry release if ``resolved`` says so, else an unsupported entry saying why."""
    if resolved is not None:
        why = source_problem(resolved, name, version)
        if why is None and version:
            return Pin(name, version, line, ecosystem="npm")
        return Pin(name, version, line, "unsupported", why or "no version", "npm", resolved)
    # npm's omit-lockfile-registry-resolved setting leaves out registry URLs.
    if version and integrity and is_semver(version):
        return Pin(name, version, line, ecosystem="npm")
    return Pin(name, version, line, "unsupported", "no resolved URL or integrity", "npm")


# --- lockfileVersion 2 and 3: the "packages" map ---------------------------------


def _split(key: str, line: int) -> list[str]:
    """A ``packages`` key's folders. Only a leading ``..`` is allowed, as npm
    writes for a ``file:`` link outside the project."""
    parts = key.split("/")
    i = 0
    while i < len(parts) and parts[i] == "..":
        i += 1
    if i == len(parts) or any(p in ("", ".", "..") or "\\" in p for p in parts[i:]):
        raise LockfileError(f"the packages entry at line {line} isn't a plain relative path")
    return parts


def _install_location(parts: list[str]) -> tuple[str, str] | None:
    """(parent location, folder name) for a path inside ``node_modules``, else None."""
    if "node_modules" not in parts:
        return None
    last = len(parts) - 1 - parts[::-1].index("node_modules")
    return "/".join(parts[:last]), "/".join(parts[last + 1 :])


def _bundled_in(location: str, packages: dict[str, Any]) -> str:
    """The name of the package whose tarball a bundled entry ships in."""
    while True:
        found = _install_location(location.split("/"))
        if found is None:
            return "another package"
        entry = packages.get(location)
        if not (isinstance(entry, dict) and entry.get("inBundle") is True):
            name = entry.get("name") if isinstance(entry, dict) else None
            real = name if isinstance(name, str) else found[1]
            return real if valid_name(real) else "another package"
        location = found[0]


def _from_packages(packages: dict[str, Any], lines: dict[KeyPath, int]) -> list[Pin]:
    pins: list[Pin] = []
    for key, entry in packages.items():
        line = lines.get(("packages", key), 0)
        if key == "":
            continue  # the project itself
        if not isinstance(entry, dict):
            raise LockfileError(f"the packages entry at line {line} isn't an object")
        found = _install_location(_split(key, line))
        if found is None or _flag(entry, "link", line):
            continue  # a workspace member or linked folder: the project's own code
        parent, folder = found
        name = _string(entry, "name", line)  # set for an alias: the package installed
        version = _string(entry, "version", line)
        resolved = _string(entry, "resolved", line)
        integrity = _string(entry, "integrity", line)
        real = name if name is not None else folder
        if not valid_name(folder) or not valid_name(real):
            pins.append(_invalid(version, line, key))
        elif _flag(entry, "inBundle", line) and _install_location(parent.split("/")):
            # It ships inside the parent's tarball. The project's own
            # bundleDependencies install from the registry as usual.
            detail = f"bundled in {_bundled_in(parent, packages)}, checked only as part of it"
            pins.append(Pin(real, version, line, "unsupported", detail, "npm"))
        else:
            pins.append(_pin(real, version, resolved, integrity, line))
    return pins


# --- lockfileVersion 1: the nested "dependencies" tree -----------------------------


def _v1_path(path: KeyPath) -> bool:
    return len(path) % 2 == 0 and all(p == "dependencies" for p in path[::2])


def _from_tree(deps: dict[str, Any], lines: dict[KeyPath, int]) -> list[Pin]:
    pins: list[Pin] = []
    todo: list[tuple[KeyPath, dict[str, Any], str | None]] = [(("dependencies",), deps, None)]
    while todo:
        prefix, table, parent = todo.pop()
        for folder, entry in table.items():
            path = (*prefix, folder)
            line = lines.get(path, 0)
            if not isinstance(entry, dict):
                raise LockfileError(f"the dependencies entry at line {line} isn't an object")
            version = _string(entry, "version", line)
            resolved = _string(entry, "resolved", line)
            integrity = _string(entry, "integrity", line)
            children = entry.get("dependencies")
            if children is not None and not isinstance(children, dict):
                raise LockfileError(
                    f"the entry at line {line} has dependencies that aren't an object"
                )
            real = folder
            target = alias_target(version) if version else None
            if target is not None:
                real, version = target
            ok = valid_name(folder) and valid_name(real)
            if not ok:
                pins.append(_invalid(version, line, "/".join(path)))
            elif _flag(entry, "bundled", line) and parent is not None:
                detail = f"bundled in {parent}, checked only as part of it"
                pins.append(Pin(real, version, line, "unsupported", detail, "npm"))
            elif version is not None and target is None and not is_semver(version):
                # lockfileVersion 1 writes the spec as the version for git, path and URL sources.
                why = source_problem(version, real, None)
                pins.append(Pin(real, None, line, "unsupported", why, "npm", version))
            else:
                pins.append(_pin(real, version, resolved, integrity, line))
            if children:
                within = real if ok else "another package"
                todo.append(((*path, "dependencies"), children, within))
    return sorted(pins, key=lambda p: p.line)


def parse(text: str) -> list[Pin]:
    """Pins from a package-lock.json or npm-shrinkwrap.json.

    Every installed package counts: dev, optional and peer dependencies too.
    The project, workspace members and links are skipped. Packages from git,
    a path, a URL or another registry, bundled packages and names that break
    npm's rules are ``unsupported``.
    """
    text = text.removeprefix("\ufeff")
    doc = _load(text)
    version = doc.get("lockfileVersion")
    if isinstance(version, bool) or not isinstance(version, int):
        raise LockfileError("no lockfileVersion; Garnet reads lockfileVersion 1, 2 and 3")
    if version in (2, 3):
        packages = doc.get("packages")
        if not isinstance(packages, dict):
            raise LockfileError(f"lockfileVersion {version} needs a packages object")
        lines = key_lines(text, lambda p: len(p) == 2 and p[0] == "packages")
        return _from_packages(packages, lines)
    if version == 1:
        deps = doc.get("dependencies", {})
        if not isinstance(deps, dict):
            raise LockfileError("the dependencies entry isn't an object")
        return _from_tree(deps, key_lines(text, _v1_path))
    shown = str(version) if 0 <= version < 1000 else "outside 1 to 3"
    raise LockfileError(
        f"lockfileVersion {shown} isn't one Garnet reads (1, 2 or 3); regenerate the "
        "lockfile with npm 7 or later"
    )
