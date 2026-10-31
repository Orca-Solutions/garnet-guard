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
_STRING = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"')
_BRACKET = re.compile(r"[{}\[\]]")
# npm writes about six levels; lockfileVersion 1 adds two for each level of
# nested node_modules. Python's own limit depends on the version and the
# stack size (3.14 measures the C stack), so Garnet sets its own.
MAX_DEPTH = 256


def _too_deep(text: str) -> bool:
    """True if objects and arrays nest more than ``MAX_DEPTH`` levels."""
    depth = 0
    for c in _BRACKET.findall(_STRING.sub("", text)):
        if c in "{[":
            depth += 1
            if depth > MAX_DEPTH:
                return True
        else:
            depth -= 1
    return False


def _load(text: str) -> dict[str, Any]:
    """The parsed document. Errors name a position, never the file's text."""
    if _too_deep(text):
        raise LockfileError("JSON nested too deeply to read")
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


def _text(value: str, what: str, line: int) -> str:
    """``value``, if it is text: JSON escapes can spell lone surrogates, which
    no output can print."""
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as err:
        raise LockfileError(f"the entry at line {line} has a {what} that isn't valid text") from err
    return value


def _string(entry: dict[str, Any], field: str, line: int) -> str | None:
    value = entry.get(field)
    if value is None:
        return None
    if isinstance(value, str):
        return _text(value, field, line)
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


def _origin(resolved: str | None, integrity: str | None) -> str | None:
    """Where an unsupported entry installs from and the content it expects, so
    a new tarball behind the same URL counts as a change."""
    return " ".join(v for v in (resolved, integrity) if v) or None


def _pin(
    name: str, version: str | None, resolved: str | None, integrity: str | None, line: int
) -> Pin:
    """A registry release if ``resolved`` says so, else an unsupported entry saying why."""
    origin = _origin(resolved, integrity)
    if resolved is not None:
        why = source_problem(resolved, name, version)
        if why is None and version:
            return Pin(name, version, line, ecosystem="npm")
        return Pin(name, version, line, "unsupported", why or "no version", "npm", origin)
    # npm's omit-lockfile-registry-resolved setting leaves out registry URLs.
    if version and integrity and is_semver(version):
        return Pin(name, version, line, ecosystem="npm")
    return Pin(name, version, line, "unsupported", "no resolved URL or integrity", "npm", origin)


def _ships_inside(entry: object, flag: str) -> bool:
    """True for an entry flagged as bundled that has no resolved URL or
    integrity of its own.

    npm fetches a flagged entry from its own ``resolved`` when the parent's
    tarball doesn't hold it, so an entry with a URL or an integrity is judged
    by that source instead. npm writes neither for a dependency it found
    inside a tarball, unless npm 6 or earlier left ``_resolved`` in that
    dependency's package.json; such an entry is checked as its source says.
    """
    return (
        isinstance(entry, dict)
        and entry.get(flag) is True
        and entry.get("resolved") is None
        and entry.get("integrity") is None
    )


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
    """The name of the package whose tarball a bundled entry ships in: the
    nearest one above it that isn't bundled itself."""
    while True:
        found = _install_location(location.split("/"))
        if found is None:
            return "another package"
        entry = packages.get(location)
        parent = found[0]
        if not (_ships_inside(entry, "inBundle") and _install_location(parent.split("/"))):
            name = entry.get("name") if isinstance(entry, dict) else None
            real = name if isinstance(name, str) else found[1]
            return real if valid_name(real) else "another package"
        location = parent


# An entry's pin, None for one that isn't checked (a workspace member or a
# link), and the URL and integrity it installs from.
Located = tuple[Pin | None, str | None]


def _from_packages(packages: dict[str, Any], lines: dict[KeyPath, int]) -> dict[str, Located]:
    """Each entry by its location."""
    pins: dict[str, Located] = {}
    for key, entry in packages.items():
        line = lines.get(("packages", key), 0)
        if key == "":
            continue  # the project itself
        _text(key, "key", line)
        if not isinstance(entry, dict):
            raise LockfileError(f"the packages entry at line {line} isn't an object")
        found = _install_location(_split(key, line))
        if found is None or _flag(entry, "link", line):
            pins[key] = (None, None)  # a workspace member or linked folder: the project's own code
            continue
        parent, folder = found
        name = _string(entry, "name", line)  # set for an alias: the package installed
        version = _string(entry, "version", line)
        resolved = _string(entry, "resolved", line)
        integrity = _string(entry, "integrity", line)
        real = name if name is not None else folder
        source = _origin(resolved, integrity)
        if not valid_name(folder) or not valid_name(real):
            pins[key] = (_invalid(version, line, key), source)
        elif (
            _flag(entry, "inBundle", line)
            and _ships_inside(entry, "inBundle")
            and _install_location(parent.split("/"))
        ):
            # It ships inside the parent's tarball. The project's own
            # bundleDependencies install from the registry as usual.
            detail = f"bundled in {_bundled_in(parent, packages)}, checked only as part of it"
            pins[key] = (Pin(real, version, line, "unsupported", detail, "npm"), source)
        else:
            pins[key] = (_pin(real, version, resolved, integrity, line), source)
    return pins


# --- lockfileVersion 1: the nested "dependencies" tree -----------------------------


def _v1_path(path: KeyPath) -> bool:
    return len(path) % 2 == 0 and all(p == "dependencies" for p in path[::2])


def _from_tree(
    deps: dict[str, Any], lines: dict[KeyPath, int], links: dict[str, str]
) -> list[tuple[str, Pin, str | None]]:
    """Each entry's install location (``node_modules/a/node_modules/b``), its
    pin, and the URL and integrity it installs from.

    ``links`` maps a link's location to its target's, where the link's own
    dependencies are installed.
    """
    pins: list[tuple[str, Pin, str | None]] = []
    todo: list[tuple[KeyPath, dict[str, Any], str | None, str]] = [
        (("dependencies",), deps, None, "")
    ]
    while todo:
        prefix, table, parent, under = todo.pop()
        for folder, entry in table.items():
            path = (*prefix, folder)
            line = lines.get(path, 0)
            _text(folder, "key", line)
            location = f"{under}/node_modules/{folder}" if under else f"node_modules/{folder}"
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
            source = _origin(resolved, integrity)
            bundled = (
                _flag(entry, "bundled", line)
                and parent is not None
                and _ships_inside(entry, "bundled")
            )
            if not ok:
                pin = _invalid(version, line, location)
            elif bundled:
                detail = f"bundled in {parent}, checked only as part of it"
                pin = Pin(real, version, line, "unsupported", detail, "npm")
            elif version is not None and target is None and not is_semver(version):
                # lockfileVersion 1 writes the spec as the version for git, path and URL sources.
                why = source_problem(version, real, None)
                source = _origin(version, integrity)
                pin = Pin(real, None, line, "unsupported", why, "npm", source)
            else:
                pin = _pin(real, version, resolved, integrity, line)
            pins.append((location, pin, source))
            if children:
                # A bundled entry's own dependencies ship in the same tarball.
                within = parent if bundled else real if ok else "another package"
                todo.append(
                    ((*path, "dependencies"), children, within, links.get(location, location))
                )
    return pins


def _same(in_packages: Located, tree: Pin, tree_source: str | None) -> bool:
    """True if a ``dependencies`` entry installs what the ``packages`` entry at
    its location does, written the lockfileVersion 1 way."""
    pin, source = in_packages
    if pin is None:
        # A link or workspace member, which lockfileVersion 1 writes as file:.
        return tree.detail == "file: source"
    if tree_source is not None and tree_source == source:
        return True  # the same URL and integrity, however the version is written
    if "registry" in (pin.source, tree.source):
        return (pin.source, pin.package, pin.version) == (tree.source, tree.package, tree.version)
    keys = ("package", "version", "detail", "origin")
    return all(getattr(pin, k) == getattr(tree, k) for k in keys)


def parse(text: str) -> list[Pin]:
    """Pins from a package-lock.json or npm-shrinkwrap.json.

    Every installed package counts: dev, optional and peer dependencies too.
    The project, workspace members and links are skipped. Packages from git,
    a path, a URL or another registry, bundled packages and names that break
    npm's rules are ``unsupported``.

    npm 7 and later install from ``packages`` whenever it is there, and npm 6
    from ``dependencies``, whatever ``lockfileVersion`` says, so both are
    read. A ``dependencies`` entry that installs something its ``packages``
    entry doesn't is reported as well.
    """
    text = text.removeprefix("\ufeff")
    doc = _load(text)
    version = doc.get("lockfileVersion")
    if isinstance(version, bool) or not isinstance(version, int):
        raise LockfileError("no lockfileVersion; Garnet reads lockfileVersion 1, 2 and 3")
    if version not in (1, 2, 3):
        shown = str(version) if 0 <= version < 1000 else "outside 1 to 3"
        raise LockfileError(
            f"lockfileVersion {shown} isn't one Garnet reads (1, 2 or 3); regenerate the "
            "lockfile with npm 7 or later"
        )
    packages = doc.get("packages")
    deps = doc.get("dependencies")
    if version in (2, 3) and not isinstance(packages, dict):
        raise LockfileError(f"lockfileVersion {version} needs a packages object")
    if packages is not None and not isinstance(packages, dict):
        raise LockfileError("the packages entry isn't an object")
    if deps is not None and not isinstance(deps, dict):
        raise LockfileError("the dependencies entry isn't an object")
    lines = key_lines(text, lambda p: (len(p) == 2 and p[0] == "packages") or _v1_path(p))
    by_location = _from_packages(packages, lines) if packages is not None else {}
    pins = [p for p, _ in by_location.values() if p is not None]
    links = {
        key: entry["resolved"]
        for key, entry in (packages or {}).items()
        if isinstance(entry, dict)
        and entry.get("link") is True
        and isinstance(entry.get("resolved"), str)
    }
    for location, pin, source in _from_tree(deps, lines, links) if deps is not None else []:
        if location not in by_location or not _same(by_location[location], pin, source):
            pins.append(pin)
    return sorted(pins, key=lambda p: p.line)
