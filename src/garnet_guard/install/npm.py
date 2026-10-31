"""Reading ``npm install|ci|update`` commands and npm projects, without running npm.

What Garnet does with each argument comes from the tables below. An option
that isn't in them is refused, so an abbreviation (npm's parser expands
``--glob`` to ``--global``) or a setting npm adds later is "can't check",
never passed through unread.

The resolve step (in :mod:`.check`) runs ``npm install --package-lock-only``
in a private copy of ``package.json``, the lockfile and ``.npmrc``. These
experiments, recorded in WORKING_RECORD.md, decide what it is given:

- npm 10.9.4 runs a git dependency's ``prepare`` script while resolving a
  lockfile, ``--ignore-scripts`` and ``npm_config_ignore_scripts`` included,
  when the dependency is on a git host and pinned to a full commit: pacote
  19 packs it to read its manifest. ``npm_config_script_shell`` set to a
  program that doesn't exist makes that script fail instead, so the
  resolve fails and the command is "can't check". npm 11.21 honours
  ``--ignore-scripts`` there and has ``--allow-git=none``.
- npm runs the ``git`` its configuration names (``.npmrc`` can set it), so
  ``npm_config_git`` points at a program that doesn't exist too.
- ``npm ci --ignore-scripts`` still runs ``prepare`` for git and folder
  dependencies on npm 10, so a lockfile with either is "can't check".
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..lockfiles import LockfileError, parse
from ..lockfiles.npm import looks_like_git, split_spec, valid_name
from .pip import Refusal

LOCKFILES = ("npm-shrinkwrap.json", "package-lock.json")  # npm prefers the first
COPIED = ("package.json", *LOCKFILES, ".npmrc")
MAX_FILE_BYTES = 64 * 1024 * 1024  # the most the lockfile parsers read

# npm 10 and 11 subcommand aliases (lib/utils/cmd-list.js), by what Garnet runs.
SUBCOMMANDS = {
    **dict.fromkeys(
        (
            "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal",
            "isntall", "add",
        ),
        "install",
    ),
    **dict.fromkeys(("ci", "clean-install", "ic", "install-clean", "isntall-clean"), "ci"),
    **dict.fromkeys(("update", "up", "upgrade", "udpate"), "update"),
}  # fmt: skip

# Options Garnet passes on, by where. npm's parser (nopt) takes
# ``--name value`` and ``--name=value`` for options with a value.
_SAVE = frozenset(
    {
        "-S", "--save", "-D", "--save-dev", "-O", "--save-optional", "-P", "--save-prod",
        "-E", "--save-exact", "-B", "--save-bundle", "--save-peer",
    }
)  # fmt: skip
# Change what is resolved, so both the resolve and npm ci get them.
_RESOLVE = frozenset(
    {
        "--legacy-peer-deps", "--strict-peer-deps", "--force", "-f", "--prefer-dedupe",
        "--prefer-offline", "--prefer-online", "--offline", "--engine-strict",
    }
)  # fmt: skip
# Change only what npm ci puts in node_modules or prints.
_INSTALL = frozenset(
    {"--no-bin-links", "--foreground-scripts", "--production", "--no-optional"}
)  # fmt: skip
_QUIET = frozenset(
    {
        "--no-audit", "--audit", "--no-fund", "--fund", "--silent", "-s", "--quiet", "-q",
        "--verbose", "-d", "--no-progress", "--progress", "--no-color",
    }
)  # fmt: skip
_VALUE_BOTH = frozenset({"--registry", "--loglevel", "--cache", "--install-strategy"})
_VALUE_RESOLVE = frozenset({"--before", "--tag", "--save-prefix", "--lockfile-version"})
_VALUE_INSTALL = frozenset({"--omit", "--include", "--cpu", "--os", "--libc"})
VALUE_OPTIONS = _VALUE_BOTH | _VALUE_RESOLVE | _VALUE_INSTALL
# Refused with a reason: each installs somewhere else, installs what the
# lockfile doesn't say, or changes how npm runs code.
_REFUSED = {
    "-g": "it installs globally, outside the project",
    "--global": "it installs globally, outside the project",
    "--location": "it can install globally, outside the project",
    "--prefix": "it installs into another folder",
    "-C": "it installs into another folder",
    "-w": "Garnet Guard doesn't check npm workspaces yet",
    "--workspace": "Garnet Guard doesn't check npm workspaces yet",
    "-ws": "Garnet Guard doesn't check npm workspaces yet",
    "--workspaces": "Garnet Guard doesn't check npm workspaces yet",
    "--include-workspace-root": "Garnet Guard doesn't check npm workspaces yet",
    "--no-package-lock": "npm writes no lockfile, so there is nothing to check against",
    "--no-save": "npm writes nothing back, so the lockfile doesn't say what it installs",
    "--install-links": "it packs folder dependencies, which runs their prepare scripts",
    "--script-shell": "it changes the program npm runs scripts with",
}

# npm settings, from any .npmrc or the environment, that stop the lockfile
# saying what is installed, and the value each must have.
CONFIG_EXPECTED = {
    "global": "false",
    "location": "user",
    "package-lock": "true",
    "save": "true",
    "install-links": "false",
    "workspaces": "null",
    "workspace": "",
    "omit-lockfile-registry-resolved": "false",
}
_CONFIG_WHY = {
    "global": "npm installs globally, outside the project",
    "location": "npm installs globally, outside the project",
    "package-lock": "npm writes no lockfile, so there is nothing to check against",
    "save": "npm writes nothing back, so the lockfile doesn't say what it installs",
    "install-links": "npm packs folder dependencies, which runs their prepare scripts",
    "workspaces": "Garnet Guard doesn't check npm workspaces yet",
    "workspace": "Garnet Guard doesn't check npm workspaces yet",
    "omit-lockfile-registry-resolved": (
        "the lockfile doesn't record each package's registry, so Garnet Guard can't tell "
        "where it comes from"
    ),
}
CONFIG_KEYS = (*CONFIG_EXPECTED, "ignore-scripts")

# The project's own scripts that npm ci runs (without --ignore-scripts).
ROOT_SCRIPTS = (
    "preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare",
    "postprepare",
)  # fmt: skip
_DEP_TABLES = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
# What a registry range or tag may hold: SemVer ranges, dist-tags, "*".
_RANGE = re.compile(r"[A-Za-z0-9.^~<>=|*+ \-]*")
_TARBALL = re.compile(r"\.(?:tgz|tar\.gz|tar)$", re.IGNORECASE)


class NpmError(Exception):
    """The project's files couldn't be read."""


@dataclass
class Plan:
    """What an ``npm install|ci|update`` command asks for, read without running npm."""

    subcommand: str  # "install", "ci" or "update"
    resolve: list[str] = field(default_factory=list)  # for npm in the copy
    handoff: list[str] = field(default_factory=list)  # for npm ci after the check
    specs: list[str] = field(default_factory=list)  # packages named on the command line
    lock_only: bool = False  # --package-lock-only: write the files, install nothing
    dry_run: bool = False  # --dry-run: check, write nothing
    ignore_scripts: bool = False  # the user's own --ignore-scripts
    refusals: list[Refusal] = field(default_factory=list)


def registry_spec(spec: str) -> bool:
    """True for ``name``, ``name@range``, ``name@tag`` or an ``npm:`` alias of one:
    what npm fetches from the registry, as npm-package-arg reads it."""
    name, rng = split_spec(spec)
    if not valid_name(name) or _TARBALL.search(spec):
        return False
    if rng.startswith("npm:"):
        target, target_range = split_spec(rng[4:])
        return valid_name(target) and _plain_range(target_range)
    return _plain_range(rng)


def _plain_range(rng: str) -> bool:
    return bool(_RANGE.fullmatch(rng)) and not looks_like_git(rng) and not _TARBALL.search(rng)


def plan(subcommand: str, args: Sequence[str]) -> Plan:
    """Read the arguments after ``npm <subcommand>`` (``subcommand`` already canonical)."""
    out = Plan(subcommand)
    j = 0
    positional_only = False
    while j < len(args):
        a = args[j]
        j += 1
        if positional_only or not a.startswith("-") or a == "-":
            _spec(a, out)
            continue
        if a == "--":
            positional_only = True
            continue
        name, eq, value = a.partition("=")
        if name in VALUE_OPTIONS:
            if not eq:
                if j >= len(args):
                    out.refusals.append(Refusal(a, "it needs a value"))
                    break
                value = args[j]
                j += 1
            words = [f"{name}={value}"]
            if name in _VALUE_BOTH or name in _VALUE_RESOLVE:
                out.resolve += words
            if name in _VALUE_BOTH or name in _VALUE_INSTALL:
                out.handoff += words
            continue
        if eq:
            out.refusals.append(Refusal(name, _REFUSED.get(name, "Garnet Guard doesn't know it")))
            continue
        if a == "--ignore-scripts":
            out.ignore_scripts = True
        elif a == "--package-lock-only":
            out.lock_only = True
        elif a == "--dry-run":
            out.dry_run = True
        elif a in _SAVE:
            out.resolve.append(a)
        elif a in _RESOLVE:
            out.resolve.append(a)
            out.handoff.append(a)
        elif a in _INSTALL:
            out.handoff.append(a)
        elif a in _QUIET:
            out.resolve.append(a)
            out.handoff.append(a)
        else:
            out.refusals.append(Refusal(a, _REFUSED.get(a, "Garnet Guard doesn't know it")))
    return out


def _spec(word: str, out: Plan) -> None:
    if out.subcommand == "ci":
        out.refusals.append(Refusal(word, "npm ci takes no packages"))
    elif registry_spec(word):
        out.specs.append(word)
        out.resolve.append(word)
    else:
        why = (
            "it installs from git, a URL, a file or a folder, which npm may run scripts from "
            "and Garnet Guard can't compare with a registry release"
        )
        out.refusals.append(Refusal(word, why))


def find_project(start: Path) -> Path:
    """The folder npm installs into: the nearest with a package.json or a
    node_modules folder (npm's local prefix), else ``start``."""
    here = start.resolve()
    for folder in (here, *here.parents):
        if (folder / "package.json").is_file() or (folder / "node_modules").is_dir():
            return folder
    return here


def lockfile_name(project: Path) -> str:
    """The lockfile npm reads and writes here: npm-shrinkwrap.json when there is one."""
    for name in LOCKFILES:
        path = project / name
        if path.exists() or path.is_symlink():
            return name
    return "package-lock.json"


def _load(data: bytes, name: str) -> dict[str, Any]:
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as err:
        raise NpmError(f"{name} isn't valid JSON") from err
    if not isinstance(doc, dict):
        raise NpmError(f"{name} isn't a JSON object")
    return doc


def project_refusals(project: Path, manifest: bytes | None) -> list[Refusal]:
    """What in the project Garnet won't resolve: workspaces, and dependencies
    that aren't registry releases. ``manifest`` is package.json's bytes."""
    out: list[Refusal] = []
    for folder in project.parents:
        found = folder / "package.json"
        if found.is_file() and not found.is_symlink():
            try:
                doc = _load(found.read_bytes()[:MAX_FILE_BYTES], "package.json")
            except (NpmError, OSError):
                continue
            if "workspaces" in doc:
                out.append(Refusal(str(found), "npm treats this folder as one of its workspaces"))
    if manifest is None:
        return out
    doc = _load(manifest, "package.json")
    if "workspaces" in doc:
        out.append(
            Refusal("package.json workspaces", "Garnet Guard doesn't check npm workspaces yet")
        )
    for table in _DEP_TABLES:
        deps = doc.get(table)
        if deps is None:
            continue
        if not isinstance(deps, dict):
            raise NpmError(f"package.json's {table} isn't an object")
        for name, rng in sorted(deps.items()):
            if not isinstance(rng, str) or not registry_spec(f"{name}@{rng}"):
                out.append(Refusal(f"package.json {table} {name}", _SOURCE_WHY))
    for path, rng in _overrides(doc.get("overrides"), ()):
        if not rng.startswith("$") and not registry_spec(f"x@{rng}"):
            out.append(Refusal(f"package.json overrides {' '.join(path)}", _SOURCE_WHY))
    return out


_SOURCE_WHY = (
    "it isn't a registry release (git, a URL, a file or a folder), which npm may run scripts "
    "from and Garnet Guard can't compare with one"
)


def _overrides(value: object, path: tuple[str, ...]) -> list[tuple[tuple[str, ...], str]]:
    """Every override's range, with the keys that lead to it."""
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, dict):
        out = []
        for key, inner in sorted(value.items()):
            if key == ".":
                out += _overrides(inner, path)
            else:
                out += _overrides(inner, (*path, str(key)))
        return out
    if value is None:
        return []
    return [(path, "?")]  # not a string or an object: npm would reject it; Garnet refuses


def config_refusals(text: str) -> tuple[list[Refusal], bool]:
    """Settings from ``npm config get <CONFIG_KEYS>`` that Garnet can't check
    under, and whether ``ignore-scripts`` is on. Values are never shown."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, eq, value = line.partition("=")
        if eq:
            values[key.strip()] = value.strip()
    out = []
    for key, expected in CONFIG_EXPECTED.items():
        got = values.get(key)
        if got is None:
            out.append(Refusal(f"npm setting {key}", "Garnet Guard couldn't read it"))
        elif got != expected and not (key == "location" and got == "project"):
            out.append(Refusal(f"npm setting {key}", _CONFIG_WHY[key]))
    return out, values.get("ignore-scripts") == "true"


def resolve_env(env: Mapping[str, str], workdir: Path) -> dict[str, str]:
    """The environment for npm in the copy: no scripts, no git, no audit.

    npm reads ``npm_config_*`` in any case, so the user's own spellings of
    these settings are taken out first. The script shell and git point at
    paths in Garnet's private folder that don't exist, so anything that
    would run a script or git fails, and the command is "can't check".
    """
    ours = {
        "npm_config_ignore_scripts": "true",
        "npm_config_script_shell": str(workdir / "no-scripts"),
        "npm_config_git": str(workdir / "no-git"),
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_update_notifier": "false",
        "npm_config_yes": "false",
    }
    out = {k: v for k, v in env.items() if k.lower().replace("-", "_") not in ours}
    out.update(ours)
    return out


# Added after the user's arguments on every resolve. npm 10 ignores the
# --allow-* settings; npm 11 refuses git, URL and file sources with them.
RESOLVE_TAIL = (
    "--package-lock-only",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--allow-git=none",
    "--allow-remote=none",
    "--allow-file=none",
    "--allow-directory=none",
)

# Lockfile entries Garnet checks like ``garnet check`` does (a GRN-E005
# finding). Any other entry npm wouldn't fetch from the registry is "can't
# check": git and folder sources run prepare scripts during npm ci on npm 10,
# and none of them has a release to compare with.
_CHECKED_UNSUPPORTED = ("private registry", "bundled in ")


def lock_refusals(lockfile: str, data: bytes) -> list[str]:
    """Why the head lockfile can't be installed as checked, one line each."""
    try:
        pins = parse(lockfile, data)
    except LockfileError as err:
        return [f"Garnet Guard couldn't read the {lockfile} npm wrote: {err}."]
    lines = []
    for p in pins:
        if p.source == "unsupported" and not (p.detail or "").startswith(_CHECKED_UNSUPPORTED):
            lines.append(
                f"{lockfile} {p.package}: {p.detail or 'unsupported source'}. npm may run its "
                "scripts, and Garnet Guard can't compare it with a registry release."
            )
    doc = _load(data, lockfile)
    packages = doc.get("packages")
    if isinstance(packages, dict):
        for key, entry in sorted(packages.items()):
            if key and isinstance(entry, dict) and entry.get("link") is True:
                lines.append(
                    f"{lockfile} {key}: a link to a folder. npm runs its prepare script, and "
                    "Garnet Guard checks registry releases only."
                )
    return lines


@dataclass(frozen=True)
class Scripted:
    """An installed package with install scripts (``hasInstallScript``)."""

    folder: str  # the name npm rebuild matches: the folder under node_modules
    package: str  # the package it is (differs for an npm: alias)
    version: str


def scripted(data: bytes) -> list[Scripted]:
    """Every registry package in a lockfile that has install scripts."""
    try:
        doc = _load(data, "lockfile")
    except NpmError:
        return []
    packages = doc.get("packages")
    if not isinstance(packages, dict):
        return []
    out = set()
    for key, entry in packages.items():
        if not isinstance(entry, dict) or entry.get("hasInstallScript") is not True:
            continue
        if "node_modules/" not in f"{key}" or entry.get("link") is True:
            continue
        folder = key.rpartition("node_modules/")[2]
        version = entry.get("version")
        name = entry.get("name", folder)
        if isinstance(version, str) and isinstance(name, str) and valid_name(folder):
            out.add(Scripted(folder, name, version))
    return sorted(out, key=lambda s: (s.folder, s.version))


def root_scripts(manifest: bytes | None) -> list[str]:
    """The project's own install-time scripts, which npm ci --ignore-scripts skips."""
    if manifest is None:
        return []
    try:
        scripts = _load(manifest, "package.json").get("scripts")
    except NpmError:
        return []
    if not isinstance(scripts, dict):
        return []
    return [name for name in ROOT_SCRIPTS if isinstance(scripts.get(name), str)]
