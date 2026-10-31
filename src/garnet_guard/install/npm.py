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
import shutil
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

# npm's commands and aliases (lib/utils/cmd-list.js), npm 10.9.4 and 11.21.1.
# npm reads its subcommand with ``deref``: camelCase to kebab-case, then the
# exact command, an alias, or a unique abbreviation of any command or alias
# (``npm upd`` is update, ``npm install-cl`` is install-clean, which is ci).
_COMMON_COMMANDS = (
    "access", "adduser", "audit", "bugs", "cache", "ci", "completion", "config", "dedupe",
    "deprecate", "diff", "dist-tag", "docs", "doctor", "edit", "exec", "explain", "explore",
    "find-dupes", "fund", "get", "help", "help-search", "init", "install", "install-ci-test",
    "install-test", "link", "ll", "login", "logout", "ls", "org", "outdated", "owner", "pack",
    "ping", "pkg", "prefix", "profile", "prune", "publish", "query", "rebuild", "repo",
    "restart", "root", "sbom", "search", "set", "shrinkwrap", "star", "stars", "start", "stop",
    "team", "test", "token", "uninstall", "unpublish", "unstar", "update", "version", "view",
    "whoami",
)  # fmt: skip
_COMMON_ALIASES = {
    "author": "owner", "home": "docs", "issues": "bugs", "info": "view", "show": "view",
    "find": "search", "add": "install", "unlink": "uninstall", "remove": "uninstall",
    "rm": "uninstall", "r": "uninstall", "un": "uninstall", "rb": "rebuild", "list": "ls",
    "ln": "link", "create": "init", "i": "install", "it": "install-test",
    "cit": "install-ci-test", "up": "update", "c": "config", "s": "search", "se": "search",
    "tst": "test", "t": "test", "ddp": "dedupe", "v": "view", "clean-install": "ci",
    "clean-install-test": "install-ci-test", "x": "exec", "why": "explain", "la": "ll",
    "verison": "version", "ic": "ci", "innit": "init", "in": "install", "ins": "install",
    "inst": "install", "insta": "install", "instal": "install", "isnt": "install",
    "isnta": "install", "isntal": "install", "isntall": "install", "install-clean": "ci",
    "isntall-clean": "ci", "hlep": "help", "dist-tags": "dist-tag", "upgrade": "update",
    "udpate": "update", "sit": "install-ci-test", "ogr": "org", "add-user": "adduser",
}  # fmt: skip
NPM_TABLES: tuple[tuple[tuple[str, ...], dict[str, str]], ...] = (
    (  # npm 10
        (*_COMMON_COMMANDS, "hook", "run-script"),
        {**_COMMON_ALIASES, "run": "run-script", "rum": "run-script", "urn": "run-script"},
    ),
    (  # npm 11
        (
            *_COMMON_COMMANDS, "approve-scripts", "deny-scripts", "install-scripts", "run",
            "stage", "trust", "undeprecate",
        ),
        {**_COMMON_ALIASES, "u": "update", "run-script": "run", "rum": "run", "urn": "run"},
    ),
)  # fmt: skip
CHECKED = ("install", "ci", "update")


def _abbrev(words: Sequence[str]) -> dict[str, str]:
    """npm's ``abbrev`` package: every unique prefix of each word, and each word."""
    ordered = sorted(set(words))
    out: dict[str, str] = {}
    prev = ""
    for n, current in enumerate(ordered):
        nxt = ordered[n + 1] if n + 1 < len(ordered) else ""
        next_matches = prev_matches = True
        j = 0
        while j < len(current):
            ch = current[j]
            next_matches = next_matches and nxt[j : j + 1] == ch
            prev_matches = prev_matches and prev[j : j + 1] == ch
            if not next_matches and not prev_matches:
                j += 1
                break
            j += 1
        prev = current
        if j == len(current) and (next_matches or prev_matches):
            out[current] = current
            continue
        for k in range(j, len(current) + 1):
            out[current[:k]] = current
    return out


_ABBREVS = tuple(_abbrev([*cmds, *aliases]) for cmds, aliases in NPM_TABLES)


def deref(word: str) -> set[str]:
    """The commands npm 10 and npm 11 run for ``word``; empty if neither knows it."""
    if re.search("[A-Z]", word):
        word = re.sub("[A-Z]", lambda m: "-" + m[0].lower(), word)
    out = set()
    for (commands, aliases), abbrevs in zip(NPM_TABLES, _ABBREVS, strict=True):
        if word in commands:
            out.add(word)
        elif word in aliases:
            out.add(aliases[word])
        elif word in abbrevs:
            found = abbrevs[word]
            while found in aliases:
                found = aliases[found]
            out.add(found)
    return out


def checked_subcommand(word: str) -> str | None:
    """install, ci or update when both npm 10 and 11 read ``word`` as that one."""
    found = deref(word)
    return next(iter(found)) if len(found) == 1 and found <= set(CHECKED) else None


# Commands that install nothing and fetch no package Garnet hasn't seen,
# whatever their arguments; the project's own scripts (run, test) included.
QUIET_COMMANDS = frozenset(
    {
        "access", "adduser", "bugs", "completion", "config", "deprecate", "undeprecate",
        "dist-tag", "docs", "doctor", "explain", "fund", "get", "help", "help-search", "hook",
        "ll", "login", "logout", "ls", "org", "owner", "ping", "pkg", "prefix", "profile",
        "publish", "query", "repo", "restart", "root", "run", "run-script", "sbom", "search",
        "set", "star", "stars", "start", "stop", "team", "test", "token", "unpublish",
        "unstar", "version", "whoami",
    }
)  # fmt: skip
# Quiet unless given a word that makes them fetch or install: ``npm init
# <initializer>`` runs npm exec, ``audit fix`` installs, ``cache add`` and
# ``pack <spec>`` fetch (which packs a git dependency), ``view`` of a spec
# that isn't a registry one fetches it.
_QUIET_UNLESS = {
    "init": lambda words: not words,
    "audit": lambda words: "fix" not in words,
    "cache": lambda words: "add" not in words,
    "pack": lambda words: not words,
    "view": lambda words: all(registry_spec(w) for w in words),
}
EXEC_COMMANDS = frozenset({"exec"})
# Package managers, which npx or npm exec can start (``npx npm i x``).
PACKAGE_MANAGERS = frozenset({"npm", "npx", "pnpm", "pnpx", "yarn", "yarnpkg", "corepack"})


def quiet_command(commands: set[str], words: Sequence[str]) -> bool:
    """True when every command in ``commands`` installs nothing with these
    arguments (``words``: the ones after the subcommand that aren't options)."""
    if not commands:
        return False
    for command in commands:
        test = _QUIET_UNLESS.get(command)
        if not (command in QUIET_COMMANDS or (test is not None and test(list(words)))):
            return False
    return True


def runs_package_manager(args: Sequence[str]) -> bool:
    """True when npx or npm exec with ``args`` may start a package manager:
    any word, or ``--package`` value, naming one (``npm@10``, ``./bin/npm``)."""
    for a in args:
        word = a.split("=", 1)[1] if a.startswith("--package=") else a
        name = split_spec(word)[0] if not word.startswith("@") else word
        if name.rsplit("/", 1)[-1].split(".")[0].lower() in PACKAGE_MANAGERS:
            return True
    return False


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
        if j < len(args) and args[j] in ("true", "false"):
            # npm's parser takes a bare true or false after a flag as its value
            # (--ignore-scripts false turns scripts on).
            out.refusals.append(Refusal(f"{a} {args[j]}", "npm reads the word as the flag's value"))
            j += 1
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


# Environment variables that make node load code before npm runs: a
# --require or --import in NODE_OPTIONS, a fallback module folder, the REPL's
# module. They are taken out of every npm run during the check.
NODE_PRELOAD = frozenset({"NODE_OPTIONS", "NODE_PATH", "NODE_REPL_EXTERNAL_MODULE"})
TESTED_MAJORS = (10, 11)


def check_env(env: Mapping[str, str]) -> dict[str, str]:
    """The user's environment for npm during the check, without node preloads."""
    out = {k: v for k, v in env.items() if k.upper() not in NODE_PRELOAD}
    out["npm_config_update_notifier"] = "false"
    return out


def npm_major(text: str) -> int | None:
    """The major version in ``npm --version``'s output."""
    m = re.fullmatch(r"\s*(\d+)\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?\s*", text)
    return int(m[1]) if m else None


def _repo_root(project: Path) -> Path | None:
    for folder in (project, *project.parents):
        if (folder / ".git").exists():
            return folder
    return None


def _interpreter(program: Path, path: str) -> Path | None:
    """The program a script's ``#!`` line starts (``env node`` from PATH). Read, never run."""
    try:
        with open(program, "rb") as fh:
            first = fh.readline(512)
    except OSError:
        return None
    if not first.startswith(b"#!"):
        return None
    parts = first[2:].decode("utf-8", "replace").split()
    if not parts:
        return None
    if Path(parts[0]).name == "env":
        names = [p for p in parts[1:] if not p.startswith("-")]
        found = shutil.which(names[0], path=path) if names else None
        return Path(found) if found else None
    return Path(parts[0])


def program_refusal(npm_exe: str, project: Path, cwd: Path, path: str) -> str | None:
    """Why Garnet won't start this npm (or the node its ``#!`` line names), if so.

    The hook runs before the user approves the command, so it doesn't start
    an npm or node from the project, from its repository, or from any
    node_modules folder (``node_modules/.bin/npm``), committed or not, nor
    corepack's npm shim, which runs the npm version ``packageManager`` names.
    """
    places = [p.resolve() for p in (project, cwd)]
    repo = _repo_root(project)
    if repo is not None:
        places.append(repo.resolve())
    exe = Path(npm_exe)
    for program, what in ((exe, "npm"), (_interpreter(exe, path), "the node npm starts with")):
        if program is None:
            continue
        real = program.resolve()
        if "node_modules" in program.parts:
            return f"{what} on PATH is {program}, in a node_modules folder"
        if "corepack" in real.parts:
            return (
                f"{what} on PATH is corepack's shim, which runs the npm version the project's "
                "packageManager names; Garnet Guard runs npm itself"
            )
        for place in places:
            if real == place or place in real.parents:
                return f"{what} on PATH is {program}, inside the project or its repository"
    return None


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
    out = {k: v for k, v in check_env(env).items() if k.lower().replace("-", "_") not in ours}
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

    path: str  # its lockfile key, the folder npm rebuild is given: node_modules/a
    package: str  # the package it is (differs from the folder for an npm: alias)
    version: str
    resolved: str
    integrity: str

    @property
    def rebuild_spec(self) -> str:
        """What npm rebuild matches by exact path (npm 10 and 11): ./node_modules/a."""
        return f"./{self.path}"


_INSTALL_PATH = re.compile(
    r"node_modules/(?:@[^/]+/)?[^/@][^/]*(?:/node_modules/(?:@[^/]+/)?[^/@][^/]*)*"
)


def entries(data: bytes | None) -> dict[str, Scripted]:
    """Every registry-style entry in a lockfile's ``packages``, by path, with
    the fields that make two installs the same (name, version, resolved,
    integrity). Only entries with an integrity count."""
    if data is None:
        return {}
    try:
        doc = _load(data, "lockfile")
    except NpmError:
        return {}
    packages = doc.get("packages")
    if not isinstance(packages, dict):
        return {}
    out = {}
    for key, entry in packages.items():
        if not isinstance(key, str) or not _INSTALL_PATH.fullmatch(key):
            continue
        if not isinstance(entry, dict) or entry.get("link") is True:
            continue
        folders = key.split("node_modules/")[1:]
        if not all(valid_name(f.rstrip("/")) for f in folders):
            continue
        folder = folders[-1]
        fields = (entry.get("name", folder), entry.get("version"), entry.get("resolved", ""))
        integrity = entry.get("integrity")
        if all(isinstance(f, str) for f in fields) and isinstance(integrity, str) and integrity:
            name, version, resolved = fields
            out[key] = Scripted(key, name, version, resolved, integrity)  # type: ignore[arg-type]
    return out


def scripted(data: bytes) -> list[Scripted]:
    """Every package in a lockfile that has install scripts, by path."""
    try:
        doc = _load(data, "lockfile")
    except NpmError:
        return []
    packages = doc.get("packages")
    found = entries(data)
    if not isinstance(packages, dict):
        return []
    return [
        found[key]
        for key in sorted(found)
        if isinstance(packages.get(key), dict) and packages[key].get("hasInstallScript") is True
    ]


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
