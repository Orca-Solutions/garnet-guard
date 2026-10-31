"""uv: what a ``uv add|remove|lock|sync`` command asks for, and how to resolve
it with builds off in a private copy of the project.

``uv lock`` builds a source distribution whose metadata is dynamic, so the
resolve step always passes ``--no-build`` and sets ``UV_NO_BUILD=1``. Neither
``no-build = false`` in ``[tool.uv]`` or ``uv.toml`` turns builds back on
over the flag; a later ``--build`` does, so it is refused (checked by
experiment, uv 0.11.32). uv may still build editable requirements, so path,
editable and workspace sources are refused too.

The copy holds ``pyproject.toml``, ``uv.lock``, ``uv.toml`` and
``.python-version`` and nothing else: never ``.venv``. It lives in a folder
only this user can read (``tempfile.mkdtemp``, mode 0700).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from ..lockfiles.base import normalize
from . import pip
from .pip import Refusal, spec_refusal
from .runner import loader_env

COPIED = ("pyproject.toml", "uv.lock", "uv.toml", ".python-version")
MAX_PROJECT_FILE_BYTES = 16 * 1024 * 1024

# uv's options for add, remove, lock and sync (uv 0.11.32), by what Garnet
# does with them. uv's parser (clap) takes ``--name value`` and
# ``--name=value``, and no abbreviations.
_SHORT = {
    "-r": "--requirements",
    "-c": "--constraints",
    "-m": "--marker",
    "-C": "--config-setting",
    "-i": "--index-url",
    "-f": "--find-links",
    "-U": "--upgrade",
    "-P": "--upgrade-package",
    "-p": "--python",
    "-q": "--quiet",
    "-v": "--verbose",
    "-n": "--no-cache",
    "-h": "--help",
    "-V": "--version",
}
# Options that take a value.
_VALUE = frozenset(
    {
        "--requirements", "--constraints", "--marker", "--optional", "--group", "--bounds",
        "--extra", "--no-extra", "--no-group", "--only-group", "--upgrade-package",
        "--upgrade-group", "--reinstall-package", "--no-install-package", "--no-editable-package",
        "--index", "--default-index", "--index-url", "--extra-index-url", "--find-links",
        "--index-strategy", "--keyring-provider", "--resolution", "--prerelease",
        "--fork-strategy", "--exclude-newer", "--exclude-newer-package", "--config-setting",
        "--config-settings-package", "--no-build-isolation-package", "--no-build-package",
        "--no-sources-package", "--link-mode", "--refresh-package", "--python", "--cache-dir",
        "--color", "--config-file", "--directory", "--project", "--allow-insecure-host",
        "--python-preference", "--python-platform", "--output-format", "--preview-features",
        "--no-binary-package", "--rev", "--tag", "--branch", "--package", "--script",
    }
)  # fmt: skip
# Global options: kept as given in the hand-off. --directory and --project
# are replaced by the copy in the resolve step.
_GLOBAL = frozenset(
    {
        "--cache-dir", "--color", "--config-file", "--directory", "--project",
        "--allow-insecure-host", "--python-preference", "--quiet", "--verbose", "--no-cache",
        "--no-config", "--offline", "--native-tls", "--system-certs", "--managed-python",
        "--no-managed-python", "--no-python-downloads", "--allow-python-downloads",
        "--no-progress", "--preview", "--no-preview", "--preview-features", "--python",
    }
)  # fmt: skip
# Index and resolver settings both uv lock and ``uv sync --frozen`` accept.
_INDEX = frozenset(
    {
        "--index", "--default-index", "--index-url", "--extra-index-url", "--find-links",
        "--no-index", "--index-strategy", "--keyring-provider", "--resolution", "--prerelease",
        "--fork-strategy", "--exclude-newer", "--exclude-newer-package", "--no-build-isolation",
        "--no-build-isolation-package", "--no-build", "--no-build-package", "--config-setting",
        "--config-settings-package", "--link-mode", "--refresh", "--refresh-package",
    }
)  # fmt: skip
# uv lock options ``uv sync --frozen`` rejects.
_LOCK_ONLY = frozenset(
    {"--upgrade", "--upgrade-package", "--upgrade-group", "--no-sources", "--no-sources-package"}
)
# Install settings: only the sync (and the hand-off) reads them.
_INSTALL = frozenset(
    {
        "--extra", "--all-extras", "--no-extra", "--dev", "--no-dev", "--only-dev", "--group",
        "--no-group", "--only-group", "--all-groups", "--no-default-groups", "--no-editable",
        "--no-editable-package", "--inexact", "--exact", "--active", "--no-active",
        "--compile-bytecode", "--reinstall", "--reinstall-package", "--no-install-project",
        "--no-install-workspace", "--no-install-local", "--no-install-package",
        "--output-format", "--python-platform", "--dry-run", "--check",
    }
)  # fmt: skip
# Options of uv add that the hand-off carries over (the rest describe the edit).
_ADD_INSTALL = frozenset(
    {
        "--active", "--compile-bytecode", "--reinstall", "--reinstall-package",
        "--no-install-project", "--no-install-workspace", "--no-install-local",
        "--no-install-package",
    }
)  # fmt: skip
_ADD_EDIT = frozenset(
    {"--requirements", "--constraints", "--marker", "--optional", "--raw", "--bounds", "--dev"}
)
_LOCK_MODES = frozenset({"--locked", "--frozen", "--check", "--check-exists", "--dry-run"})
_PATH_VALUES = frozenset(
    {"--requirements", "--constraints", "--find-links", "--config-file", "--cache-dir"}
)
_BUILDS = "it lets uv build from source, which runs the package's build code"
_REFUSED = {
    "--build": _BUILDS,
    "--no-binary": _BUILDS,
    "--no-binary-package": _BUILDS,
    "--editable": "an editable dependency is built, which runs its build code",
    "--rev": "it adds a dependency from git, which uv builds from source",
    "--tag": "it adds a dependency from git, which uv builds from source",
    "--branch": "it adds a dependency from git, which uv builds from source",
    "--lfs": "it adds a dependency from git, which uv builds from source",
    "--script": "it changes a script's inline metadata, which Garnet Guard doesn't read yet",
    "--package": "it changes one member of a workspace, and Garnet Guard reads single "
    "projects only",
    "--all-packages": "it syncs a whole workspace, and Garnet Guard reads single projects only",
    "--workspace": "it adds a workspace member, and Garnet Guard reads single projects only",
    "--no-project": "it runs without a project, and Garnet Guard reads the project's uv.lock",
    "--isolated": "it ignores the project's settings, which Garnet Guard reads",
}
# uv settings in the environment: the resolve step drops these and applies
# them as flags itself, so the copy, not the user's folder, is what uv reads.
_ENV_FLAGS = {"UV_FROZEN": "--frozen", "UV_LOCKED": "--locked", "UV_NO_SYNC": "--no-sync"}
_ENV_DROPPED = ("UV_PROJECT", "UV_WORKING_DIR", "UV_WORKING_DIRECTORY", *_ENV_FLAGS)
TRUE = frozenset({"1", "true", "yes", "on", "y", "t"})


class UvError(Exception):
    """The project's files couldn't be read or written."""


@dataclass
class Plan:
    """What a ``uv add|remove|lock|sync`` command asks for, read without running uv."""

    subcommand: str
    args: list[str]  # every argument after the subcommand, as given
    resolve: list[str] = field(default_factory=list)  # for the resolve step, in the copy
    index_args: list[str] = field(default_factory=list)  # global and index options, for probes
    lock_args: list[str] = field(default_factory=list)  # sync: what ``uv lock`` accepts
    handoff: list[str] = field(default_factory=list)  # for ``uv sync --frozen`` after the check
    start: Path = Path(".")  # where uv looks for the project
    requested: dict[str, SpecifierSet] = field(default_factory=dict)
    no_sync: bool = False
    frozen: bool = False
    locked: bool = False
    check_only: bool = False  # uv lock --check, --check-exists or --dry-run
    upgrade: bool = False  # sync with --upgrade or --upgrade-package: re-lock
    pre: bool = False
    compare_newest: bool = True
    refusals: list[Refusal] = field(default_factory=list)


def _words(args: Sequence[str]) -> list[tuple[str | None, str | None, list[str]]]:
    """Split uv arguments into (option, value, words as given) and (None, positional, …)."""
    out: list[tuple[str | None, str | None, list[str]]] = []
    j = 0
    while j < len(args):
        a = args[j]
        if a == "--":
            out.extend((None, p, [p]) for p in args[j + 1 :])
            break
        if a.startswith("--"):
            name, eq, value = a.partition("=")
            if name in _VALUE and not eq:
                value = args[j + 1] if j + 1 < len(args) else ""
                out.append((name, value, list(args[j : j + 2])))
                j += 2
                continue
            out.append((name, value if eq else None, [a]))
        elif a.startswith("-") and len(a) > 1:
            name = _SHORT.get(a[:2], a[:2])
            rest = a[2:]
            if name in _VALUE:
                if rest:
                    out.append((name, rest.removeprefix("="), [a]))
                else:
                    value = args[j + 1] if j + 1 < len(args) else ""
                    out.append((name, value, list(args[j : j + 2])))
                    j += 1
            elif rest and all(_SHORT.get("-" + ch, "?") not in _VALUE for ch in rest):
                # A cluster such as -qU. One with an option that takes a value is
                # left whole, so it is refused as unknown.
                if all(("-" + ch) in _SHORT for ch in rest):
                    out.append((name, None, [a[:2]]))
                    out.extend((_SHORT["-" + ch], None, ["-" + ch]) for ch in rest)
                else:
                    out.append((a, None, [a]))
            else:
                out.append((name if not rest else a, None, [a]))
        else:
            out.append((None, a, [a]))
        j += 1
    return out


def _known(opt: str) -> bool:
    return (
        opt in _GLOBAL
        or opt in _INDEX
        or opt in _LOCK_ONLY
        or opt in _INSTALL
        or opt in _ADD_EDIT
        or opt in _LOCK_MODES
        or opt in _REFUSED
        or opt in ("--no-sync", "--no-workspace", "--help", "--version")
    )


def plan(subcommand: str, args: Sequence[str], *, cwd: Path, env: Mapping[str, str]) -> Plan:
    """Read a uv command's arguments. ``args`` are the ones after the subcommand."""
    out = Plan(subcommand, list(args), start=cwd)
    words = _words(args)
    directory: Path | None = None
    project: Path | None = None
    for var, flag in _ENV_FLAGS.items():
        if env.get(var, "").strip().lower() in TRUE:
            _mode(flag, out)
    working = env.get("UV_WORKING_DIR") or env.get("UV_WORKING_DIRECTORY")
    if working:
        directory = cwd / working
    for opt, value, _given in words:  # uv changes to --directory before it reads anything
        if opt == "--directory" and value:
            directory = cwd / value
    if env.get("UV_PROJECT"):
        project = (directory or cwd) / env["UV_PROJECT"]
    for opt, value, given in words:
        if opt is None:
            out.resolve.append(value or "")
            if subcommand == "add":
                _requested(value or "", out)
            elif subcommand in ("lock", "sync"):
                out.refusals.append(Refusal(value or "", "uv doesn't take packages here"))
            continue
        value = value or ""
        if opt in _REFUSED:
            out.refusals.append(Refusal(" ".join(given), _REFUSED[opt]))
            continue
        if not _known(opt):
            out.refusals.append(Refusal(" ".join(given), "Garnet Guard doesn't know this option"))
            continue
        if opt in ("--help", "--version") or (
            opt == "--frozen" and subcommand in ("add", "remove")
        ):
            why = (
                "it adds or removes the dependency without locking, so Garnet Guard can't see "
                "what it would install"
                if opt == "--frozen"
                else "it prints uv's help or version"
            )
            out.refusals.append(Refusal(opt, why))
            continue
        if opt == "--project":
            project = (directory or cwd) / value
        if opt in _LOCK_MODES or opt == "--no-sync":
            _mode(opt, out)
        if opt in ("--upgrade", "--upgrade-package", "--upgrade-group"):
            out.upgrade = True
            if opt == "--upgrade-package":
                _requested(value, out)
        if opt == "--prerelease" and value in ("allow", "if-necessary"):
            out.pre = True
        if opt in ("--exclude-newer", "--exclude-newer-package") or (
            opt == "--resolution" and value != "highest"
        ):
            out.compare_newest = False
        here = directory or cwd
        word = [opt, str(here / value)] if opt in _PATH_VALUES and value else list(given)
        if opt in ("--requirements", "--constraints") and value:
            _read_requirements(opt, value, here, out)
        if opt in ("--directory", "--project", "--allow-python-downloads"):
            pass  # the copy replaces the folder; the resolve step never downloads a Python
        elif opt in _LOCK_MODES or opt == "--no-sync":
            # The resolve step adds its own --no-sync; a sync's --locked and
            # --frozen decide whether it re-locks at all.
            if subcommand == "lock" or (opt == "--locked" and subcommand != "sync"):
                out.resolve.extend(given)
        else:
            out.resolve.extend(word)
        if opt not in ("--directory", "--project", "--allow-python-downloads"):
            if opt in _GLOBAL or opt in _INDEX:
                out.index_args.extend(word)
            if subcommand == "sync" and (opt in _GLOBAL or opt in _INDEX or opt in _LOCK_ONLY):
                out.lock_args.extend(word)
        _handoff(subcommand, opt, value, given, out)
    out.start = project or directory or cwd
    return out


def _mode(flag: str, out: Plan) -> None:
    if flag == "--frozen":
        out.frozen = True
    elif flag == "--locked":
        out.locked = True
    elif flag == "--no-sync":
        out.no_sync = True
    elif flag in ("--check", "--check-exists", "--dry-run") and out.subcommand == "lock":
        out.check_only = True


# File names uv reads as something other than a requirements.txt file.
_NOT_REQUIREMENTS_TXT = (".toml", ".py", ".cfg", ".yml", ".yaml")


def _read_requirements(opt: str, value: str, here: Path, out: Plan) -> None:
    """Read a ``-r`` or ``-c`` file as pip's plan does, so that a path, URL,
    VCS or editable line in it is refused before uv runs, as on the command line."""
    shown = f"{opt} {value}"
    if os.path.basename(value).lower().endswith(_NOT_REQUIREMENTS_TXT):
        why = "uv reads it as project metadata or a script, which Garnet Guard doesn't read yet"
        out.refusals.append(Refusal(shown, why))
        return
    read = pip.Plan([])
    target = read.requested if opt == "--requirements" else read.constraints
    pip.read_requirements_file(value, here, read, target)
    out.refusals.extend(read.refusals)
    if opt == "--requirements" and out.subcommand == "add":
        for name, spec in read.requested.items():
            out.requested[name] = out.requested.get(name, SpecifierSet()) & spec
    out.pre = out.pre or read.pre


def _requested(spec: str, out: Plan) -> None:
    why = spec_refusal(spec)
    if why:
        out.refusals.append(Refusal(spec, why))
        return
    req = Requirement(spec)
    name = normalize(req.name)
    out.requested[name] = out.requested.get(name, SpecifierSet()) & req.specifier


def _handoff(subcommand: str, opt: str, value: str, given: list[str], out: Plan) -> None:
    """The options ``uv sync --frozen`` gets after the check."""
    if opt in _GLOBAL or opt in _INDEX:
        out.handoff.extend(given)
    elif subcommand == "sync":
        if opt in _INSTALL:
            out.handoff.extend(given)
    elif subcommand == "add":
        if opt in _ADD_INSTALL:
            out.handoff.extend(given)
        elif opt == "--optional":
            out.handoff.extend(["--extra", value])
        elif opt == "--group":
            out.handoff.extend(["--group", value])
    elif subcommand == "remove" and opt in _ADD_INSTALL:
        out.handoff.extend(given)


def interpreters(args: Sequence[str], env: Mapping[str, str], cwd: Path) -> list[str]:
    """The interpreters a uv command names as paths or program names: ``-p`` and
    ``--python``, ``UV_PYTHON`` and the project's ``.python-version``. uv starts
    the one it picks to query it, so the hook looks at each before uv runs."""
    words = [(value, cwd) for opt, value, _ in _words(args) if opt == "--python" and value]
    if env.get("UV_PYTHON"):
        words.append((env["UV_PYTHON"], cwd))
    project = find_project(plan("lock", args, cwd=cwd, env=env).start)
    pinned = project / ".python-version" if project else None
    if project and pinned and pinned.is_file() and not pinned.is_symlink():
        try:
            text = pinned.read_text("utf-8", errors="replace")[:4096]
        except OSError:
            text = ""
        for line in text.splitlines():
            if line.strip() and not line.strip().startswith("#"):
                words.append((line.strip(), project))
    out = []
    for word, base in words:
        if os.sep in word or (os.altsep and os.altsep in word) or word.startswith((".", "~")):
            out.append(os.path.normpath(base / os.path.expanduser(word)))
        elif found := shutil.which(word, path=env.get("PATH", "")):
            out.append(found)
    return out


def resolve_env(env: Mapping[str, str]) -> dict[str, str]:
    """The environment for the resolve step: builds off, the user's folder
    settings dropped (the plan carries them as flags), and no loader preload
    from the command (runner.loader_env)."""
    out = {k: v for k, v in loader_env(env).items() if k not in _ENV_DROPPED}
    out["UV_NO_BUILD"] = "1"
    out.pop("UV_NO_BUILD_ISOLATION", None)
    # A project's [tool.uv] can name where Python downloads come from
    # (python-downloads-json-url, python-install-mirror); uv runs what it
    # downloads to query it. The resolve step never downloads a Python.
    out["UV_PYTHON_DOWNLOADS"] = "never"
    return out


# Passed on every resolve and probe call, with UV_PYTHON_DOWNLOADS=never.
NO_PYTHON_DOWNLOADS = "--no-python-downloads"


# --- The project ------------------------------------------------------------


def find_project(start: Path) -> Path | None:
    """The folder uv would treat as the project: the nearest with a pyproject.toml."""
    here = start.resolve()
    for folder in (here, *here.parents):
        if (folder / "pyproject.toml").is_file():
            return folder
    return None


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_PROJECT_FILE_BYTES + 1)
    except OSError as err:
        raise UvError(f"can't read {path.name}: {err.strerror or 'error'}") from err
    if len(data) > MAX_PROJECT_FILE_BYTES:
        raise UvError(f"{path.name} is larger than {MAX_PROJECT_FILE_BYTES} bytes")
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as err:
        raise UvError(f"can't read {path.name}: {err}") from err


def project_refusals(project: Path) -> list[Refusal]:
    """What in the project Garnet Guard won't resolve: workspaces, local and
    editable sources, and metadata only a build can produce."""
    doc = _read_toml(project / "pyproject.toml")
    out: list[Refusal] = []
    tool = doc.get("tool")
    uv = tool.get("uv") if isinstance(tool, dict) else None
    uv = uv if isinstance(uv, dict) else {}
    if "workspace" in uv:
        out.append(
            Refusal("[tool.uv.workspace]", "Garnet Guard reads single projects, not workspaces")
        )
    for parent in project.parents:
        candidate = parent / "pyproject.toml"
        if candidate.is_file():
            try:
                outer = _read_toml(candidate)
            except UvError:
                continue
            outer_tool = outer.get("tool")
            outer_uv = outer_tool.get("uv") if isinstance(outer_tool, dict) else None
            if isinstance(outer_uv, dict) and "workspace" in outer_uv:
                out.append(
                    Refusal(
                        str(candidate),
                        "this project may be a member of that workspace, and Garnet Guard reads "
                        "single projects only",
                    )
                )
                break
    sources = uv.get("sources")
    if isinstance(sources, dict):
        for name in sorted(sources):
            entries = sources[name] if isinstance(sources[name], list) else [sources[name]]
            for entry in entries:
                kind = next(
                    (
                        k
                        for k in ("path", "git", "url", "workspace")
                        if isinstance(entry, dict) and k in entry
                    ),
                    None,
                )
                if kind or (isinstance(entry, dict) and entry.get("editable")):
                    out.append(
                        Refusal(
                            f"[tool.uv.sources] {name}",
                            f"it comes from a {kind or 'editable'} source, which uv builds "
                            "and Garnet Guard can't compare with a release",
                        )
                    )
    meta = doc.get("project")
    out.extend(_direct_references(doc, uv))
    dynamic = meta.get("dynamic") if isinstance(meta, dict) else None
    packaged = uv.get("package", "build-system" in doc) is not False
    if isinstance(dynamic, list) and dynamic and packaged:
        fields = ", ".join(sorted(str(d) for d in dynamic))
        out.append(
            Refusal(
                f"[project] dynamic = {fields}",
                "uv would have to run the project's build backend to read it",
            )
        )
    return out


def _direct_references(doc: Mapping[str, Any], uv: Mapping[str, Any]) -> list[Refusal]:
    """Requirements in the project's dependency tables that name a URL, a path
    or git (``name @ git+…``) instead of a release."""
    tables: list[tuple[str, object]] = []
    meta = doc.get("project")
    if isinstance(meta, dict):
        tables.append(("[project] dependencies", meta.get("dependencies")))
        optional = meta.get("optional-dependencies")
        if isinstance(optional, dict):
            for extra in sorted(optional):
                tables.append((f"[project.optional-dependencies] {extra}", optional[extra]))
    groups = doc.get("dependency-groups")
    if isinstance(groups, dict):
        for group in sorted(groups):
            tables.append((f"[dependency-groups] {group}", groups[group]))
    for key in ("dev-dependencies", "constraint-dependencies", "override-dependencies"):
        tables.append((f"[tool.uv] {key}", uv.get(key)))
    out = []
    for where, entries in tables:
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, str):
                continue  # an include-group table
            why = spec_refusal(entry)
            if why:
                out.append(Refusal(f"{where}: {entry}", why))
    return out


def lock_sources(lock: bytes) -> list[tuple[str, str]]:
    """Packages in uv.lock that don't come from a package index: (name, source kind).

    The project itself (``editable = "."`` or ``virtual = "."``) isn't listed.
    """
    try:
        doc = tomllib.loads(lock.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return [("uv.lock", "unreadable")]
    out = []
    for pkg in doc.get("package", []):
        if not isinstance(pkg, dict):
            continue
        source = pkg.get("source")
        name = str(pkg.get("name", ""))
        if not isinstance(source, dict) or not source:
            out.append((name, "unknown"))
            continue
        kind = next(iter(source))
        if kind == "registry":
            continue
        if kind in ("editable", "virtual") and source.get(kind) == ".":
            continue
        out.append((name, kind))
    return sorted(out)


def requires_python_floor(project: Path) -> Version | None:
    """The lowest Python the project supports, from ``requires-python``."""
    try:
        meta = _read_toml(project / "pyproject.toml").get("project")
        text = meta.get("requires-python") if isinstance(meta, dict) else None
        spec = SpecifierSet(text) if isinstance(text, str) else None
    except (UvError, InvalidSpecifier):
        return None
    if spec is None:
        return None
    floors = []
    for s in spec:
        if s.operator in (">=", "~=", "==", "==="):
            try:
                floors.append(Version(s.version.rstrip(".*")))
            except InvalidVersion:
                continue
        elif s.operator == ">":
            try:
                floors.append(Version(s.version))
            except InvalidVersion:
                continue
    return max(floors) if floors else None


# --- The private copy -------------------------------------------------------


def _digest(data: bytes | None) -> str | None:
    return hashlib.sha256(data).hexdigest() if data is not None else None


@dataclass(frozen=True)
class Copy:
    """The project files copied into ``root``, and what they held then."""

    root: Path
    project: Path
    originals: Mapping[str, bytes | None]

    def head(self, name: str) -> bytes | None:
        path = self.root / name
        return path.read_bytes() if path.is_file() else None


def copy_project(project: Path, into: Path) -> Copy:
    """Copy the project's files into ``into``, an empty folder only this user can read."""
    if any(into.iterdir()):
        raise UvError("the folder for the copy isn't empty")
    originals: dict[str, bytes | None] = {}
    for name in COPIED:
        path = project / name
        if path.is_symlink():
            raise UvError(f"{name} is a symlink; Garnet Guard reads regular files only")
        if not path.exists():
            originals[name] = None
            continue
        if not path.is_file():
            raise UvError(f"{name} isn't a regular file")
        data = path.read_bytes()
        if len(data) > MAX_PROJECT_FILE_BYTES:
            raise UvError(f"{name} is larger than {MAX_PROJECT_FILE_BYTES} bytes")
        originals[name] = data
        target = into / name
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    return Copy(into, project, originals)


class Changed(Exception):
    """A project file changed while Garnet Guard was checking."""


def write_back(copy: Copy, names: Sequence[str]) -> list[str]:
    """Write the checked files from the copy into the project.

    Nothing is written unless every copied file still holds what it held
    when it was copied; then ``Changed`` names the ones that differ.
    Returns the files written.
    """
    changed = []
    for name, before in sorted(copy.originals.items()):
        path = copy.project / name
        now = path.read_bytes() if path.is_file() and not path.is_symlink() else None
        if path.is_symlink() or _digest(now) != _digest(before):
            changed.append(name)
    if changed:
        raise Changed(", ".join(changed))
    written = []
    for name in names:
        new = copy.head(name)
        if new is None or new == copy.originals.get(name):
            continue
        target = copy.project / name
        temp = copy.project / f".{name}.garnet-{os.getpid()}"
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(new)
            if target.exists():
                os.chmod(temp, target.stat().st_mode & 0o7777)
            os.replace(temp, target)
        except BaseException:
            temp.unlink(missing_ok=True)
            raise
        written.append(name)
    return written


def lock_version(lock: bytes | None, name: str) -> str | None:
    """The version uv.lock pins for ``name``, if it lists one."""
    if lock is None:
        return None
    try:
        doc = tomllib.loads(lock.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None
    for pkg in doc.get("package", []):
        if isinstance(pkg, dict) and normalize(str(pkg.get("name", ""))) == name:
            version = pkg.get("version")
            return version if isinstance(version, str) else None
    return None


def requirement_name(spec: str) -> str | None:
    try:
        return normalize(Requirement(spec).name)
    except InvalidRequirement:
        return None


def no_wheel_packages(stderr: str) -> list[str]:
    """The packages uv's error says need a wheel it couldn't find with builds off."""
    out = []
    for line in stderr.splitlines():
        line = line.strip()
        if line.startswith("hint: Wheels are required for `"):
            name = line.split("`", 2)[1]
            if name not in out:
                out.append(name)
    return out
