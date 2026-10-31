"""pip: what an install command asks for, and whether pip can resolve it
without building anything.

``pip install --dry-run --report`` still runs a package's build backend to
learn an sdist's metadata. ``--only-binary :all:`` stops that, but only when
it comes after the user's own options, and only when nothing pip reads later
turns building back on: a requirements or constraints file with
``--no-binary`` or ``--only-binary :none:``, or a file named by pip's
configuration or environment (checked by experiment, pip 26.2.2). So every
``-r`` and ``-c`` file is read here first, recursively, and anything that
would build, or that Garnet can't compare, is refused before pip runs.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet

from ..lockfiles.base import PYPI_FILE_HOST, normalize
from ..lockfiles.requirements import logical_lines

MAX_REQUIREMENTS_BYTES = 1024 * 1024
MAX_REQUIREMENTS_DEPTH = 20
MAX_REPORT_BYTES = 64 * 1024 * 1024

# pip install's options (pip 26.2.2), and whether each takes a value. pip
# accepts any unique prefix of a long option, so names are matched that way.
_LONG_OPTIONS: dict[str, bool] = {
    "--requirement": True,
    "--constraint": True,
    "--build-constraint": True,
    "--requirements-from-script": True,
    "--editable": True,
    "--target": True,
    "--platform": True,
    "--python-version": True,
    "--implementation": True,
    "--abi": True,
    "--root": True,
    "--prefix": True,
    "--src": True,
    "--upgrade-strategy": True,
    "--config-settings": True,
    "--global-option": True,
    "--progress-bar": True,
    "--root-user-action": True,
    "--report": True,
    "--group": True,
    "--all-releases": True,
    "--only-final": True,
    "--no-binary": True,
    "--only-binary": True,
    "--index-url": True,
    "--extra-index-url": True,
    "--refresh-package": True,
    "--find-links": True,
    "--uploaded-prior-to": True,
    "--python": True,
    "--log": True,
    "--keyring-provider": True,
    "--proxy": True,
    "--retries": True,
    "--timeout": True,
    "--exists-action": True,
    "--trusted-host": True,
    "--cert": True,
    "--client-cert": True,
    "--cache-dir": True,
    "--use-feature": True,
    "--use-deprecated": True,
    "--resume-retries": True,
    "--no-deps": False,
    "--only-deps": False,
    "--dry-run": False,
    "--user": False,
    "--upgrade": False,
    "--force-reinstall": False,
    "--ignore-installed": False,
    "--ignore-requires-python": False,
    "--no-build-isolation": False,
    "--check-build-dependencies": False,
    "--break-system-packages": False,
    "--compile": False,
    "--no-compile": False,
    "--no-warn-script-location": False,
    "--no-warn-conflicts": False,
    "--require-hashes": False,
    "--no-require-hashes": False,
    "--no-clean": False,
    "--pre": False,
    "--prefer-binary": False,
    "--no-index": False,
    "--help": False,
    "--debug": False,
    "--isolated": False,
    "--require-virtualenv": False,
    "--verbose": False,
    "--version": False,
    "--quiet": False,
    "--no-input": False,
    "--no-proxy-env": False,
    "--no-cache-dir": False,
    "--disable-pip-version-check": False,
    "--no-color": False,
}
_SHORT_OPTIONS: dict[str, str] = {
    "-r": "--requirement",
    "-c": "--constraint",
    "-e": "--editable",
    "-t": "--target",
    "-C": "--config-settings",
    "-i": "--index-url",
    "-f": "--find-links",
    "-U": "--upgrade",
    "-I": "--ignore-installed",
    "-h": "--help",
    "-v": "--verbose",
    "-V": "--version",
    "-q": "--quiet",
}
# Options a requirements file may hold (pip's req_file.py). Unique prefixes
# count there too.
_FILE_OPTIONS: dict[str, bool] = {
    k: _LONG_OPTIONS[k]
    for k in (
        "--index-url",
        "--extra-index-url",
        "--no-index",
        "--constraint",
        "--requirement",
        "--editable",
        "--find-links",
        "--no-binary",
        "--only-binary",
        "--prefer-binary",
        "--require-hashes",
        "--pre",
        "--trusted-host",
        "--use-feature",
        "--config-settings",
        "--global-option",
    )
} | {"--hash": True}

# Options that point pip somewhere other than the environment Garnet reads
# the base from, or at requirements Garnet doesn't parse.
_REFUSED: dict[str, str] = {
    "--no-binary": "it lets pip build from source, which runs the package's build code",
    "--editable": "an editable install builds the project, which runs its build code",
    "--target": "it installs into another folder, and Garnet reads what's installed from "
    "the environment",
    "--prefix": "it installs under another prefix, and Garnet reads what's installed from "
    "the environment",
    "--root": "it installs under another root, and Garnet reads what's installed from "
    "the environment",
    "--user": "it installs into the user site, which Garnet doesn't read what's installed from",
    "--platform": "it resolves for another platform than the environment's",
    "--python-version": "it resolves for another Python than the environment's",
    "--implementation": "it resolves for another Python than the environment's",
    "--abi": "it resolves for another Python than the environment's",
    "--group": "it reads requirements from pyproject.toml, which Garnet doesn't read for pip yet",
    "--requirements-from-script": "it reads requirements from a script, which Garnet doesn't "
    "read for pip yet",
}
# pip settings from its environment variables and configuration files that
# Garnet refuses: they add requirement files after the command line, or move
# the install (checked by experiment: PIP_REQUIREMENT, PIP_CONSTRAINT and
# pip.conf ``requirement`` re-enable builds through a file's --no-binary).
_REFUSED_SETTINGS = (
    "requirement",
    "constraint",
    "editable",
    "target",
    "prefix",
    "root",
    "user",
    "python",
    "group",
    "requirements-from-script",
    "platform",
    "python-version",
    "implementation",
    "abi",
)
_FALSE = frozenset({"", "0", "false", "no", "off"})
# pip's ARCHIVE_EXTENSIONS (pip/_internal/utils/filetypes.py, pip 26.2.2).
_ARCHIVE_EXTENSIONS = frozenset(
    {".zip", ".whl", ".tar.bz2", ".tbz", ".tar.xz", ".txz", ".tlz", ".tar.lz", ".tar.lzma"}
    | {".tar.gz", ".tgz", ".tar"}
)
_EXTRAS = re.compile(r"^(.+)(\[[^\]]+\])$")
_VCS = ("git+", "hg+", "svn+", "bzr+")


class PipError(Exception):
    """pip's output couldn't be read. Garnet then reports the install as not checked."""


@dataclass(frozen=True)
class Refusal:
    """Something in the command Garnet won't resolve or can't compare."""

    what: str  # what the user wrote (escape before printing)
    why: str


@dataclass
class Plan:
    """What a ``pip install`` command asks for, read without running pip."""

    args: list[str]  # the user's arguments from "install" on, --python removed
    python: str | None = None  # --python, when given
    requested: dict[str, SpecifierSet] = field(default_factory=dict)
    constraints: dict[str, SpecifierSet] = field(default_factory=dict)
    pre: bool = False
    compare_newest: bool = True  # False when the command limits releases by date or type
    refusals: list[Refusal] = field(default_factory=list)

    @property
    def insert_at(self) -> int:
        """Where Garnet's own options go: at the end, or before a ``--``."""
        return self.args.index("--") if "--" in self.args else len(self.args)


def _long(name: str, table: Mapping[str, bool]) -> str | None:
    """The option ``name`` stands for: itself, or the one long option it's a prefix of."""
    if name in table:
        return name
    hits = [k for k in table if k.startswith(name)]
    return hits[0] if len(hits) == 1 else None


def _options(args: Sequence[str]) -> list[tuple[str | None, str | None, int]]:
    """Split pip arguments into (option, value, index) and (None, positional, index)."""
    out: list[tuple[str | None, str | None, int]] = []
    j = 0
    while j < len(args):
        a = args[j]
        if a == "--":
            out.extend((None, p, j + 1 + k) for k, p in enumerate(args[j + 1 :]))
            break
        if a.startswith("--"):
            name, eq, value = a.partition("=")
            opt = _long(name, _LONG_OPTIONS) or name
            if _LONG_OPTIONS.get(opt) and not eq:
                value = args[j + 1] if j + 1 < len(args) else ""
                j += 1
            out.append((opt, value if (eq or _LONG_OPTIONS.get(opt)) else None, j))
        elif a.startswith("-") and len(a) > 1:
            k = 1
            while k < len(a):
                opt = _SHORT_OPTIONS.get("-" + a[k], "-" + a[k])
                if _LONG_OPTIONS.get(opt):
                    value = a[k + 1 :]
                    if not value:
                        value = args[j + 1] if j + 1 < len(args) else ""
                        j += 1
                    out.append((opt, value.removeprefix("="), j))
                    break
                out.append((opt, None, j))
                k += 1
        else:
            out.append((None, a, j))
        j += 1
    return out


def _is_archive(name: str) -> bool:
    """pip's is_archive_file: the extension, with ``.tar`` kept in front of the last one."""
    base, ext = posixpath.splitext(name)
    if base.lower().endswith(".tar"):
        ext = base[-4:] + ext
    return ext.lower() in _ARCHIVE_EXTENSIONS


def spec_refusal(spec: str) -> str | None:
    """Why a requirement Garnet can't resolve without building, or compare, is refused.

    pip (constructors.parse_req_from_line) takes ``;`` markers and then
    ``[extras]`` off before it asks whether what is left is an archive file,
    so ``x.tar.gz[a]`` and ``x.tar.lzma; python_version>"3"`` are local files
    to pip, built during its dry run. They are read the same way here.
    """
    if spec.startswith(_VCS) or "://" in spec:
        return "it installs from a URL or a version control system, not from PyPI"
    name = spec.split(";", 1)[0].strip()
    if m := _EXTRAS.match(name):
        name = m[1].rstrip()
    local = "/" in spec or "\\" in spec or name.startswith((".", "~"))
    if local or _is_archive(name) or _is_archive(spec.strip()):
        return "it installs a local file or folder, not a release from PyPI"
    try:
        req = Requirement(spec)
    except InvalidRequirement:
        return "Garnet can't read it as a requirement"
    if req.url:
        return "it installs from a URL, not from PyPI"
    return None


def plan(args: Sequence[str], *, cwd: Path, env: Mapping[str, str]) -> Plan:
    """Read a ``pip install`` command's arguments and every file they name.

    ``args`` starts at the subcommand (``install …``); pip's general options
    may come before it.
    """
    out = Plan(list(args))
    seen: set[str] = set()
    python_at: list[int] = []
    for opt, value, at in _options(args):
        if opt is None:
            if value == "install" and not out.requested and "install" not in seen:
                seen.add("install")
                continue
            _requirement(value or "", value or "", out, out.requested)
            continue
        if opt == "--python":
            out.python = value
            python_at.append(at)
        elif opt in _REFUSED:
            shown = f"{opt} {value}" if value else opt
            out.refusals.append(Refusal(shown, _REFUSED[opt]))
        elif opt in ("--requirement", "--constraint"):
            target = out.requested if opt == "--requirement" else out.constraints
            _read_file(value or "", cwd, out, target, 0, seen)
        elif opt == "--pre" or (opt == "--all-releases" and value):
            out.pre = True
        elif opt in ("--uploaded-prior-to", "--only-final"):
            out.compare_newest = False
    for at in sorted(python_at, reverse=True):  # Garnet chooses the interpreter itself
        word = out.args[at]
        del out.args[at]
        if not word.startswith("--python=") and at - 1 >= 0:
            del out.args[at - 1]
    out.refusals.extend(env_refusals(env))
    return out


def _requirement(spec: str, shown: str, out: Plan, target: dict[str, SpecifierSet]) -> None:
    why = spec_refusal(spec)
    if why:
        out.refusals.append(Refusal(shown, why))
        return
    req = Requirement(spec)
    name = normalize(req.name)
    target[name] = target.get(name, SpecifierSet()) & req.specifier


def read_requirements_file(
    name: str, base: Path, out: Plan, target: dict[str, SpecifierSet]
) -> None:
    """Read one requirements or constraints file into ``out``, and the files it names."""
    _read_file(name, base, out, target, 0, set())


def _read_file(
    name: str,
    base: Path,
    out: Plan,
    target: dict[str, SpecifierSet],
    depth: int,
    seen: set[str],
) -> None:
    """Read one requirements or constraints file, and the files it names."""
    if "://" in name:
        out.refusals.append(
            Refusal(name, "it's a requirements file at a URL, which Garnet doesn't fetch")
        )
        return
    path = (base / os.path.expanduser(name)) if not os.path.isabs(name) else Path(name)
    if depth > MAX_REQUIREMENTS_DEPTH:
        out.refusals.append(Refusal(name, "requirements files nest too deep"))
        return
    try:
        real = str(path.resolve())
        if real in seen:
            return
        seen.add(real)
        with open(path, "rb") as fh:
            data = fh.read(MAX_REQUIREMENTS_BYTES + 1)
    except OSError as err:
        out.refusals.append(Refusal(name, f"Garnet can't read it ({err.strerror or 'error'})"))
        return
    if len(data) > MAX_REQUIREMENTS_BYTES:
        out.refusals.append(Refusal(name, "it's larger than 1 MB"))
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        out.refusals.append(Refusal(name, "it isn't UTF-8"))
        return
    here = path.parent
    for line_no, line in logical_lines(text):
        where = f"{name} line {line_no}"
        if "${" in line:
            out.refusals.append(
                Refusal(
                    where, "it uses an environment variable, which pip expands and Garnet doesn't"
                )
            )
            continue
        _file_line(line, where, here, out, target, depth, seen)


def _file_line(
    line: str,
    where: str,
    here: Path,
    out: Plan,
    target: dict[str, SpecifierSet],
    depth: int,
    seen: set[str],
) -> None:
    try:
        words = shlex.split(line)
    except ValueError:
        out.refusals.append(Refusal(where, "Garnet can't split it into words"))
        return
    if not words:
        return
    first = 0
    if not words[0].startswith("-"):
        # A requirement, then its own options from the first word that starts with "-".
        first = next((k for k, w in enumerate(words) if w.startswith("-")), len(words))
        spec = " ".join(words[:first])
        _requirement(spec, f"{where}: {spec}", out, target)
    j = first
    while j < len(words):
        w = words[j]
        name, eq, value = w.partition("=")
        if name.startswith("--"):
            opt = _long(name, _FILE_OPTIONS)
        else:
            opt = _SHORT_OPTIONS.get(name[:2]) if name.startswith("-") else None
            if opt and len(name) > 2:
                value, eq = name[2:], "="
        if opt is None:
            out.refusals.append(Refusal(f"{where}: {w}", "Garnet doesn't know this option"))
            return
        if _FILE_OPTIONS.get(opt) and not eq:
            value = words[j + 1] if j + 1 < len(words) else ""
            j += 1
        j += 1
        if opt == "--no-binary" or (opt == "--only-binary" and value != ":all:"):
            out.refusals.append(
                Refusal(
                    f"{where}: {opt} {value}",
                    "it lets pip build from source, which runs the package's build code",
                )
            )
        elif opt == "--editable":
            out.refusals.append(Refusal(f"{where}: -e {value}", _REFUSED["--editable"]))
        elif opt in ("--requirement", "--constraint"):
            into = target if opt == "--requirement" else out.constraints
            _read_file(value, here, out, into, depth + 1, seen)
        elif opt == "--pre":
            out.pre = True


def env_refusals(env: Mapping[str, str]) -> list[Refusal]:
    """pip settings in the environment that Garnet refuses (see ``_REFUSED_SETTINGS``)."""
    out = []
    for key in _REFUSED_SETTINGS:
        var = "PIP_" + key.upper().replace("-", "_")
        value = env.get(var)
        if value is None or (key == "user" and value.strip().lower() in _FALSE):
            continue
        out.append(Refusal(var, _setting_why(key)))
    return out


def config_refusals(config_list: str) -> list[Refusal]:
    """The same, from ``pip config list`` (``section.key='value'`` lines).

    Values are never repeated: pip's configuration can hold index URLs with
    credentials.
    """
    out = []
    for line in config_list.splitlines():
        key, eq, value = line.partition("=")
        if not eq or "." not in key:
            continue
        name = key.split(".", 1)[1].strip().replace("_", "-")
        if name not in _REFUSED_SETTINGS:
            continue
        if name == "user" and value.strip().strip("'\"").lower() in _FALSE:
            continue
        out.append(Refusal(f"pip configuration {key.strip()}", _setting_why(name)))
    return out


def _setting_why(key: str) -> str:
    if key in ("requirement", "constraint"):
        return "it adds a file pip reads after the command line, which Garnet doesn't read"
    if key == "editable":
        return _REFUSED["--editable"]
    return _REFUSED.get("--" + key, "Garnet can't tell what it changes")


# --- What pip printed -------------------------------------------------------


@dataclass(frozen=True)
class Resolved:
    """One distribution pip's report says it would install."""

    name: str
    version: str
    sha256: str | None
    from_pypi: bool
    wheel: bool
    requested: bool


def _load(data: bytes, what: str) -> dict[str, Any]:
    if len(data) > MAX_REPORT_BYTES:
        raise PipError(f"pip's {what} is larger than {MAX_REPORT_BYTES} bytes")
    try:
        doc = json.loads(data)
    except ValueError as err:
        raise PipError(f"pip's {what} isn't JSON") from err
    if not isinstance(doc, dict) or doc.get("version") != "1":
        raise PipError(f"pip's {what} isn't format version 1")
    return doc


def parse_report(data: bytes) -> list[Resolved]:
    """The ``install`` list of ``pip install --dry-run --report``."""
    doc = _load(data, "installation report")
    items = doc.get("install")
    if not isinstance(items, list):
        raise PipError("pip's installation report has no install list")
    out = []
    for item in items:
        meta = item.get("metadata") if isinstance(item, dict) else None
        info = item.get("download_info") if isinstance(item, dict) else None
        if not isinstance(meta, dict) or not isinstance(info, dict):
            raise PipError("pip's installation report has an entry without metadata")
        name, version, url = meta.get("name"), meta.get("version"), info.get("url")
        if not (isinstance(name, str) and isinstance(version, str) and isinstance(url, str)):
            raise PipError("pip's installation report has an entry without a name or version")
        archive = info.get("archive_info")
        hashes = archive.get("hashes") if isinstance(archive, dict) else None
        sha = hashes.get("sha256") if isinstance(hashes, dict) else None
        out.append(
            Resolved(
                normalize(name),
                version,
                sha if isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha) else None,
                url.startswith(PYPI_FILE_HOST),
                url.split("?", 1)[0].split("#", 1)[0].endswith(".whl"),
                item.get("requested") is True,
            )
        )
    return out


@dataclass(frozen=True)
class Installed:
    """What ``pip inspect`` says the environment has."""

    pins: dict[str, str]  # name -> version, for distributions installed from an index
    other: frozenset[str]  # names installed from a URL, a path or in editable mode
    python_version: str | None


def parse_inspect(data: bytes) -> Installed:
    """``pip inspect``: installed distributions, as name==version pins."""
    doc = _load(data, "inspect report")
    items = doc.get("installed")
    if not isinstance(items, list):
        raise PipError("pip inspect listed no installed distributions")
    pins: dict[str, str] = {}
    other: set[str] = set()
    for item in items:
        meta = item.get("metadata") if isinstance(item, dict) else None
        if not isinstance(meta, dict):
            continue
        name, version = meta.get("name"), meta.get("version")
        if not (isinstance(name, str) and isinstance(version, str)):
            continue
        if item.get("direct_url") is not None:
            other.add(normalize(name))
        else:
            pins[normalize(name)] = version
    env = doc.get("environment")
    python = env.get("python_full_version") if isinstance(env, dict) else None
    return Installed(pins, frozenset(other), python if isinstance(python, str) else None)


_NO_VERSION = re.compile(
    r"Could not find a version that satisfies the requirement (\S+)"
    r"(?: \(from ([^)]*)\))?(?: \(from versions: ([^)]*)\))?"
)


@dataclass(frozen=True)
class Unresolvable:
    """A requirement pip found no usable distribution for, with builds off."""

    requirement: str  # as pip printed it, e.g. "docopt>=0.6.2"
    wanted_by: str | None  # "num2words", when pip said who needs it
    versions: str  # pip's "from versions:" list; "none" when nothing matched


def unresolvable(stderr: str) -> list[Unresolvable]:
    """The requirements pip's error output says it couldn't satisfy."""
    out = []
    for m in _NO_VERSION.finditer(stderr):
        out.append(Unresolvable(m[1], m[2] or None, (m[3] or "none").strip()))
    return out


def pins_text(pins: Mapping[str, tuple[str, str | None]]) -> str:
    """A constraints file pinning each distribution, with its hash when known."""
    lines = []
    for name in sorted(pins):
        version, sha = pins[name]
        lines.append(f"{name}=={version}" + (f" --hash=sha256:{sha}" if sha else ""))
    return "\n".join(lines) + "\n"
