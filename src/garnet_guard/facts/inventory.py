"""Turn artifact bytes into content facts. Reads bytes only; never executes."""

from __future__ import annotations

import ast
import builtins
import hashlib
import re
import sys
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from email.message import Message
from email.parser import BytesHeaderParser

from packaging.requirements import InvalidRequirement
from packaging.requirements import Requirement as _Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ..models import (
    CallSite,
    EntryPoint,
    FactError,
    FileEntry,
    FileKind,
    Limits,
    ModuleIndex,
    PthFile,
    Requirement,
)
from ..safe_archive import ArchiveError, ArchiveReader, LimitExceeded, open_archive
from .pyindex import (
    ModuleScan,
    index_build_script,
    module_name,
    parse,
    scan_module,
    sensitive_calls,
    sensitive_set,
)

_NATIVE_EXT = (".so", ".pyd", ".dylib", ".dll", ".exe")
_SITE_PREFIX = re.compile(r"^[^/]+\.data/(purelib|platlib)/")
# Mach-O: 64- and 32-bit, little- and big-endian, and the universal ("fat")
# headers, 32- and 64-bit, that hold one slice per architecture.
_MACHO_MAGIC = (
    b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xfe\xed\xfa\xce",
    b"\xca\xfe\xba\xbe",
    b"\xca\xfe\xba\xbf",
)
# The rules that read the files of an archive Garnet couldn't read to the end.
# GRN-C009 reads a wheel's entry points, and GRN-C012 every Python file of a wheel.
_ARCHIVE_RULES = ("GRN-C001", "GRN-C003", "GRN-C004")
_WHEEL_RULES = (*_ARCHIVE_RULES, "GRN-C009", "GRN-C012")
# Names GRN-C012 never counts as the release's own: the standard library's
# modules, the builtins, and the first name of each entry of the §6.3 list
# (exec, os, subprocess, requests, ...), so a top-level ``exec.py`` or
# ``requests.py`` can't hide a call the list names.
_NEVER_OWN = (
    frozenset(sys.stdlib_module_names)
    | frozenset(dir(builtins))
    | frozenset(m[0] for s in sensitive_set() if (m := re.match(r"\w+", s)))
)
_SCRIPT_EXT = (".sh", ".bash", ".bat", ".cmd", ".ps1", ".js", ".mjs", ".cjs", ".vbs")


@dataclass
class Inspection:
    """Content facts for one artifact, filled in by ``inspect_artifact``."""

    files: list[FileEntry] = field(default_factory=list)
    modules: list[ModuleIndex] = field(default_factory=list)
    pth_files: list[PthFile] = field(default_factory=list)
    build_backend: str | None = None
    setup_py_calls: tuple[CallSite, ...] = ()
    unparsed: list[str] = field(default_factory=list)
    entry_points: set[str] = field(default_factory=set)
    requirements: tuple[Requirement, ...] = ()
    requirements_read: bool = False
    entry_point_specs: tuple[EntryPoint, ...] = ()
    entry_points_read: bool = False  # a wheel read to the end, every entry_points.txt seen
    errors: list[FactError] = field(default_factory=list)
    complete: bool = True  # False: the archive couldn't be read to the end


def git_blob_id(data: bytes) -> str:
    """The id git gives a file with these bytes (GRN-C007 compares it with the
    source tree). Git names objects by SHA-1; it is an identifier, not a check."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324


def native_format(body: bytes) -> str | None:
    """The executable format a file's bytes say it is (ELF, Mach-O or PE), or None.

    A PE file starts with ``MZ`` and names where its ``PE`` header is; both
    are checked, so a text file that happens to start with ``MZ`` is not one.
    """
    if body.startswith(b"\x7fELF"):
        return "ELF"
    if body.startswith(_MACHO_MAGIC):
        # 0xCAFEBABE also starts a Java class file, whose next word is its
        # version (45 or more); a universal Mach-O binary counts its slices there.
        if body.startswith(b"\xca\xfe\xba\xbe") and int.from_bytes(body[4:8], "big") >= 45:
            return None
        return "Mach-O"
    if body.startswith(b"MZ") and len(body) >= 0x40:
        offset = int.from_bytes(body[0x3C:0x40], "little")
        if body[offset : offset + 4] == b"PE\0\0":
            return "PE"
    return None


# The magic numbers of Pythons that read a PEP 552 flags word: 3.7a4 (3392)
# onward. Python 2's start at 20121.
_PEP552_MAGIC = range(3392, 20000)


def hash_based_pyc(body: bytes) -> bool:
    """Whether a ``.pyc`` is hash-based (PEP 552, flags word 1 or 3): Python
    loads it from ``__pycache__`` in place of the source beside it without
    comparing its code with that source. Unchecked (1), it doesn't look at
    the source; checked (3), it compares only the source's hash with the one
    in the file's own header, which anyone can compute from the source.

    Before 3.7 that word held the source's timestamp, so the magic number is
    checked first. With bit 0 clear (0 or 2) the file is timestamp-based, and
    Python refuses a value above 3.
    """
    return (
        len(body) >= 16
        and body[2:4] == b"\r\n"
        and int.from_bytes(body[0:2], "little") in _PEP552_MAGIC
        and int.from_bytes(body[4:8], "little") in (1, 3)
    )


def _kind(path: str, body: bytes) -> FileKind:
    """Classify a file by its extension, then its first bytes.

    A ``.py`` or ``.pth`` stays one whatever it holds, so the rules that read
    those files still see it (a DLL named ``.py`` doesn't parse: GRN-E002).
    ``FileEntry.binary`` records native bytes under any name, for GRN-C004:
    num2words 0.5.15 shipped a DLL as ``_build.py``.
    """
    lower = path.lower()
    if lower.endswith(".py"):
        return "py"
    if lower.endswith(".pth"):
        return "pth"
    if lower.endswith(".pyc"):
        return "pyc"
    if lower.endswith(_NATIVE_EXT) or ".so." in lower or native_format(body) is not None:
        return "native"
    if lower.endswith(_SCRIPT_EXT) or body.startswith(b"#!"):
        return "script"
    if ".data/" in lower or lower.endswith((".json", ".txt", ".csv", ".yaml", ".yml", ".toml")):
        return "data"
    return "other"


def _strip_prefix(paths: list[str]) -> str:
    """sdists put everything under ``name-version/``; find that prefix."""
    tops = {p.split("/", 1)[0] for p in paths}
    if len(tops) == 1 and all("/" in p for p in paths):
        return next(iter(tops)) + "/"
    return ""


def site_path(path: str) -> str:
    """Where a wheel file lands relative to site-packages.

    ``demo-1.1.data/purelib/demo.pth`` installs as ``demo.pth``; the folder
    name carries the version, so comparing releases by it would see every
    file as new.
    """
    return _SITE_PREFIX.sub("", path)


def exec_lines(pth: bytes) -> tuple[str, ...]:
    """Lines of a .pth file that the site module executes."""
    out = []
    for raw in pth.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if line.startswith(("import ", "import\t")):
            out.append(line)
    return tuple(out)


def project_name(filename: str) -> str:
    """The project a wheel or sdist belongs to, normalized (PEP 503).

    ``requests-2.32.3-py3-none-any.whl`` and ``requests-2.32.3.tar.gz`` are
    both ``requests``. The scans use it to tell the ``requests`` project
    calling its own modules from a release that ships a ``requests.py``.
    """
    if filename.endswith(".whl"):
        name = filename.split("-", 1)[0]
    else:
        stem = re.sub(r"\.(tar\.gz|tar\.bz2|tar\.xz|tgz|tar|zip)$", "", filename)
        name = stem.rpartition("-")[0] or stem
    return canonicalize_name(name)


def _own_packages(paths: list[str]) -> frozenset[str]:
    """The release's own top-level packages, so calls into them are followed."""
    own = set()
    for p in paths:
        if p.endswith(".py"):
            first = p.split("/", 1)[0]
            own.add(first[:-3] if first.endswith(".py") else first)
    return frozenset(own)


def wheel_own(paths: list[str]) -> frozenset[str]:
    """The release's own top-level packages as GRN-C012 counts them: without
    a name the sensitive call set depends on. A top-level ``subprocess.py``
    never shadows the standard library's, a module file never stands in for
    the builtin ``exec``, and a call to ``requests.post`` counts whether a
    ``requests.py`` beside the package or the requests project answers it."""
    return _own_packages(paths) - _NEVER_OWN


def inspect_artifact(filename: str, data: bytes, limits: Limits, *, sdist: bool) -> Inspection:
    """Read every file in a wheel or sdist and record what it contains.

    Python files are parsed, never run. Archive problems and limits become
    ``FactError``s in the result. In a wheel, each module also records every
    sensitive call it makes anywhere, for GRN-C012.
    """
    result = Inspection()
    rules = _ARCHIVE_RULES if sdist else _WHEEL_RULES
    sources: dict[str, bytes] = {}  # module → source, for calls across modules
    calls_out: dict[str, tuple[str, ...]] = {}  # module → own callables it calls at import
    handed_out: dict[str, tuple[tuple[str, str], ...]] = {}  # module → own callables it hands on
    try:
        reader = open_archive(data, filename, limits)
        entries = reader.entries()
        prefix = _strip_prefix([e.path for e in entries]) if sdist else ""
        rel_paths = [e.path[len(prefix) :] for e in entries]
        if sdist:
            # in an sdist, packages often live under src/
            own = _own_packages([p[4:] if p.startswith("src/") else p for p in rel_paths])
        else:
            own = _own_packages(rel_paths)
        anywhere_own = wheel_own(rel_paths)
        project = project_name(filename)
        for entry, rel in zip(entries, rel_paths, strict=True):
            body = reader.read(entry.path)
            kind = _kind(rel, body)
            digest = hashlib.sha256(body).hexdigest()
            result.files.append(
                FileEntry(
                    rel,
                    len(body),
                    digest,
                    kind,
                    native_format(body),
                    hash_based=kind == "pyc" and hash_based_pyc(body),
                )
            )
            site = rel if sdist else site_path(rel)
            if kind == "pth":
                # In a wheel only a .pth that lands in site-packages itself runs:
                # at the wheel root or at the root of .data/purelib or platlib.
                if sdist or "/" not in site:
                    result.pth_files.append(PthFile(rel, exec_lines(body)))
            elif kind == "py":
                if len(body) > limits.max_py_file_bytes:
                    result.errors.append(
                        FactError(
                            "GRN-E003",
                            f"{filename}: {rel} is larger than the parse limit",
                            ("GRN-C003",) if sdist else ("GRN-C003", "GRN-C012"),
                            rel,
                        )
                    )
                    continue
                mod_path = site[4:] if sdist and site.startswith("src/") else site
                mod = module_name(mod_path)
                try:
                    if sdist and rel == "setup.py":
                        result.setup_py_calls = index_build_script(body)
                        continue
                    tree = parse(body, path=rel)
                    scan = scan_module(
                        body, path=rel, own=own, project=project, module=mod, tree=tree
                    )
                except (SyntaxError, ValueError, RecursionError):
                    result.unparsed.append(rel)
                    continue
                anywhere = None if sdist else _names(body, rel, anywhere_own, tree)
                result.modules.append(
                    ModuleIndex(mod, rel, scan.calls, scan.imports, git_blob_id(body), anywhere)
                )
                sources[mod] = body
                calls_out[mod] = scan.calls_out
                handed_out[mod] = scan.handed_out
            elif sdist and rel == "pyproject.toml":
                result.build_backend = _build_backend(body)
                result.entry_points |= _pyproject_entry_points(body)
            elif not sdist and loaded_entry_points_file(site):
                result.entry_points |= entry_point_modules(body)
                result.entry_point_specs += parse_entry_points(body, rel)
            elif (sdist and rel == "PKG-INFO") or (
                not sdist and rel.endswith(".dist-info/METADATA") and rel.count("/") == 1
            ):
                reqs = declared_requirements(body, sdist=sdist)
                if reqs is not None:
                    result.requirements = reqs
                    result.requirements_read = True
        _follow_calls_out(result, sources, calls_out, handed_out, own, project)
        result.entry_points_read = not sdist
    except LimitExceeded as err:
        result.errors.append(FactError("GRN-E003", f"{filename}: {err}", rules))
        result.complete = False
    except ArchiveError as err:
        result.errors.append(FactError("GRN-E002", f"{filename}: {err}", rules))
        result.complete = False
    result.files.sort(key=lambda f: f.path)
    result.modules.sort(key=lambda m: m.path)
    result.pth_files.sort(key=lambda p: p.path)
    result.unparsed.sort()
    # Stable: lines of one name keep the order of their files and their lines.
    result.entry_point_specs = tuple(
        sorted(result.entry_point_specs, key=lambda e: (e.group, e.name))
    )
    return result


def _names(body: bytes, rel: str, own: frozenset[str], tree: ast.Module) -> tuple[str, ...] | None:
    """The names of the sensitive calls anywhere in a parsed file, or None if
    the file is nested too deep to walk."""
    try:
        calls = sensitive_calls(body, path=rel, own=own, tree=tree)
    except (SyntaxError, ValueError, RecursionError):
        return None
    return tuple(sorted({c.name for c in calls}))


def wheel_files(
    filename: str, data: bytes, limits: Limits
) -> tuple[list[FileEntry], frozenset[str], list[FactError]]:
    """Every file in a wheel with its size, hash and kind, and the wheel's own
    top-level packages, without parsing anything. GRN-C012 lists another wheel
    of the release this way and parses only the files that differ."""
    files: list[FileEntry] = []
    errors: list[FactError] = []
    own: frozenset[str] = frozenset()
    try:
        reader = open_archive(data, filename, limits)
        entries = reader.entries()
        own = _own_packages([e.path for e in entries])
        for entry in entries:
            body = reader.read(entry.path)
            kind = _kind(entry.path, body[:4])
            files.append(FileEntry(entry.path, len(body), hashlib.sha256(body).hexdigest(), kind))
    except LimitExceeded as err:
        errors.append(FactError("GRN-E003", f"{filename}: {err}", ("GRN-C012",)))
    except ArchiveError as err:
        errors.append(FactError("GRN-E002", f"{filename}: {err}", ("GRN-C012",)))
    files.sort(key=lambda f: f.path)
    return files, own, errors


def file_reader(
    filename: str, data: bytes, limits: Limits, *, sdist: bool
) -> Callable[[str], bytes]:
    """Read single files back from an artifact, by the paths ``inspect_artifact``
    recorded. GRN-C007 uses it after the tag lookup to index only the files
    that aren't in the source tree. The archive is opened on first use."""
    opened: list[tuple[ArchiveReader, str]] = []

    def read(rel: str) -> bytes:
        if not opened:
            reader = open_archive(data, filename, limits)
            paths = [e.path for e in reader.entries()]
            opened.append((reader, _strip_prefix(paths) if sdist else ""))
        reader, prefix = opened[0]
        return reader.read(prefix + rel)

    return read


def _callee(name: str, modules: Mapping[str, bytes]) -> tuple[str, str] | None:
    """Split ``pkg.mod.Class.method`` into the longest module known and the rest."""
    parts = name.split(".")
    for n in range(len(parts) - 1, 0, -1):
        mod = ".".join(parts[:n])
        if mod in modules:
            return mod, ".".join(parts[n:])
    return None


def _follow_calls_out(
    result: Inspection,
    sources: Mapping[str, bytes],
    calls_out: Mapping[str, tuple[str, ...]],
    handed_out: Mapping[str, tuple[tuple[str, str], ...]],
    own: frozenset[str],
    project: str,
) -> None:
    """Follow import-time calls into the package's other modules.

    memoryos 2.0.34 ran ``get_logger()`` at module level in most modules; that
    function called ``configure_logging()``, which imported ``_stage0`` and
    ran its ``trigger()``, which started a bundled binary. Each callable is
    parsed once, and its sensitive calls are added to the module that holds
    them once per module whose import reaches it, marked with that module,
    so a check can tell a call every import runs from one that only a test
    file reaches. A callable that import-time code only handed to another
    call (``partial(f)``) is followed the same way, carrying that call.
    """
    by_module = {m.module: i for i, m in enumerate(result.modules)}
    pending: list[tuple[str, str, str | None]] = sorted(
        (callee, mod, None) for mod, names in calls_out.items() for callee in names
    )
    pending += sorted(
        (callee, mod, to) for mod, pairs in handed_out.items() for callee, to in pairs
    )
    seen: set[tuple[tuple[str, str], str, str | None]] = set()
    scans: dict[tuple[tuple[str, str], str | None], ModuleScan | None] = {}
    extra: dict[str, list[CallSite]] = {}
    while pending:
        name, origin, to = pending.pop(0)
        target = _callee(name, sources)
        if target is None or (target, origin, to) in seen:
            continue
        seen.add((target, origin, to))
        mod, entry = target
        if (target, to) not in scans:
            index = result.modules[by_module[mod]]
            try:
                scans[target, to] = scan_module(
                    sources[mod],
                    path=index.path,
                    own=own,
                    project=project,
                    module=mod,
                    entry=entry,
                    handed=to,
                )
            except (SyntaxError, ValueError, RecursionError):
                scans[target, to] = None
        scan = scans[target, to]
        if scan is None:
            continue
        origin_path = result.modules[by_module[origin]].path
        extra.setdefault(mod, []).extend(
            replace(c, from_module=origin_path if origin != mod else None) for c in scan.calls
        )
        pending.extend((callee, origin, None) for callee in scan.calls_out)
        pending.extend((callee, origin, ctx) for callee, ctx in scan.handed_out)
    for mod, calls in extra.items():
        i = by_module[mod]
        index = result.modules[i]
        merged = sorted(
            set(index.top_level_calls) | set(calls),
            key=lambda c: (c.line, c.name, c.via or "", c.from_module or "", c.handed_to or ""),
        )
        result.modules[i] = replace(index, top_level_calls=tuple(merged))


def _build_backend(pyproject: bytes) -> str | None:
    """``build-system.build-backend``, prefixed ``in-tree:`` when the sdist ships it."""
    try:
        doc = tomllib.loads(pyproject.decode("utf-8", "replace"))
    except tomllib.TOMLDecodeError:
        return None
    bs = doc.get("build-system")
    if not isinstance(bs, dict):
        return None
    backend = bs.get("build-backend")
    if not isinstance(backend, str):
        return None
    if bs.get("backend-path"):
        return f"in-tree:{backend}"
    return backend


def loaded_entry_points_file(site: str) -> bool:
    """Whether a wheel file, by where it installs in site-packages, is an
    ``entry_points.txt`` that ``importlib.metadata`` reads.

    importlib.metadata takes every folder at the top of site-packages whose
    name ends in ``.dist-info`` or ``.egg-info``, ignoring case, as an
    installed package, and opens ``entry_points.txt`` in it by name, which
    on macOS and Windows matches the name in any case. So a second metadata
    folder in a wheel, at its root or under ``.data/purelib/``, counts too.
    One under ``.data/data/`` lands in site-packages only under some install
    schemes; it is not read (GRN-C010 lists it).
    """
    folder, _, name = site.lower().partition("/")
    return name == "entry_points.txt" and folder.endswith((".dist-info", ".egg-info"))


def parse_entry_points(text: bytes, path: str = "") -> tuple[EntryPoint, ...]:
    """Every entry point an entry_points.txt declares, read the way
    ``importlib.metadata`` reads it on Python 3.11 to 3.14 (pytest, setuptools
    and pip all read entry points through it).

    Lines are stripped. A blank line or one that starts with ``#`` is
    skipped; nothing else is a comment, so ``;demo = x`` is an entry point
    named ``;demo``. A line that starts with ``[`` and ends with ``]`` names
    the group with its brackets stripped, so ``[[pytest11]]`` is
    ``pytest11``; spaces are stripped too, as ``pkg_resources`` does, so
    ``[ pytest11 ]`` also counts as ``pytest11``. Lines before the first group
    are skipped. Any other line is ``name = target``, split at the first
    ``=``; the name may be empty. A line without ``=`` is skipped (it makes
    importlib.metadata raise, so nothing in the file loads).

    Every line is kept, a name repeated in a group too: pip installs the last
    target of a script, a lookup by name returns the first, and a tool that
    loads a whole group (setuptools, keyring) loads each one. The result is
    sorted by group and name, with file order kept within a name.
    """
    out: list[EntryPoint] = []
    group: str | None = None
    for raw in text.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            group = line.strip("[]").strip()
            continue
        if group is None or "=" not in line:
            continue
        name, target = (s.strip() for s in line.split("=", 1))
        out.append(EntryPoint(group, name, target, path))
    return tuple(sorted(out, key=lambda e: (e.group, e.name)))


def entry_point_modules(text: bytes) -> set[str]:
    """Modules named by an entry_points.txt (``name = module:attr``), read as
    ``parse_entry_points`` reads it.

    Entry points such as ``pytest11`` load a module whenever another tool
    runs, so those modules count as live code.
    """
    out = {e.target.split(":", 1)[0].split("[", 1)[0].strip() for e in parse_entry_points(text)}
    return {m for m in out if m}


_REQ_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")


def _sdist_fixes_requirements(msg: Message) -> bool:
    """Whether an sdist's PKG-INFO states the dependencies its wheels will have.

    PEP 643: from metadata version 2.2 a field not listed as ``Dynamic`` is
    the same in every wheel built from the sdist. Older PKG-INFO files often
    leave ``Requires-Dist`` out even when ``setup.py`` declares dependencies.
    """
    try:
        version = Version(str(msg.get("Metadata-Version", "")).strip())
    except InvalidVersion:
        return False
    dynamic = {str(d).strip().lower() for d in msg.get_all("Dynamic") or []}
    return version >= Version("2.2") and "requires-dist" not in dynamic


def declared_requirements(
    metadata: bytes, *, sdist: bool = False
) -> tuple[Requirement, ...] | None:
    """The ``Requires-Dist`` entries of a METADATA or PKG-INFO file that install
    without an extra, one per name, in the order they are declared, with any
    later line for the same name in ``also`` and ``also_installs``.

    A requirement whose marker mentions ``extra`` is installed only when
    someone asks for that extra, so it is left out. A line ``packaging`` can't
    parse is kept under the name it starts with, so an odd line is still seen.
    For an sdist, None means its PKG-INFO doesn't fix the dependencies.
    """
    msg = BytesHeaderParser().parsebytes(metadata)
    if sdist and not _sdist_fixes_requirements(msg):
        return None
    by_name: dict[str, list[Requirement]] = {}
    for raw in msg.get_all("Requires-Dist") or []:
        line = " ".join(str(raw).split())
        if not line:
            continue
        url: str | None = None
        try:
            req = _Requirement(line)
        except InvalidRequirement:
            m = _REQ_NAME.match(line)
            if m is None:
                continue
            name = canonicalize_name(m.group(0))
        else:
            if req.marker is not None and "extra" in str(req.marker):
                continue
            name = canonicalize_name(req.name)
            url = req.url
        by_name.setdefault(name, []).append(Requirement(name, line, source=url))
    # The first line for a name is the one compared; a second one (another
    # marker, a direct URL) is kept on it.
    return tuple(first.with_others(rest) for first, *rest in by_name.values())


def _pyproject_entry_points(pyproject: bytes) -> set[str]:
    """Modules named by ``[project]`` scripts and entry points."""
    try:
        doc = tomllib.loads(pyproject.decode("utf-8", "replace"))
    except tomllib.TOMLDecodeError:
        return set()
    project = doc.get("project")
    if not isinstance(project, dict):
        return set()
    groups: list[object] = [project.get("scripts"), project.get("gui-scripts")]
    eps = project.get("entry-points")
    if isinstance(eps, dict):
        groups += list(eps.values())
    out = set()
    for g in groups:
        if isinstance(g, dict):
            for target in g.values():
                if isinstance(target, str):
                    out.add(target.split(":", 1)[0].strip())
    return {m for m in out if m}
