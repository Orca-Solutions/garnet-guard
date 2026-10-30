"""Turn artifact bytes into content facts. Reads bytes only; never executes."""

from __future__ import annotations

import hashlib
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from email.message import Message
from email.parser import BytesHeaderParser

from packaging.requirements import InvalidRequirement
from packaging.requirements import Requirement as _Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ..models import (
    CallSite,
    FactError,
    FileEntry,
    FileKind,
    Limits,
    ModuleIndex,
    PthFile,
    Requirement,
)
from ..safe_archive import ArchiveError, LimitExceeded, open_archive
from .pyindex import ModuleScan, index_build_script, module_name, scan_module, sensitive_calls

_NATIVE_EXT = (".so", ".pyd", ".dylib", ".dll", ".exe")
_SITE_PREFIX = re.compile(r"^[^/]+\.data/(purelib|platlib)/")
_NATIVE_MAGIC = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
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
    errors: list[FactError] = field(default_factory=list)


def git_blob_id(data: bytes) -> str:
    """The id git gives a file with these bytes (GRN-C007 compares it with the
    source tree). Git names objects by SHA-1; it is an identifier, not a check."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324


def _kind(path: str, head: bytes) -> FileKind:
    """Classify a file by its extension and first bytes."""
    lower = path.lower()
    if lower.endswith(".py"):
        return "py"
    if lower.endswith(".pth"):
        return "pth"
    if lower.endswith(_NATIVE_EXT) or ".so." in lower or head.startswith(_NATIVE_MAGIC):
        return "native"
    if lower.endswith(_SCRIPT_EXT) or head.startswith(b"#!"):
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


def _own_packages(paths: list[str]) -> frozenset[str]:
    """The release's own top-level packages, so calls into them aren't flagged."""
    own = set()
    for p in paths:
        if p.endswith(".py"):
            first = p.split("/", 1)[0]
            own.add(first[:-3] if first.endswith(".py") else first)
    return frozenset(own)


def inspect_artifact(filename: str, data: bytes, limits: Limits, *, sdist: bool) -> Inspection:
    """Read every file in a wheel or sdist and record what it contains.

    Python files are parsed, never run. Archive problems and limits become
    ``FactError``s in the result.
    """
    result = Inspection()
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
        for entry, rel in zip(entries, rel_paths, strict=True):
            body = reader.read(entry.path)
            kind = _kind(rel, body[:4])
            result.files.append(FileEntry(rel, len(body), hashlib.sha256(body).hexdigest(), kind))
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
                            ("GRN-C003",),
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
                    scan = scan_module(body, path=rel, own=own, module=mod)
                    anywhere = sensitive_calls(body, path=rel, own=own)
                except (SyntaxError, ValueError, RecursionError):
                    result.unparsed.append(rel)
                    continue
                result.modules.append(
                    ModuleIndex(mod, rel, scan.calls, scan.imports, git_blob_id(body), anywhere)
                )
                sources[mod] = body
                calls_out[mod] = scan.calls_out
                handed_out[mod] = scan.handed_out
            elif sdist and rel == "pyproject.toml":
                result.build_backend = _build_backend(body)
                result.entry_points |= _pyproject_entry_points(body)
            elif not sdist and rel.endswith(".dist-info/entry_points.txt") and rel.count("/") == 1:
                result.entry_points |= entry_point_modules(body)
            elif (sdist and rel == "PKG-INFO") or (
                not sdist and rel.endswith(".dist-info/METADATA") and rel.count("/") == 1
            ):
                reqs = declared_requirements(body, sdist=sdist)
                if reqs is not None:
                    result.requirements = reqs
                    result.requirements_read = True
        _follow_calls_out(result, sources, calls_out, handed_out, own)
    except LimitExceeded as err:
        result.errors.append(FactError("GRN-E003", f"{filename}: {err}", ("GRN-C001", "GRN-C003")))
    except ArchiveError as err:
        result.errors.append(FactError("GRN-E002", f"{filename}: {err}", ("GRN-C001", "GRN-C003")))
    result.files.sort(key=lambda f: f.path)
    result.modules.sort(key=lambda m: m.path)
    result.pth_files.sort(key=lambda p: p.path)
    result.unparsed.sort()
    return result


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
                    sources[mod], path=index.path, own=own, module=mod, entry=entry, handed=to
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


def entry_point_modules(text: bytes) -> set[str]:
    """Modules named by an entry_points.txt (``name = module:attr``).

    Entry points such as ``pytest11`` load a module whenever another tool
    runs, so those modules count as live code.
    """
    out = set()
    for raw in text.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "[")) or "=" not in line:
            continue
        target = line.split("=", 1)[1].strip()
        out.add(target.split(":", 1)[0].split("[", 1)[0].strip())
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
    without an extra, one per name, in the order they are declared.

    A requirement whose marker mentions ``extra`` is installed only when
    someone asks for that extra, so it is left out. A line ``packaging`` can't
    parse is kept under the name it starts with, so an odd line is still seen.
    For an sdist, None means its PKG-INFO doesn't fix the dependencies.
    """
    msg = BytesHeaderParser().parsebytes(metadata)
    if sdist and not _sdist_fixes_requirements(msg):
        return None
    out: list[Requirement] = []
    seen: set[str] = set()
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
        if name in seen:
            continue
        seen.add(name)
        out.append(Requirement(name, line, source=url))
    return tuple(out)


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
