"""Turn artifact bytes into content facts. Reads bytes only; never executes."""

from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass, field

from ..models import CallSite, FactError, FileEntry, FileKind, Limits, ModuleIndex, PthFile
from ..safe_archive import ArchiveError, LimitExceeded, open_archive
from .pyindex import index_module, module_name

_NATIVE_EXT = (".so", ".pyd", ".dylib", ".dll", ".exe")
_NATIVE_MAGIC = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
_SCRIPT_EXT = (".sh", ".bash", ".bat", ".cmd", ".ps1", ".js", ".mjs", ".cjs", ".vbs")


@dataclass
class Inspection:
    files: list[FileEntry] = field(default_factory=list)
    modules: list[ModuleIndex] = field(default_factory=list)
    pth_files: list[PthFile] = field(default_factory=list)
    build_backend: str | None = None
    setup_py_calls: tuple[CallSite, ...] = ()
    unparsed: list[str] = field(default_factory=list)
    errors: list[FactError] = field(default_factory=list)


def _kind(path: str, head: bytes) -> FileKind:
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


def exec_lines(pth: bytes) -> tuple[str, ...]:
    """Lines of a .pth file that the site module executes."""
    out = []
    for raw in pth.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if line.startswith(("import ", "import\t")):
            out.append(line)
    return tuple(out)


def _own_packages(paths: list[str]) -> frozenset[str]:
    own = set()
    for p in paths:
        if p.endswith(".py"):
            first = p.split("/", 1)[0]
            own.add(first[:-3] if first.endswith(".py") else first)
    return frozenset(own)


def inspect_artifact(filename: str, data: bytes, limits: Limits, *, sdist: bool) -> Inspection:
    result = Inspection()
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
            if kind == "pth":
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
                try:
                    calls, imports = index_module(body, path=rel, own=own)
                except (SyntaxError, ValueError, RecursionError):
                    result.unparsed.append(rel)
                    continue
                if sdist and rel == "setup.py":
                    result.setup_py_calls = calls
                else:
                    mod_path = rel[4:] if sdist and rel.startswith("src/") else rel
                    result.modules.append(ModuleIndex(module_name(mod_path), rel, calls, imports))
            elif sdist and rel == "pyproject.toml":
                result.build_backend = _build_backend(body)
    except LimitExceeded as err:
        result.errors.append(FactError("GRN-E003", f"{filename}: {err}", ("GRN-C001", "GRN-C003")))
    except ArchiveError as err:
        result.errors.append(FactError("GRN-E002", f"{filename}: {err}", ("GRN-C001", "GRN-C003")))
    result.files.sort(key=lambda f: f.path)
    result.modules.sort(key=lambda m: m.path)
    result.pth_files.sort(key=lambda p: p.path)
    result.unparsed.sort()
    return result


def _build_backend(pyproject: bytes) -> str | None:
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
