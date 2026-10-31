"""Turn an npm tarball into content facts. Reads bytes only; never runs npm."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

from ..models import FactError, FileEntry, JsUse, Limits, Requirement
from ..safe_archive import ArchiveError, LimitExceeded, open_archive
from .inventory import _kind, _strip_prefix
from .jsscan import is_js, loaded_uses

# Lifecycle scripts npm runs on the machine that installs a package from the
# registry (GRN-C002). ``prepare`` is left out on purpose: npm runs it for git
# dependencies and in the package's own checkout, never for a published
# tarball, and in the top-200 backtest every ``prepare`` change was a build
# tool switch. SPEC §6.2 still lists it; see docs/rules/GRN-C002.md.
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")


@dataclass
class NpmInspection:
    """Content facts for one tarball, filled in by ``inspect_tarball``."""

    files: list[FileEntry] = field(default_factory=list)
    scripts: tuple[tuple[str, str], ...] = ()
    requirements: tuple[Requirement, ...] = ()
    requirements_read: bool = False
    js_uses: tuple[JsUse, ...] = ()
    js_scanned: bool = False
    errors: list[FactError] = field(default_factory=list)


def install_scripts(package_json: bytes) -> tuple[tuple[str, str], ...]:
    """The install-time scripts of a package.json, as sorted (name, command) pairs.

    A ``scripts`` entry that isn't a string is recorded with its JSON form, so a
    reviewer sees what npm would refuse to run rather than nothing.
    """
    try:
        doc = json.loads(package_json.decode("utf-8", "replace"))
    except ValueError:
        return ()
    scripts = doc.get("scripts") if isinstance(doc, dict) else None
    if not isinstance(scripts, dict):
        return ()
    out = []
    for name in INSTALL_SCRIPTS:
        if name in scripts:
            cmd = scripts[name]
            out.append((name, cmd if isinstance(cmd, str) else json.dumps(cmd, sort_keys=True)))
    return tuple(out)


# The package.json tables npm installs from the registry, with the label the
# finding shows. ``bundleDependencies`` ship inside the tarball and
# ``devDependencies`` are never installed for a dependency.
_DEPENDENCY_TABLES = (
    ("dependencies", ""),
    ("optionalDependencies", "optional"),
    ("peerDependencies", "peer"),
)


# A version range or dist-tag, which npm resolves on the registry. Anything
# else (``git+https://…``, ``github:user/repo``, ``user/repo``, ``file:…``, a
# tarball URL) installs from somewhere the registry doesn't describe.
_REGISTRY_RANGE = re.compile(r"^[\w.+\-*^~<>=|\s]*$")


def _dependency(name: str, rng: str, label: str) -> Requirement:
    spec = f"{name}@{rng}" + (f" ({label})" if label else "")
    if rng.startswith("npm:"):
        target = rng[4:]
        at = target.rfind("@")
        return Requirement(name, spec, alias_of=target[:at] if at > 0 else target)
    if _REGISTRY_RANGE.match(rng):
        return Requirement(name, spec)
    return Requirement(name, spec, source=rng)


def declared_dependencies(package_json: bytes) -> tuple[Requirement, ...]:
    """The packages a package.json makes npm install, one per name, with any
    other declaration of the name in ``also`` and ``also_installs``.

    ``peerDependencies`` count because npm 7 and later install them; a peer
    marked optional in ``peerDependenciesMeta`` doesn't.
    """
    try:
        doc = json.loads(package_json.decode("utf-8", "replace"))
    except ValueError:
        return ()
    if not isinstance(doc, dict):
        return ()
    meta = doc.get("peerDependenciesMeta")
    optional_peers = (
        {k for k, v in meta.items() if isinstance(v, dict) and v.get("optional")}
        if isinstance(meta, dict)
        else set()
    )
    by_name: dict[str, list[Requirement]] = {}
    for table, label in _DEPENDENCY_TABLES:
        deps = doc.get(table)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(name, str):
                continue
            if table == "peerDependencies" and name in optional_peers:
                continue
            rng = spec if isinstance(spec, str) else json.dumps(spec, sort_keys=True)
            by_name.setdefault(name, []).append(_dependency(name, rng.strip(), label))
    # The first declaration of a name is the one compared; the others (npm
    # lets optionalDependencies override dependencies) are kept on it.
    return tuple(first.with_others(rest) for first, *rest in by_name.values())


def inspect_tarball(filename: str, data: bytes, limits: Limits) -> NpmInspection:
    """Read every file in an npm tarball and record what it contains.

    npm puts the package under one folder (normally ``package/``); paths are
    recorded relative to it. ``package.json`` at that root is the manifest npm
    installs from, so its scripts are the ones that would run, and its entry
    points name the JavaScript GRN-C011 reads. A JavaScript file over the
    source size limit isn't read; that is GRN-E003 for GRN-C011.
    """
    result = NpmInspection()
    sources: dict[str, str] = {}
    manifest: bytes | None = None
    too_big: list[str] = []
    try:
        reader = open_archive(data, filename, limits)
        entries = reader.entries()
        prefix = _strip_prefix([e.path for e in entries])
        for entry in entries:
            rel = entry.path[len(prefix) :]
            body = reader.read(entry.path)
            kind = _kind(rel, body)
            result.files.append(FileEntry(rel, len(body), hashlib.sha256(body).hexdigest(), kind))
            if rel == "package.json":
                manifest = body
                result.scripts = install_scripts(body)
                result.requirements = declared_dependencies(body)
                result.requirements_read = True
            if is_js(rel):
                if len(body) > limits.max_js_file_bytes:
                    too_big.append(rel)
                else:
                    sources[rel] = body.decode("utf-8", "replace")
    except LimitExceeded as err:
        result.errors.append(FactError("GRN-E003", f"{filename}: {err}", _CONTENT))
        return _sorted(result)
    except ArchiveError as err:
        result.errors.append(FactError("GRN-E002", f"{filename}: {err}", _CONTENT))
        return _sorted(result)
    result.js_uses, unread = loaded_uses(manifest, sources, frozenset(too_big))
    result.js_scanned = True
    for rel in unread:
        msg = f"{filename}: {rel} is larger than {limits.max_js_file_bytes:,} bytes, so it wasn't read"
        result.errors.append(FactError("GRN-E003", msg, ("GRN-C011",)))
    return _sorted(result)


_CONTENT = ("GRN-C002", "GRN-C011")


def _sorted(result: NpmInspection) -> NpmInspection:
    result.files.sort(key=lambda f: f.path)
    return result
