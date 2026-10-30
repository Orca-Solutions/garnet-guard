"""Turn an npm tarball into content facts. Reads bytes only; never runs npm."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from ..models import FactError, FileEntry, Limits
from ..safe_archive import ArchiveError, LimitExceeded, open_archive
from .inventory import _kind, _strip_prefix

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


def inspect_tarball(filename: str, data: bytes, limits: Limits) -> NpmInspection:
    """Read every file in an npm tarball and record what it contains.

    npm puts the package under one folder (normally ``package/``); paths are
    recorded relative to it. ``package.json`` at that root is the manifest npm
    installs from, so its scripts are the ones that would run.
    """
    result = NpmInspection()
    try:
        reader = open_archive(data, filename, limits)
        entries = reader.entries()
        prefix = _strip_prefix([e.path for e in entries])
        for entry in entries:
            rel = entry.path[len(prefix) :]
            body = reader.read(entry.path)
            kind = _kind(rel, body[:4])
            result.files.append(FileEntry(rel, len(body), hashlib.sha256(body).hexdigest(), kind))
            if rel == "package.json":
                result.scripts = install_scripts(body)
    except LimitExceeded as err:
        result.errors.append(FactError("GRN-E003", f"{filename}: {err}", ("GRN-C002",)))
    except ArchiveError as err:
        result.errors.append(FactError("GRN-E002", f"{filename}: {err}", ("GRN-C002",)))
    result.files.sort(key=lambda f: f.path)
    return result
