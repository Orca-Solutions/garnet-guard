"""Which registry a pnpm or Yarn 2+ project installs from, read from the
repository's .npmrc and pnpm-workspace.yaml (pnpm) and .yarnrc.yml (Yarn 2+).

pnpm-lock.yaml and a Yarn 2+ yarn.lock don't record the registry of a
package from the default one; the project's configuration says where that
is. A package whose registry, by that configuration, isn't npm's public one
is GRN-E005 rather than checked against the public package of the same
name, as a package-lock.json entry with such a ``resolved`` URL already is.

These files can hold tokens. Only the registry keys are read, and nothing
from them is ever shown: the finding names the file, not the registry.
Pure: the caller reads the files (``workspace.registry_settings``).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field

from .base import LockfileError
from .yamldoc import Mapping as YamlMapping
from .yamldoc import load

NPMRC = ".npmrc"
PNPM_WORKSPACE = "pnpm-workspace.yaml"
YARNRC = ".yarnrc.yml"
# A configured registry counts as the public one only when it is exactly
# one of these; any other URL, a path, a port, credentials or plain HTTP
# makes it another registry.
PUBLIC = frozenset({"https://registry.npmjs.org", "https://registry.yarnpkg.com"})


@dataclass(frozen=True)
class Registries:
    """Whether each package's registry is npm's public one.

    ``default`` and each entry of ``scopes`` (``@scope``) is None when the
    configuration sets nothing, True when it names the public registry and
    False for any other. ``source`` is the file the setting came from.
    ``also`` is a second file's settings, for a tool that may read either:
    a package counts as public only if neither sends it elsewhere.
    """

    source: str = ""
    default: bool | None = None
    scopes: Mapping[str, bool | None] = field(default_factory=dict)
    also: Registries | None = None

    def other_registry(self, name: str) -> str | None:
        """The file that sends ``name`` to a registry other than npm's
        public one, or None when it installs from the public registry."""
        scope = name.partition("/")[0] if name.startswith("@") else None
        public = self.scopes.get(scope) if scope is not None else None
        if public is None:
            public = self.default
        if public is False:
            return self.source
        return self.also.other_registry(name) if self.also is not None else None

    def public_scope(self, scope: str) -> bool:
        """True if a file names npm's public registry for ``@scope``."""
        if self.scopes.get(scope) is True:
            return True
        return self.also is not None and self.also.public_scope(scope)


NONE = Registries()


def _public(url: str) -> bool:
    return "${" not in url and url.strip().rstrip("/") in PUBLIC


def _ini_value(raw: str) -> str:
    """An .npmrc value as npm's ``ini`` reads it: quotes removed, or an
    unquoted value cut at an inline ``;`` or ``#`` comment."""
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        if value[0] == '"':
            try:
                decoded = json.loads(value)
            except ValueError:
                return value[1:-1]
            return decoded if isinstance(decoded, str) else value[1:-1]
        return value[1:-1]
    out = []
    escaped = False
    for c in value:
        if escaped:
            out.append(c)
            escaped = False
        elif c == "\\":
            escaped = True
        elif c in ";#":
            break
        else:
            out.append(c)
    return "".join(out).strip()


def npmrc(text: str) -> Registries:
    """``registry=`` and ``@scope:registry=`` from an .npmrc, last one winning.

    A value that names an environment variable (``${NPM_REGISTRY}``) is
    taken as another registry: Garnet can't see the variable, so it can't
    tell the package installs from the public one.
    """
    default: bool | None = None
    scopes: dict[str, bool | None] = {}
    in_section = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in ";#":
            continue
        if line.startswith("[") and line.endswith("]"):
            in_section = True  # npm reads a section's keys as nested, not as settings
            continue
        key, eq, value = line.partition("=")
        if not eq or in_section:
            continue
        key = _ini_value(key)
        if key == "registry":
            default = _public(_ini_value(value))
        elif key.startswith("@") and key.endswith(":registry") and "/" not in key:
            scopes[key[: -len(":registry")]] = _public(_ini_value(value))
    return Registries(NPMRC, default, scopes)


def pnpm_workspace(text: str) -> Registries:
    """``registries`` from a pnpm-workspace.yaml. pnpm 10 copies that file's
    settings over .npmrc's, so a ``registries`` table (``default`` and
    ``@scope`` URLs) replaces the registries .npmrc set; a ``registry`` key
    there changes nothing, since pnpm has read the registries by then.
    Raises ``LockfileError`` for one Garnet can't read."""
    doc = load(text, schema="core")
    if doc is None:
        return Registries(PNPM_WORKSPACE)
    if not isinstance(doc, YamlMapping):
        raise LockfileError("the top level isn't a mapping")
    if "registries" not in doc:
        return Registries(PNPM_WORKSPACE)
    table = doc["registries"]
    if not isinstance(table, YamlMapping):
        raise LockfileError(f"line {doc.lines['registries']}: registries isn't a mapping")
    default = False  # with no default, pnpm has no registry for unscoped packages
    scopes: dict[str, bool | None] = {}
    for key, url in table.items():
        line = table.lines[key]
        if not isinstance(key, str) or not isinstance(url, str):
            raise LockfileError(f"line {line}: a registries entry Garnet can't read")
        if key == "default":
            default = _public(url)
        elif key.startswith("@"):
            scopes[key] = _public(url)
    return Registries(PNPM_WORKSPACE, default, scopes)


def yarnrc(text: str) -> Registries:
    """``npmRegistryServer`` and ``npmScopes.<scope>.npmRegistryServer`` from
    a .yarnrc.yml. Raises ``LockfileError`` for one Garnet can't read."""
    doc = load(text, schema="failsafe")
    if doc is None:
        return Registries(YARNRC)
    if not isinstance(doc, YamlMapping):
        raise LockfileError("the top level isn't a mapping")
    default = _server(doc, "the npmRegistryServer setting")
    scopes: dict[str, bool | None] = {}
    table = doc.get("npmScopes")
    if table is not None:
        if not isinstance(table, YamlMapping):
            raise LockfileError(f"line {doc.lines['npmScopes']}: npmScopes isn't a mapping")
        for scope, settings in table.items():
            line = table.lines[scope]
            if not isinstance(scope, str) or not isinstance(settings, YamlMapping):
                raise LockfileError(f"line {line}: an npmScopes entry Garnet can't read")
            scopes["@" + scope.removeprefix("@")] = _server(settings, "an npmRegistryServer")
    return Registries(YARNRC, default, scopes)


def _server(table: YamlMapping, what: str) -> bool | None:
    value = table.get("npmRegistryServer")
    if value is None:
        return None
    if not isinstance(value, str):
        raise LockfileError(f"line {table.lines['npmRegistryServer']}: {what} isn't text")
    return _public(value)
