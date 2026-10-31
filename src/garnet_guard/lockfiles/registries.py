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
import re
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


# .npmrc is read the way pnpm 10 reads it: with the ``ini`` 1.x parser
# that config-chain uses. Lines end only at CR or LF; a line is a section
# header only if it is exactly ``[name]``, with nothing before the ``[``
# or after the ``]``; a line whose value holds U+2028 or U+2029 matches
# none of the parser's patterns and is skipped. Keys and values are
# trimmed the way JavaScript's ``trim`` trims, which removes a byte order
# mark and leaves other control characters.
_JS_SPACE = (
    "\t\n\x0b\x0c\r \xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
    "\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)
_INI_LINES = re.compile("[\r\n]+")
_INI_COMMENT = re.compile(f"[{_JS_SPACE}]*[;#]")
_INI_SECTION = re.compile(r"\[[^\]]*\]")
_INI_SETTING = re.compile("([^=]+)(?:=([^\n\r\u2028\u2029]*))?")


def _json(text: str) -> object:
    """JSON.parse, which reads no NaN or Infinity."""

    def constant(name: str) -> object:
        raise ValueError(name)

    return json.loads(text, parse_constant=constant)


def _ini_value(raw: str) -> object:
    """A key or value as ``ini``'s ``unsafe`` reads it: trimmed, then a
    quoted one JSON-decoded (kept as written if that fails), an unquoted
    one cut at an inline ``;`` or ``#`` comment, ``\\;``, ``\\#`` and
    ``\\\\`` unescaped and any other backslash kept."""
    value = raw.strip(_JS_SPACE)
    if (value[:1] == '"' and value[-1:] == '"') or (value[:1] == "'" and value[-1:] == "'"):
        if value[0] == "'":
            value = value[1:-1]
        try:
            return _json(value)
        except (ValueError, RecursionError):
            return value
    out = []
    escaped = False
    for c in value:
        if escaped:
            out.append(c if c in "\\;#" else "\\" + c)
            escaped = False
        elif c in ";#":
            break
        elif c == "\\":
            escaped = True
        else:
            out.append(c)
    if escaped:
        out.append("\\")
    return "".join(out).strip(_JS_SPACE)


def _js_key(key: object) -> str:
    """The property name JavaScript makes of a decoded key (``String(key)``)."""
    if isinstance(key, str):
        return key
    if isinstance(key, list):
        return ",".join("" if k is None else _js_key(k) for k in key)
    if isinstance(key, dict):
        return "[object Object]"
    return json.dumps(key)  # true, false, null or a number: never a registry key


def _npmrc_settings(text: str) -> dict[str, object]:
    """The top-level settings of an .npmrc, as ``ini.parse`` builds them."""
    settings: dict[str, object] = {}
    in_section = False
    for line in _INI_LINES.split(text):
        if not line or _INI_COMMENT.match(line):
            continue
        if _INI_SECTION.fullmatch(line):
            in_section = True  # the keys after it are the section's, not settings
            continue
        m = _INI_SETTING.fullmatch(line)
        if m is None or in_section:
            continue
        raw_key = _ini_value(m[1])
        listed = isinstance(raw_key, str) and len(raw_key) > 2 and raw_key.endswith("[]")
        key = raw_key[:-2] if listed and isinstance(raw_key, str) else _js_key(raw_key)
        if key == "__proto__":
            continue
        value = True if m[2] is None else _ini_value(m[2])
        if isinstance(value, str) and value in ("true", "false", "null"):
            value = json.loads(value)
        current = settings.get(key)
        if listed and not isinstance(current, list):
            current = [current] if current else []
        if isinstance(current, list):
            current.append(value)
            value = current
        settings[key] = value
    return settings


def npmrc(text: str) -> Registries:
    """``registry`` and ``@scope:registry`` from an .npmrc, last one winning,
    read as pnpm reads them (see ``_INI_LINES`` above).

    A value that isn't text, or that names an environment variable
    (``${NPM_REGISTRY}``), is taken as another registry: pnpm stops on the
    first, and Garnet can't see the variable, so it can't tell the package
    installs from the public one. As in pnpm, the scope of a scope key runs
    to its first colon (``@corp:x:registry`` is ``@corp``'s).
    """
    default: bool | None = None
    scopes: dict[str, bool | None] = {}
    for key, value in _npmrc_settings(text).items():
        public = isinstance(value, str) and _public(value)
        if key == "registry":
            default = public
        elif key.startswith("@") and key.endswith(":registry"):
            scope = key[: key.index(":")]
            if "/" not in scope:
                scopes[scope] = public
    return Registries(NPMRC, default, scopes)


def pnpm_workspace(text: str) -> Registries:
    """``registries`` from a pnpm-workspace.yaml. pnpm 10 copies that file's
    settings over .npmrc's, so a ``registries`` table (``default`` and
    ``@scope`` URLs) replaces the registries .npmrc set; a ``registry`` key
    there changes nothing, since pnpm has read the registries by then.
    Raises ``LockfileError`` for one Garnet can't read; only ``registries``
    is held to the YAML reader's rules (anchors, aliases, tags elsewhere,
    in a catalog say, are passed over)."""
    doc = load(text, schema="core", read=frozenset({"registries"}))
    if doc is None:
        return Registries(PNPM_WORKSPACE)
    if not isinstance(doc, YamlMapping):
        raise LockfileError("the top level isn't a mapping")
    if "registries" not in doc:
        return Registries(PNPM_WORKSPACE)
    table = doc["registries"]
    if not isinstance(table, YamlMapping):
        raise LockfileError(f"line {doc.lines['registries']}: registries isn't a mapping")
    # With no default, pnpm 10 installs unscoped packages from npm's public
    # registry, even when .npmrc names another one (which Garnet still
    # counts, as it counts either file).
    default: bool | None = None
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
    a .yarnrc.yml. Raises ``LockfileError`` for one Garnet can't read; only
    those two keys are held to the YAML reader's rules."""
    doc = load(text, schema="failsafe", read=frozenset({"npmRegistryServer", "npmScopes"}))
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
            server = _server(settings, "an npmRegistryServer")
            # Yarn looks a scope up by its name without the @ (npmScopes
            # has no key normalization), so it never reads an '@corp' entry.
            if not scope.startswith("@"):
                scopes["@" + scope] = server
    return Registries(YARNRC, default, scopes)


def _server(table: YamlMapping, what: str) -> bool | None:
    value = table.get("npmRegistryServer")
    if value is None:
        return None
    if not isinstance(value, str):
        raise LockfileError(f"line {table.lines['npmRegistryServer']}: {what} isn't text")
    return _public(value)
