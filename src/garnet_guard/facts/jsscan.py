"""Find process, network and eval uses in an npm package's JavaScript. Reads text only.

No JavaScript parser ships with Python, and a new runtime dependency needs an
ADR, so this is a tokenizer: it skips comments, strings, template literals and
regular expressions, and looks at the names that are left. It never runs the
code. It answers three questions about each use: which file, which line, and
whether the code runs when the file is loaded or only when a function is
called. The last is a heuristic: a brace that opens a function body (after
``function (...)``, ``=>`` or a method's parameter list) starts code that
waits to be called, unless the function is invoked on the spot.

Which files load is read from package.json (``main``, ``module``,
``exports``, ``bin``, ``browser``) and followed through relative
``require`` and ``import``, the way GRN-C003 follows a Python package's own
imports.
"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from ..models import JsUse

# The modules whose use GRN-C011 reports, and the kind of use each is.
SENSITIVE_MODULES: Mapping[str, str] = {
    "child_process": "process",
    "cluster": "process",
    "worker_threads": "process",
    "dgram": "network",
    "dns": "network",
    "http": "network",
    "http2": "network",
    "https": "network",
    "net": "network",
    "tls": "network",
    "vm": "eval",
}
# Globals that run code from a string or reach the network.
_CALLED_GLOBALS = {"eval": "eval", "Function": "eval", "fetch": "network"}
_NAMED_GLOBALS = {"XMLHttpRequest": "network", "WebSocket": "network"}
# javascript-obfuscator names every variable _0x followed by hex digits. A
# file with this many of them was put through it.
_OBFUSCATED = re.compile(r"_0x[0-9a-f]{4,}")
OBFUSCATED_MIN = 20
# Changed together with what the scan reports, so a reviewer can tell which
# list a result came from.
JS_SET_VERSION = "2026-10-a"

_JS_EXT = (".js", ".mjs", ".cjs")
_KEYWORDS_BEFORE_REGEX = frozenset(
    {
        "return",
        "typeof",
        "instanceof",
        "in",
        "of",
        "new",
        "delete",
        "void",
        "throw",
        "case",
        "do",
        "else",
        "yield",
        "await",
    }
)
_BLOCK_KEYWORDS = frozenset({"if", "for", "while", "switch", "catch", "with"})
# Tokens after which ``function`` starts a declaration, not an expression.
_STATEMENT_START = frozenset({";", "{", "}", "export", "default"})

_NAME = re.compile(r"[A-Za-z_$\u0080-￿][\w$\u0080-￿]*")
_NUMBER = re.compile(r"\d[\w.]*|\.\d[\w]*")
_PUNCT = re.compile(r"=>|\.\.\.|\?\.|[{}()\[\];,<>+\-*%&|^!~?:=.@#]")
_SPACE = re.compile(r"[ \t\r\f\v ﻿  ]+")


@dataclass(frozen=True)
class Token:
    kind: str  # "name" | "punct" | "string" | "number" | "regex" | "template"
    text: str
    line: int


def tokens(src: str) -> Iterator[Token]:
    """The tokens of ``src``, without comments or whitespace.

    A string's token text is its contents with simple escapes left as they
    are. A template literal yields a ``template`` token for its text and the
    tokens of each ``${…}`` inside it, so a call inside a template is seen.
    """
    i, n, line = 0, len(src), 1
    prev: Token | None = None
    # One entry per open template expression: the brace depth inside it.
    templates: list[int] = []

    def regex_allowed() -> bool:
        if prev is None:
            return True
        if prev.kind in ("number", "string", "regex", "template"):
            return False
        if prev.kind == "name":
            return prev.text in _KEYWORDS_BEFORE_REGEX
        return prev.text not in (")", "]", "}")

    while i < n:
        ch = src[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if m := _SPACE.match(src, i):
            i = m.end()
            continue
        if src.startswith("//", i) or (src.startswith("#!", i) and i == 0):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            end = n if j < 0 else j + 2
            line += src.count("\n", i, end)
            i = end
            continue
        if ch in "'\"":
            j, text, crossed = _string(src, i, ch)
            tok = Token("string", text, line)
            line += crossed
            i = j
        elif ch == "`" or (ch == "}" and templates and templates[-1] == 0):
            if ch == "}":
                templates.pop()
            j, text, crossed, opened = _template(src, i + 1)
            tok = Token("template", text, line)
            line += crossed
            i = j
            if opened:
                templates.append(0)
        elif ch == "/" and regex_allowed():
            j = _regex(src, i)
            tok = Token("regex", src[i:j], line)
            i = j
        elif m := _NAME.match(src, i):
            tok = Token("name", m.group(), line)
            i = m.end()
        elif m := _NUMBER.match(src, i):
            tok = Token("number", m.group(), line)
            i = m.end()
        else:
            m2 = _PUNCT.match(src, i)
            text = m2.group() if m2 else ch
            if templates and text == "{":
                templates[-1] += 1
            elif templates and text == "}":
                templates[-1] -= 1
            tok = Token("punct", text, line)
            i += len(text)
        prev = tok
        yield tok


def _string(src: str, i: int, quote: str) -> tuple[int, str, int]:
    """End index, contents and newlines crossed for a quoted string starting at ``i``."""
    j, n, line = i + 1, len(src), 0
    out: list[str] = []
    while j < n:
        c = src[j]
        if c == "\\" and j + 1 < n:
            if src[j + 1] == "\n":
                line += 1
            out.append(src[j : j + 2])
            j += 2
            continue
        if c == quote:
            return j + 1, "".join(out), line
        if c == "\n":
            break  # an unterminated string ends at the line
        out.append(c)
        j += 1
    return j, "".join(out), line


def _template(src: str, j: int) -> tuple[int, str, int, bool]:
    """Scan template text from ``j`` to its closing backtick or the next ``${``.

    Returns the end index, the text, the newlines crossed, and whether a
    ``${`` expression was opened.
    """
    n, lines = len(src), 0
    start = j
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == "`":
            return j + 1, src[start:j], lines, False
        if c == "$" and src.startswith("${", j):
            return j + 2, src[start:j], lines, True
        if c == "\n":
            lines += 1
        j += 1
    return n, src[start:n], lines, False


def _regex(src: str, i: int) -> int:
    """End index of a regular expression literal starting at ``i``."""
    j, n, in_class = i + 1, len(src), False
    while j < n:
        c = src[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            return j  # not a regex after all; stop at the line
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            j += 1
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            return j
        j += 1
    return j


def _module_name(spec: str) -> str | None:
    """The built-in module a specifier names (``node:child_process``, ``child_process/x``)."""
    base = spec.removeprefix("node:").split("/", 1)[0]
    return base if base in SENSITIVE_MODULES else None


@dataclass(frozen=True)
class FileScan:
    uses: tuple[JsUse, ...]
    relative: tuple[str, ...]  # the relative specifiers the file requires or imports


def scan(path: str, src: str) -> FileScan:
    """The sensitive uses in one file and the relative modules it loads."""
    toks = list(tokens(src))
    # Function bodies: (open index, close index), and whether each is invoked
    # where it is defined, as in (function () { … })() or !function () { … }().
    bodies: list[tuple[int, int]] = []
    stack: list[tuple[int, bool]] = []  # (open index, is a function body)
    for k, t in enumerate(toks):
        if t.kind != "punct":
            continue
        if t.text == "{":
            stack.append((k, _opens_function(toks, k)))
        elif t.text == "}" and stack:
            start, is_fn = stack.pop()
            if is_fn:
                bodies.append((start, k))
    deferred = [(a, b) for a, b in bodies if not _invoked(toks, a, b)]

    def at_load(k: int) -> bool:
        return not any(a < k < b for a, b in deferred)

    uses: list[JsUse] = []
    relative: list[str] = []
    for k, t in enumerate(toks):
        spec = _loaded_specifier(toks, k)
        if spec is not None:
            if spec.startswith((".", "/")):
                relative.append(spec)
            elif (mod := _module_name(spec)) is not None:
                uses.append(JsUse(path, t.line, SENSITIVE_MODULES[mod], mod, at_load(k)))
            continue
        if t.kind != "name" or _member(toks, k):
            continue
        nxt = toks[k + 1] if k + 1 < len(toks) else None
        if t.text in _CALLED_GLOBALS and nxt is not None and nxt.text == "(":
            if not _defines(toks, k):
                uses.append(JsUse(path, t.line, _CALLED_GLOBALS[t.text], t.text, at_load(k)))
        elif t.text in _NAMED_GLOBALS:
            uses.append(JsUse(path, t.line, _NAMED_GLOBALS[t.text], t.text, at_load(k)))
    obfuscated = [
        k for k, t in enumerate(toks) if t.kind == "name" and _OBFUSCATED.fullmatch(t.text)
    ]
    if len(obfuscated) >= OBFUSCATED_MIN:
        k = obfuscated[0]
        uses.append(JsUse(path, toks[k].line, "obfuscated", "_0x… names", at_load(k)))
    return FileScan(tuple(uses), tuple(relative))


def _member(toks: list[Token], k: int) -> bool:
    """True when ``toks[k]`` is a property (``x.eval``, ``x?.fetch``) or a key (``{eval: …}``)."""
    if k > 0 and toks[k - 1].text in (".", "?."):
        return True
    return 0 < k < len(toks) - 1 and toks[k + 1].text == ":" and toks[k - 1].text in ("{", ",")


def _defines(toks: list[Token], k: int) -> bool:
    """True when the name at ``k`` is being defined, not called: ``function
    fetch(…) {`` or a method ``async fetch(…) {`` (lru-cache has one)."""
    if k > 0 and toks[k - 1].text == "function":
        return True
    depth = 0
    for j in range(k + 1, len(toks)):
        if toks[j].text == "(":
            depth += 1
        elif toks[j].text == ")":
            depth -= 1
            if depth == 0:
                return j + 1 < len(toks) and toks[j + 1].text == "{"
    return False


def _loaded_specifier(toks: list[Token], k: int) -> str | None:
    """The module ``toks[k]`` starts loading, for ``require("x")``, ``import("x")``,
    ``import … from "x"``, ``import "x"`` and ``export … from "x"``."""
    t = toks[k]
    if t.kind != "name" or _member(toks, k):
        return None
    if t.text in ("require", "import") and k + 2 < len(toks) and toks[k + 1].text == "(":
        arg = toks[k + 2]
        if arg.kind in ("string", "template") and k + 3 < len(toks) and toks[k + 3].text == ")":
            return arg.text
        return None
    if t.text == "import" and k + 1 < len(toks) and toks[k + 1].kind == "string":
        return toks[k + 1].text
    if t.text == "from" and k + 1 < len(toks) and toks[k + 1].kind == "string":
        # ``from`` is only a keyword after an import or export clause.
        for j in range(k - 1, max(-1, k - 200), -1):
            if toks[j].text in ("import", "export"):
                return toks[k + 1].text
            if toks[j].text == ";":
                break
    return None


def _opens_function(toks: list[Token], k: int) -> bool:
    """True when the brace at ``k`` opens a function body."""
    if k == 0:
        return False
    before = toks[k - 1]
    if before.text == "=>":
        return True
    if before.text != ")":
        return False
    depth = 0
    for j in range(k - 1, -1, -1):
        if toks[j].text == ")":
            depth += 1
        elif toks[j].text == "(":
            depth -= 1
            if depth == 0:
                head = toks[j - 1] if j > 0 else None
                if head is None:
                    return False
                if head.kind == "name" and head.text in _BLOCK_KEYWORDS:
                    return False
                # function f(…) {, function (…) {, method(…) {, async (…) {
                return head.kind == "name" or head.text == "*"
    return False


def _invoked(toks: list[Token], open_: int, close: int) -> bool:
    """True when the function whose body runs from ``open_`` to ``close`` is
    called where it is defined: ``(function () { … })()``, ``!function () { … }()``
    or ``(() => { … }).call(this)``. A declaration followed by a statement
    that starts with ``(`` is not a call."""
    texts = [t.text for t in toks[close + 1 : close + 4]]
    if texts[:2] == [")", "("] or texts[:3] in ([")", ".", "call"], [")", ".", "apply"]):
        return True
    return texts[:1] == ["("] and _is_expression(toks, open_)


def _is_expression(toks: list[Token], open_: int) -> bool:
    """True when the ``function`` whose body opens at ``open_`` stands where an
    expression goes (after ``!``, ``=``, ``(``, ``,`` …), not as a statement."""
    if toks[open_ - 1].text != ")":
        return False  # an arrow body: ``=> { … }(`` doesn't parse
    depth = 0
    for j in range(open_ - 1, -1, -1):
        if toks[j].text == ")":
            depth += 1
        elif toks[j].text == "(":
            depth -= 1
            if depth == 0:
                k = j - 1
                if k >= 0 and toks[k].text != "function" and toks[k - 1].text in ("function", "*"):
                    k -= 1  # a named function expression: function name (…)
                while k >= 0 and toks[k].text in ("*",):
                    k -= 1
                if k < 0 or toks[k].text != "function":
                    return False  # a method: never called where it is defined
                before = toks[k - 1] if k > 0 else None
                if before is not None and before.text == "async":
                    before = toks[k - 2] if k > 1 else None
                return before is not None and before.text not in _STATEMENT_START
    return False


def entry_files(package_json: bytes, paths: set[str]) -> set[str]:
    """The files package.json names as ways in: ``main`` (``index.js`` when it
    is missing), ``module``, ``browser``, ``bin`` and every target in
    ``exports``. A target with a ``*`` matches files by its prefix and suffix."""
    try:
        doc = json.loads(package_json.decode("utf-8", "replace"))
    except ValueError:
        doc = {}
    if not isinstance(doc, dict):
        doc = {}
    targets: list[str] = []
    main = doc.get("main")
    targets.append(main if isinstance(main, str) else "index.js")
    for key in ("module", "browser", "bin", "exports"):
        _strings(doc.get(key), targets)
    out: set[str] = set()
    for target in targets:
        if "*" in target:
            head, _, tail = _clean(target).partition("*")
            out |= {p for p in paths if p.startswith(head) and p.endswith(tail)}
        elif (found := resolve(_clean(target), paths)) is not None:
            out.add(found)
    return out


def _strings(value: object, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _strings(v, out)
    elif isinstance(value, list):
        for v in value:
            _strings(v, out)


def _clean(path: str) -> str:
    return posixpath.normpath(path.lstrip("/")).removeprefix("./")


def resolve(target: str, paths: set[str]) -> str | None:
    """The file Node loads for ``target``: the file itself, with a JavaScript
    extension added, or the folder's ``index``."""
    if target in paths and target.endswith(_JS_EXT):
        return target
    for ext in _JS_EXT:
        if target + ext in paths:
            return target + ext
    for ext in _JS_EXT:
        if posixpath.join(target, "index" + ext) in paths:
            return posixpath.join(target, "index" + ext)
    return None


def is_js(path: str) -> bool:
    return path.endswith(_JS_EXT)


def loaded_uses(
    package_json: bytes | None, sources: Mapping[str, str], unread: frozenset[str] = frozenset()
) -> tuple[tuple[JsUse, ...], tuple[str, ...]]:
    """The sensitive uses in every file the package's entry points load,
    following relative requires and imports, sorted by path and line, and the
    loaded files in ``unread`` (present but not read, such as files over the
    size limit), whose uses are unknown."""
    paths = set(sources) | unread
    todo = sorted(entry_files(package_json or b"{}", paths), reverse=True)
    seen: set[str] = set()
    uses: list[JsUse] = []
    skipped: list[str] = []
    while todo:
        path = todo.pop()
        if path in seen:
            continue
        seen.add(path)
        if path not in sources:
            skipped.append(path)
            continue
        result = scan(path, sources[path])
        uses += result.uses
        here = posixpath.dirname(path)
        for spec in result.relative:
            target = _clean(posixpath.join(here, spec)) if spec.startswith(".") else _clean(spec)
            found = resolve(target, paths)
            if found is not None and found not in seen:
                todo.append(found)
    return tuple(sorted(uses, key=lambda u: (u.path, u.line, u.name))), tuple(sorted(skipped))
