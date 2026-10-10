"""Static index of a Python module: what runs at import time.

Parses source with ``ast`` only. Nothing is imported or executed.

"Top level" means statements that run when the module is imported: module
statements, class bodies, decorators and default arguments, plus the bodies
of functions in the same module that top-level code calls or hands to
something else (``threading.Thread(target=f)``, ``atexit.register(f)``).
Code under ``if __name__ == "__main__":`` is skipped.
"""

from __future__ import annotations

import ast
import warnings
from collections.abc import Iterable, Iterator

from ..models import CallSite

SENSITIVE_SET_VERSION = "2026-10-a"

# SPEC §6.3. Exact names, and prefixes that match a module and everything in it.
_EXACT = frozenset(
    {
        "exec",
        "eval",
        "compile",
        "__import__",
        "os.system",
        "os.popen",
        "pty.spawn",
        "marshal.loads",
        "pickle.loads",
    }
)
_PREFIXES = (
    "os.exec",
    "os.spawn",
    "os.posix_spawn",
    "subprocess.",
    "ctypes.",
    "socket.",
    "urllib.request.",
    "http.client.",
    "httpx.",
    "requests.",
    "aiohttp.",
)


def sensitive_set() -> tuple[str, ...]:
    """The §6.3 list as shown by ``garnet explain``."""
    return (
        *sorted(_EXACT),
        "importlib.import_module (non-literal argument)",
        *(p + "*" for p in _PREFIXES),
        "base64.*decode (when the result reaches one of the above)",
    )


def is_sensitive(name: str, call: ast.Call | None = None) -> bool:
    if name in _EXACT:
        return True
    if name == "importlib.import_module":
        if call is None:
            return True
        return not (call.args and isinstance(call.args[0], ast.Constant))
    return any(name.startswith(p) for p in _PREFIXES)


def _dotted(node: ast.expr) -> list[str] | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return list(reversed(parts))
    return None


class _Resolver:
    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}
        self.imports: set[str] = set()

    def note_import(self, node: ast.Import | ast.ImportFrom) -> None:
        if isinstance(node, ast.Import):
            for a in node.names:
                self.imports.add(a.name)
                if a.asname:
                    self.aliases[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    self.aliases[top] = top
        else:
            if node.level:
                return  # relative imports stay inside the package
            mod = node.module or ""
            self.imports.add(mod)
            for a in node.names:
                self.aliases[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name

    def resolve(self, func: ast.expr) -> str | None:
        parts = _dotted(func)
        if not parts:
            return None
        head = self.aliases.get(parts[0], parts[0])
        return ".".join([head, *parts[1:]])


def _is_main_guard(node: ast.stmt) -> bool:
    if not isinstance(node, ast.If):
        return False
    t = node.test
    return (
        isinstance(t, ast.Compare)
        and isinstance(t.left, ast.Name)
        and t.left.id == "__name__"
        and len(t.comparators) == 1
        and isinstance(t.comparators[0], ast.Constant)
        and t.comparators[0].value == "__main__"
    )


def _walk_exec(nodes: Iterable[ast.AST]) -> Iterator[ast.AST]:
    """Yield nodes that execute when these statements run (not function bodies)."""
    stack = list(nodes)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stack.extend(node.decorator_list)
            stack.extend(d for d in node.args.defaults)
            stack.extend(d for d in node.args.kw_defaults if d is not None)
            continue
        if isinstance(node, ast.Lambda):
            continue
        if isinstance(node, ast.stmt) and _is_main_guard(node):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def index_module(
    source: bytes, *, path: str = "<module>", own: frozenset[str] = frozenset()
) -> tuple[tuple[CallSite, ...], tuple[str, ...]]:
    """Return (import-time call sites, imports). Raises SyntaxError/ValueError.

    ``own`` names the release's own top-level packages; calls into them are
    not sensitive even if the names collide (the ``requests`` package calling
    its own ``requests.adapters``).
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # package source triggers SyntaxWarnings
        tree = ast.parse(source, filename=path)
    resolver = _Resolver()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            resolver.note_import(node)

    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[stmt.name] = stmt

    calls: list[CallSite] = []
    seen_funcs: set[str] = set()

    def scan(nodes: Iterable[ast.AST], via: str | None) -> None:
        reached: list[str] = []
        for node in _walk_exec(nodes):
            if isinstance(node, ast.Call):
                name = resolver.resolve(node.func)
                if name is not None and name.split(".")[0] not in own and is_sensitive(name, node):
                    calls.append(CallSite(name=name, line=node.lineno, via=via))
            if isinstance(node, ast.Name) and node.id in functions:
                reached.append(node.id)
        for fname in reached:
            if fname not in seen_funcs:
                seen_funcs.add(fname)
                scan(functions[fname].body, fname)

    scan(tree.body, None)
    uniq = sorted(set(calls), key=lambda c: (c.line, c.name, c.via or ""))
    return tuple(uniq), tuple(sorted(i for i in resolver.imports if i))


def module_name(path: str) -> str:
    p = path[:-3] if path.endswith(".py") else path
    if p.endswith("/__init__"):
        p = p[: -len("/__init__")]
    return p.replace("/", ".")
