"""Static index of a Python module: what runs at import time.

Parses source with ``ast`` only. Nothing is imported or executed.

"Top level" means statements that run when the module is imported: module
statements, class bodies, decorators and default arguments, plus the bodies
of functions in the same module that top-level code calls, decorates with,
or passes to a call (``threading.Thread(target=f)``, ``atexit.register(f)``).
A function that is only returned or stored is not followed.
Code under ``if __name__ == "__main__":`` is skipped.
"""

from __future__ import annotations

import ast
import warnings
from collections.abc import Iterable, Iterator, Mapping

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
    """True if calling ``name`` is in the sensitive set.

    ``importlib.import_module`` counts only with a non-literal argument.
    """
    if name in _EXACT:
        return True
    if name == "importlib.import_module":
        if call is None:
            return True
        return not (call.args and isinstance(call.args[0], ast.Constant))
    return any(name.startswith(p) for p in _PREFIXES)


def _dotted(node: ast.expr) -> list[str] | None:
    """``a.b.c`` as ``["a", "b", "c"]``, or None if it isn't a plain dotted name."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return list(reversed(parts))
    return None


class _Resolver:
    """Tracks imports and aliases, so ``sp.run`` resolves to ``subprocess.run``."""

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}
        self.imports: set[str] = set()
        self.package: str | None = None  # this module's package, for relative imports

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
                # Relative imports don't alias outside names; record what they
                # load so callers can tell which of the package's modules run.
                base = self._relative_base(node.level)
                if base is not None:
                    mod = ".".join(p for p in (base, node.module or "") if p)
                    self.imports.add(mod)
                    self.imports.update(f"{mod}.{a.name}" for a in node.names if a.name != "*")
                return
            mod = node.module or ""
            self.imports.add(mod)
            for a in node.names:
                self.aliases[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name
                if mod and a.name != "*":
                    self.imports.add(f"{mod}.{a.name}")  # may be a submodule

    def _relative_base(self, level: int) -> str | None:
        if self.package is None:
            return None
        parts = self.package.split(".") if self.package else []
        if level - 1 > len(parts):
            return None
        return ".".join(parts[: len(parts) - (level - 1)])

    def resolve(self, func: ast.expr) -> str | None:
        parts = _dotted(func)
        if not parts:
            return None
        head = self.aliases.get(parts[0], parts[0])
        return ".".join([head, *parts[1:]])


def _is_main_guard(node: ast.stmt) -> bool:
    """True for ``if __name__ == "__main__":``, which doesn't run on import."""
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
            yield node  # for its decorators; the body runs only when called
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


def _local_refs(exprs: Iterable[ast.expr], functions: Mapping[str, ast.AST]) -> list[str]:
    """Local functions that a call or decorator runs or is handed.

    Only a call's target, its direct arguments (``Thread(target=f)``,
    ``atexit.register(f)``) and decorators count. A function that is merely
    returned or stored is not reached.
    """
    out = []
    for e in exprs:
        if isinstance(e, ast.Starred):
            e = e.value
        if isinstance(e, ast.Name) and e.id in functions:
            out.append(e.id)
    return out


def index_module(
    source: bytes,
    *,
    path: str = "<module>",
    own: frozenset[str] = frozenset(),
    module: str | None = None,
) -> tuple[tuple[CallSite, ...], tuple[str, ...]]:
    """Return (import-time call sites, imports). Raises SyntaxError/ValueError.

    ``own`` names the release's own top-level packages; calls into them are
    not sensitive even if the names collide (the ``requests`` package calling
    its own ``requests.adapters``). ``module`` is the dotted module name, used
    to resolve relative imports into the imports list.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # package source triggers SyntaxWarnings
        tree = ast.parse(source, filename=path)
    resolver = _Resolver()
    if module is not None:
        is_pkg = path.endswith("__init__.py")
        resolver.package = module if is_pkg else module.rpartition(".")[0]
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
                reached += _local_refs(
                    [node.func, *node.args, *(k.value for k in node.keywords)], functions
                )
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                reached += _local_refs(node.decorator_list, functions)
        for fname in reached:
            if fname not in seen_funcs:
                seen_funcs.add(fname)
                scan(functions[fname].body, fname)

    scan(tree.body, None)
    uniq = sorted(set(calls), key=lambda c: (c.line, c.name, c.via or ""))
    return tuple(uniq), tuple(sorted(i for i in resolver.imports if i))


def module_name(path: str) -> str:
    """The dotted name for a path: ``pkg/sub/__init__.py`` is ``pkg.sub``."""
    p = path[:-3] if path.endswith(".py") else path
    if p.endswith("/__init__"):
        p = p[: -len("/__init__")]
    return p.replace("/", ".")
