"""Static index of a Python module: what runs at import time.

Parses source with ``ast`` only. Nothing is imported or executed.

"Top level" means statements that run when the module is imported: module
statements, class bodies, decorators and default arguments, plus the bodies
of functions in the same module that top-level code calls, decorates with,
or passes to a call (``threading.Thread(target=f)``, ``atexit.register(f)``).
The same goes for lambdas it calls or passes, classes it instantiates (their
``__init__`` and ``__new__``) and methods it calls on those classes.
A function that is only returned or stored is not followed.
Code under ``if __name__ == "__main__":`` is skipped.

Calls into the package's own other modules are reported as ``calls_out``
(``memos.log.get_logger``), and ``scan_module`` can start at such a function
instead of the module body, so the inventory can follow a chain of calls
across modules.

Names are resolved through imports and simple aliasing (``sp = subprocess``),
``from x import *`` of a sensitive module, ``getattr(x, "name")`` with a
literal name, and ``__import__("x")`` or ``importlib.import_module("x")``
with a literal name. A ``base64.*decode`` whose result reaches a sensitive
call is reported with that call, so ``exec(base64.b64decode(...))`` is new
even where ``exec`` was already used.
"""

from __future__ import annotations

import ast
import builtins
import warnings
from collections.abc import Container, Iterable, Iterator, Mapping
from dataclasses import dataclass

from ..models import CallSite

SENSITIVE_SET_VERSION = "2026-10-b"

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
_BUILTINS = frozenset(dir(builtins))


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


def _is_decode(name: str) -> bool:
    """``base64.b64decode`` and friends."""
    return name.startswith("base64.") and name.endswith("decode")


def _const_str(node: ast.expr) -> str | None:
    """A string literal, or ``'a' + 'b'`` folded; None for anything else."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _const_str(node.left), _const_str(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _getattr_literal(call: ast.Call) -> str | None:
    """The attribute name in ``getattr(obj, "name")``."""
    if isinstance(call.func, ast.Name) and call.func.id == "getattr" and len(call.args) >= 2:
        return _const_str(call.args[1])
    return None


def _import_literal(call: ast.Call) -> str | None:
    """The module in ``__import__("m")`` or ``importlib.import_module("m")``."""
    func = call.func
    literal = (
        isinstance(func, ast.Name)
        and func.id == "__import__"
        or isinstance(func, ast.Attribute)
        and func.attr == "import_module"
        and isinstance(func.value, ast.Name)
        and func.value.id == "importlib"
    )
    if literal and call.args:
        return _const_str(call.args[0])
    return None


def _dotted(node: ast.expr, modules: Container[str] = ()) -> list[str] | None:
    """``a.b.c`` as ``["a", "b", "c"]``, or None if it isn't a plain dotted name.

    ``getattr(a, "b").c`` and ``__import__("a").b`` read the same way. So does
    ``getattr(<anything>, "m")`` when ``m`` names a module the file imported:
    num2words 0.5.15 wrote ``getattr(sys.modules[__name__], "ctypes")``.
    """
    parts: list[str] = []
    while True:
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Call) and (attr := _getattr_literal(node)) is not None:
            parts.append(attr)
            node = node.args[0]
            if attr in modules and not isinstance(node, (ast.Name, ast.Attribute, ast.Call)):
                return list(reversed(parts))
        else:
            break
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return list(reversed(parts))
    if isinstance(node, ast.Call) and (mod := _import_literal(node)) is not None:
        parts.extend(reversed(mod.split(".")))
        return list(reversed(parts))
    return None


class _Resolver:
    """Tracks imports and aliases, so ``sp.run`` resolves to ``subprocess.run``."""

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}
        self.imports: set[str] = set()
        self.star_modules: list[str] = []  # ``from m import *``, in order
        self.defined: set[str] = set()  # names the module defines itself
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
            return
        if node.level:
            # A relative import names one of the package's own modules; record
            # what it loads, and alias the names so calls into it can be followed.
            base = self._relative_base(node.level)
            if base is None:
                return
            mod = ".".join(p for p in (base, node.module or "") if p)
        else:
            mod = node.module or ""
        self.imports.add(mod)
        for a in node.names:
            if a.name == "*":
                if mod:
                    self.star_modules.append(mod)
                continue
            self.aliases[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name
            if mod:
                self.imports.add(f"{mod}.{a.name}")  # may be a submodule

    def note_assignment(self, node: ast.Assign) -> None:
        """``sp = subprocess`` or ``ct = getattr(..., "ctypes")`` aliases the name."""
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            return
        parts = _dotted(node.value, self.module_names())
        if parts is None:
            return
        head = parts[0]
        if head in self.aliases:
            self.aliases[node.targets[0].id] = ".".join([self.aliases[head], *parts[1:]])

    def _relative_base(self, level: int) -> str | None:
        if self.package is None:
            return None
        parts = self.package.split(".") if self.package else []
        if level - 1 > len(parts):
            return None
        return ".".join(parts[: len(parts) - (level - 1)])

    def module_names(self) -> set[str]:
        """Names bound to a module by a plain ``import m``."""
        return {k for k, v in self.aliases.items() if "." not in v}

    def resolve(self, func: ast.expr) -> str | None:
        parts = _dotted(func, self.module_names())
        if not parts:
            return None
        head, rest = parts[0], parts[1:]
        if head in self.aliases:
            return ".".join([self.aliases[head], *rest])
        if head not in self.defined and head not in _BUILTINS:
            # A bare name after ``from subprocess import *`` may be subprocess.run.
            for mod in self.star_modules:
                name = ".".join([mod, head, *rest])
                if is_sensitive(name):
                    return name
        return ".".join(parts)


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
    """Yield nodes that execute when these statements run (not function bodies).

    Nodes come out in source order, so an assignment is seen before the
    statement that uses the name.
    """
    stack = list(reversed(list(nodes)))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node  # for its decorators; the body runs only when called
            run_now = [*node.decorator_list, *node.args.defaults]
            run_now += [d for d in node.args.kw_defaults if d is not None]
            stack.extend(reversed(run_now))
            continue
        if isinstance(node, ast.Lambda):
            continue  # its body runs only when called; ``scan`` follows those
        if isinstance(node, ast.stmt) and _is_main_guard(node):
            continue
        yield node
        stack.extend(reversed(list(ast.iter_child_nodes(node))))


def _constructor(cls: ast.ClassDef, classes: Mapping[str, ast.ClassDef]) -> list[ast.stmt]:
    """What runs when the class is instantiated: ``__new__`` and ``__init__``.

    A class without either inherits them from a base defined in the module.
    """
    body: list[ast.stmt] = []
    seen: set[str] = set()
    todo = [cls]
    while todo:
        c = todo.pop(0)
        if c.name in seen:
            continue
        seen.add(c.name)
        for stmt in c.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if stmt.name in ("__new__", "__init__"):
                    body.extend(stmt.body)
        if body:
            return body
        todo.extend(classes[b.id] for b in c.bases if isinstance(b, ast.Name) and b.id in classes)
    return body


def _reachable(tree: ast.Module) -> dict[str, list[ast.AST]]:
    """Module-level callables by name, with what runs when each is called.

    Functions and stored lambdas by name, classes by name (instantiation) and
    their methods as ``Class.method``.
    """
    out: dict[str, list[ast.AST]] = {}
    classes: dict[str, ast.ClassDef] = {}
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[stmt.name] = list(stmt.body)
        elif isinstance(stmt, ast.ClassDef):
            classes[stmt.name] = stmt
        elif (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and isinstance(stmt.value, ast.Lambda)
        ):
            out[stmt.targets[0].id] = [stmt.value.body]
    for name, cls in classes.items():
        out[name] = list(_constructor(cls, classes))
        for stmt in cls.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out[f"{name}.{stmt.name}"] = list(stmt.body)
    return out


def _local_refs(exprs: Iterable[ast.expr], reachable: Mapping[str, object]) -> list[str]:
    """Module-level callables that a call or decorator runs or is handed.

    Only a call's target, its direct arguments (``Thread(target=f)``,
    ``atexit.register(f)``) and decorators count. A function that is merely
    returned or stored is not reached.
    """
    out = []
    for e in exprs:
        if isinstance(e, ast.Starred):
            e = e.value
        if isinstance(e, ast.Name) and e.id in reachable:
            out.append(e.id)
        elif isinstance(e, ast.Attribute):
            parts = _dotted(e)
            if parts and len(parts) == 2 and ".".join(parts) in reachable:
                out.append(".".join(parts))
    return out


def _decoded_inputs(
    args: Iterable[ast.expr], resolver: _Resolver, decoded: Mapping[str, str]
) -> list[str]:
    """``base64.*decode`` calls whose result is among these arguments.

    Direct (``exec(b64decode(x))``), wrapped (``exec(zlib.decompress(b64decode(x))))``)
    or through a name assigned from a decode in the same scope.
    """
    out: list[str] = []
    for arg in args:
        for sub in ast.walk(arg):
            if isinstance(sub, ast.Call):
                name = resolver.resolve(sub.func)
                if name is not None and _is_decode(name):
                    out.append(name)
            elif isinstance(sub, ast.Name) and sub.id in decoded:
                out.append(decoded[sub.id])
    return sorted(set(out))


@dataclass(frozen=True)
class ModuleScan:
    """What one module runs, from its body or from one of its callables."""

    calls: tuple[CallSite, ...]  # sensitive calls reached
    imports: tuple[str, ...]  # modules the file imports
    calls_out: tuple[str, ...]  # the package's own callables it calls, dotted


def scan_module(
    source: bytes,
    *,
    path: str = "<module>",
    own: frozenset[str] = frozenset(),
    module: str | None = None,
    entry: str | None = None,
) -> ModuleScan:
    """Index what runs at import, or what runs when ``entry`` is called.

    Raises SyntaxError/ValueError. ``own`` names the release's own top-level
    packages; calls into them are not sensitive even if the names collide
    (the ``requests`` package calling its own ``requests.adapters``) and are
    returned as ``calls_out`` instead. ``module`` is the dotted module name,
    used to resolve relative imports. ``entry`` is a function, ``Class``
    (instantiation) or ``Class.method`` defined in the module; an unknown
    entry runs nothing.
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
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            resolver.defined.add(stmt.name)
        elif isinstance(stmt, ast.Assign):
            resolver.defined.update(t.id for t in stmt.targets if isinstance(t, ast.Name))
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            resolver.defined.add(stmt.target.id)

    reachable = _reachable(tree)
    calls: list[CallSite] = []
    calls_out: set[str] = set()
    seen: set[str] = set()
    decoded: dict[str, str] = {}  # name → the base64 decode it was assigned from

    def scan(nodes: Iterable[ast.AST], via: str | None) -> None:
        reached: list[str] = []
        for node in _walk_exec(nodes):
            if isinstance(node, ast.Call):
                args = [node.func, *node.args, *(k.value for k in node.keywords)]
                name = resolver.resolve(node.func)
                if name is not None and name.split(".")[0] in own:
                    calls_out.add(name)
                elif name is not None and is_sensitive(name, node):
                    calls.append(CallSite(name=name, line=node.lineno, via=via))
                    for decode in _decoded_inputs(args[1:], resolver, decoded):
                        calls.append(CallSite(name=f"{decode} → {name}", line=node.lineno, via=via))
                reached += _local_refs(args, reachable)
                for lam in (a for a in args if isinstance(a, ast.Lambda)):
                    scan([lam.body], via or "<lambda>")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                reached += _local_refs(node.decorator_list, reachable)
            elif isinstance(node, ast.Assign):
                resolver.note_assignment(node)
                for decode in _decoded_inputs([node.value], resolver, decoded):
                    decoded.update((t.id, decode) for t in node.targets if isinstance(t, ast.Name))
        for key in reached:
            if key not in seen:
                seen.add(key)
                scan(reachable[key], key)

    if entry is None:
        scan(tree.body, None)
    elif entry in reachable:
        seen.add(entry)
        scan(reachable[entry], entry)
    uniq = sorted(set(calls), key=lambda c: (c.line, c.name, c.via or ""))
    return ModuleScan(
        tuple(uniq), tuple(sorted(i for i in resolver.imports if i)), tuple(sorted(calls_out))
    )


def index_module(
    source: bytes,
    *,
    path: str = "<module>",
    own: frozenset[str] = frozenset(),
    module: str | None = None,
) -> tuple[tuple[CallSite, ...], tuple[str, ...]]:
    """Return (import-time call sites, imports). Raises SyntaxError/ValueError."""
    scan = scan_module(source, path=path, own=own, module=module)
    return scan.calls, scan.imports


def module_name(path: str) -> str:
    """The dotted name for a path: ``pkg/sub/__init__.py`` is ``pkg.sub``."""
    p = path[:-3] if path.endswith(".py") else path
    if p.endswith("/__init__"):
        p = p[: -len("/__init__")]
    return p.replace("/", ".")


def index_build_script(source: bytes, *, path: str = "setup.py") -> tuple[CallSite, ...]:
    """Every sensitive call in a build script, at any depth. Raises SyntaxError/ValueError.

    ``setup.py`` runs as a script when the sdist is built, and a ``cmdclass``
    hook in it runs at install, so a call inside a function or a method counts
    too. ``via`` names the enclosing function or ``Class.method``.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        tree = ast.parse(source, filename=path)
    resolver = _Resolver()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            resolver.note_import(node)
    calls: list[CallSite] = []

    def visit(node: ast.AST, via: str | None) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, f"{via}.{child.name}" if via else child.name)
            elif isinstance(child, ast.ClassDef):
                visit(child, child.name)
            else:
                if isinstance(child, ast.Call):
                    name = resolver.resolve(child.func)
                    if name is not None and is_sensitive(name, child):
                        calls.append(CallSite(name=name, line=child.lineno, via=via))
                visit(child, via)

    visit(tree, None)
    return tuple(sorted(set(calls), key=lambda c: (c.line, c.name, c.via or "")))
