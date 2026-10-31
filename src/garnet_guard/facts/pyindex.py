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
with a literal name. A name under the module that defines a listed one counts
as that name (``posix.system`` as ``os.system``, ``builtins.exec`` as
``exec``) and is recorded as written.
A ``base64.*decode`` whose result reaches a sensitive call is reported with
that call, so ``exec(base64.b64decode(...))`` is new even where ``exec`` was
already used.

Reads of credentials and CI settings in the same code are indexed too, as
call sites marked ``read``: an environment variable such as ``GITHUB_TOKEN``
or ``CI`` (``os.environ[...]``, ``os.getenv``, ``"CI" in os.environ``), the
whole environment (``dict(os.environ)``), or a cloud metadata address. They
are evidence, not sensitive calls; GRN-C003 reports new ones at info.
"""

from __future__ import annotations

import ast
import builtins
import copy
import hashlib
import re
import warnings
from collections.abc import Container, Iterable, Iterator, Mapping
from dataclasses import dataclass

from ..models import ARGS_TEXT_LIMIT, CallSite

SENSITIVE_SET_VERSION = "2026-10-c"

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
        # 2026-10-c: processes started without subprocess.
        "os.fork",
        "os.forkpty",
        "os.startfile",
        "pty.fork",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "multiprocessing.Process",
        "multiprocessing.context.SpawnProcess",  # what get_context("spawn").Process is
        "multiprocessing.context.ForkProcess",
        "multiprocessing.context.ForkServerProcess",
        "_winapi.CreateProcess",
        "distutils.spawn.spawn",
        "distutils.util.spawn",  # distutils.spawn.spawn, imported into these modules
        "distutils.ccompiler.spawn",
        "distutils.archive_util.spawn",
        "pydoc.pipepager",
        "pydoc.tempfilepager",
        # 2026-10-c: code loaded from a file or built from a code object.
        "importlib.__import__",  # importlib's own __import__, which imports as the builtin does
        "importlib.util.spec_from_file_location",
        "importlib.util.spec_from_loader",
        "imp.load_source",  # imp is deprecated, and present up to Python 3.11
        "imp.load_compiled",
        "imp.load_dynamic",
        "imp.load_module",
        "imp.load_package",
        "types.FunctionType",
        "types.LambdaType",  # the same type
        "types.CodeType",
        # 2026-10-c: network connections the prefixes below don't cover.
        "asyncio.open_connection",
        "asyncio.open_unix_connection",
        "asyncio.start_server",
        "asyncio.start_unix_server",
        "ssl.create_connection",  # the socket module's, imported into ssl
        "ssl.socket",
        "urllib3.PoolManager",
        "urllib3.ProxyManager",
        "urllib3.HTTPConnectionPool",
        "urllib3.HTTPSConnectionPool",
        "urllib3.connection_from_url",
        "urllib3.proxy_from_url",
        "urllib3.request",
        "urllib3.connection.HTTPConnection",
        "urllib3.connection.HTTPSConnection",
        "urllib3.connection.VerifiedHTTPSConnection",  # HTTPSConnection under another name
        "urllib3.contrib.socks.SOCKSProxyManager",
    }
)
_PREFIXES = (
    "os.exec",
    "os.spawn",
    "os.posix_spawn",
    "subprocess.",
    "_posixsubprocess.",
    "ctypes.",
    "runpy.",
    "zipimport.",
    "importlib.machinery.SourceFileLoader",
    "importlib.machinery.SourcelessFileLoader",
    "importlib.machinery.ExtensionFileLoader",
    "socket.",
    "urllib.request.",
    "http.client.",
    "httpx.",
    "requests.",
    "aiohttp.",
    "ftplib.",
    "smtplib.",
    "poplib.",
    "imaplib.",
    "telnetlib.",
    "xmlrpc.client.",
    "webbrowser.",
)
# 2026-10-c: names under a prefix above that build a value and start nothing:
# subprocess's exception and result classes, and the function that quotes a
# command line without running it.
_INERT = frozenset(
    {
        "subprocess.CalledProcessError",
        "subprocess.CompletedProcess",
        "subprocess.SubprocessError",
        "subprocess.TimeoutExpired",
        "subprocess.list2cmdline",
    }
)
# 2026-10-c: modules that define what a module above re-exports, or that
# re-export it, so a name under them is the same object: ``posix.system is
# os.system``. An empty target is the bare name: ``builtins.exec is exec``.
_SAME_AS: Mapping[str, tuple[str, ...]] = {
    "builtins": ("",),
    "posix": ("os",),
    "nt": ("os",),
    "_socket": ("socket",),
    "_ctypes": ("ctypes",),
    "_pickle": ("pickle",),
    "asyncio.subprocess": ("asyncio",),
    "asyncio.streams": ("asyncio",),
    "multiprocessing.context": ("multiprocessing",),
    "importlib._bootstrap": ("importlib", "importlib.util"),
    "_frozen_importlib": ("importlib", "importlib.util"),
    "importlib._bootstrap_external": ("importlib.machinery", "importlib.util"),
    "_frozen_importlib_external": ("importlib.machinery", "importlib.util"),
    "setuptools._distutils": ("distutils",),
    "urllib3.poolmanager": ("urllib3",),
    "urllib3.connectionpool": ("urllib3", "urllib3.connection"),
}
# Top-level names in the set that are packages on PyPI, each the import name of
# its project. Every other one is in the standard library or a builtin.
_THIRD_PARTY = frozenset({"requests", "httpx", "aiohttp", "urllib3", "setuptools"})
_BUILTINS = frozenset(dir(builtins))


def sensitive_set() -> tuple[str, ...]:
    """The §6.3 list as shown by ``garnet explain``."""
    return (
        *sorted(_EXACT),
        "importlib.import_module (non-literal argument)",
        *(_prefix_line(p) for p in _PREFIXES),
        "base64.*decode (when the result reaches one of the above)",
        *(
            f"{twin}.<name>, counted as {' or '.join(_under(t, '<name>') for t in targets)}"
            for twin, targets in sorted(_SAME_AS.items())
        ),
    )


def _prefix_line(prefix: str) -> str:
    """``prefix*``, naming the names under it that ``_INERT`` leaves out."""
    out = sorted(n[len(prefix) :] for n in _INERT if n.startswith(prefix))
    if not out:
        return prefix + "*"
    return f"{prefix}* except {', '.join(out[:-1])} and {out[-1]}, which start nothing"


def _under(module: str, name: str) -> str:
    """``module.name``, or the bare name for the empty module (builtins)."""
    return f"{module}.{name}" if module else name


# Reads of credentials and CI settings at import (GRN-C003 reports new ones at info).
READ_SET_VERSION = "2026-10-a"
_ENV_NAMES = frozenset({"CI", "GOOGLE_APPLICATION_CREDENTIALS"})
_ENV_PREFIXES = ("GITHUB_", "ACTIONS_", "AWS_", "AZURE_", "GCP_", "NPM_", "PYPI_", "TWINE_")
_ENV_SUFFIXES = ("_TOKEN", "_SECRET", "_SECRET_KEY", "_API_KEY", "_ACCESS_KEY", "_PASSWORD")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,99}")
_ENV_GETTERS = frozenset(
    {"os.getenv", "os.getenvb", "os.environ.get", "os.environ.setdefault", "os.environ.pop"}
)
_ENV_COPIES = frozenset({"copy", "items", "keys", "values"})
_METADATA_HOSTS = (
    "169.254.169.254",  # AWS, Azure, GCP, Oracle and others
    "169.254.170.2",  # AWS ECS task credentials
    "fd00:ec2::254",  # AWS over IPv6
    "metadata.google.internal",
    "100.100.100.200",  # Alibaba Cloud
)
WHOLE_ENVIRONMENT = "the whole environment (os.environ)"


def credential_env(name: str) -> bool:
    """An environment variable that holds a credential or says the code runs in CI."""
    if not _ENV_NAME.fullmatch(name):
        return False
    upper = name.upper()
    return upper in _ENV_NAMES or upper.startswith(_ENV_PREFIXES) or upper.endswith(_ENV_SUFFIXES)


def _env_read(name: str) -> str:
    return f"environment variable {name}"


def _reads(node: ast.AST, resolver: _Resolver) -> list[str]:
    """What this node reads that a credential stealer reads, as call-site names."""

    def environ(expr: ast.expr) -> bool:
        return resolver.resolve(expr) == "os.environ"

    out: list[str] = []
    if isinstance(node, ast.Call):
        name = resolver.resolve(node.func)
        key = _const_str(node.args[0]) if node.args else None
        if name in _ENV_GETTERS and key is not None and credential_env(key):
            out.append(_env_read(key))
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _ENV_COPIES and environ(func.value):
            out.append(WHOLE_ENVIRONMENT)
        # dict(os.environ), json.dumps(os.environ); env=os.environ only hands it on
        values = [*node.args, *(k.value for k in node.keywords if k.arg != "env")]
        values = [v.value if isinstance(v, ast.Starred) else v for v in values]
        if any(environ(v) for v in values):
            out.append(WHOLE_ENVIRONMENT)
    elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
        key = _const_str(node.slice)
        if key is not None and credential_env(key) and environ(node.value):
            out.append(_env_read(key))
    elif isinstance(node, ast.Compare) and len(node.ops) == 1:
        key = _const_str(node.left)
        if (
            isinstance(node.ops[0], (ast.In, ast.NotIn))
            and key is not None
            and credential_env(key)
            and environ(node.comparators[0])
        ):
            out.append(_env_read(key))
    elif isinstance(node, ast.Dict):
        if any(k is None and environ(v) for k, v in zip(node.keys, node.values, strict=True)):
            out.append(WHOLE_ENVIRONMENT)  # {**os.environ}
    elif isinstance(node, ast.Constant) and isinstance(node.value, str):
        out += [f"cloud metadata address {h}" for h in _METADATA_HOSTS if h in node.value]
    return out


def is_sensitive(name: str, call: ast.Call | None = None) -> bool:
    """True if calling ``name`` is in the sensitive set.

    ``importlib.import_module`` counts only with a non-literal argument. A
    name under a module in ``_SAME_AS`` counts as the name it re-exports.
    """
    names = [name]
    for twin, targets in _SAME_AS.items():
        if name.startswith(twin + "."):
            names += [_under(t, name[len(twin) + 1 :]) for t in targets]
    return any(_listed(n, call) for n in names)


def _listed(name: str, call: ast.Call | None) -> bool:
    if name in _EXACT:
        return True
    if name == "importlib.import_module":
        if call is None:
            return True
        return not (call.args and isinstance(call.args[0], ast.Constant))
    return name not in _INERT and any(name.startswith(p) for p in _PREFIXES)


def _own(name: str, own: Container[str], project: str | None, call: ast.Call | None = None) -> bool:
    """Whether a call to ``name`` is the release's own code, not a call in the set.

    A call in the set stays one whatever top-level modules the release ships:
    Python may not import an empty ``os.py``, ``requests.py`` or ``builtins.py``
    beside the package under that name at all, because the standard library
    comes first on ``sys.path``, an installed package directory comes before a
    module of the same name in site-packages, and ``builtins`` is built in.
    The one exception is the library itself: the ``requests`` project
    (``project``, the release's normalized name) calling its own
    ``requests.adapters``. ``scan_module`` follows a call into a module the
    release ships either way.
    """
    head = name.split(".")[0]
    if head not in own:
        return False
    if not is_sensitive(name, call):
        return True
    return head in _THIRD_PARTY and head == project


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
        # ``__builtins__`` is the builtins module in a script (``setup.py``).
        self.aliases: dict[str, str] = {"__builtins__": "builtins"}
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
        if head in self.defined:
            return None  # the module's own function, class or variable shadows the name
        if head not in _BUILTINS:
            # A bare name after ``from subprocess import *`` may be subprocess.run.
            for mod in self.star_modules:
                name = ".".join([mod, head, *rest])
                if is_sensitive(name):
                    return name
        root = func
        while isinstance(root, ast.Attribute):
            root = root.value
        if rest and isinstance(root, ast.Name):
            # ``requests.append(r)`` on a local list, or ``socket.settimeout`` on a
            # local beside ``import socket as socket_``: the head is no module here.
            return None
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


def parse(source: bytes, *, path: str = "<module>") -> ast.Module:
    """Parse source with ``ast``, never compiling or running it. Raises
    SyntaxError/ValueError. ``scan_module`` and ``sensitive_calls`` take the
    tree, so a file both read is parsed once."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # package source triggers SyntaxWarnings
        return ast.parse(source, filename=path)


@dataclass(frozen=True)
class ModuleScan:
    """What one module runs, from its body or from one of its callables."""

    calls: tuple[CallSite, ...]  # sensitive calls reached
    imports: tuple[str, ...]  # modules the file imports
    calls_out: tuple[str, ...]  # the package's own callables it calls, dotted
    handed_out: tuple[tuple[str, str], ...] = ()  # own callables handed to a call, with the call


def scan_module(
    source: bytes,
    *,
    path: str = "<module>",
    own: frozenset[str] = frozenset(),
    project: str | None = None,
    module: str | None = None,
    entry: str | None = None,
    handed: str | None = None,
    tree: ast.Module | None = None,
) -> ModuleScan:
    """Index what runs at import, or what runs when ``entry`` is called.

    Raises SyntaxError/ValueError. ``own`` names the release's own top-level
    packages, and calls into them are returned as ``calls_out``. A call in the
    set among them is a sensitive call as well, unless ``project`` (the
    release's normalized name) is the library it belongs to: the ``requests``
    project calling its own ``requests.adapters`` (see ``_own``). ``module`` is
    the dotted module name,
    used to resolve relative imports. ``entry`` is a function, ``Class``
    (instantiation) or ``Class.method`` defined in the module; an unknown
    entry runs nothing. ``handed`` names the call that ``entry`` was handed to
    when that call is not known to run it; it is carried on every call site.
    ``tree`` is ``source`` already parsed.
    """
    if tree is None:
        tree = parse(source, path=path)
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
    handed_out: set[tuple[str, str]] = set()
    seen: set[str] = set()
    decoded: dict[str, str] = {}  # name → the base64 decode it was assigned from

    def scan(
        nodes: Iterable[ast.AST],
        via: str | None,
        scope: Mapping[str, list[ast.AST]] | None = None,
        handed: str | None = None,
    ) -> None:
        # Callables these statements can reach by name: the module's, plus any
        # function defined inside the body being scanned (mrmustard 0.7.4 ran
        # ``threading.Thread(target=_run).start()`` on a ``_run`` nested in the
        # function it called at import). ``handed`` is the call the function
        # being scanned was handed to (``partial(f)``, ``Thread(target=f)``);
        # whether that call runs it is for the check to judge, so every call
        # site found from here carries it.
        local: dict[str, list[ast.AST]] = dict(scope if scope is not None else reachable)
        reached: list[tuple[str, str | None]] = []
        for node in _walk_exec(nodes):
            for read in _reads(node, resolver):
                calls.append(
                    CallSite(read, getattr(node, "lineno", 0), via, handed_to=handed, read=True)
                )
            if isinstance(node, ast.Call):
                args = [*node.args, *(k.value for k in node.keywords)]
                name = resolver.resolve(node.func)
                if name is not None and name.split(".")[0] in own:
                    # Followed into the module the release ships, also when the
                    # call counts below: that module may be the one Python imports.
                    if handed is None:
                        calls_out.add(name)
                    else:
                        handed_out.add((name, handed))
                if (
                    name is not None
                    and is_sensitive(name, node)
                    and not _own(name, own, project, node)
                ):
                    calls.append(CallSite(name, node.lineno, via, handed_to=handed))
                    for decode in _decoded_inputs(args, resolver, decoded):
                        calls.append(
                            CallSite(f"{decode} → {name}", node.lineno, via, handed_to=handed)
                        )
                # The call runs its target; ``partial(f)()`` runs f too. What it is
                # handed (``Thread(target=f)``, ``partial(f)``) is followed as handed.
                called = _local_refs([node.func], local)
                if isinstance(node.func, ast.Call):
                    inner = node.func
                    called += _local_refs([*inner.args, *(k.value for k in inner.keywords)], local)
                reached += [(key, handed) for key in called]
                to = handed or _display(node.func, resolver, own, project)
                reached += [(key, to) for key in _local_refs(args, local)]
                for arg in args:
                    if isinstance(arg, (ast.Name, ast.Attribute)):
                        target = resolver.resolve(arg)
                        if target is not None and target.split(".")[0] in own:
                            handed_out.add((target, to))
                if isinstance(node.func, ast.Lambda):
                    scan([node.func.body], via or "<lambda>", local, handed)
                for lam in (a for a in args if isinstance(a, ast.Lambda)):
                    scan([lam.body], via or "<lambda>", local, to)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                reached += [(key, handed) for key in _local_refs(node.decorator_list, local)]
                if not isinstance(node, ast.ClassDef):
                    local[node.name] = list(node.body)
            elif isinstance(node, ast.Assign):
                resolver.note_assignment(node)
                for decode in _decoded_inputs([node.value], resolver, decoded):
                    decoded.update((t.id, decode) for t in node.targets if isinstance(t, ast.Name))
                if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    if isinstance(node.value, ast.Lambda):
                        local[node.targets[0].id] = [node.value.body]
        reached.sort(key=lambda r: r[1] is not None)  # a function both called and handed: called
        for key, ctx in reached:
            nested = key not in reachable
            mark = f"{via}.{key}" if nested else key  # two functions may nest the same name
            if mark in seen:
                continue
            if ctx is None:
                seen.add(mark)
            elif f"{mark}@{ctx}" in seen:
                continue  # handed to two different calls: scanned once per call
            else:
                seen.add(f"{mark}@{ctx}")
            scan(local[key], key, local if nested else None, ctx)

    if entry is None:
        scan(tree.body, None, None, handed)
    elif entry in reachable:
        seen.add(entry)
        scan(reachable[entry], entry, None, handed)
    uniq = sorted(set(calls), key=lambda c: (c.line, c.name, c.via or "", c.handed_to or ""))
    return ModuleScan(
        tuple(uniq),
        tuple(sorted(i for i in resolver.imports if i)),
        tuple(sorted(calls_out)),
        tuple(sorted(handed_out)),
    )


def _display(func: ast.expr, resolver: _Resolver, own: frozenset[str], project: str | None) -> str:
    """The call a function was handed to, as the finding names it."""
    name = resolver.resolve(func)
    if name is not None and not _own(name, own, project):
        return name
    return ast.unparse(func)[:60]


def index_module(
    source: bytes,
    *,
    path: str = "<module>",
    own: frozenset[str] = frozenset(),
    project: str | None = None,
    module: str | None = None,
) -> tuple[tuple[CallSite, ...], tuple[str, ...]]:
    """Return (import-time call sites, imports). Raises SyntaxError/ValueError."""
    scan = scan_module(source, path=path, own=own, project=project, module=module)
    return scan.calls, scan.imports


def module_name(path: str) -> str:
    """The dotted name for a path: ``pkg/sub/__init__.py`` is ``pkg.sub``."""
    p = path[:-3] if path.endswith(".py") else path
    if p.endswith("/__init__"):
        p = p[: -len("/__init__")]
    return p.replace("/", ".")


def sensitive_calls(
    source: bytes,
    *,
    path: str = "<module>",
    own: frozenset[str] = frozenset(),
    project: str | None = None,
    tree: ast.Module | None = None,
    with_args: bool = False,
) -> tuple[CallSite, ...]:
    """Every sensitive call in a file, at any depth. Raises SyntaxError/ValueError.

    ``scan_module`` asks what runs at import. This asks what the file can do
    at all. ``setup.py`` runs as a script when the sdist is built, and a
    ``cmdclass`` hook in it runs at install, so a call inside a function or a
    method counts too (GRN-C002). GRN-C007 compares a published file with the
    same file in the source repository, where a call that only exists in the
    published copy matters whether or not anything calls it at import.
    ``via`` names the enclosing function or ``Class.method``. ``own`` and
    ``project`` leave out calls into the release's own packages, as in
    ``scan_module``. ``tree`` is ``source`` already parsed. ``with_args``
    records each call's arguments (``call_arguments``). A file nested
    deeper than Python's recursion limit raises RecursionError.
    """
    if tree is None:
        tree = parse(source, path=path)
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
                    if name is not None and not _own(name, own, project, child):
                        if is_sensitive(name, child):
                            args, key = call_arguments(child) if with_args else (None, None)
                            calls.append(
                                CallSite(
                                    name=name, line=child.lineno, via=via, args=args, args_key=key
                                )
                            )
                visit(child, via)

    visit(tree, None)
    return tuple(sorted(set(calls), key=lambda c: (c.line, c.name, c.via or "", c.args_key or "")))


class _Plain(ast.NodeTransformer):
    """Drop what doesn't change a value: the ``u`` prefix of a string literal."""

    def visit_Constant(self, node: ast.Constant) -> ast.Constant:
        node.kind = None
        return node


def call_arguments(call: ast.Call) -> tuple[str, str]:
    """A call's arguments as text, and a key that is equal for equal arguments.

    Nothing is evaluated: two calls have the same key when their argument
    trees are the same, with positions, formatting, comments, quote style and
    a ``u`` string prefix left out, and keyword arguments sorted by name
    (``**`` arguments after them, in their order). Python binds keywords by
    name, so their order doesn't change what the call receives. Any other
    difference, ``['make']`` against ``('make',)`` or a renamed variable,
    gives a different key. The text is ``ast.unparse`` of the same tree in
    parentheses, clipped to ``ARGS_TEXT_LIMIT`` characters; the key is a
    SHA-256 of the whole tree's ``ast.dump``.
    """
    keywords = sorted(call.keywords, key=lambda k: (k.arg is None, k.arg or ""))
    shape = _Plain().visit(
        copy.deepcopy(ast.Call(func=ast.Name("_", ast.Load()), args=call.args, keywords=keywords))
    )
    text = ast.unparse(shape)[1:]
    if len(text) > ARGS_TEXT_LIMIT:
        text = text[: ARGS_TEXT_LIMIT - 1] + "…"
    key = hashlib.sha256(ast.dump(shape).encode()).hexdigest()
    return text, key


def index_build_script(source: bytes, *, path: str = "setup.py") -> tuple[CallSite, ...]:
    """Every sensitive call in a build script, at any depth, with its arguments
    (see ``sensitive_calls``)."""
    return sensitive_calls(source, path=path, with_args=True)
