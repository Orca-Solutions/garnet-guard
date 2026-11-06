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
read in source order, ``from x import *`` of a sensitive module, ``getattr(x, "name")`` with a
literal name, and ``__import__("x")`` or ``importlib.import_module("x")``
with a literal name. A ``def`` without decorators rebinds its name for the
rest of the block it is in: a call there after it calls that function, even
when an alias for the name was assigned earlier in the walk, such as in the
other branch of an ``if`` (six's ``exec_``). A name under the module that defines a listed one counts
as that name (``posix.system`` as ``os.system``, ``builtins.exec`` as
``exec``) and is recorded as written.
A ``base64.*decode`` whose result reaches a sensitive call is reported with
that call, so ``exec(base64.b64decode(...))`` is new even where ``exec`` was
already used.

Encoded literals, values built from literals that reach ``exec`` or a name
lookup, and lookups on ``os``, ``sys``, ``builtins``, ``ctypes`` and
``importlib`` by a name the source doesn't hold are indexed as call sites
marked ``obscured``, for GRN-C005 (see ``obfuscation.py``).

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
from collections.abc import Callable, Container, Iterable, Iterator, Mapping
from dataclasses import dataclass
from functools import partial

from ..models import ARGS_TEXT_LIMIT, MAKEFILES, CallSite
from .obfuscation import Tracker, TreeFacts

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


# The modules a name in the set starts with, and the modules that hold the
# same objects: an import of one, by a name built from pieces, is GRN-C005's.
SENSITIVE_HEADS = frozenset(
    n.split(".")[0] for n in (*_EXACT, *_PREFIXES, *_SAME_AS, "importlib.import_module")
) - {"exec", "eval", "compile", "__import__", ""}


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
        # One per block being walked (``_walk_exec``): the names an undecorated
        # def bound in it, each with the alias it unbound (None: none).
        self._frames: list[dict[str, str | None]] = []

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

    def note_import_in_order(self, node: ast.Import | ast.ImportFrom) -> None:
        """An import met in the walk binds again a name that a def unbound
        (``bind_def``); every other alias stays as the walk left it."""
        aliases, imports, stars = dict(self.aliases), set(self.imports), list(self.star_modules)
        self.note_import(node)
        self.aliases.update(aliases)
        self.imports, self.star_modules = imports, stars

    def open_block(self) -> None:
        self._frames.append({})

    def bind_def(self, name: str) -> None:
        """An undecorated ``def name`` ran: until its block ends, ``name`` is
        that function, not an alias assigned before it."""
        if self._frames:
            self._frames[-1].setdefault(name, self.aliases.get(name))
            self.aliases.pop(name, None)

    def close_block(self) -> None:
        """After the block, the name may again hold what it held before (the
        branch with the def may not have run), so an alias the def unbound
        comes back unless something was assigned to the name since."""
        for name, alias in self._frames.pop().items():
            if alias is not None:
                self.aliases.setdefault(name, alias)

    def _bound(self, name: str) -> bool:
        return any(name in frame for frame in self._frames)

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
        if head in self.defined or self._bound(head):
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


@dataclass(frozen=True)
class _Mark:
    """A point in the walk that is not a node: a block of statements opens or
    closes, or an undecorated def binds its name."""

    kind: str  # "open", "close" or "bind"
    name: str = ""


_OPEN, _CLOSE = _Mark("open"), _Mark("close")


def _children(node: ast.AST) -> list[ast.AST | _Mark]:
    """``ast.iter_child_nodes``, in the same order, with each list of
    statements (an ``if`` or ``else`` branch, a loop, ``try`` or ``with``
    body, an ``except`` handler, a class body) between an open and a close."""
    out: list[ast.AST | _Mark] = []
    for _, value in ast.iter_fields(node):
        if isinstance(value, ast.AST):
            out.append(value)
        elif isinstance(value, list):
            block = bool(value) and all(isinstance(v, ast.stmt) for v in value)
            items = [v for v in value if isinstance(v, ast.AST)]
            out.extend([_OPEN, *items, _CLOSE] if block else items)
    return out


def _walk_exec(nodes: Iterable[ast.AST]) -> Iterator[ast.AST | _Mark]:
    """Yield nodes that execute when these statements run (not function bodies).

    Nodes come out in source order, so an assignment is seen before the
    statement that uses the name. Each block of statements, ``nodes`` too,
    comes between an open and a close mark, and an undecorated def is
    followed, after its default arguments, by a mark that it binds its name.
    """
    stack: list[ast.AST | _Mark] = list(reversed([_OPEN, *nodes, _CLOSE]))
    while stack:
        node = stack.pop()
        if isinstance(node, _Mark):
            yield node
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node  # for its decorators; the body runs only when called
            run_now: list[ast.AST | _Mark] = [*node.decorator_list, *node.args.defaults]
            run_now += [d for d in node.args.kw_defaults if d is not None]
            if not node.decorator_list:
                # A decorated def binds whatever the decorator returns.
                run_now.append(_Mark("bind", node.name))
            stack.extend(reversed(run_now))
            continue
        if isinstance(node, ast.Lambda):
            continue  # its body runs only when called; ``scan`` follows those
        if isinstance(node, ast.stmt) and _is_main_guard(node):
            continue
        yield node
        stack.extend(reversed(_children(node)))


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


@dataclass(frozen=True)
class ModulePrep:
    """A module parsed and read once, for ``scan_module`` to scan from its
    body or from any number of its callables: ``_follow_calls_out`` scans a
    module once per callable that import-time code reaches (sympy 1.14.0:
    34,843 scans of 1,533 modules), and parsing and reading the imports
    again each time cost more than the scans."""

    tree: ast.Module
    imports: tuple[ast.Import | ast.ImportFrom, ...]  # in ``ast.walk`` order
    defined: frozenset[str]  # names the module's top level binds
    reachable: Mapping[str, list[ast.AST]]  # ``_reachable``
    tree_facts: TreeFacts | None = None  # what GRN-C005's tracker reads first, when it is on


def prepare_module(
    source: bytes,
    *,
    path: str = "<module>",
    tree: ast.Module | None = None,
    obfuscation: bool = False,
) -> ModulePrep:
    """Parse ``source`` (or take ``tree``) and read what every scan of it
    needs, with GRN-C005's tree facts when ``obfuscation`` is on. Raises
    SyntaxError/ValueError."""
    if tree is None:
        tree = parse(source, path=path)
    imports = tuple(n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)))
    defined: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(stmt.name)
        elif isinstance(stmt, ast.Assign):
            defined.update(t.id for t in stmt.targets if isinstance(t, ast.Name))
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            defined.add(stmt.target.id)
    facts = TreeFacts.read(tree) if obfuscation else None
    return ModulePrep(tree, imports, frozenset(defined), _reachable(tree), facts)


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
    prep: ModulePrep | None = None,
    obfuscation: bool = True,
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
    ``tree`` is ``source`` already parsed, and ``prep`` is ``source`` already
    prepared (``prepare_module``), which saves the parse and the read of
    the imports when a module is scanned from several entries. With
    ``obfuscation`` off, GRN-C005's sites aren't read: that read costs
    about as much again as the rest.
    """
    if prep is None:
        prep = prepare_module(source, path=path, tree=tree)
    tree = prep.tree
    resolver = _Resolver()
    if module is not None:
        is_pkg = path.endswith("__init__.py")
        resolver.package = module if is_pkg else module.rpartition(".")[0]
    for node in prep.imports:
        resolver.note_import(node)
    resolver.defined.update(prep.defined)
    reachable = prep.reachable
    # GRN-C005, off by default: a None tracker reads nothing.
    tracker = (
        Tracker(resolver.resolve, is_sensitive, tree, SENSITIVE_HEADS, prep.tree_facts)
        if obfuscation
        else None
    )
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
            if isinstance(node, _Mark):
                if node is _OPEN:
                    resolver.open_block()
                elif node is _CLOSE:
                    resolver.close_block()
                else:
                    resolver.bind_def(node.name)
                continue
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                resolver.note_import_in_order(node)
            for read in _reads(node, resolver):
                calls.append(
                    CallSite(read, getattr(node, "lineno", 0), via, handed_to=handed, read=True)
                )
            if tracker is not None:
                obscured = tracker.sites(node)
                if isinstance(node, (ast.For, ast.AsyncFor, ast.AugAssign)):
                    obscured += tracker.forget(node.target)
                elif isinstance(node, ast.AnnAssign):
                    obscured += tracker.note_assign(node)
                for what, line, key in obscured:
                    calls.append(CallSite(what, line, via, handed_to=handed, obscured=key))
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
                if tracker is not None:
                    for what, line, key in tracker.note_assign(node):
                        calls.append(CallSite(what, line, via, handed_to=handed, obscured=key))
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
    """Return (import-time call sites, imports), without GRN-C005's sites.
    Raises SyntaxError/ValueError."""
    scan = scan_module(source, path=path, own=own, project=project, module=module)
    return tuple(c for c in scan.calls if c.obscured is None), scan.imports


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
    records each call's arguments (``call_arguments``), with a variable
    read as the literal it holds where ``_Bindings`` can tell. A file nested
    deeper than Python's recursion limit raises RecursionError.
    """
    if tree is None:
        tree = parse(source, path=path)
    resolver = _Resolver()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            resolver.note_import(node)
    # A name the file defines at top level shadows a module of the same name,
    # as in ``scan_module``; an alias assigned to it (``run = subprocess.call``)
    # still resolves, since aliases are looked up first.
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            resolver.defined.add(stmt.name)
        elif isinstance(stmt, ast.Assign):
            resolver.defined.update(t.id for t in stmt.targets if isinstance(t, ast.Name))
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            resolver.defined.add(stmt.target.id)
    found: list[tuple[ast.Call, str, str | None, ast.AST]] = []  # call, name, via, scope

    def visit(node: ast.AST, via: str | None, scope: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, f"{via}.{child.name}" if via else child.name, child)
            elif isinstance(child, ast.ClassDef):
                visit(child, child.name, child)
            else:
                if isinstance(child, ast.Assign):
                    # ``run = subprocess.call`` or ``sp = subprocess``: a call
                    # through the alias is the call it names, from here on.
                    resolver.note_assignment(child)
                if isinstance(child, ast.Call):
                    name = resolver.resolve(child.func)
                    if name is not None and not _own(name, own, project, child):
                        if is_sensitive(name, child):
                            found.append((child, name, via, scope))
                visit(child, via, child if isinstance(child, _SCOPES) else scope)

    visit(tree, None, tree)
    if not with_args:
        # Without arguments, a call is one per line and name.
        calls = {CallSite(name=name, line=call.lineno, via=via) for call, name, via, _ in found}
        return tuple(sorted(calls, key=lambda c: (c.line, c.name, c.via or "")))
    # With arguments, each call is kept: two identical calls on one line are
    # two calls a trusted setup.py may have made once. A variable passed to
    # one of these calls is followed to its value when nothing else touches it.
    shapes = _Shapes(tree, source)
    passed = {id(a) for call, *_ in found for a in (*call.args, *(k.value for k in call.keywords))}
    bindings = _Bindings(tree, passed)
    kept = []
    for call, name, via, scope in found:
        follow = partial(bindings.value, scope)
        args, key = call_arguments(call, shapes, follow)
        kept.append(
            CallSite(
                name=name,
                line=call.lineno,
                via=via,
                args=args,
                args_key=key,
                mentions=argument_mentions(call, follow),
            )
        )
    return tuple(sorted(kept, key=lambda c: (c.line, c.name, c.via or "", c.args_key or "")))


_SCOPES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.ClassDef,
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)
_LITERAL = (ast.Constant, ast.List, ast.Tuple, ast.Set, ast.Dict, ast.UnaryOp, ast.Load)
_MUTABLE = (ast.List, ast.Set, ast.Dict)


def _literal(node: ast.AST) -> bool:
    """A value written out in full: constants, and lists, tuples, sets and
    dicts of them (a sign in front is fine). Nothing is evaluated."""
    return all(isinstance(n, _LITERAL) for n in ast.walk(node)) and all(
        isinstance(n.op, (ast.UAdd, ast.USub, ast.Invert, ast.Not))
        for n in ast.walk(node)
        if isinstance(n, ast.UnaryOp)
    )


class _Bindings:
    """What each scope of a file binds each name to, so that a variable passed
    to a sensitive call can be read as the value it holds.

    A name is followed when the scope Python would read it from (its own,
    else the enclosing functions', else the module's, class bodies skipped
    as Python skips them) binds it exactly once, by a plain assignment
    (``cmd = [...]``) to a literal value, and, when that value is a list, set
    or dict, every other use of the name in the file passes it straight to
    one of the calls being indexed, so nothing can have changed it in
    between. A parameter, a name bound twice, in a loop, by ``import`` or
    ``global``, or a value with a call or another name in it, is not
    followed, and the call keeps the variable's name.
    """

    def __init__(self, tree: ast.Module, passed: Container[int]) -> None:
        self.parent: dict[int, ast.AST | None] = {id(tree): None}
        self.bound: dict[int, dict[str, list[ast.AST]]] = {}
        self.declared: dict[int, set[str]] = {}
        self.loads: dict[str, list[ast.Name]] = {}  # every read of a name, any scope
        self.passed = passed
        stack: list[ast.AST] = [tree]
        while stack:
            scope = stack.pop()
            bound: dict[str, list[ast.AST]] = {}
            declared: set[str] = set()
            todo = list(ast.iter_child_nodes(scope))
            while todo:
                node = todo.pop()
                if isinstance(node, _SCOPES):
                    self.parent[id(node)] = scope
                    stack.append(node)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        bound.setdefault(node.name, []).append(node)
                    continue
                if isinstance(node, ast.Assign) and (
                    len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                ):
                    bound.setdefault(node.targets[0].id, []).append(node)
                    todo.append(node.value)
                    continue
                if isinstance(node, ast.Name):
                    if isinstance(node.ctx, ast.Load):
                        self.loads.setdefault(node.id, []).append(node)
                    else:
                        bound.setdefault(node.id, []).append(node)
                elif isinstance(node, ast.arg):
                    bound.setdefault(node.arg, []).append(node)
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    for a in node.names:
                        bound.setdefault((a.asname or a.name).split(".")[0], []).append(node)
                elif isinstance(node, ast.ExceptHandler) and node.name:
                    bound.setdefault(node.name, []).append(node)
                elif isinstance(node, (ast.Global, ast.Nonlocal)):
                    declared.update(node.names)
                elif isinstance(node, (ast.MatchAs, ast.MatchStar, ast.MatchMapping)):
                    name = node.rest if isinstance(node, ast.MatchMapping) else node.name
                    if name:
                        bound.setdefault(name, []).append(node)
                todo.extend(ast.iter_child_nodes(node))
            self.bound[id(scope)] = bound
            self.declared[id(scope)] = declared

    def value(self, scope: ast.AST, name: str) -> ast.expr | None:
        """The literal ``name`` holds wherever it is read in ``scope``, or None."""
        at: ast.AST | None = scope
        while at is not None:
            if name in self.declared[id(at)]:
                return None
            if (at is scope or not isinstance(at, ast.ClassDef)) and name in self.bound[id(at)]:
                bindings = self.bound[id(at)][name]
                if len(bindings) != 1 or not isinstance(bindings[0], ast.Assign):
                    return None
                binding = bindings[0]
                if not _literal(binding.value):
                    return None
                if any(isinstance(n, _MUTABLE) for n in ast.walk(binding.value)) and any(
                    id(load) not in self.passed for load in self.loads.get(name, ())
                ):
                    return None
                return binding.value
            at = self.parent[id(at)]
        return None


class _Plain(ast.NodeTransformer):
    """Drop what doesn't change a value: the ``u`` prefix of a string literal."""

    def visit_Constant(self, node: ast.Constant) -> ast.Constant:
        node.kind = None
        return node


ARGS_UNPARSED = 2_000  # syntax nodes in an argument list shown with ast.unparse


class _Shapes:
    """A digest and a size for every node of a file, computed once, bottom
    up and without recursion, so a call nested in another's arguments, or
    nested deeper than the recursion limit, costs no more to compare."""

    def __init__(self, tree: ast.AST, source: bytes) -> None:
        self.digest: dict[int, bytes] = {}
        self.size: dict[int, int] = {}
        self.lines = source.splitlines(keepends=True)
        stack: list[tuple[ast.AST, bool]] = [(tree, False)]
        while stack:
            node, ready = stack.pop()
            if not ready:
                stack.append((node, True))
                stack.extend((c, False) for c in ast.iter_child_nodes(node))
                continue
            h = hashlib.sha256(type(node).__name__.encode())
            n = 1
            for field, value in ast.iter_fields(node):
                if field == "kind" and isinstance(node, ast.Constant):
                    continue  # the u prefix
                items = value if isinstance(value, list) else [value]
                h.update(b"\0" + field.encode() + (b"[" if isinstance(value, list) else b"("))
                for item in items:
                    if isinstance(item, ast.AST):
                        h.update(self.digest[id(item)])
                        n += self.size[id(item)]
                    else:
                        h.update(repr(item).encode("utf-8", "surrogatepass") + b",")
            self.digest[id(node)] = h.digest()
            self.size[id(node)] = n

    def segment(self, node: ast.AST) -> str:
        """``node``'s source text (offsets are UTF-8 bytes), as one line."""
        lo, hi = getattr(node, "lineno", 0), getattr(node, "end_lineno", None)
        c0, c1 = getattr(node, "col_offset", 0), getattr(node, "end_col_offset", None)
        if not lo or hi is None or c1 is None:
            return "…"
        chunk = self.lines[lo - 1 : hi]
        if not chunk:
            return "…"
        if len(chunk) == 1:
            raw = chunk[0][c0:c1]
        else:
            raw = chunk[0][c0:] + b"".join(chunk[1:-1]) + chunk[-1][:c1]
        raw = raw[: 4 * ARGS_TEXT_LIMIT]  # only the start is shown
        text = " ".join(raw.decode("utf-8", "replace").split())
        return "".join(ch if ch.isprintable() else repr(ch)[1:-1] for ch in text)


def call_arguments(
    call: ast.Call,
    shapes: _Shapes | None = None,
    follow: Callable[[str], ast.expr | None] | None = None,
) -> tuple[str, str]:
    """A call's arguments as text, and a key that is equal for equal arguments.

    Nothing is evaluated: two calls have the same key when their argument
    trees are the same, with positions, formatting, comments, quote style and
    a ``u`` string prefix left out, and keyword arguments sorted by name
    (``**`` arguments after them, in their order). Python binds keywords by
    name, so their order doesn't change what the call receives. Any other
    difference, ``['make']`` against ``('make',)`` or a renamed variable,
    gives a different key. ``follow`` gives the literal a variable name
    holds, or None (``_Bindings.value``); a followed argument is keyed by
    that literal, as if it were written in the call, so ``call(cmd)`` with
    ``cmd = ['make']`` and ``call(['make'])`` have the same key, and the
    text ends ``with cmd = ['make']``. The key is a SHA-256 over every node
    of the arguments (``_Shapes``), computed without recursion. The text is
    ``ast.unparse`` of the arguments in parentheses when they have at most
    ``ARGS_UNPARSED`` nodes, or else their source text on one line, clipped
    to ``ARGS_TEXT_LIMIT`` characters.
    """
    keywords = sorted(call.keywords, key=lambda k: (k.arg is None, k.arg or ""))
    held: dict[str, ast.expr] = {}  # each followed name, in argument order
    for a in (*call.args, *(k.value for k in keywords)):
        if follow is not None and isinstance(a, ast.Name) and isinstance(a.ctx, ast.Load):
            value = follow(a.id)
            if value is not None:
                held.setdefault(a.id, value)

    def read(a: ast.expr) -> ast.expr:
        return held[a.id] if isinstance(a, ast.Name) and a.id in held else a

    if shapes is None:
        shapes = _Shapes(ast.Tuple(elts=[call, *held.values()], ctx=ast.Load()), b"")
    h = hashlib.sha256(b"call")
    for a in call.args:
        h.update(b"a" + shapes.digest[id(read(a))])
    for k in keywords:
        h.update(b"k" + repr(k.arg).encode() + shapes.digest[id(read(k.value))])
    key = h.hexdigest()
    nodes = sum(shapes.size[id(a)] for a in call.args) + sum(
        shapes.size[id(k.value)] for k in keywords
    )
    nodes += sum(shapes.size[id(v)] for v in held.values())
    text: str | None = None
    if nodes <= ARGS_UNPARSED:
        try:
            shape = _Plain().visit(
                copy.deepcopy(
                    ast.Call(func=ast.Name("_", ast.Load()), args=call.args, keywords=keywords)
                )
            )
            text = ast.unparse(shape)[1:]
            for name, value in held.items():
                shown = ast.unparse(_Plain().visit(copy.deepcopy(value)))
                text += f" with {name} = {shown}"
        except RecursionError:
            text = None
    if text is None:
        parts = [shapes.segment(a) for a in call.args]
        parts += [
            f"{k.arg}={shapes.segment(k.value)}" if k.arg else f"**{shapes.segment(k.value)}"
            for k in keywords
        ]
        text = "(" + ", ".join(parts) + ")"
        for name, value in held.items():
            text += f" with {name} = {shapes.segment(value)}"
    if len(text) > ARGS_TEXT_LIMIT:
        text = text[: ARGS_TEXT_LIMIT - 1] + "…"
    return text, key


MENTION_LIMIT = 200  # characters of a string argument read as a path


def argument_mentions(
    call: ast.Call, follow: Callable[[str], ast.expr | None] | None = None
) -> tuple[str, ...]:
    """The relative paths a call's string arguments may name, for a check to
    look up among the release's files: each string constant in the
    arguments (and in a variable ``follow`` reads), each whitespace-separated
    word of it, with a leading ``./`` taken off, and the files ``make``
    reads for the word ``make``, each under the directory a ``cwd`` keyword
    names. An absolute path, an empty string and a string over
    ``MENTION_LIMIT`` characters are left out. A ``cwd`` that isn't a string
    written out (or held by a variable ``follow`` reads), or that is
    absolute, puts the paths where this can't see, so none is recorded.
    Nothing is evaluated: ``'build.sh'`` is read as a name, not opened.
    """
    base = ""
    nodes: list[ast.AST] = list(call.args)
    for k in call.keywords:
        if k.arg != "cwd":
            nodes.append(k.value)
            continue
        where: ast.expr | None = k.value
        if follow is not None and isinstance(where, ast.Name) and isinstance(where.ctx, ast.Load):
            where = follow(where.id)
        if isinstance(where, ast.Constant) and where.value is None:
            continue
        if not (isinstance(where, ast.Constant) and isinstance(where.value, str)):
            return ()
        base = where.value
        while base.startswith("./"):
            base = base[2:]
        base = base.rstrip("/")
        if base.startswith("/") or "\0" in base:
            return ()
        if base == ".":
            base = ""
    if follow is not None:
        for a in list(nodes):
            if isinstance(a, ast.Name) and isinstance(a.ctx, ast.Load):
                value = follow(a.id)
                if value is not None:
                    nodes.append(value)
    out: set[str] = set()
    for node in nodes:
        for n in ast.walk(node):
            if not (isinstance(n, ast.Constant) and isinstance(n.value, str)):
                continue
            text = n.value
            if len(text) > MENTION_LIMIT:
                continue
            for word in {text, *text.split()}:
                if word == "make":
                    out.update(f"{base}/{m}" if base else m for m in MAKEFILES)
                while word.startswith("./"):
                    word = word[2:]
                if word and not word.startswith("/") and "\0" not in word:
                    out.add(f"{base}/{word}" if base else word)
    return tuple(sorted(out))


def index_build_script(source: bytes, *, path: str = "setup.py") -> tuple[CallSite, ...]:
    """Every sensitive call in a build script, at any depth, with its arguments
    (see ``sensitive_calls``)."""
    return sensitive_calls(source, path=path, with_args=True)
