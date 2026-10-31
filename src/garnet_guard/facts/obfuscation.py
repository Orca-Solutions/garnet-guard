"""Encoded literals and names built at run time, for GRN-C005. ``ast`` only.

``pyindex.scan_module`` hands every node that runs at import to a ``Tracker``,
which records three things as call sites marked ``obscured``:

- **Encoded literals.** A string or bytes literal holding a run of more than
  ``BLOB_CHARS`` characters in one encoding's alphabet (hex, base64, base85,
  Ascii85) whose entropy is over that alphabet's threshold, or raw binary
  bytes over 4.5 bits per byte. A run may be wrapped at a fixed width, as
  base64 encoders and PEM write it. Passed to a decoder, a literal counts from
  ``DECODED_CHARS`` characters. PEM blocks (``-----BEGIN ...-----``) are
  certificates and keys, so neither counts them; one that reaches ``exec``
  through a decoder is still a built value, below.
- **Values built from literals that reach code or a name.** ``exec``,
  ``eval``, ``compile``, ``marshal.loads`` or ``pickle.loads`` given a value
  made from literals by a decoder, ``chr``, ``join``, slicing, concatenation
  or the like, and ``getattr``, ``__import__``, ``importlib.import_module``
  or ``sys.modules`` given a name made that way. A plain literal doesn't
  count (GRN-C003 reads those), and neither does a name that comes from a
  variable, so a plugin loader's ``import_module(name)`` stays quiet.
- **Lookups on the modules that reach the sensitive APIs by a name the source
  doesn't hold.** ``getattr(os, name)``, ``vars(os)[name]``,
  ``os.__dict__.get(name)``, ``sys.modules[name]`` and ``__builtins__[name]``
  on ``os``, ``sys``, ``builtins``, ``ctypes`` or ``importlib`` (and the
  modules that define what they hold, such as ``posix``). ``sys.modules`` with
  the module's own name (``sys.modules[__name__]``) doesn't count. A subscript
  with a literal key counts when the key names a sensitive call
  (``__builtins__["exec"]``), which GRN-C003 doesn't follow.

Nothing is run. To name what a built value holds, small values are folded
here from the literals with a fixed set of pure operations (``chr``,
``bytes``, ``join``, slicing, base64 and hex decoding, rot13), each capped in
size; decompression and formatting are never folded.
"""

from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import itertools
import math
import re
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TypeVar

T = TypeVar("T")

OBFUSCATION_SET_VERSION = "2026-10-a"

BLOB_CHARS = 2048  # an encoded literal longer than this counts on its own
DECODED_CHARS = 256  # an encoded literal at least this long counts when it is decoded
MIN_WRAP = 32  # the narrowest line width read as a wrapped encoded run
BINARY_SHARE = 0.1  # a bytes literal with more than this share of non-text bytes is binary
# Bits per character a run must exceed. Hex can't pass 4.5 (16 symbols are 4
# bits), so it has its own; 3.0 leaves out runs of a few repeated digits.
_ALPHABETS: tuple[tuple[str, re.Pattern[str], float], ...] = (
    ("hex", re.compile(r"[0-9A-Fa-f]+"), 3.0),
    ("base64", re.compile(r"[A-Za-z0-9+/_-]+={0,2}"), 4.5),
    ("base85", re.compile(r"[0-9A-Za-z!#$%&()*+;<=>?@^_`{|}~-]+"), 5.5),
    ("Ascii85", re.compile(r"[!-u]+"), 5.5),
)
_BINARY_BITS = 4.5
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{1,64}-----.*?-----END [A-Z0-9 ]{1,64}-----", re.S)

# The modules whose attributes reach the §6.3 calls, and the modules that
# define what they hold (``posix.system is os.system``).
LOOKUP_MODULES = frozenset(
    {
        "os",
        "posix",
        "nt",
        "sys",
        "builtins",
        "ctypes",
        "_ctypes",
        "importlib",
        "importlib.util",
        "importlib.machinery",
        "importlib._bootstrap",
        "importlib._bootstrap_external",
        "_frozen_importlib",
        "_frozen_importlib_external",
    }
)
# Calls that run the value they are given, or build code from it.
RUNNERS = frozenset({"exec", "eval", "compile", "marshal.loads", "pickle.loads", "_pickle.loads"})
# Calls that take a module or attribute name, and the argument that holds it.
NAME_TAKERS = {
    "getattr": 1,
    "__import__": 0,
    "importlib.__import__": 0,
    "importlib.import_module": 0,
}
DECODERS = frozenset(
    {
        "base64.b64decode",
        "base64.standard_b64decode",
        "base64.urlsafe_b64decode",
        "base64.b32decode",
        "base64.b32hexdecode",
        "base64.b16decode",
        "base64.b85decode",
        "base64.a85decode",
        "base64.z85decode",
        "base64.decodebytes",
        "base64.decodestring",
        "binascii.a2b_base64",
        "binascii.a2b_hex",
        "binascii.unhexlify",
        "binascii.a2b_uu",
        "binascii.a2b_qp",
        "codecs.decode",
        "zlib.decompress",
        "bz2.decompress",
        "lzma.decompress",
        "gzip.decompress",
        "bytes.fromhex",
        "bytearray.fromhex",
    }
)
# Builtins and str/bytes methods that turn literals into other values.
_BUILDERS = frozenset(
    {"chr", "ord", "bytes", "bytearray", "str", "int", "list", "tuple", "reversed", "map"}
)
_METHODS = frozenset(
    {
        "join",
        "decode",
        "encode",
        "replace",
        "lower",
        "upper",
        "strip",
        "lstrip",
        "rstrip",
        "swapcase",
        "translate",
        "format",
    }
)
_OPS = {ast.Add: "concatenation", ast.Mod: "% formatting", ast.Mult: "repetition"}
_INT_OPS = (ast.Add, ast.Sub, ast.BitXor, ast.BitAnd, ast.BitOr, ast.Mult, ast.Mod)
_SELF_NAMES = frozenset({"__name__", "__package__"})
# Steps that put visible literal pieces together. A value made only with
# these counts when the name it spells reaches a sensitive module or call.
ASSEMBLING = frozenset(
    {
        "concatenation",
        "% formatting",
        "an f-string",
        "repetition",
        ".join()",
        ".format()",
        ".decode()",
        ".encode()",
        ".lower()",
        ".upper()",
        ".strip()",
        ".lstrip()",
        ".rstrip()",
        "str()",
    }
)
_FOLD_CAP = 4096  # characters or bytes in any folded value
MAX_DEPTH = 100  # nested operations read in one value
_MAX_SOURCE_NODES = 200  # nodes printed of an expression in evidence
_TEXT_CODECS = frozenset({"utf-8", "utf8", "ascii", "latin-1", "latin1", "iso-8859-1"})
_ROT13 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


def obfuscation_set() -> tuple[str, ...]:
    """What GRN-C005 reads, as ``garnet explain`` shows it."""
    alphabets = ", ".join(f"{k} over {t} bits per character" for k, _, t in _ALPHABETS)
    return (
        f"encoded literals: a run of more than {BLOB_CHARS:,} characters ({alphabets}), "
        f"or binary bytes over {_BINARY_BITS} bits per byte; from {DECODED_CHARS} "
        "characters when passed to a decoder; PEM blocks count only when run",
        "runs a value built from literals: " + ", ".join(sorted(RUNNERS)),
        "takes a name built from literals: " + ", ".join(sorted(NAME_TAKERS)) + ", sys.modules",
        "decoders: " + ", ".join(sorted(DECODERS)),
        "looked up by a name not in the source: " + ", ".join(sorted(LOOKUP_MODULES)),
    )


@dataclass(frozen=True)
class Blob:
    """An encoded run in a literal: its alphabet, length and entropy."""

    kind: str
    chars: int
    bits: float

    def describe(self) -> str:
        unit = "bytes" if self.kind == "binary" else "characters"
        per = "byte" if self.kind == "binary" else "character"
        what = "binary bytes literal" if self.kind == "binary" else f"{self.kind} literal"
        return f"a {what} of {self.chars:,} {unit} ({self.bits:.1f} bits per {per})"


def entropy(data: str | bytes) -> float:
    """Shannon entropy in bits per character (or byte)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def _text_like(data: bytes) -> bool:
    other = sum(1 for b in data if not (32 <= b < 127 or b in (9, 10, 13)))
    return other <= BINARY_SHARE * len(data)


def _groups(text: str) -> Iterable[str]:
    """Runs of text with no whitespace in them, a block of lines wrapped at one
    width (each line but the last that width, at least ``MIN_WRAP``) joined
    into one run."""
    group: list[str] = []
    width = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or any(ch.isspace() for ch in line):
            if group:
                yield "".join(group)
                group = []
            yield from line.split()
            continue
        if group and len(group[-1]) == width >= MIN_WRAP and len(line) <= width:
            group.append(line)
            continue
        if group:
            yield "".join(group)
        group, width = [line], len(line)
    if group:
        yield "".join(group)


def blob(value: str | bytes, min_chars: int) -> Blob | None:
    """The longest encoded run of at least ``min_chars`` in a literal, or None."""
    if len(value) < min_chars:
        return None
    if isinstance(value, bytes):
        if not _text_like(value):
            bits = entropy(value)
            return Blob("binary", len(value), round(bits, 1)) if bits > _BINARY_BITS else None
        value = value.decode("latin-1")
    best: Blob | None = None
    for group in _groups(_PEM.sub(" ", value)):
        if len(group) < min_chars:
            continue
        for kind, pattern, threshold in _ALPHABETS:
            for m in pattern.finditer(group):
                run = m.group()
                if len(run) < min_chars or (best is not None and len(run) <= best.chars):
                    continue
                bits = entropy(run)
                if bits > threshold:
                    best = Blob(kind, len(run), round(bits, 1))
    return best


def literal_key(value: str | bytes) -> str:
    """What identifies a literal across releases: its bytes."""
    data = value if isinstance(value, bytes) else value.encode("utf-8", "surrogatepass")
    return "blob:" + hashlib.sha256(data).hexdigest()[:16]


class _Unknown:
    """A built value that isn't folded."""


UNKNOWN = _Unknown()
Value = object


@dataclass(frozen=True)
class Built:
    """A value made from literals: the steps that made it, the literals it was
    made from, and the value itself when it was small enough to fold."""

    steps: tuple[str, ...]
    literals: tuple[str | bytes, ...]
    value: Value = UNKNOWN

    @property
    def plain(self) -> bool:
        """A literal as written, or a name bound to one: nothing built."""
        return not self.steps

    @property
    def disguised(self) -> bool:
        """Made with a step that hides what the literals say (a decoder, chr(),
        slicing, xor), not only by putting visible pieces together."""
        return any(step not in ASSEMBLING for step in self.steps)

    def text(self) -> str | None:
        """The folded value as text, when it is a string."""
        v = self.value
        if isinstance(v, bytes):
            try:
                v = v.decode("utf-8")
            except UnicodeDecodeError:
                return None
        return v if isinstance(v, str) else None

    def how(self) -> str:
        """The steps as a phrase: ``base64.b64decode and .decode()``."""
        steps = list(dict.fromkeys(self.steps))
        return steps[0] if len(steps) == 1 else ", ".join(steps[:-1]) + " and " + steps[-1]

    def key(self) -> str:
        """Identifies the value across releases: its steps and literals."""
        data = repr((self.steps, self.literals)).encode("utf-8", "surrogatepass")
        return hashlib.sha256(data).hexdigest()[:16]


def show(value: str) -> str:
    """A folded name for evidence: quoted, escaped, clipped."""
    r = repr(value)
    return r if len(r) <= 60 else r[:59] + "…"


def _capped(v: Value) -> Value:
    if isinstance(v, (str, bytes, list, tuple)) and len(v) > _FOLD_CAP:
        return UNKNOWN
    if isinstance(v, int) and not isinstance(v, bool) and abs(v) >= 2**32:
        return UNKNOWN
    return v


def _join(parts: Iterable[tuple[T, ...]]) -> tuple[T, ...]:
    return tuple(x for part in parts for x in part)


class Tracker:
    """Records GRN-C005 sites for the nodes one module runs at import.

    ``resolve`` is the module's name resolver (``pyindex._Resolver.resolve``),
    and ``sensitive`` tells whether a dotted name is a §6.3 call.
    """

    def __init__(
        self,
        resolve: Callable[[ast.expr], str | None],
        sensitive: Callable[[str], bool],
        tree: ast.AST | None = None,
        heads: frozenset[str] = frozenset(),
    ) -> None:
        self.resolve = resolve
        self.sensitive = sensitive
        self.heads = heads  # modules a §6.3 name starts with: os, subprocess, socket, ...
        self.names: dict[str, Built] = {}  # names bound to a literal or a built value
        self.consumed: set[int] = set()  # nodes already described by an enclosing site
        self.rebound = _rebound(tree) if tree is not None else frozenset()
        self.depth = 0
        self.loop: dict[str, Built] = {}  # a comprehension's variable, while it is folded

    def callee(self, func: ast.expr) -> str | None:
        """The dotted name of what a call calls. ``bytes.fromhex`` too, which the
        resolver leaves alone because a dotted name on a bare name that no
        import binds is usually a local object."""
        name = self.resolve(func)
        if name is None and isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.value.id in ("bytes", "bytearray") and func.value.id not in self.rebound:
                return f"{func.value.id}.{func.attr}"
        return name

    # --- what a value is made of -------------------------------------------

    def build(self, node: ast.expr, bound: frozenset[str] = frozenset()) -> Built | None:
        """``node`` as a value made only from literals, or None if anything
        else goes into it (a variable, a call outside the fixed set) or it is
        nested deeper than ``MAX_DEPTH``, so a deep expression can't exhaust
        the stack."""
        if self.depth >= MAX_DEPTH:
            return None
        self.depth += 1
        try:
            return self._build(node, bound)
        finally:
            self.depth -= 1

    def _build(self, node: ast.expr, bound: frozenset[str]) -> Built | None:
        if isinstance(node, ast.Constant):
            v = node.value
            lits = (v,) if isinstance(v, (str, bytes)) else ()
            return Built((), lits, v)
        if isinstance(node, ast.Name):
            if node.id in self.loop:
                return self.loop[node.id]
            if node.id in bound:
                return Built((), (), UNKNOWN)
            if node.id in self.rebound:
                return None  # which binding holds here can't be told without running it
            return self.names.get(node.id)
        if isinstance(node, (ast.Tuple, ast.List)):
            parts = [self.build(e, bound) for e in node.elts]
            if any(p is None for p in parts):
                return None
            ps = [p for p in parts if p is not None]
            values = [p.value for p in ps]
            folded: Value = UNKNOWN if any(v is UNKNOWN for v in values) else _capped(list(values))
            return Built(_join(p.steps for p in ps), _join(p.literals for p in ps), folded)
        if isinstance(node, ast.BinOp):
            return self._binop(node, bound)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd, ast.Invert)):
            operand = self.build(node.operand, bound)
            if operand is None:
                return None
            n = operand.value
            signed: Value = UNKNOWN
            if isinstance(n, int) and not isinstance(n, bool):
                signed = (
                    -n
                    if isinstance(node.op, ast.USub)
                    else ~n
                    if isinstance(node.op, ast.Invert)
                    else n
                )
            return Built(operand.steps, operand.literals, signed)
        if isinstance(node, ast.JoinedStr):
            if all(isinstance(v, ast.Constant) for v in node.values):
                text = "".join(str(v.value) for v in node.values if isinstance(v, ast.Constant))
                return Built((), (text,), text)
            fparts = [
                self.build(v.value if isinstance(v, ast.FormattedValue) else v, bound)
                for v in node.values
            ]
            if any(p is None for p in fparts):
                return None
            fs = [p for p in fparts if p is not None]
            return Built(
                ("an f-string", *_join(p.steps for p in fs)), _join(p.literals for p in fs)
            )
        if isinstance(node, ast.Subscript):
            return self._subscript(node, bound)
        if isinstance(node, (ast.ListComp, ast.GeneratorExp)):
            return self._comprehension(node, bound)
        if isinstance(node, ast.Call):
            return self._call(node, bound)
        return None

    def _binop(self, node: ast.BinOp, bound: frozenset[str]) -> Built | None:
        left, right = self.build(node.left, bound), self.build(node.right, bound)
        if left is None or right is None:
            return None
        lv, rv = left.value, right.value
        if not isinstance(node.op, (*_OPS, *_INT_OPS)):
            return None
        text = isinstance(lv, (str, bytes))
        step = _OPS[type(node.op)] if text and type(node.op) in _OPS else "arithmetic"
        if isinstance(node.op, ast.BitXor):
            step = "xor"
        value: Value = UNKNOWN
        if isinstance(lv, int) and isinstance(rv, int) and isinstance(node.op, _INT_OPS):
            value = _int_op(node.op, lv, rv)
        elif isinstance(node.op, ast.Add) and isinstance(lv, str) and isinstance(rv, str):
            value = _capped(lv + rv)
        elif isinstance(node.op, ast.Add) and isinstance(lv, bytes) and isinstance(rv, bytes):
            value = _capped(lv + rv)
        elif isinstance(node.op, ast.Mult) and isinstance(lv, (str, bytes)) and isinstance(rv, int):
            value = lv * rv if 0 <= rv * len(lv) <= _FOLD_CAP else UNKNOWN
        steps = (*left.steps, *right.steps, step)
        return Built(steps, left.literals + right.literals, value)

    def _subscript(self, node: ast.Subscript, bound: frozenset[str]) -> Built | None:
        inner = self.build(node.value, bound)
        if inner is None:
            return None
        sl = node.slice
        value: Value = UNKNOWN
        if isinstance(sl, ast.Slice):
            ends = [
                self.build(e, bound) if e is not None else Built((), (), None)
                for e in (sl.lower, sl.upper, sl.step)
            ]
            if any(e is None for e in ends):
                return None
            bounds = [e.value for e in ends if e is not None]
            if all(b is None or isinstance(b, int) for b in bounds) and isinstance(
                inner.value, (str, bytes, list, tuple)
            ):
                lo, hi, st = (b if isinstance(b, int) else None for b in bounds)
                value = inner.value[lo:hi:st]
            return Built((*inner.steps, "slicing"), inner.literals, value)
        index = self.build(sl, bound)
        if index is None:
            return None
        iv, v = index.value, inner.value
        if (
            isinstance(iv, int)
            and isinstance(v, (str, bytes, list, tuple))
            and -len(v) <= iv < len(v)
        ):
            value = v[iv]
        return Built(
            (*inner.steps, *index.steps, "indexing"), inner.literals + index.literals, value
        )

    def _comprehension(
        self, node: ast.ListComp | ast.GeneratorExp, bound: frozenset[str]
    ) -> Built | None:
        if len(node.generators) != 1:
            return None
        gen = node.generators[0]
        if not isinstance(gen.target, ast.Name) or gen.is_async:
            return None
        source = self.build(gen.iter, bound)
        if source is None:
            return None
        inner = bound | {gen.target.id}
        parts = [self.build(e, inner) for e in (node.elt, *gen.ifs)]
        if any(p is None for p in parts):
            return None
        ps = [p for p in parts if p is not None]
        value: Value = UNKNOWN
        items = source.value
        if not gen.ifs and isinstance(items, (str, bytes, list, tuple)) and len(items) <= _FOLD_CAP:
            out = [self._fold_with(node.elt, gen.target.id, x) for x in items]
            if all(o is not UNKNOWN for o in out):
                value = out
        steps = (*source.steps, *_join(p.steps for p in ps))
        return Built(
            steps or ("a comprehension",), source.literals + _join(p.literals for p in ps), value
        )

    def _fold_with(self, elt: ast.expr, name: str, item: Value) -> Value:
        """The comprehension's element with its variable holding ``item``."""
        saved = self.loop.get(name)
        self.loop[name] = Built((), (), item)
        try:
            b = self.build(elt)
        finally:
            if saved is None:
                del self.loop[name]
            else:
                self.loop[name] = saved
        return b.value if b is not None else UNKNOWN

    def _call(self, node: ast.Call, bound: frozenset[str]) -> Built | None:
        # Keyword arguments (``b64decode(s, validate=True)``) must be literals
        # too; the call is then not folded.
        kwargs = [self.build(k.value, bound) for k in node.keywords]
        if any(k is None for k in kwargs):
            return None
        func = node.func
        name = self.callee(func)
        receiver: Built | None = None
        if isinstance(func, ast.Attribute) and func.attr in _METHODS and name not in DECODERS:
            receiver = self.build(func.value, bound)
            if receiver is None:
                return None
            step = f".{func.attr}()"
        elif name in DECODERS:
            step = name
        elif name == "map" and len(node.args) == 2 and isinstance(node.args[0], ast.Name):
            fn = self.resolve(node.args[0])
            if fn not in _BUILDERS:
                return None
            src = self.build(node.args[1], bound)
            if src is None:
                return None
            mapped: Value = UNKNOWN
            if isinstance(src.value, (str, bytes, list, tuple)) and fn in ("chr", "ord"):
                mapped = _fold_each(fn, src.value)
            return Built((*src.steps, f"map({fn})"), src.literals, mapped)
        elif name in _BUILDERS:
            step = f"{name}()"
        else:
            return None
        args = [self.build(a, bound) for a in node.args]
        if any(a is None for a in args):
            return None
        built = [a for a in args if a is not None]
        parts = ([receiver] if receiver is not None else []) + built
        value: Value = UNKNOWN
        if not node.keywords:
            value = _fold_call(
                f".{func.attr}"
                if isinstance(func, ast.Attribute) and receiver is not None
                else str(name),
                receiver.value if receiver is not None else None,
                [a.value for a in built],
            )
        return Built(
            (*_join(p.steps for p in parts), step), _join(p.literals for p in parts), value
        )

    # --- sites ---------------------------------------------------------------

    def note_assign(self, node: ast.Assign | ast.AnnAssign) -> None:
        """``BLOB = "..."`` or ``n = "".join(...)``: the name holds that value."""
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name) or node.value is None:
            return
        built = self.build(node.value)
        if built is None:
            self.names.pop(targets[0].id, None)
        else:
            self.names[targets[0].id] = built

    def forget(self, target: ast.expr) -> None:
        """A loop or ``with`` target, or an augmented assignment, rebinds names."""
        for sub in ast.walk(target):
            if isinstance(sub, ast.Name):
                self.names.pop(sub.id, None)

    def sites(self, node: ast.AST) -> list[tuple[str, int, str]]:
        """(what it is, line, key) for each GRN-C005 site at this node. The key
        is what the trusted version must have had for the site not to be new:
        ``blob:`` and ``built:`` keys anywhere in it, ``lookup:`` keys in the
        same module."""
        if id(node) in self.consumed:
            return []
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            b = blob(node.value, BLOB_CHARS + 1)
            return [(f"has {b.describe()}", line, literal_key(node.value))] if b else []
        if isinstance(node, ast.Call):
            return [(s, line, k) for s, k in self._call_sites(node)]
        if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            found = self._lookup(node.value, node.slice, "[]")
            return [(s, line, k) for s, k in found]
        return []

    def _consume(self, nodes: Iterable[ast.AST]) -> None:
        for n in nodes:
            self.consumed.update(id(sub) for sub in ast.walk(n))

    def _call_sites(self, node: ast.Call) -> list[tuple[str, str]]:
        name = self.callee(node.func)
        if name is not None and name.startswith("builtins."):
            name = name[len("builtins.") :]
        if name in RUNNERS and node.args:
            return self._run(name, node.args[0])
        if name in NAME_TAKERS and len(node.args) > NAME_TAKERS[name]:
            arg = node.args[NAME_TAKERS[name]]
            if name == "getattr":
                return self._lookup(node.args[0], arg, "getattr")
            return self._imported(name, arg)
        if name in DECODERS and node.args:
            return self._decoded(name, node.args[0])
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "get" and node.args:
            return self._lookup(func.value, node.args[0], ".get")
        return []

    def _sensitive_module(self, text: str | None) -> bool:
        """A module name a §6.3 entry starts with (``os``, ``subprocess``, ``http.client``)."""
        return text is not None and text.split(".")[0] in self.heads

    def _blob_in(self, built: Built, min_chars: int) -> Blob | None:
        found = [b for v in built.literals if (b := blob(v, min_chars)) is not None]
        return max(found, key=lambda b: b.chars) if found else None

    def _run(self, runner: str, arg: ast.expr) -> list[tuple[str, str]]:
        built = self.build(arg)
        if built is None or not built.disguised:
            return []  # a literal, or visible pieces put together: GRN-C003 reports the call
        self._consume([arg])
        what = f"runs {runner} on a value built from literals with {built.how()}"
        inside = self._blob_in(built, DECODED_CHARS)
        if inside is not None:
            what += f", from {inside.describe()}"
        return [(what, f"built:{runner}:{built.key()}")]

    def _imported(self, taker: str, arg: ast.expr) -> list[tuple[str, str]]:
        built = self.build(arg)
        if built is None or built.plain:
            return []
        text = built.text()
        if not built.disguised and not self._sensitive_module(text):
            return []
        self._consume([arg])
        named = f" {show(text)}" if text is not None else ""
        what = f"imports{named} with {taker} by a name built with {built.how()}"
        return [(what, f"built:{taker}:{built.key()}")]

    def _decoded(self, decoder: str, arg: ast.expr) -> list[tuple[str, str]]:
        built = self.build(arg)
        if built is None or not built.plain or len(built.literals) != 1:
            return []
        value = built.literals[0]
        b = blob(value, DECODED_CHARS)
        if b is None:
            return []
        self._consume([arg])
        return [(f"passes {b.describe()} to {decoder}", literal_key(value))]

    def _namespace(self, obj: ast.expr) -> tuple[str, str] | None:
        """(module, how it is written) when ``obj`` is a lookup module, its
        ``__dict__`` or ``vars()`` of it, or ``sys.modules``. A name bound more
        than once (``import builtins as m`` and later ``m = __import__(x)``)
        may hold either, so it isn't read as the module."""
        root: ast.expr = obj.args[0] if isinstance(obj, ast.Call) and obj.args else obj
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name) and root.id in self.rebound:
            return None
        if isinstance(obj, ast.Call) and len(obj.args) == 1 and not obj.keywords:
            if self.resolve(obj.func) in ("vars", "builtins.vars"):
                inner = self.resolve(obj.args[0])
                if inner in LOOKUP_MODULES:
                    return inner, f"vars({_source(obj.args[0], 40)})"
            return None
        name = self.resolve(obj)
        if name is None:
            return None
        if name == "sys.modules":
            return name, "sys.modules"
        mod = name[: -len(".__dict__")] if name.endswith(".__dict__") else name
        if mod in LOOKUP_MODULES:
            return mod, _source(obj, 40)
        return None

    def _lookup(self, obj: ast.expr, key: ast.expr, how: str) -> list[tuple[str, str]]:
        """``getattr(obj, key)``, ``obj[key]`` or ``obj.get(key)``."""
        ns = self._namespace(obj)
        if ns is None and how != "getattr":
            return []
        built = self.build(key)
        if ns is None:
            # A name built from literals reaching getattr on any object.
            if how != "getattr" or built is None or not built.disguised:
                return []
            self._consume([key])
            text = built.text()
            named = f": {show(text)}" if text is not None else ""
            what = f"passes getattr a name built with {built.how()}{named}"
            return [(what, f"built:getattr:{built.key()}")]
        mod, written = ns
        if mod == "sys.modules" and _self_name(key):
            return []
        if built is not None and built.plain and isinstance(key, ast.Constant):
            # A literal key: GRN-C003 follows getattr(os, "system"); a subscript
            # (``__builtins__["exec"]``) counts here when it names a listed call.
            text = built.text()
            if how == "getattr" or mod == "sys.modules" or text is None:
                return []
            if not self.sensitive(_under(mod, text)):
                return []
            what = f"looks up {_attribute(mod, text)} by subscript: {_source(_call_like(obj, key, how), 80)}"
            return [(what, f"lookup:{mod}{how}{text}")]
        written_call = _source(_call_like(obj, key, how), 80)
        target = "a module in sys.modules" if mod == "sys.modules" else f"an attribute of {mod}"
        if built is not None:
            self._consume([key])
            text = built.text()
            if built.plain:
                if text is None or not self.sensitive(_under(mod, text)):
                    return []
                what = f"looks up {_attribute(mod, text)} through a name bound to a literal: {written_call}"
                return [(what, f"lookup:{mod}{how}{text}")]
            if not built.disguised and text is not None:
                reaches = (
                    self._sensitive_module(text)
                    if mod == "sys.modules"
                    else self.sensitive(_under(mod, text))
                )
                if not reaches:
                    return []
            named = f" {_attribute(mod, text)}" if text is not None else ""
            what = f"looks up{named or ' ' + target} by a name built with {built.how()}: {written_call}"
            return [(what, f"built:{how}:{mod}:{built.key()}")]
        what = f"looks up {target} by a name not written in the source: {written_call}"
        return [(what, f"lookup:{mod}{how}{_source(key, 200)}")]


def _rebound(tree: ast.AST) -> frozenset[str]:
    """Names a module binds more than once, anywhere in it, or binds both by an
    import and otherwise. Repeated imports of a name don't count."""
    other: Counter[str] = Counter()
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            other[node.id] += 1
        elif isinstance(node, ast.arg):
            other[node.arg] += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            other[node.name] += 1
        elif isinstance(node, ast.ExceptHandler) and node.name:
            other[node.name] += 1
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            imported.update((a.asname or a.name).split(".")[0] for a in node.names)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            other.update({n: 2 for n in node.names})
    return frozenset(n for n, k in other.items() if k > 1 or n in imported)


def _self_name(key: ast.expr) -> bool:
    """``__name__``, ``__package__``, ``__spec__.name`` or ``x.__module__``: a
    module looking itself (or a class's module) up in ``sys.modules``."""
    if isinstance(key, ast.Name):
        return key.id in _SELF_NAMES
    if isinstance(key, ast.Attribute):
        if key.attr in ("__module__", "__name__"):
            return True
        return key.attr == "name" and isinstance(key.value, ast.Name) and key.value.id == "__spec__"
    return False


def _attribute(module: str, text: str) -> str:
    """What a folded name reaches, for evidence: ``os.system``, or the name
    quoted when it isn't a plain identifier (it may hold control characters)."""
    if module == "sys.modules":
        return f"the module {show(text)}"
    if text.isascii() and text.isidentifier():
        return _under(module, text)
    return f"the {module} attribute {show(text)}"


def _under(module: str, name: str) -> str:
    return name if module == "builtins" else f"{module}.{name}"


def _call_like(obj: ast.expr, key: ast.expr, how: str) -> ast.expr:
    """The lookup as the source writes it, for evidence."""
    if how == "getattr":
        return ast.Call(ast.Name("getattr"), [obj, key], [])
    if how == ".get":
        return ast.Call(ast.Attribute(obj, "get"), [key], [])
    return ast.Subscript(obj, key)


def _source(node: ast.expr, n: int) -> str:
    """``node`` as source, clipped to ``n`` characters. An expression of more
    than ``_MAX_SOURCE_NODES`` nodes is cut first: ``ast.unparse`` recurses."""
    seen = sum(1 for _ in itertools.islice(ast.walk(node), _MAX_SOURCE_NODES + 1))
    if seen > _MAX_SOURCE_NODES:
        node = _shallow(node)
    try:
        return _clip(ast.unparse(node), n)
    except RecursionError:
        return "…"


def _shallow(node: ast.expr) -> ast.expr:
    """The lookup with its arguments elided, for an expression too big to print."""
    if isinstance(node, ast.Call):
        return ast.Call(
            node.func if _small(node.func) else ast.Name("…"), [_elide(a) for a in node.args], []
        )
    if isinstance(node, ast.Subscript):
        return ast.Subscript(_elide(node.value), _elide(node.slice))
    return ast.Name("…")


def _small(node: ast.expr) -> bool:
    return sum(1 for _ in itertools.islice(ast.walk(node), 21)) <= 20


def _elide(node: ast.expr) -> ast.expr:
    return node if _small(node) else ast.Name("…")


def _clip(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def _int_op(op: ast.operator, a: int, b: int) -> Value:
    if isinstance(op, ast.Add):
        return _capped(a + b)
    if isinstance(op, ast.Sub):
        return _capped(a - b)
    if isinstance(op, ast.BitXor):
        return _capped(a ^ b)
    if isinstance(op, ast.BitAnd):
        return _capped(a & b)
    if isinstance(op, ast.BitOr):
        return _capped(a | b)
    if isinstance(op, ast.Mult):
        return _capped(a * b)
    if isinstance(op, ast.Mod) and b:
        return _capped(a % b)
    return UNKNOWN


def _fold_each(fn: str, items: str | bytes | list[Value] | tuple[Value, ...]) -> Value:
    out: list[Value] = []
    for x in items:
        v = _fold_call(fn, None, [x])
        if v is UNKNOWN:
            return UNKNOWN
        out.append(v)
    return out


def _fold_call(fn: str, receiver: Value, args: list[Value]) -> Value:
    """The result of one of the fixed operations on folded values, or UNKNOWN.

    Only pure operations on str, bytes, ints and lists, each result capped.
    Decompression, formatting and codecs outside a short list are never run.
    """
    if receiver is UNKNOWN or any(a is UNKNOWN for a in args):
        return UNKNOWN
    if any(isinstance(v, (str, bytes)) and len(v) > 2 * _FOLD_CAP for v in (receiver, *args)):
        return UNKNOWN
    try:
        return _capped(_fold(fn, receiver, args))
    except (ValueError, TypeError, OverflowError, binascii.Error, UnicodeError, IndexError):
        return UNKNOWN


def _fold(fn: str, receiver: Value, args: list[Value]) -> Value:
    a0 = args[0] if args else None
    if fn == "chr" and isinstance(a0, int):
        return chr(a0)
    if fn == "ord" and isinstance(a0, (str, bytes)) and len(a0) == 1:
        return ord(a0)
    if fn in ("bytes", "bytearray") and isinstance(a0, (list, tuple, bytes)) and len(args) == 1:
        return bytes(a0)
    if fn in ("list", "tuple", "reversed") and isinstance(a0, (str, bytes, list, tuple)):
        return list(reversed(a0)) if fn == "reversed" else list(a0)
    if fn == "str" and isinstance(a0, (str, int)) and len(args) == 1:
        return str(a0)
    if fn == "int" and isinstance(a0, (str, bytes)) and len(a0) <= 64:
        base = args[1] if len(args) > 1 else 10
        return int(a0, base) if isinstance(base, int) else UNKNOWN
    if fn in ("bytes.fromhex", "bytearray.fromhex", "binascii.unhexlify", "binascii.a2b_hex"):
        if isinstance(a0, str):
            return bytes.fromhex(a0)
        return binascii.unhexlify(a0) if isinstance(a0, bytes) else UNKNOWN
    if fn in ("base64.b64decode", "base64.standard_b64decode", "binascii.a2b_base64"):
        return base64.b64decode(a0) if isinstance(a0, (str, bytes)) else UNKNOWN
    if fn == "base64.urlsafe_b64decode" and isinstance(a0, (str, bytes)):
        return base64.urlsafe_b64decode(a0)
    if fn == "base64.b32decode" and isinstance(a0, (str, bytes)):
        return base64.b32decode(a0)
    if fn == "base64.b16decode" and isinstance(a0, (str, bytes)):
        return base64.b16decode(a0)
    if fn == "base64.b85decode" and isinstance(a0, (str, bytes)):
        return base64.b85decode(a0)
    if fn == "codecs.decode" and len(args) == 2 and isinstance(args[1], str):
        codec = args[1].lower().replace("_", "-")
        if codec in ("rot13", "rot-13") and isinstance(a0, str):
            return a0.translate(_ROT13)
        if codec in ("hex", "hex-codec") and isinstance(a0, (str, bytes)):
            return bytes.fromhex(a0 if isinstance(a0, str) else a0.decode("ascii"))
        if codec in ("base64", "base64-codec") and isinstance(a0, (str, bytes)):
            return base64.b64decode(a0)
        if codec in _TEXT_CODECS and isinstance(a0, bytes):
            return a0.decode(codec)
        return UNKNOWN
    if fn.startswith("."):
        return _method(fn[1:], receiver, args)
    return UNKNOWN


def _method(name: str, receiver: Value, args: list[Value]) -> Value:
    r = receiver
    if name == "join" and isinstance(r, (str, bytes)) and len(args) == 1:
        items = args[0]
        if isinstance(items, (list, tuple, str)) and all(type(i) is type(r) for i in items):
            return r.join(items)  # type: ignore[arg-type]
        return UNKNOWN
    if name in ("decode", "encode"):
        codec = args[0] if args else "utf-8"
        if not isinstance(codec, str) or codec.lower() not in _TEXT_CODECS or len(args) > 1:
            return UNKNOWN
        if name == "decode" and isinstance(r, bytes):
            return r.decode(codec)
        if name == "encode" and isinstance(r, str):
            return r.encode(codec)
        return UNKNOWN
    if name == "replace" and isinstance(r, (str, bytes)) and len(args) == 2:
        old, new = args
        if type(old) is type(r) and type(new) is type(r) and old:
            out = r.replace(old, new)  # type: ignore[arg-type]
            return out if len(out) <= _FOLD_CAP else UNKNOWN
        return UNKNOWN
    if name in ("lower", "upper", "strip", "lstrip", "rstrip", "swapcase") and not args:
        if isinstance(r, (str, bytes)):
            changed: Value = getattr(r, name)()
            return changed
    return UNKNOWN
