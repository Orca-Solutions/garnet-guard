"""GRN-C005 obfuscated-blob: encoded literals and computed lookups at import.

Synthetic shapes only; no real malware. The facts come from
``facts/obfuscation.py`` through ``scan_module``; the check is
``checks.content.obfuscated_blob``.
"""

from __future__ import annotations

import base64
import random
import zlib

from garnet_guard.checks.docs import DOCS, PLANNED
from garnet_guard.cli import main
from garnet_guard.engine import run_checks
from garnet_guard.facts.obfuscation import BLOB_CHARS, DECODED_CHARS, blob, entropy
from garnet_guard.facts.pyindex import index_module, scan_module
from garnet_guard.models import Change, Finding, ReleaseFacts, Severity, Verdict
from garnet_guard.report import escape
from tests.builders import release

CHANGE = Change("pypi", "demo", "1.0", "1.1")
INIT = "def hello():\n    return 1\n"
PKG = {"demo/__init__.py": INIT}
_RNG = random.Random(54)
RANDOM = _RNG.randbytes(3000)
B64 = base64.b64encode(RANDOM).decode()  # 4,000 characters, about 6 bits each
HEX = RANDOM[:1100].hex()  # 2,200 characters, 4 bits each


def sites(src: str, **kw: object) -> list[tuple[int, str]]:
    """GRN-C005's sites in one module, as (line, what)."""
    calls = scan_module(src.encode(), **kw).calls  # type: ignore[arg-type]
    return [(c.line, c.name) for c in calls if c.obscured is not None]


def c005(base: ReleaseFacts, cand: ReleaseFacts) -> list[Finding]:
    return [f for f in run_checks(CHANGE, base, cand).findings if f.rule_id == "GRN-C005"]


def lines(findings: list[Finding]) -> list[str]:
    return [e.summary for f in findings for e in f.evidence if e.kind == "file"]


# --- encoded literals --------------------------------------------------------


def test_entropy_and_alphabets() -> None:
    assert entropy("") == 0.0 and entropy("aaaa") == 0.0 and entropy("ab") == 1.0
    found = blob(B64, BLOB_CHARS + 1)
    assert found is not None and found.kind == "base64" and found.chars == 4000
    assert found.bits > 5.9
    hexed = blob(HEX, BLOB_CHARS + 1)
    assert hexed is not None and hexed.kind == "hex" and hexed.bits == 4.0
    raw = blob(zlib.compress(RANDOM), BLOB_CHARS + 1)
    assert raw is not None and raw.kind == "binary"
    assert blob(base64.b85encode(RANDOM).decode(), BLOB_CHARS + 1) is not None
    assert blob(B64[:BLOB_CHARS], BLOB_CHARS + 1) is None  # 2,048 is not over 2,048


def test_wrapped_base64_counts_as_one_run() -> None:
    wrapped = "\n".join(B64[i : i + 76] for i in range(0, len(B64), 76))
    found = blob(wrapped, BLOB_CHARS + 1)
    assert found is not None and found.chars == 4000
    indented = "\n".join("    " + B64[i : i + 64] for i in range(0, len(B64), 64))
    assert blob(indented, BLOB_CHARS + 1) is not None


def test_text_that_is_not_an_encoding_is_not_a_blob() -> None:
    words = " ".join(_RNG.choice(["alpha", "beta", "gamma", "delta", "omega"]) for _ in range(900))
    listed = "\n".join(f"Builtin{_RNG.randrange(10**6)}Name" for _ in range(400))
    template = ("<div class='x'>{{ value }}</div>\n" * 100) + "<script>var a = 1;</script>"
    regex = "(?:" + "|".join(f"word{i}x" for i in range(600)) + ")"
    for text in (words, listed, template, regex, "A" * 5000, "0" * 3000, "VV" * 3000):
        assert blob(text, BLOB_CHARS + 1) is None, text[:40]


def test_pem_blocks_do_not_count_on_their_own() -> None:
    pem = "".join(
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join(B64[i : i + 64] for i in range(n, n + 2560, 64))
        + "\n-----END CERTIFICATE-----\n"
        for n in (0, 1280)
    )
    assert blob(pem, BLOB_CHARS + 1) is None
    assert sites(f'CERTS = """{pem}"""\n') == []
    # Decoding a PEM block is what certificates are for; running one is not.
    assert sites(f'import base64\nK = base64.b64decode("""{pem}""")\n') == []
    ((_, ran),) = sites(f'import base64\nexec(base64.b64decode("""{pem}"""))\n')
    assert ran == "runs exec on a value built from literals with base64.b64decode"
    body = B64[:600]
    ((_, what),) = sites(f"import base64\nK = base64.b64decode('{body}')\n")
    assert what.startswith("passes a base64 literal of 600 characters (")
    assert what.endswith(" bits per character) to base64.b64decode")


def test_long_encoded_literals_at_import() -> None:
    assert sites(f"X = '{B64}'\n") == [
        (1, "has a base64 literal of 4,000 characters (6.0 bits per character)")
    ]
    assert sites(f"X = '{HEX}'\n") == [
        (1, "has a hex literal of 2,200 characters (4.0 bits per character)")
    ]
    raw = zlib.compress(RANDOM)
    (found,) = sites(f"X = {raw!r}\n")
    assert found[1].startswith("has a binary bytes literal of ")
    # In a function nothing calls at import, it isn't reached.
    assert sites(f"def payload():\n    return '{B64}'\n") == []


def test_decoder_takes_shorter_literals() -> None:
    short = B64[: DECODED_CHARS - 1]
    assert sites(f"import base64\nX = base64.b64decode('{short}')\n") == []
    enough = B64[:DECODED_CHARS]
    ((_, what),) = sites(f"import binascii\nX = binascii.a2b_base64('{enough}')\n")
    assert what.startswith("passes a base64 literal of 256 characters (")
    # Through a name bound to the literal.
    assert sites(f"import zlib\nB = {zlib.compress(RANDOM[:400])!r}\nzlib.decompress(B)\n")


# --- values built from literals ----------------------------------------------


def test_decoded_and_run() -> None:
    src = f"import base64, zlib\nB = '{B64}'\nexec(zlib.decompress(base64.b64decode(B)))\n"
    assert sites(src) == [
        (2, "has a base64 literal of 4,000 characters (6.0 bits per character)"),
        (
            3,
            "runs exec on a value built from literals with base64.b64decode and "
            "zlib.decompress, from a base64 literal of 4,000 characters (6.0 bits per character)",
        ),
    ]
    short = "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"
    assert sites(short) == [(2, "runs exec on a value built from literals with base64.b64decode")]
    hexed = "exec(bytes.fromhex('7072696e74283129').decode())\n"
    assert sites(hexed) == [
        (1, "runs exec on a value built from literals with bytes.fromhex and .decode()")
    ]
    xor = "exec(bytes(c ^ 7 for c in b'wuni').decode())\n"
    assert sites(xor) == [
        (1, "runs exec on a value built from literals with xor, bytes() and .decode()")
    ]
    marshal = "import marshal, base64\ncode = marshal.loads(base64.b64decode('YQ=='))\n"
    assert sites(marshal)[0][1].startswith("runs marshal.loads on a value built from literals")


def test_a_plain_literal_run_is_grn_c003s() -> None:
    assert sites("exec('x = 1')\n") == []
    assert sites("CODE = 'x = 1'\nexec(CODE)\n") == []
    assert sites("import sys\nexec(sys.argv[1])\n") == []  # not from literals


def test_names_built_from_literals() -> None:
    chars = "import os\ngetattr(os, ''.join(map(chr, [115, 121, 115, 116, 101, 109])))('id')\n"
    ((_, what),) = sites(chars)
    assert what.startswith("looks up os.system by a name built with map(chr) and .join(): ")
    rev = "import builtins\ngetattr(builtins, 'cexe'[::-1])('1')\n"
    assert sites(rev) == [
        (2, "looks up exec by a name built with slicing: getattr(builtins, 'cexe'[::-1])")
    ]
    rot = "import codecs, os\ngetattr(os, codecs.decode('flfgrz', 'rot13'))('id')\n"
    assert sites(rot)[0][1].startswith("looks up os.system by a name built with codecs.decode")
    comp = "import os\ngetattr(os, ''.join([chr(c) for c in (115, 121, 115, 116, 101, 109)]))\n"
    assert sites(comp)[0][1].startswith("looks up os.system by a name built with chr()")
    split = "import os\ngetattr(os, 'sys' + 'tem')('id')\n"
    assert sites(split)[0][1].startswith("looks up os.system by a name built with concatenation")
    imp = "import base64\n__import__(base64.b64decode('b3M=').decode()).system('id')\n"
    assert sites(imp) == [
        (2, "imports 'os' with __import__ by a name built with base64.b64decode and .decode()")
    ]
    lib = "import importlib\nimportlib.import_module(chr(111) + chr(115))\n"
    assert sites(lib)[0][1].startswith("imports 'os' with importlib.import_module")
    other = "getattr(obj, ''.join(map(chr, [115, 121, 115, 116, 101, 109])))\n"
    assert sites(other) == [(1, "passes getattr a name built with map(chr) and .join(): 'system'")]
    built_name = "import os\nn = ''.join(['sys', 'tem'])\ngetattr(os, n)('id')\n"
    assert sites(built_name)[0][1].startswith("looks up os.system by a name built with .join()")


def test_assembled_names_count_only_when_they_reach_a_sensitive_name() -> None:
    # Concatenation, formatting and .join() alone are how loaders and shims build names.
    quiet = [
        "import importlib\nPKG = 'demo'\nimportlib.import_module(PKG + '.plugins')\n",
        "importlib = __import__('importlib')\nimportlib.import_module('%s.%s' % ('a', 'b'))\n",
        "class A:\n    def f(self):\n        return 1\ngetattr(A(), '_' + 'f')\n",
        "getattr(obj, ''.join(['sys', 'tem']))\n",
        "exec('x' + ' = 1')\n",
        "import os\ngetattr(os, 'path' + 'sep')\n",
        "import os\ngetattr(os, f'curdir')\n",
    ]
    for src in quiet:
        assert sites(src) == [], src
    assert sites("import importlib\nimportlib.import_module('o' + 's')\n") == [
        (2, "imports 'os' with importlib.import_module by a name built with concatenation")
    ]
    assert sites("import os\ngetattr(os, 'sys' + 'tem')\n")[0][1].startswith(
        "looks up os.system by a name built with concatenation"
    )
    assert sites("exec(''.join(map(chr, [120, 61, 49])))\n")[0][1].startswith(
        "runs exec on a value built from literals with map(chr) and .join()"
    )


def test_c003_still_reads_literal_lookups_and_c005_leaves_them() -> None:
    src = "import os\ngetattr(os, 'sys' + 'tem')('id')\n"
    calls, _ = index_module(src.encode())
    assert {c.name for c in calls} == {"os.system"}
    assert sites("import os\ngetattr(os, 'system')('id')\n") == []


# --- lookups on the sensitive modules by a name the source doesn't hold --------


def test_lookups_by_a_name_not_in_the_source() -> None:
    assert sites("import os\ndef f(n):\n    return getattr(os, n)\nf(x)\n") == [
        (3, "looks up an attribute of os by a name not written in the source: getattr(os, n)")
    ]
    assert sites("import sys\nm = sys.modules[name]\n") == [
        (
            2,
            "looks up a module in sys.modules by a name not written in the source: sys.modules[name]",
        )
    ]
    assert sites("import os\nos.__dict__.get(k)\n") == [
        (2, "looks up an attribute of os by a name not written in the source: os.__dict__.get(k)")
    ]
    assert sites("import ctypes\nfn = vars(ctypes)[k]\n")[0][1].startswith(
        "looks up an attribute of ctypes"
    )
    assert sites("import posix\ngetattr(posix, k)\n")[0][1].startswith(
        "looks up an attribute of posix"
    )


def test_subscript_lookups_of_listed_names() -> None:
    assert sites("__builtins__['exec']('1')\n") == [
        (1, "looks up exec by subscript: __builtins__['exec']")
    ]
    assert sites("import os\nvars(os)['system']('id')\n") == [
        (2, "looks up os.system by subscript: vars(os)['system']")
    ]
    assert sites("import os\nn = 'system'\ngetattr(os, n)('id')\n") == [
        (3, "looks up os.system through a name bound to a literal: getattr(os, n)")
    ]
    # A listed module, but not a listed name.
    assert sites("import os\nvars(os)['sep']\nn = 'sep'\ngetattr(os, n)\n") == []


def test_legitimate_lookups_stay_quiet() -> None:
    quiet = [
        # a module looking itself, or a class's module, up
        "import sys\nthis = sys.modules[__name__]\n",
        "import sys\nm = sys.modules[cls.__module__]\nn = sys.modules[__spec__.name]\n",
        "import sys\nsys.modules[__name__].x = 1\nsys.modules[name] = mod\n",  # a store
        # a dispatch table on a module that isn't one of the five
        "import handlers\nHANDLERS = {k: getattr(handlers, k) for k in KEYS}\n"
        "getattr(handlers, attr)()\n",
        # plugin loaders: the name comes from entry points or configuration
        "import importlib\nfor ep in eps:\n    importlib.import_module(ep.value)\n",
        "import importlib\nimportlib.import_module(f'demo.plugins.{name}')\n",
        "import importlib\nimportlib.import_module('demo.backends.' + config['backend'])\n",
        "__import__(name)\n",
        # the environment is not a module
        "import os\nx = os.environ[name]\ny = os.environ.get(name)\n",
        # a name bound twice may hold either value
        "import builtins as m\nm = __import__(mod)\ngetattr(m, klass)\n",
        # a literal attribute name is GRN-C003's to read
        "import sys\ngetattr(sys, 'frozen', False)\n",
    ]
    for src in quiet:
        assert sites(src) == [], src


def test_escaped_names_in_evidence() -> None:
    src = "import os\ngetattr(os, chr(27) + '[31m' + chr(0x202E) + 'x')\n"
    ((_, what),) = sites(src)
    assert "\x1b" not in what and "\u202e" not in what
    assert escape(what) == what
    assert what.startswith("looks up the os attribute '\\x1b[31m\\u202ex' by a name built")
    ((_, sub),) = sites("import ctypes\nvars(ctypes)['CDLL\\x1b']\n")
    assert "\x1b" not in sub and escape(sub) == sub


def test_folding_is_bounded() -> None:
    # A repetition past the cap isn't folded; the site is still recorded.
    src = "import os\ngetattr(os, 'a' * 100000)\n"
    ((_, what),) = sites(src)
    assert "repetition" in what and "'aaaa" not in what
    deep = "import os\ngetattr(os, " + "chr(115) + " * 300 + "'x')\n"
    assert sites(deep)


# --- the check: reachability, test files and the diff ------------------------

BLOB_MODULE = f"import base64, zlib\n_B = '{B64}'\nexec(zlib.decompress(base64.b64decode(_B)))\n"
LOOKUP = "import os\ndef _go(n):\n    getattr(os, n)('id')\n_go(NAME)\n"


def test_new_blob_reports_at_info() -> None:
    base = release("1.0", PKG)
    cand = release("1.1", {"demo/__init__.py": INIT + f"_X = '{B64}'\n"})
    result = run_checks(CHANGE, base, cand)
    (f,) = [f for f in result.findings if f.rule_id == "GRN-C005"]
    assert f.severity == Severity.INFO == f.default_severity
    assert result.verdict == Verdict.PASS
    assert f.title == "1.1 adds encoded literals or computed lookups at import in 1 module(s)"
    assert lines([f]) == [
        "demo/__init__.py:3 has a base64 literal of 4,000 characters (6.0 bits per character)"
    ]
    assert any(e.kind == "note" and "reported at info" in e.summary for e in f.evidence)


def test_decoded_and_run_reports_with_grn_c003() -> None:
    result = run_checks(
        CHANGE, release("1.0", PKG), release("1.1", {"demo/_p.py": BLOB_MODULE, **PKG})
    )
    ids = {f.rule_id for f in result.findings}
    assert {"GRN-C003", "GRN-C005"} <= ids
    (c5,) = [f for f in result.findings if f.rule_id == "GRN-C005"]
    assert lines([c5]) == [
        "new module demo/_p.py:2 has a base64 literal of 4,000 characters (6.0 bits per character)",
        "new module demo/_p.py:3 runs exec on a value built from literals with base64.b64decode "
        "and zlib.decompress, from a base64 literal of 4,000 characters (6.0 bits per character)",
    ]


def test_reached_through_a_function_and_another_module() -> None:
    cand = release(
        "1.1",
        {
            "demo/__init__.py": INIT + "from demo import _boot\n_boot.start()\n",
            "demo/_boot.py": "import os\ndef start():\n    name = KEY\n    getattr(os, name)('id')\n",
        },
    )
    base = release("1.0", {"demo/__init__.py": INIT, "demo/_boot.py": "def start():\n    pass\n"})
    assert lines(c005(base, cand)) == [
        "demo/_boot.py:4 looks up an attribute of os by a name not written in the source: "
        "getattr(os, name) (in start(), reached at import from demo/__init__.py)"
    ]


def test_trusted_version_had_it() -> None:
    old = release("1.0", {"demo/__init__.py": INIT + BLOB_MODULE + LOOKUP})
    same = release("1.1", {"demo/__init__.py": INIT + "\n\n" + BLOB_MODULE + LOOKUP})
    assert c005(old, same) == []
    # The blob moved to another module: the literal is the same, so not new.
    moved = release("1.1", {"demo/__init__.py": INIT + LOOKUP, "demo/_data.py": BLOB_MODULE})
    assert c005(old, moved) == []
    # A changed payload is new, though the code around it is the same.
    other = BLOB_MODULE.replace(B64[:8], "AAAAAAAA")
    changed = release("1.1", {"demo/__init__.py": INIT + other + LOOKUP})
    assert len(lines(c005(old, changed))) == 2


def test_a_lookup_is_compared_with_the_same_module() -> None:
    old = release("1.0", {"demo/__init__.py": INIT + LOOKUP, "demo/b.py": INIT})
    added = release("1.1", {"demo/__init__.py": INIT + LOOKUP, "demo/b.py": INIT + LOOKUP})
    assert lines(c005(old, added)) == [
        "demo/b.py:5 looks up an attribute of os by a name not written in the source: "
        "getattr(os, n) (in _go(), reached at import)"
    ]


def test_byte_identical_and_unchanged_files_stay_quiet() -> None:
    old = release("1.0", {"demo/__init__.py": INIT, "demo/old.py": BLOB_MODULE})
    renamed = release("1.1", {"demo/__init__.py": INIT, "demo/new_name.py": BLOB_MODULE})
    assert c005(old, renamed) == []


def test_test_files_and_sdist_extras_are_left_out() -> None:
    data = f"import base64\nVECTOR = base64.b64decode('{B64}')\n"
    tests_only = release(
        "1.1", {**PKG, "tests/test_codec.py": data, "demo/tests/conftest.py": data}
    )
    assert c005(release("1.0", PKG), tests_only) == []
    # A test module the package imports runs whenever the package does.
    imported = release(
        "1.1",
        {
            "demo/__init__.py": INIT + "from demo.tests import fixtures\n",
            "demo/tests/fixtures.py": data,
        },
    )
    assert lines(c005(release("1.0", PKG), imported))
    sdist = release(
        "1.1",
        sdist_files={**PKG, "docs/conf.py": data, "examples/run.py": data},
        sdist_only=True,
    )
    assert c005(release("1.0", sdist_files=PKG, sdist_only=True), sdist) == []


def test_a_function_only_handed_on_is_left_out() -> None:
    src = (
        INIT + "import functools, os\ndef _f(n):\n    getattr(os, n)\nfunctools.partial(_f, 'x')\n"
    )
    assert c005(release("1.0", PKG), release("1.1", {"demo/__init__.py": src})) == []
    run = (
        INIT
        + "import threading, os\ndef _f():\n    getattr(os, N)\nthreading.Thread(target=_f).start()\n"
    )
    assert lines(c005(release("1.0", PKG), release("1.1", {"demo/__init__.py": run})))


def test_c003_is_unchanged_by_the_new_sites() -> None:
    """GRN-C003 compares call names; GRN-C005's sites never count as calls."""
    old = release("1.0", {"demo/__init__.py": INIT + f"_X = '{B64}'\n"})
    new = release("1.1", {"demo/__init__.py": INIT + f"_X = '{B64[::-1]}'\n"})
    ids = {f.rule_id for f in run_checks(CHANGE, old, new).findings}
    assert "GRN-C003" not in ids and "GRN-C005" in ids


def test_evidence_is_capped_and_sorted() -> None:
    body = "".join(
        f"_X{i} = '{base64.b64encode(_RNG.randbytes(1600)).decode()}'\n" for i in range(30)
    )
    (f,) = c005(release("1.0", PKG), release("1.1", {"demo/__init__.py": body}))
    files = [e for e in f.evidence if e.kind == "file"]
    assert len(files) == 25 and [e.line for e in files] == sorted(e.line for e in files)
    assert any(e.summary == "and 5 more" for e in f.evidence)


def test_docs_and_explain(capsys) -> None:
    doc = DOCS["GRN-C005"]
    assert doc.default == Severity.INFO and "GRN-C005" not in PLANNED
    assert len(doc.summary) <= 1024 and len(doc.explanation) <= 1024
    assert main(["explain", "GRN-C005"]) == 0
    out = capsys.readouterr().out
    assert "default info" in out and "What it reads (set 2026-10-a)" in out
    assert "base64.b64decode" in out and "sys.modules" in out


def test_deep_expressions_are_read_without_exhausting_the_stack() -> None:
    deep = "import os\ngetattr(os, " + "chr(115) + " * 2000 + "'x')\n"
    assert sites(deep)  # read as a name not written in the source
    calls, _ = index_module(deep.encode())
    assert calls == ()


def test_a_comprehension_variable_used_twice_still_folds() -> None:
    src = (
        "import os\nX = [c for c in range(3)]\n"
        "getattr(os, ''.join(chr(c) for c in [115, 121, 115, 116, 101, 109]))('id')\n"
    )
    ((_, what),) = sites(src)
    assert what.startswith("looks up os.system by a name built with chr() and .join()")


# --- review findings (2026-10-31) -------------------------------------------

RUN = "import subprocess\nsubprocess.run(['git', 'status'])\n"


def test_an_expression_that_fails_when_folded_keeps_grn_c003s_scan() -> None:
    # A zero slice step raises ValueError when run. It isn't folded, and the
    # call after it is still read.
    src = f"P = 'getcwd'[::0]\n{RUN}"
    calls, _ = index_module(src.encode())
    assert [c.name for c in calls] == ["subprocess.run"]
    boot = "import subprocess\ndef start():\n    if 0:\n        _ = 'abc'[::0]\n    subprocess.run(['git', 'status'])\n"
    init = INIT + "from demo import _boot\n_boot.start()\n"
    old = release("1.0", {"demo/__init__.py": init, "demo/_boot.py": "def start():\n    pass\n"})
    new = release("1.1", {"demo/__init__.py": init, "demo/_boot.py": boot})
    rules = {f.rule_id for f in run_checks(CHANGE, old, new).findings}
    assert "GRN-C003" in rules


def test_a_value_garnet_cannot_read_is_reported_not_passed(monkeypatch) -> None:
    import garnet_guard.facts.obfuscation as ob

    def broken(self: object, node: object, bound: object) -> None:
        raise ValueError("synthetic")

    monkeypatch.setattr(ob.Tracker, "_build", broken)
    src = f"import os\nP = 'x'\ngetattr(os, P)\n{RUN}"
    calls = scan_module(src.encode()).calls
    stopped = [c for c in calls if c.obscured is not None]
    assert [(c.line, c.obscured) for c in stopped] == [
        (2, "unread:an expression Garnet couldn't read (ValueError)")
    ]
    assert [c.name for c in calls if c.obscured is None] == ["subprocess.run"]
    # Reported even when the trusted version stopped at the same place.
    old = release("1.0", {"demo/__init__.py": INIT + src})
    new = release("1.1", {"demo/__init__.py": INIT + src + "\n"})
    assert lines(c005(old, new)) == [
        "demo/__init__.py:4 stops reading values built from literals here: an expression "
        "Garnet couldn't read (ValueError); the rest of the module isn't checked for GRN-C005"
    ]


def test_a_name_that_doubles_itself_stays_small() -> None:
    src = "A0 = 'x'\n" + "".join(f"A{i + 1} = A{i} + A{i}\n" for i in range(40))
    src += "import os\ngetattr(os, A40[:6])\n"
    ((_, what),) = sites(src)
    assert what.startswith("looks up an attribute of os by a name built with concatenation")


def test_nested_comprehensions_stop_at_the_allowance() -> None:
    text = "'" + "a" * 60 + "'"
    expr = "0"
    for i in range(4):
        expr = f"[{expr} for c{i} in {text}]"
    src = f"import os\ngetattr(os, {expr})\n{RUN}"
    found = sites(src)
    assert [w.split(":")[0] for _, w in found] == ["stops reading values built from literals here"]
    calls, _ = index_module(src.encode())
    assert [c.name for c in calls] == ["subprocess.run"]


def test_pem_headers_without_an_end_are_read_in_one_pass() -> None:
    import time

    start = time.monotonic()
    assert blob("-----BEGIN A-----" * 20000, BLOB_CHARS + 1) is None
    assert time.monotonic() - start < 2  # about 30 s with the earlier pattern
    pem = "-----BEGIN DATA-----\n" + B64 + "\n-----END DATA-----"
    assert blob(pem, BLOB_CHARS + 1) is None
    assert blob(pem + "\n" + B64, BLOB_CHARS + 1) is not None


def test_a_literal_used_many_times_is_read_once() -> None:
    import time

    big = "QUJD" * 25000
    src = f"import base64\nA = '{big}'\nL = [" + ", ".join(["A"] * 400) + "]\n"
    src += "exec(base64.b64decode(''.join(L)))\n"
    start = time.monotonic()
    assert sites(src)
    assert time.monotonic() - start < 2


def test_a_changed_number_or_slice_bound_is_a_new_value() -> None:
    def chars(word: str) -> str:
        return str([ord(c) for c in word])

    cases = [
        (  # the same steps, other numbers
            f"getattr(os, ''.join(map(chr, {chars('getcwd')})))\n",
            f"getattr(os, ''.join(map(chr, {chars('getpid')})))\n",
        ),
        ("getattr(os, 'getcwdgetpid'[:6])\n", "getattr(os, 'getcwdgetpid'[6:])\n"),
        (
            "exec(bytes(c ^ 7 for c in b'wuni').decode())\n",
            "exec(bytes(c ^ 9 for c in b'wuni').decode())\n",
        ),
    ]
    for before, after in cases:
        old = release("1.0", {"demo/__init__.py": INIT + "import os\n" + before})
        new = release("1.1", {"demo/__init__.py": INIT + "import os\n" + before + after})
        assert len(lines(c005(old, new))) == 1, after
        same = release("1.1", {"demo/__init__.py": INIT + "import os\n\n" + before})
        assert c005(old, same) == [], before


def test_a_lookup_in_a_new_function_is_new() -> None:
    old = release("1.0", {"demo/__init__.py": INIT + LOOKUP})
    src = INIT + LOOKUP + "def _run(n):\n    getattr(os, n)()\n_run(OTHER)\n"
    assert lines(c005(old, release("1.1", {"demo/__init__.py": src}))) == [
        "demo/__init__.py:8 looks up an attribute of os by a name not written in the source: "
        "getattr(os, n) (in _run(), reached at import)"
    ]


def test_a_module_name_the_source_assigns_is_not_the_modules_own() -> None:
    src = "import sys\nclass K:\n    pass\nK.__module__ = ''.join(map(chr, [111, 115]))\n"
    src += "sys.modules[K.__module__].getcwd()\n"
    assert [line for line, _ in sites(src)] == [5]
    assert sites("import sys\nclass K:\n    pass\nsys.modules[K.__module__]\n") == []


def test_a_long_lookup_key_is_compared_in_full() -> None:
    pad = " + ".join(f"K{i}" for i in range(80))
    old = release("1.0", {"demo/__init__.py": INIT + f"import os\ngetattr(os, {pad} + A)\n"})
    new = release("1.1", {"demo/__init__.py": INIT + f"import os\ngetattr(os, {pad} + B)\n"})
    assert len(lines(c005(old, new))) == 1
