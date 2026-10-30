"""The JavaScript scanner behind GRN-C011, and the rule on npm releases.

Every fixture is inert text: the scanner reads names, and nothing here would
do anything if it ran.
"""

from __future__ import annotations

import io
import json
import tarfile
from dataclasses import replace

from garnet_guard.engine import run_checks
from garnet_guard.facts.jsscan import entry_files, loaded_uses, scan, tokens
from garnet_guard.facts.npmmeta import inspect_tarball
from garnet_guard.models import Change, Limits, ReleaseFacts, Severity
from tests.builders import release


def _uses(src: str) -> list[tuple[str, int, bool]]:
    return [(u.name, u.line, u.at_load) for u in scan("index.js", src).uses]


def test_comments_strings_and_regexes_are_not_code() -> None:
    src = "\n".join(
        [
            '// require("child_process")',
            '/* eval("x") */',
            "const a = 'fetch(1)';",
            'const b = "new Function(x)";',
            "const c = /eval\\(/g;",
            "const d = x / y / z; const e = `WebSocket`;",
        ]
    )
    assert _uses(src) == []


def test_template_expressions_are_code() -> None:
    assert _uses("const s = `a ${eval('1')} b ${`c ${fetch(u)}`}`;") == [
        ("eval", 1, True),
        ("fetch", 1, True),
    ]


def test_modules_by_require_import_and_export() -> None:
    src = "\n".join(
        [
            "const cp = require('child_process');",
            'import { request } from "node:https";',
            'import "net";',
            "const vm = await import('vm');",
            'export { lookup } from "dns/promises";',
            "require.resolve('http');",
            "const fs = require('fs');",
        ]
    )
    assert _uses(src) == [
        ("child_process", 1, True),
        ("https", 2, True),
        ("net", 3, True),
        ("vm", 4, True),
        ("dns", 5, True),
    ]


def test_properties_and_keys_are_not_globals() -> None:
    assert _uses("o.fetch(1); o?.eval(2); const k = { fetch: 1, eval: 2 };") == []


def test_a_function_or_method_named_like_a_global_is_not_a_call() -> None:
    src = "class Cache { async fetch(k, o = {}) { return k } }\nfunction eval(x) { return x }"
    assert _uses(src) == []


def test_function_bodies_wait_to_be_called() -> None:
    src = "\n".join(
        [
            "function later() { return fetch(u) }",
            "const f = (x) => { eval(x) };",
            "class A { m(a) { new WebSocket(a) } }",
            "if (ok) { require('dns') }",
            "for (const x of xs) { XMLHttpRequest }",
        ]
    )
    assert _uses(src) == [
        ("fetch", 1, False),
        ("eval", 2, False),
        ("WebSocket", 3, False),
        ("dns", 4, True),
        ("XMLHttpRequest", 5, True),
    ]


def test_functions_called_where_they_are_defined_run_at_load() -> None:
    src = "\n".join(
        [
            "(function () { fetch(u) })();",
            "!function () { eval(x) }();",
            "(() => { require('net') })();",
            "(function () { new Function(x) }).call(this);",
        ]
    )
    assert [at for _, _, at in _uses(src)] == [True, True, True, True]


def test_a_declaration_then_a_parenthesis_is_not_a_call() -> None:
    assert _uses("function f() { fetch(u) }\n(g)();") == [("fetch", 1, False)]


def test_obfuscated_names_are_reported_once() -> None:
    src = " ".join(f"var _0x{i:04x}ab = {i};" for i in range(25))
    assert _uses(src) == [("_0x… names", 1, True)]
    assert _uses(" ".join(f"var _0x{i:04x}ab = 1;" for i in range(5))) == []


def test_line_numbers_cross_strings_and_templates() -> None:
    src = "const a = `one\ntwo`;\nconst b = 'x\\\ny';\nfetch(u);"
    assert _uses(src) == [("fetch", 5, True)]
    assert [t.line for t in tokens("a\n/* x\ny */ b")] == [1, 3]


def test_entry_files_from_package_json() -> None:
    paths = {"index.js", "lib/a.js", "lib/b.mjs", "bin/cli.js", "dist/x/index.cjs", "src/s.js"}
    doc = {
        "main": "./lib/a",
        "bin": {"demo": "bin/cli.js"},
        "exports": {".": {"import": "./lib/b.mjs", "require": "./lib/a.js"}, "./x": "./dist/x"},
    }
    assert entry_files(json.dumps(doc).encode(), paths) == {
        "lib/a.js",
        "lib/b.mjs",
        "bin/cli.js",
        "dist/x/index.cjs",
    }
    assert entry_files(b"{}", paths) == {"index.js"}  # main defaults to index.js
    wild = {"exports": {"./*": "./src/*.js"}}
    assert entry_files(json.dumps(wild).encode(), paths) == {"index.js", "src/s.js"}


def test_relative_loads_are_followed_and_others_are_not() -> None:
    sources = {
        "index.js": "require('./lib/helper'); require('demo-other');",
        "lib/helper.js": "import './deep/index.js';",
        "lib/deep/index.js": "const cp = require('child_process');",
        "unused.js": "fetch(u);",
    }
    uses, unread = loaded_uses(b"{}", sources)
    assert [(u.path, u.name) for u in uses] == [("lib/deep/index.js", "child_process")]
    assert unread == ()


# --- the rule on npm releases --------------------------------------------


def _tarball(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text in sorted(files.items()):
            data = text.encode()
            info = tarfile.TarInfo(f"package/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def npm_js(
    version: str, files: dict[str, str], limits: Limits | None = None
) -> tuple[ReleaseFacts, tuple[str, ...]]:
    """An npm release built from a real tarball of ``files``, and its error codes."""
    files = {"package.json": json.dumps({"name": "demo", "version": version}), **files}
    ins = inspect_tarball(f"demo-{version}.tgz", _tarball(files), limits or Limits())
    rel = release(version)
    art = replace(
        rel.artifacts[0],
        filename=f"demo-{version}.tgz",
        packagetype="tarball",
        inspected=True,
        files=tuple(ins.files),
        modules=(),
        js_uses=ins.js_uses,
        js_scanned=ins.js_scanned,
    )
    return replace(rel, ecosystem="npm", artifacts=(art,)), tuple(e.code for e in ins.errors)


CHANGE = Change("npm", "demo", "1.0", "1.1")


def _c011(base: ReleaseFacts, cand: ReleaseFacts) -> list[str]:
    result = run_checks(CHANGE, base, cand)
    found = [f for f in result.findings if f.rule_id == "GRN-C011"]
    assert all(f.severity == Severity.INFO for f in found)
    return [e.summary for f in found for e in f.evidence]


def test_a_new_process_call_in_the_main_file_is_reported() -> None:
    base, _ = npm_js("1.0", {"index.js": "module.exports = (s) => s.trim();"})
    cand, _ = npm_js(
        "1.1", {"index.js": "require('child_process').exec(x);\nmodule.exports = (s) => s;"}
    )
    assert _c011(base, cand) == ["index.js:1 loads child_process (when the file loads)"]


def test_an_obfuscated_line_shaped_like_chalk_561_is_reported() -> None:
    """chalk 5.6.1 added one obfuscated line to index.js; the real tarball is
    gone from the registry, so this is the shape only: many _0x names."""
    clean = "export default function chalk(s) { return s; }\n"
    shaped = clean + " ".join(f"var _0x{i:04x}ab = {i};" for i in range(30)) + "\n"
    base, _ = npm_js("1.0", {"index.js": clean})
    cand, _ = npm_js("1.1", {"index.js": shaped})
    assert _c011(base, cand) == [
        "index.js:2 has _0x… names in the shape javascript-obfuscator writes (when the file loads)"
    ]


def test_a_use_the_trusted_version_had_is_not_new() -> None:
    base, _ = npm_js("1.0", {"index.js": "require('./old')", "old.js": "fetch(u)"})
    cand, _ = npm_js("1.1", {"index.js": "require('./new')", "new.js": "fetch(v)"})
    assert _c011(base, cand) == []


def test_a_file_nothing_loads_is_not_read() -> None:
    base, _ = npm_js("1.0", {"index.js": ""})
    cand, _ = npm_js("1.1", {"index.js": "", "scripts/release.js": "require('child_process')"})
    assert _c011(base, cand) == []


def test_a_loaded_file_over_the_limit_is_budget_exceeded() -> None:
    big = "x;" * 40
    _, errors = npm_js("1.1", {"index.js": big}, Limits(max_js_file_bytes=32))
    assert errors == ("GRN-E003",)
    _, errors = npm_js("1.1", {"index.js": "", "other.js": big}, Limits(max_js_file_bytes=32))
    assert errors == ()
