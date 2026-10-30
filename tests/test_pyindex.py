from garnet_guard.facts.pyindex import index_module


def names(src: str) -> set[str]:
    calls, _ = index_module(src.encode())
    return {c.name for c in calls}


def test_top_level_call_resolves_alias() -> None:
    assert names("import subprocess as sp\nsp.run(['x'])\n") == {"subprocess.run"}
    assert names("from os import system\nsystem('x')\n") == {"os.system"}


def test_function_body_not_import_time() -> None:
    assert names("import subprocess\ndef f():\n    subprocess.run(['x'])\n") == set()


def test_function_reached_through_thread_target() -> None:
    src = (
        "import subprocess, threading\n"
        "def _run():\n    subprocess.Popen(['x'])\n"
        "threading.Thread(target=_run, daemon=True).start()\n"
    )
    calls, _ = index_module(src.encode())
    assert [(c.name, c.via) for c in calls] == [("subprocess.Popen", "_run")]


def test_main_guard_skipped() -> None:
    assert names("import os\nif __name__ == '__main__':\n    os.system('x')\n") == set()


def test_exec_and_literal_import_module() -> None:
    assert names("exec('1')\n") == {"exec"}
    assert names("import importlib\nimportlib.import_module('json')\n") == set()
    assert names("import importlib\nm='x'\nimportlib.import_module(m)\n") == {
        "importlib.import_module"
    }


def test_class_body_and_decorators_run_at_import() -> None:
    assert names("import os\nclass A:\n    x = os.popen('id')\n") == {"os.popen"}


def test_own_package_calls_not_sensitive() -> None:
    calls, _ = index_module(
        b"from requests.adapters import HTTPAdapter\nHTTPAdapter()\n", own=frozenset({"requests"})
    )
    assert calls == ()


def test_returned_function_is_not_reached() -> None:
    # pip 26.2's vendored platformdirs: picks a function at import, never calls it.
    src = (
        b"import ctypes\n"
        b"def via_ctypes():\n    return ctypes.windll.LoadLibrary('shell32')\n"
        b"def _pick():\n    return via_ctypes\n"
        b"get_folder = _pick()\n"
        b"TABLE = {'a': via_ctypes}\n"
    )
    calls, _ = index_module(src)
    assert calls == ()


def test_function_passed_to_a_call_or_decorator_is_reached() -> None:
    src = (
        b"import atexit, os, subprocess, threading\n"
        b"def a():\n    os.system('a')\n"
        b"def b():\n    subprocess.run(['b'])\n"
        b"def deco(f):\n    os.system('deco')\n    return f\n"
        b"threading.Thread(target=a).start()\n"
        b"atexit.register(b)\n"
        b"@deco\ndef c():\n    pass\n"
    )
    calls, _ = index_module(src)
    assert {(c.name, c.via) for c in calls} == {
        ("os.system", "a"),
        ("subprocess.run", "b"),
        ("os.system", "deco"),
    }


def test_lambda_called_or_passed_at_import_is_reached() -> None:
    assert names("import os\n(lambda: os.system('id'))()\n") == {"os.system"}
    assert names("import atexit, subprocess\natexit.register(lambda: subprocess.run(['x']))\n") == {
        "subprocess.run"
    }
    assert names("import os\nf = lambda: os.system('id')\nf()\n") == {"os.system"}
    # Stored and never called: not reached, like a function.
    assert names("import os\nf = lambda: os.system('id')\n") == set()


def test_class_instantiated_at_import_runs_its_init() -> None:
    cls = "import os\nclass Boot:\n    def __init__(self):\n        os.system('id')\n"
    calls, _ = index_module((cls + "Boot()\n").encode())
    assert [(c.name, c.via) for c in calls] == [("os.system", "Boot")]
    assert names(cls) == set()  # defined, never instantiated
    assert names(cls + "class Sub(Boot):\n    pass\nSub()\n") == {"os.system"}
    static = "import os\nclass K:\n    @staticmethod\n    def boot():\n        os.system('id')\n"
    assert names(static + "K.boot()\n") == {"os.system"}
    assert names(static) == set()


def test_star_import_of_a_sensitive_module() -> None:
    assert names("from subprocess import *\nrun(['x'])\n") == {"subprocess.run"}
    assert names("from os import *\nsystem('x')\n") == {"os.system"}
    # Builtins, the module's own definitions and harmless names stay quiet.
    assert names("from subprocess import *\nprint('x')\nlist()\n") == set()
    assert names("from subprocess import *\ndef run():\n    pass\nrun()\n") == set()
    assert names("from os import *\ngetcwd()\n") == set()


def test_getattr_and_import_with_literal_names_resolve() -> None:
    assert names("import os\ngetattr(os, 'system')('id')\n") == {"os.system"}
    assert names("import os\ngetattr(os, 'sys' + 'tem')('id')\n") == {"os.system"}
    assert names("import importlib\nimportlib.import_module('os').system('id')\n") == {"os.system"}
    assert names("__import__('os').system('id')\n") == {"__import__", "os.system"}
    # A name built at runtime can't be followed without running code.
    assert names("import os\nn = 'system'\ngetattr(os, n)('id')\n") == set()


def test_base64_decode_feeding_a_sensitive_call_is_its_own_entry() -> None:
    assert names("import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))\n") == {
        "exec",
        "base64.b64decode → exec",
    }
    assert names("import base64, zlib\nexec(zlib.decompress(base64.b85decode('x')))\n") == {
        "exec",
        "base64.b85decode → exec",
    }
    assert names("import base64\nblob = base64.b64decode('x')\nexec(blob)\n") == {
        "exec",
        "base64.b64decode → exec",
    }
    assert names("from base64 import b64decode as d\nexec(d('x'))\n") == {
        "exec",
        "base64.b64decode → exec",
    }
    # Decoding on its own is not sensitive.
    assert names("import base64\nprint(base64.b64decode('x'))\n") == set()


def test_assignment_aliases_and_getattr_on_a_module_object() -> None:
    from garnet_guard.facts.pyindex import scan_module

    assert names("import subprocess\nsp = subprocess\nsp.run(['x'])\n") == {"subprocess.run"}
    assert names("import os\nrun = os.system\nrun('x')\n") == {"os.system"}
    # num2words 0.5.15: the module reached through sys.modules, then CDLL through getattr.
    src = (
        "import os, sys, ctypes\n"
        "try:\n"
        "    ct = getattr(sys.modules[__name__], 'ctypes')\n"
        "    lib = getattr(ct, 'CDLL')(os.path.join('here', '_build.py'))\n"
        "    getattr(lib, 'main')()\n"
        "except Exception:\n"
        "    pass\n"
    )
    assert names(src) == {"ctypes.CDLL"}
    # Only a module the file imported is read that way.
    assert names("import sys\nx = getattr(sys.modules[__name__], 'ctypes')\nx.CDLL('a')\n") == set()
    assert scan_module(b"import os\nclass K:\n    pass\n", entry="missing").calls == ()


def test_calls_into_own_package_are_reported_not_flagged() -> None:
    from garnet_guard.facts.pyindex import scan_module

    src = b"from memos.log import get_logger\nfrom . import util\nlogger = get_logger(__name__)\nutil.setup()\n"
    scan = scan_module(
        src, own=frozenset({"memos"}), module="memos.api.client", path="memos/api/client.py"
    )
    assert scan.calls == ()
    assert scan.calls_out == ("memos.api.util.setup", "memos.log.get_logger")


def test_scan_from_an_entry_follows_the_chain_inside_the_module() -> None:
    from garnet_guard.facts.pyindex import scan_module

    src = (
        b"import subprocess\n"
        b"def configure():\n"
        b"    from memos._stage0 import trigger\n"
        b"    trigger()\n"
        b"def get_logger(name):\n"
        b"    configure()\n"
        b"    return name\n"
        b"def unused():\n"
        b"    subprocess.run(['x'])\n"
    )
    scan = scan_module(src, own=frozenset({"memos"}), module="memos.log", entry="get_logger")
    assert scan.calls == () and scan.calls_out == ("memos._stage0.trigger",)
    assert scan_module(src, own=frozenset({"memos"}), module="memos.log").calls_out == ()


def test_nested_function_handed_to_a_call_is_followed() -> None:
    # The mrmustard 0.7.4 shape: a module-level call runs a function that
    # defines _run inside itself and starts it on a thread.
    src = (
        "import threading\n\n"
        "def _check():\n"
        "    def _run():\n"
        "        import subprocess, urllib.request\n"
        "        subprocess.check_output(['uname', '-a'])\n"
        "        urllib.request.urlopen('https://example.invalid/x')\n"
        "    threading.Thread(target=_run, daemon=True).start()\n\n"
        "_check()\n"
    )
    assert names(src) == {"subprocess.check_output", "urllib.request.urlopen"}
    # Two functions nesting the same name are followed separately.
    twice = (
        "import os, socket\n\n"
        "def a():\n    def _go():\n        os.system('x')\n    _go()\n\n"
        "def b():\n    def _go():\n        socket.socket()\n    _go()\n\n"
        "a()\nb()\n"
    )
    assert names(twice) == {"os.system", "socket.socket"}
    # A nested function that is only returned does not run.
    stored = (
        "import os\n\n"
        "def make():\n    def _go():\n        os.system('x')\n    return _go\n\n"
        "handler = make()\n"
    )
    assert names(stored) == set()


def test_a_dotted_name_needs_an_imported_head() -> None:
    # curl-cffi 0.15.0: a local list called requests; oscrypto 0.17.3: a local
    # socket beside ``import socket as socket_``.
    assert names("def run():\n    requests = []\n    requests.append(1)\nrun()\n") == set()
    assert (
        names(
            "import socket as socket_\ndef f(s):\n    socket = s\n    socket.settimeout(5)\nf(1)\n"
        )
        == set()
    )
    assert names("import os.path\nos.system('x')\n") == {"os.system"}
    assert names("import socket as socket_\nsocket_.socket()\n") == {"socket.socket"}


def test_a_module_level_definition_shadows_a_builtin() -> None:
    # nltk 3.10.4 redos.py defines its own compile().
    assert names("def compile(src, flags):\n    return src\n\ncompile('a', 0)\n") == set()
    assert names("import re\ncompile = re.compile\ncompile('a')\n") == set()
    assert names("class exec:\n    pass\n\nexec('a')\n") == set()
    assert names("compile('a', 'b', 'exec')\n") == {"compile"}


def test_a_handed_function_carries_the_call_it_went_to() -> None:
    from garnet_guard.facts.pyindex import scan_module

    def handed(src: str) -> set[str | None]:
        return {c.handed_to for c in scan_module(src.encode()).calls}

    body = "import subprocess\nfrom functools import partial\n\ndef _run():\n    subprocess.run(['x'])\n\n"
    # partd 1.3.0 built partial(Encode, ...) at import; nothing ran Encode.
    assert handed(body + "runner = partial(_run)\n") == {"functools.partial"}
    # The same partial called at once runs _run.
    assert handed(body + "partial(_run)()\n") == {None}
    # A function both handed and called counts as called.
    assert handed(body + "runner = partial(_run)\n_run()\n") == {None}
    assert handed(body + "import threading\nthreading.Thread(target=_run).start()\n") == {
        "threading.Thread"
    }
    assert handed("import atexit, os\natexit.register(lambda: os.system('x'))\n") == {
        "atexit.register"
    }
    # A factory the module defines itself is named as written.
    src = body + "def wrap(f):\n    return f\n\nrun = wrap(_run)\n"
    assert handed(src) == {"wrap"}
    # Handing one of the package's own callables is recorded with the call.
    scan = scan_module(
        b"from functools import partial\nfrom memos import work\njob = partial(work.go)\n",
        own=frozenset({"memos"}),
        module="memos.api",
        path="memos/api.py",
    )
    assert scan.calls_out == () and scan.handed_out == (("memos.work.go", "functools.partial"),)


def test_sensitive_calls_anywhere_names_the_enclosing_function() -> None:
    from garnet_guard.facts.pyindex import sensitive_calls

    src = (
        "import subprocess as sp\n"
        "import demo.helpers\n"
        "class Model:\n"
        "    def __init__(self):\n"
        "        sp.Popen(['x'])\n"
        "def dl():\n"
        "    demo.helpers.run()\n"
        "    return sp.run(['y'])\n"
        "sp.call(['z'])\n"
    )
    calls = sensitive_calls(src.encode(), own=frozenset({"demo"}))
    assert [(c.name, c.line, c.via) for c in calls] == [
        ("subprocess.Popen", 5, "Model.__init__"),
        ("subprocess.run", 8, "dl"),
        ("subprocess.call", 9, None),
    ]
