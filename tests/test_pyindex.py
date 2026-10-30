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
        ("subprocess.Popen", 5, "__init__"),
        ("subprocess.run", 8, "dl"),
        ("subprocess.call", 9, None),
    ]
