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
