from dataclasses import replace

from garnet_guard.engine import run_checks
from garnet_guard.models import Change, FactError, Severity, TagInfo, Verdict
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
