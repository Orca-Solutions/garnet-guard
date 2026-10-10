from garnet_guard.checks import ALL_CHECKS, DOCS
from garnet_guard.cli import main
from garnet_guard.engine import report, run_checks
from garnet_guard.models import Change
from garnet_guard.report import escape, to_json, to_text
from tests.builders import release


def test_every_check_has_docs() -> None:
    ids = [r for r, _, _ in ALL_CHECKS]
    assert len(ids) == len(set(ids))
    assert all(r in DOCS for r in ids)


def test_explain(capsys) -> None:
    assert main(["explain", "GRN-C003"]) == 0
    out = capsys.readouterr().out
    assert "new-import-time-exec" in out and "subprocess.*" in out
    assert "docs/rules/GRN-C003.md" in out
    assert main(["explain", "GRN-X999"]) == 3


def test_escape_strips_control_and_bidi() -> None:
    assert escape("a\x1b[31mb\u202ec") == "a\\x1b[31mb\\x202ec"


def test_json_is_deterministic() -> None:
    change = Change("pypi", "demo", "1.0", "1.1")
    r = report([run_checks(change, release("1.0"), release("1.1", provenance="none", tag=False))])
    assert to_json(r) == to_json(r)
    assert '"rule_id": "GRN-T001"' in to_json(r)
    assert "/docs/rules/GRN-T001.md" in to_json(r)
    assert "GRN-T004" in to_text(r)
    assert r.exit_code(fail_on=__import__("garnet_guard").Severity.WARN) == 1
