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


def test_check_end_to_end_without_network(tmp_path, monkeypatch, capsys) -> None:
    import json

    from garnet_guard import cli

    base = tmp_path / "base.txt"
    head = tmp_path / "requirements.txt"
    base.write_text("demo==1.0\n")
    head.write_text("demo==1.1\nflask>=3\n")

    def fake_evaluate(changes, *, options=None):
        assert [(c.package, c.baseline, c.candidate) for c in changes] == [("demo", "1.0", "1.1")]
        return [run_checks(changes[0], release("1.0"), release("1.1", provenance="none"))]

    monkeypatch.setattr(cli, "evaluate", fake_evaluate)
    monkeypatch.chdir(tmp_path)
    code = main(
        ["check", "--base", str(base), "--head", str(head), "--format", "json", "--fail-on", "warn"]
    )
    doc = json.loads(capsys.readouterr().out)
    assert code == 1
    assert doc["verdict"] == "warn"
    assert [(c["package"], c["verdict"]) for c in doc["changes"]] == [
        ("demo", "warn"),
        ("flask", "pass"),
    ]
    assert doc["changes"][0]["lockfile"] == "requirements.txt"
    assert doc["changes"][0]["line"] == 1
    assert doc["changes"][1]["findings"][0]["rule_id"] == "GRN-E004"


def test_check_usage_errors(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["check"]) == 3  # no base
    assert main(["check", "--git-base", "HEAD"]) == 3  # no lockfiles, no repo
    (tmp_path / "a.txt").write_text("x==1\n")
    assert main(["check", "--base", "a.txt", "--head", "a.txt", "--policy", "p.toml"]) == 3


def test_check_refuses_symlinked_lockfile(tmp_path, monkeypatch, capsys) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("TOKEN=hunter2\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "base.txt").write_text("")
    (repo / "requirements.txt").symlink_to(secret)
    monkeypatch.chdir(repo)
    assert main(["check", "--base", "base.txt", "--format", "json"]) == 3
    assert main(["check", "--base", "base.txt", "--head", "requirements.txt"]) == 3
    captured = capsys.readouterr()
    assert "hunter2" not in captured.out + captured.err
    assert "symlink" in captured.err
