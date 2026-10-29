import json
from pathlib import Path

import jsonschema
import pytest

from garnet_guard import sarif
from garnet_guard.checks import DOCS
from garnet_guard.cli import main
from garnet_guard.engine import report, run_checks
from garnet_guard.markdown import ReportFormatError
from garnet_guard.models import Change
from tests.builders import release

# The official SARIF 2.1.0 schema, from github.com/oasis-tcs/sarif-spec
# (sarif-2.1/schema/sarif-schema-2.1.0.json at 1742a253), so validation needs no network.
SCHEMA = json.loads((Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json").read_text())


def _validate(log: dict) -> None:
    jsonschema.Draft4Validator(SCHEMA).validate(log)


def _change(*findings: dict, **extra: object) -> dict:
    return {
        "ecosystem": "pypi",
        "package": "examplelib",
        "baseline": "2.6.1",
        "candidate": "2.6.2",
        "lockfile": "uv.lock",
        "line": 12,
        "verdict": "warn",
        "findings": list(findings),
        **extra,
    }


def _finding(rule: str = "GRN-T004", title: str = "no tag", severity: str = "warn", **extra):
    return {"rule_id": rule, "title": title, "severity": severity, **extra}


def _results(*changes: dict) -> list[dict]:
    log = sarif.render({"changes": list(changes)})
    _validate(log)
    return log["runs"][0]["results"]


def test_report_is_valid_sarif_and_follows_the_spec() -> None:
    change = Change("pypi", "demo", "1.0", "1.1", lockfile="sub/uv.lock", line=7)
    rep = report([run_checks(change, release("1.0"), release("1.1", provenance="none", tag=False))])
    out = sarif.to_sarif(rep)
    assert out == sarif.to_sarif(rep)
    log = json.loads(out)
    _validate(log)

    assert log["version"] == "2.1.0"
    (run,) = log["runs"]
    driver = run["tool"]["driver"]
    assert driver["name"] == "garnet"
    assert [r["id"] for r in driver["rules"]] == sorted(DOCS)
    assert {r["ruleId"] for r in run["results"]} >= {"GRN-T001", "GRN-T004"}
    for r in run["results"]:
        rule = driver["rules"][r["ruleIndex"]]
        assert rule["id"] == r["ruleId"]
        assert r["level"] == "warning"
        assert r["message"]["text"].startswith("demo 1.0 → 1.1: ")
        loc = r["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "sub/uv.lock"
        assert loc["region"] == {"startLine": 7}
    t004 = driver["rules"][sorted(DOCS).index("GRN-T004")]
    assert t004["defaultConfiguration"] == {"level": "warning"}
    assert t004["helpUri"].endswith("/docs/rules/GRN-T004.md")
    assert "trust" in t004["properties"]["tags"]


def test_rule_metadata_fits_code_scanning_limits() -> None:
    log = sarif.render({"changes": []})
    _validate(log)
    for rule in log["runs"][0]["tool"]["driver"]["rules"]:
        assert len(rule["name"]) <= 255
        assert len(rule["shortDescription"]["text"]) <= 1024
        assert len(rule["fullDescription"]["text"]) <= 1024
        assert len(rule["properties"]["tags"]) <= 10
    assert log["runs"][0]["results"] == []


def test_severities_map_to_levels() -> None:
    results = _results(
        _change(
            _finding("GRN-K001", "known bad", "block"),
            _finding("GRN-T004", "no tag", "warn"),
            _finding("GRN-E004", "unpinned", "info"),
            _finding("GRN-C001", "turned off by policy", "off"),
        )
    )
    assert [(r["ruleId"], r["level"]) for r in results] == [
        ("GRN-K001", "error"),
        ("GRN-T004", "warning"),
        ("GRN-E004", "note"),
    ]


def test_package_strings_cant_add_links_or_control_characters() -> None:
    title = "see [the fix](https://evil.example) \\[x\\]\x1b[31m red\u202e\nnext"
    (r,) = _results(
        _change(
            _finding(title=title, release="2.6.1]"),
            package="lib[x](https://evil.example)",
        )
    )
    msg = r["message"]["text"]
    assert "[the fix](" not in msg and "](" not in msg.replace("\\](", "")
    assert "\\[the fix\\](https://evil.example)" in msg
    assert "\x1b" not in msg and "\u202e" not in msg
    assert msg.count("\n") == 0
    assert msg.startswith("lib\\[x\\](https://evil.example) 2.6.1 → 2.6.2: ")
    assert msg.endswith("(in 2.6.1\\])")


def test_evidence_lines_are_included_and_capped() -> None:
    evidence = [
        {"kind": "tag", "summary": "tag v2.6.1 exists", "url": "https://github.com/o/r/tags"}
    ]
    evidence += [{"kind": "note", "summary": "no https", "url": "javascript:alert(1)"}]
    evidence += [{"kind": "note", "summary": f"file {i}"} for i in range(12)]
    (r,) = _results(_change(_finding(evidence=evidence)))
    lines = r["message"]["text"].split("\n")
    assert lines[1:3] == ["", "Evidence:"]
    assert lines[3] == "- tag v2.6.1 exists <https://github.com/o/r/tags>"
    assert lines[4] == "- no https"
    assert len(lines) == 3 + 10 + 1
    assert lines[-1] == "- and 4 more in the JSON report"


def test_suppressed_findings_carry_a_suppression() -> None:
    ignore = {
        "package": "examplelib",
        "rules": ["GRN-T004"],
        "reason": "tags moved to [a] new repo",
    }
    by_obj, by_str, active = _results(
        _change(
            _finding(suppressed_by=ignore),
            _finding("GRN-T001", suppressed_by="garnet.toml"),
            _finding("GRN-C001"),
        )
    )
    assert by_obj["suppressions"] == [
        {
            "kind": "external",
            "status": "accepted",
            "justification": "tags moved to \\[a\\] new repo",
        }
    ]
    assert by_str["suppressions"][0]["justification"] == "garnet.toml"
    assert "suppressions" not in active


def test_fingerprints_are_stable_and_distinct() -> None:
    a = _results(_change(_finding()))[0]["partialFingerprints"]
    b = _results(_change(_finding(), line=40))[0]["partialFingerprints"]
    c = _results(_change(_finding(), candidate="2.6.3"))[0]["partialFingerprints"]
    assert a == b  # the same finding on a moved line is the same alert
    assert a != c


def test_location_paths_and_lines() -> None:
    (r,) = _results(_change(_finding(), lockfile="./deps/my reqs.txt", line=None))
    loc = r["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"] == {"uri": "deps/my%20reqs.txt", "uriBaseId": "%SRCROOT%"}
    assert loc["region"] == {"startLine": 1}
    (r,) = _results(_change(_finding(), lockfile="deps\\uv.lock", line=0))
    assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "deps/uv.lock"


@pytest.mark.parametrize(
    "change",
    [
        _change(_finding("GRN-X999")),
        _change(_finding(severity="critical")),
        _change(_finding(), lockfile="../outside/uv.lock"),
        _change(_finding(), lockfile="/etc/passwd"),
        _change(_finding(), lockfile="C:\\repo\\uv.lock"),
        _change(_finding(), lockfile="a/\x1b/uv.lock"),
        _change(_finding(), lockfile="."),
        _change(_finding(), lockfile=None),
        "not an object",
        _change("not an object"),
    ],
)
def test_untrusted_documents_are_refused(change: object) -> None:
    with pytest.raises(ReportFormatError):
        sarif.render({"changes": [change]})


def test_renderer_command(tmp_path: Path) -> None:
    doc = tmp_path / "report.json"
    doc.write_text(json.dumps({"changes": [_change(_finding())]}))
    out = tmp_path / "garnet.sarif"
    assert sarif.main([str(doc), "--output", str(out)]) == 0
    _validate(json.loads(out.read_text()))
    doc.write_text(json.dumps({"changes": [_change(_finding("GRN-X999"))]}))
    assert sarif.main([str(doc), "--output", str(tmp_path / "bad.sarif")]) == 3
    assert not (tmp_path / "bad.sarif").exists()
    doc.write_text("{not json")
    assert sarif.main([str(doc)]) == 3


def test_check_writes_sarif(tmp_path, monkeypatch) -> None:
    from garnet_guard import cli

    (tmp_path / "base.txt").write_text("demo==1.0\n")
    (tmp_path / "requirements.txt").write_text("flask>=3\ndemo==1.1\n")

    def fake_evaluate(changes, *, options=None):
        return [run_checks(changes[0], release("1.0"), release("1.1", provenance="none"))]

    monkeypatch.setattr(cli, "evaluate", fake_evaluate)
    monkeypatch.chdir(tmp_path)
    args = ["check", "--base", "base.txt", "--head", "requirements.txt", "--format", "sarif"]
    assert main([*args, "--output", "out.sarif", "--fail-on", "warn"]) == 1
    log = json.loads((tmp_path / "out.sarif").read_text())
    _validate(log)
    places = {
        (r["ruleId"], r["locations"][0]["physicalLocation"]["region"]["startLine"])
        for r in log["runs"][0]["results"]
    }
    assert ("GRN-T001", 2) in places
    assert ("GRN-E004", 1) in places
