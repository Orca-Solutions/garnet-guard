import json
from datetime import date
from pathlib import Path

import pytest

from garnet_guard import markdown as md
from garnet_guard.checks import DOCS
from garnet_guard.cli import main
from garnet_guard.engine import _finding, _lowest, report, run_checks, unchecked_result
from garnet_guard.models import Change, Limits, Policy, RawFinding, Severity
from garnet_guard.policy import PolicyError, load_policy, parse_policy, severity_for
from garnet_guard.report import to_json, to_text
from tests.builders import release

TODAY = date(2026, 11, 1)
CHANGE = Change("pypi", "demo", "1.0", "1.1")

SPEC_EXAMPLE = """
[garnet]
version = 1
default = "warn"
fail_on = "block"

[garnet.rules]
"GRN-T001" = "block"
"GRN-C004" = "off"

[[garnet.ignore]]
ecosystem = "pypi"
package = "numpy"
versions = ">=2.0"
rules = ["GRN-C004"]
reason = "ships compiled wheels"
until = "2027-06-30"

[garnet.limits]
budget_seconds = 60
"""


def policy(text: str, *, pyproject: bool = False) -> Policy:
    return parse_policy(text.encode(), source="garnet.toml", pyproject=pyproject)


def ignore_toml(**fields: str) -> str:
    entry = {
        "package": '"demo"',
        "rules": '["GRN-T004"]',
        "reason": '"tags moved to a monorepo; checked by hand"',
        "until": '"2026-12-31"',
    }
    entry.update(fields)
    body = "\n".join(f"{k} = {v}" for k, v in entry.items() if v)
    return f"[garnet]\nversion = 1\n\n[[garnet.ignore]]\n{body}\n"


def lost_tag_result(pol: Policy, *, today: date = TODAY, change: Change = CHANGE):
    """1.0 → 1.1 loses its git tag: one GRN-T004 warning."""
    return run_checks(change, release("1.0"), release("1.1", tag=False), policy=pol, today=today)


# --- Parsing -----------------------------------------------------------------


def test_planned_rules_can_be_named_already() -> None:
    p = policy(ignore_toml(rules='["GRN-C004", "GRN-T006"]'))
    assert p.ignores[0].rules == ("GRN-C004", "GRN-T006")


def test_spec_example_parses() -> None:
    p = policy(SPEC_EXAMPLE)
    assert p.source == "garnet.toml" and len(p.sha256 or "") == 64
    assert p.default == Severity.WARN and p.fail_on == Severity.BLOCK
    assert p.rules == {"GRN-C004": Severity.OFF, "GRN-T001": Severity.BLOCK}
    (i,) = p.ignores
    assert (i.package, i.versions, i.rules, i.until) == (
        "numpy",
        ">=2.0",
        ("GRN-C004",),
        date(2027, 6, 30),
    )
    assert p.limits.budget_seconds == 60 and p.limits.max_entries == Limits().max_entries


def test_pyproject_table_and_its_absence() -> None:
    p = policy('[tool.garnet]\nversion = 1\nfail_on = "warn"\n', pyproject=True)
    assert p.fail_on == Severity.WARN
    assert policy('[project]\nname = "x"\n', pyproject=True) == Policy()


def test_toml_date_works_too() -> None:
    p = policy(ignore_toml(until="2026-12-31"))
    assert p.ignores[0].until == date(2026, 12, 31)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[garnet]\n", "needs version = 1"),
        ("[garnet]\nversion = 2\n", "reads version 1"),
        ("[garnet]\nversion = true\n", "reads version 1"),
        ("[garnet]\nversion = 1\nfail-on = 'warn'\n", "unknown key 'fail-on'"),
        ("[garnet]\nversion = 1\n[other]\n", "unknown top-level key 'other'"),
        ("version = 1\n", "unknown top-level key 'version'"),
        ("", "no [garnet] table"),
        ("[garnet\n", "not valid TOML"),
        ("[garnet]\nversion = 1\ndefault = 'off'\n", "default = 'off'"),
        ("[garnet]\nversion = 1\nfail_on = 'pass'\n", "fail_on = 'pass'"),
        ("[garnet]\nversion = 1\n[garnet.rules]\nGRN-X999 = 'warn'\n", "unknown rule"),
        ("[garnet]\nversion = 1\n[garnet.rules]\nGRN-T001 = 'loud'\n", "GRN-T001"),
        ("[garnet]\nversion = 1\n[garnet.limits]\nbudget_seconds = 600\n", "only be lowered"),
        ("[garnet]\nversion = 1\n[garnet.limits]\nbudget_seconds = 0\n", "positive"),
        ("[garnet]\nversion = 1\n[garnet.limits]\nmax_files = 5\n", "unknown key 'max_files'"),
        ("[garnet]\nversion = 1\nignore = 'numpy'\n", "array of tables"),
    ],
)
def test_invalid_policies_are_errors(text: str, message: str) -> None:
    with pytest.raises(PolicyError, match=message.replace("[", r"\[")):
        policy(text)


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"reason": ""}, "needs reason"),
        ({"until": ""}, "needs until"),
        ({"rules": ""}, "needs rules"),
        ({"package": ""}, "needs package"),
        ({"reason": '"  "'}, "reason must be a non-empty string"),
        ({"until": '"next year"'}, "ISO date"),
        ({"until": "2026-12-31T10:00:00"}, "ISO date"),
        ({"rules": "[]"}, "non-empty list"),
        ({"rules": '["GRN-Z001"]'}, "unknown rule"),
        ({"versions": '"two or more"'}, "version specifier"),
        ({"ecosystem": '"cargo"'}, "ecosystem"),
        ({"owner": '"jason"'}, "unknown key 'owner'"),
        ({"acknowledge_critical": '"yes"'}, "true or false"),
    ],
)
def test_invalid_ignores_are_errors(fields: dict[str, str], message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        policy(ignore_toml(**fields))


@pytest.mark.parametrize("rule", ["GRN-T007", "GRN-T008", "GRN-K001"])
def test_critical_rules_need_acknowledgement(rule: str) -> None:
    with pytest.raises(PolicyError, match="acknowledge_critical = true"):
        policy(ignore_toml(rules=f'["{rule}"]'))
    p = policy(ignore_toml(rules=f'["{rule}"]', acknowledge_critical="true"))
    assert p.ignores[0].acknowledge_critical
    with pytest.raises(PolicyError, match="can't be lowered"):
        policy(f'[garnet]\nversion = 1\n[garnet.rules]\n"{rule}" = "warn"\n')


@pytest.mark.parametrize("rule", ["GRN-E001", "GRN-E002", "GRN-E003", "GRN-E004", "GRN-E005"])
def test_couldnt_check_rules_cant_be_turned_down(rule: str) -> None:
    with pytest.raises(PolicyError, match="didn't run"):
        policy(f'[garnet]\nversion = 1\n[garnet.rules]\n"{rule}" = "off"\n')
    raised = policy(f'[garnet]\nversion = 1\n[garnet.rules]\n"{rule}" = "block"\n')
    assert severity_for(raised, DOCS[rule]) == Severity.BLOCK


def test_load_policy_location_order(tmp_path: Path) -> None:
    assert load_policy(cwd=tmp_path) == Policy()
    (tmp_path / "pyproject.toml").write_text("[tool.garnet]\nversion = 1\nfail_on = 'warn'\n")
    assert load_policy(cwd=tmp_path).source == "pyproject.toml"
    (tmp_path / "garnet.toml").write_text("[garnet]\nversion = 1\nfail_on = 'never'\n")
    assert load_policy(cwd=tmp_path).fail_on == Severity.OFF
    other = tmp_path / "ci-policy.toml"
    other.write_text("[garnet]\nversion = 1\n")
    assert load_policy(other).source == str(other)
    with pytest.raises(PolicyError, match="no such policy file"):
        load_policy(tmp_path / "missing.toml")


# --- Severities ----------------------------------------------------------------


def test_default_cap_and_rule_settings() -> None:
    p = policy('[garnet]\nversion = 1\ndefault = "block"\n[garnet.rules]\n"GRN-T004" = "info"\n')
    assert severity_for(p, DOCS["GRN-T001"]) == Severity.BLOCK  # warn rule, capped up
    assert severity_for(p, DOCS["GRN-T004"]) == Severity.INFO  # explicit setting wins
    assert severity_for(p, DOCS["GRN-E004"]) == Severity.INFO  # not a warn rule
    quiet = policy('[garnet]\nversion = 1\ndefault = "info"\n')
    assert severity_for(quiet, DOCS["GRN-T001"]) == Severity.INFO
    assert severity_for(quiet, DOCS["GRN-E001"]) == Severity.WARN  # couldn't-check keeps warn


def test_off_rules_are_left_out_and_block_counts() -> None:
    off = lost_tag_result(policy('[garnet]\nversion = 1\n[garnet.rules]\n"GRN-T004" = "off"\n'))
    assert off.findings == () and off.verdict == "pass"
    block = lost_tag_result(policy('[garnet]\nversion = 1\n[garnet.rules]\n"GRN-T004" = "block"\n'))
    assert block.verdict == "block" and block.findings[0].default_severity == Severity.WARN


def test_a_check_can_still_lower_a_policy_severity() -> None:
    p = policy('[garnet]\nversion = 1\n[garnet.rules]\n"GRN-C003" = "block"\n')
    raw = RawFinding("GRN-C003", "test file", (), lowered_to=Severity.INFO)
    assert _finding(CHANGE, raw, p, TODAY).severity == Severity.INFO


def test_policy_limits_only_lower_options() -> None:
    lowered = _lowest(Limits(), Limits(budget_seconds=30))
    assert lowered.budget_seconds == 30 and lowered.max_entries == Limits().max_entries


# --- Ignores -------------------------------------------------------------------


def test_ignore_suppresses_but_still_reports() -> None:
    p = policy(ignore_toml())
    result = lost_tag_result(p)
    (f,) = result.findings
    assert f.rule_id == "GRN-T004" and f.severity == Severity.WARN
    assert f.suppressed_by == p.ignores[0]
    assert result.verdict == "pass"
    rep = report([result], policy=p, today=TODAY)
    assert rep.verdict == "pass" and rep.exit_code(Severity.WARN) == 0
    doc = json.loads(to_json(rep))
    found = doc["changes"][0]["findings"][0]
    assert found["severity"] == "warn"
    assert found["suppressed_by"] == {
        "package": "demo",
        "rules": ["GRN-T004"],
        "reason": "tags moved to a monorepo; checked by hand",
        "until": "2026-12-31",
        "acknowledge_critical": False,
    }
    assert doc["policy"] == {"source": "garnet.toml", "sha256": p.sha256, "expired": []}
    text = to_text(rep)
    assert "ignored GRN-T004" in text and "ignored until 2026-12-31: tags moved" in text


def test_unsuppressed_findings_still_count() -> None:
    p = policy(ignore_toml())
    result = run_checks(
        CHANGE, release("1.0"), release("1.1", tag=False, provenance="none"), policy=p, today=TODAY
    )
    assert result.verdict == "warn"
    assert [(f.rule_id, f.suppressed_by is None) for f in result.findings] == [
        ("GRN-T001", True),
        ("GRN-T004", False),
    ]


@pytest.mark.parametrize(
    ("fields", "change", "applies"),
    [
        ({}, Change("pypi", "Demo_Pkg", "1.0", "1.1"), False),
        ({"package": '"Demo_Pkg"'}, Change("pypi", "demo-pkg", "1.0", "1.1"), True),
        ({"versions": '">=1.1,<2"'}, CHANGE, True),
        ({"versions": '"==1.0"'}, CHANGE, False),
        ({"versions": '">=1.1"'}, Change("pypi", "demo", "1.0", "1.2rc1"), True),
        ({"versions": '">=1.1"'}, Change("pypi", "demo", "1.0", "not-a-version"), False),
        ({"ecosystem": '"pypi"'}, CHANGE, True),
        ({"ecosystem": '"npm"'}, CHANGE, False),
        ({"rules": '["GRN-T001"]'}, CHANGE, False),
    ],
)
def test_what_an_ignore_matches(fields: dict[str, str], change: Change, applies: bool) -> None:
    result = lost_tag_result(policy(ignore_toml(**fields)), change=change)
    assert (result.findings[0].suppressed_by is not None) is applies


def test_ignore_expires_after_its_until_date() -> None:
    p = policy(ignore_toml(until='"2026-12-31"'))
    assert lost_tag_result(p, today=date(2026, 12, 31)).verdict == "pass"  # last day applies

    later = date(2027, 1, 1)
    result = lost_tag_result(p, today=later)
    (f,) = result.findings
    assert result.verdict == "warn" and f.suppressed_by is None
    assert "expired on 2026-12-31" in f.evidence[-1].summary
    rep = report([result], policy=p, today=later)
    assert rep.expired == p.ignores
    assert json.loads(to_json(rep))["policy"]["expired"][0]["until"] == "2026-12-31"
    assert "note: this ignore expired and no longer applies: demo GRN-T004" in to_text(rep)


def test_expired_ignores_are_reported_even_with_nothing_to_match() -> None:
    p = policy(ignore_toml(package='"other"', until='"2026-01-01"'))
    rep = report([lost_tag_result(p)], policy=p, today=TODAY)
    assert [i.package for i in rep.expired] == ["other"]


def test_first_live_ignore_wins() -> None:
    two = ignore_toml(reason='"first"') + (
        '\n[[garnet.ignore]]\npackage = "demo"\nrules = ["GRN-T004"]\n'
        'reason = "second"\nuntil = "2027-01-31"\n'
    )
    assert lost_tag_result(policy(two)).findings[0].suppressed_by.reason == "first"  # type: ignore[union-attr]


def test_unchecked_changes_follow_the_policy() -> None:
    p = policy(ignore_toml(package='"flask"', rules='["GRN-E004"]'))
    change = Change("pypi", "flask", None, ">=3", lockfile="requirements.txt", line=2)
    result = unchecked_result(change, "GRN-E004", "flask>=3 isn't pinned", policy=p, today=TODAY)
    assert result.findings[0].suppressed_by is not None


def test_comment_shows_ignored_rules_and_expired_ignores() -> None:
    old = '\n[[garnet.ignore]]\npackage = "old"\nrules = ["GRN-T004"]\nreason = "r"\nuntil = "2026-01-01"\n'
    p = policy(ignore_toml() + old)
    rep = report([lost_tag_result(p)], policy=p, today=TODAY)
    out = md.to_markdown(rep)
    assert "ignored by the policy: `GRN-T004`" in out
    assert "nothing worth a look" in out
    assert "ignore for `old` (`GRN-T004`) expired on `2026-01-01`" in out


# --- CLI -----------------------------------------------------------------------


@pytest.fixture
def project(tmp_path, monkeypatch):
    from garnet_guard import cli

    (tmp_path / "base.txt").write_text("demo==1.0\n")
    (tmp_path / "requirements.txt").write_text("demo==1.1\n")

    def fake_evaluate(changes, *, policy=None, options=None):
        return [
            run_checks(c, release("1.0"), release("1.1", tag=False), policy=policy) for c in changes
        ]

    monkeypatch.setattr(cli, "evaluate", fake_evaluate)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def check(*extra: str) -> int:
    return main(["check", "--base", "base.txt", "--head", "requirements.txt", *extra])


def test_cli_reads_garnet_toml_and_fail_on(project, capsys) -> None:
    assert check("--fail-on", "warn") == 1
    capsys.readouterr()
    (project / "garnet.toml").write_text(ignore_toml(until='"2099-12-31"'))
    assert check("--fail-on", "warn", "--format", "json") == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["policy"]["source"] == "garnet.toml" and doc["verdict"] == "pass"
    assert check("--fail-on", "warn", "--no-policy") == 1

    (project / "garnet.toml").write_text("[garnet]\nversion = 1\nfail_on = 'warn'\n")
    assert check() == 1  # the policy's fail_on
    assert check("--fail-on", "block") == 0  # the flag wins
    assert check("--policy", "garnet.toml", "--no-policy") == 3


def test_cli_invalid_policy_exits_3(project, capsys) -> None:
    (project / "garnet.toml").write_text(ignore_toml(reason='""'))
    assert check() == 3
    assert "ignore #1 reason must be a non-empty string" in capsys.readouterr().err


def test_policy_check_command(project, capsys) -> None:
    assert main(["policy", "check"]) == 0
    assert "defaults apply" in capsys.readouterr().out
    (project / "garnet.toml").write_text(
        ignore_toml(until='"2099-12-31"')
        + '\n[[garnet.ignore]]\npackage = "old"\nrules = ["GRN-C001"]\n'
        'reason = "reviewed"\nuntil = "2020-01-01"\n'
    )
    assert main(["policy", "check"]) == 0
    out = capsys.readouterr().out
    assert "garnet.toml: valid" in out
    assert "ignore demo GRN-T004 until 2099-12-31 (applies)" in out
    assert "ignore old GRN-C001 until 2020-01-01 (EXPIRED, no longer applies)" in out
    (project / "bad.toml").write_text("[garnet]\nversion = 1\nextra = 1\n")
    assert main(["policy", "check", "bad.toml"]) == 3
