"""The agent hooks: every outcome's JSON on both agents, the fast path, the
deadline, the caps, and the printed configurations. No network."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

import pytest

from garnet_guard.engine import Options
from garnet_guard.install import gate, hooks
from garnet_guard.install.runner import Ran
from garnet_guard.models import (
    Change,
    ChangeResult,
    Evidence,
    Finding,
    Policy,
    Severity,
    Verdict,
)
from tests.test_install_check import (
    BASE_LOCK,
    FIXTURES,
    HEAD_LOCK,
    FakeRunner,
    deps,
    evaluator,
    pip_answers,
    releases,
    uv_project,
)

AGENTS = ("claude-code", "codex")


@pytest.fixture
def where(tmp_path: Path) -> dict[str, str]:
    """A folder with stand-in pip, python and npm programs (never run)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "python").write_text("")
    (bin_dir / "python").chmod(0o755)
    (bin_dir / "pip").write_text(f"#!{bin_dir / 'python'}\n")
    (bin_dir / "pip").chmod(0o755)
    (bin_dir / "npm").write_text("#!/bin/sh\n")
    (bin_dir / "npm").chmod(0o755)
    return {"PATH": str(bin_dir), "HOME": str(tmp_path), "cwd": str(tmp_path)}


def event(command: str | list[str], cwd: str, tool: str = "Bash", **extra: Any) -> dict[str, Any]:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
        "cwd": cwd,
        "session_id": "s",
        "tool_use_id": "t",
        "permission_mode": "default",
        **extra,
    }


def answer(
    agent: str, payload: dict[str, Any], where: dict[str, str], **kw: Any
) -> dict[str, Any] | None:
    stdout, stderr = io.StringIO(), io.StringIO()
    hooks.handle(
        agent,
        payload,
        stdout=stdout,
        stderr=stderr,
        env={"PATH": where["PATH"], "HOME": where["HOME"], **kw.pop("hook_env", {})},
        deps=kw.pop("deps", None)
        or deps(FakeRunner(pip_answers("pip-report-requests-2.32.3.json")), **kw),
        exit_now=lambda code: None,
        **({"deadline_seconds": kw.pop("deadline")} if "deadline" in kw else {}),
    )
    text = stdout.getvalue().strip()
    if not text:
        return None
    assert text.count("\n") == 0  # exactly one JSON object
    out = json.loads(text)
    assert isinstance(out, dict)
    for value in _strings(out):
        assert len(value) <= 10_000
        assert "\x1b" not in value
    return out


def _strings(obj: object) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _strings(v)]
    return []


def spec(out: dict[str, Any] | None) -> dict[str, Any]:
    assert out is not None
    inner = out["hookSpecificOutput"]
    assert inner["hookEventName"] == "PreToolUse"
    return inner  # type: ignore[no-any-return]


@pytest.mark.parametrize("agent", AGENTS)
def test_pass_sends_context_and_no_decision(
    agent: str, where: dict[str, str], tmp_path: Path
) -> None:
    out = answer(
        agent,
        event("pip install requests==2.32.3", where["cwd"], scratchpad_dir=str(tmp_path)),
        where,
    )
    inner = spec(out)
    assert "permissionDecision" not in inner and "permissionDecisionReason" not in inner
    assert "systemMessage" not in (out or {})
    context = inner["additionalContext"]
    assert "requests 2.32.2 -> 2.32.3" in context and "nothing at warn or above" in context
    assert context.startswith(hooks.DATA_NOTE)
    # The answer says everything, so no report file is written.
    assert "Full report" not in context and not list(tmp_path.rglob("garnet-report-*"))


@pytest.mark.parametrize("agent", AGENTS)
def test_warn_adds_a_system_message(agent: str, where: dict[str, str]) -> None:
    out = answer(
        agent,
        event("pip install requests==2.32.3", where["cwd"]),
        where,
        evaluate=evaluator({"requests": ("GRN-T004", Severity.WARN)}),
    )
    inner = spec(out)
    assert "permissionDecision" not in inner
    assert (
        "GRN-T004" in inner["additionalContext"]
        and "garnet explain GRN-T004" in inner["additionalContext"]
    )
    assert out is not None and out["systemMessage"].startswith("Garnet Guard: pip install")


def test_findings_name_each_rule_once_and_skip_repeated_evidence(where: dict[str, str]) -> None:
    def evaluate(changes: list[Change], policy: Policy, options: Options) -> list[ChangeResult]:
        out = []
        for c in changes:
            found = tuple(
                Finding(
                    rule, "n", Severity.WARN, Severity.WARN, c, title, (Evidence("f", ev),), "", ""
                )
                for rule, title, ev in (
                    ("GRN-E001", "Couldn't fully check: OSV lookup failed", "OSV lookup failed"),
                    ("GRN-T004", "A new uploader", "uploaded by mallory"),
                )
            )
            out.append(ChangeResult(c, Verdict.WARN, found))
        return out

    out = answer(
        "claude-code", event("pip install requests==2.32.3", where["cwd"]), where, evaluate=evaluate
    )
    context = spec(out)["additionalContext"]
    assert '"OSV lookup failed" ("OSV lookup failed")' not in context
    # Package-supplied titles and evidence are in double quotes.
    assert '"A new uploader" ("uploaded by mallory")' in context
    assert "Rule details: garnet explain GRN-E001, garnet explain GRN-T004." in context


@pytest.mark.parametrize("scratchpad", [True, False])
def test_findings_write_the_full_report(
    scratchpad: bool, where: dict[str, str], tmp_path: Path
) -> None:
    extra = {"scratchpad_dir": str(tmp_path)} if scratchpad else {}
    out = answer(
        "codex",
        event("pip install requests==2.32.3", where["cwd"], **extra),
        where,
        evaluate=evaluator({"requests": ("GRN-T004", Severity.WARN)}),
    )
    context = spec(out)["additionalContext"]
    report = Path(context.rsplit("Full report: ", 1)[1].rstrip("."))
    # Claude Code's scratch folder, else the system temp folder (tmp_path's, in tests).
    folder = tmp_path if scratchpad else Path(tempfile.gettempdir())
    assert report.parent == folder and report.name.startswith("garnet-report-")
    assert report.stat().st_mode & 0o077 == 0  # only this user can read it
    text = report.read_text()
    assert text.startswith("Command: pip install requests==2.32.3")
    assert "GRN-T004" in text and "evidence line" in text


@pytest.mark.parametrize("agent", AGENTS)
def test_block_denies_with_the_findings(agent: str, where: dict[str, str]) -> None:
    out = answer(
        agent,
        event("cd . && pip install requests==2.32.3", where["cwd"]),
        where,
        evaluate=evaluator({"requests": ("GRN-T001", Severity.BLOCK)}),
    )
    inner = spec(out)
    assert inner["permissionDecision"] == "deny"
    reason = inner["permissionDecisionReason"]
    assert "GRN-T001 requests 2.32.2 -> 2.32.3" in reason and "evidence line" in reason
    assert "garnet explain GRN-T001" in reason


@pytest.mark.parametrize(("agent", "decision"), [("claude-code", "ask"), ("codex", "deny")])
def test_cant_check_asks_or_denies(agent: str, decision: str, where: dict[str, str]) -> None:
    stderr = (FIXTURES / "pip-num2words-0.5.14.stderr").read_text()
    run = FakeRunner(pip_answers("pip-report-num2words.json", probe_err=stderr))
    registry = releases(
        num2words=[("0.5.6", "wheel"), ("0.5.14", "wheel")], docopt=[("0.6.2", "sdist")]
    )
    out = answer(
        agent,
        event("pip install num2words", where["cwd"]),
        where,
        deps=deps(run, registry=registry),
    )
    inner = spec(out)
    assert inner["permissionDecision"] == decision
    reason = inner["permissionDecisionReason"]
    assert "num2words 0.5.14 needs docopt>=0.6.2, which is published only as source" in reason
    assert "What it could check without building: Changes: num2words (new) -> 0.5.6." in reason
    assert "pip install num2words==0.5.6 can be checked." in reason
    assert all(c[2] for c in run.calls)  # the hook never installs
    if agent == "claude-code":  # the "ask" reason goes to the user; the agent reads this
        context = inner["additionalContext"]
        assert "num2words 0.5.14 needs docopt>=0.6.2" in context
        assert "pip install num2words==0.5.6 can be checked." in context


@pytest.mark.parametrize(("agent", "decision"), [("claude-code", "ask"), ("codex", "deny")])
@pytest.mark.parametrize(
    "command", ["pip install $(cat reqs.txt)", "eval pip install x", "pip install 'x"]
)
def test_cant_tell_asks_or_denies(
    agent: str, decision: str, command: str, where: dict[str, str]
) -> None:
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    inner = spec(answer(agent, event(command, where["cwd"]), where, deps=deps(run)))
    assert inner["permissionDecision"] == decision
    assert "as its own command with literal arguments" in inner["permissionDecisionReason"]
    if agent == "claude-code":
        assert "as its own command with literal arguments" in inner["additionalContext"]
    assert run.calls == []


@pytest.mark.parametrize(("agent", "decision"), [("claude-code", "ask"), ("codex", "deny")])
@pytest.mark.parametrize(
    "command",
    [
        "if [ -f requirements.txt ]; then pip install $(cat r); fi",
        'for p in requests six; do pip install "$p"; done',
        "python -m uv sync",
        'echo "pip install requests" | sh',
        "stdbuf -oL pip install requests",
        "pip --bogus 1 install requests",
        "$(echo pip) install requests",
        "`echo pip` install requests",
        "P=pip; $P install requests",
        'P=pip && "$P" install requests',
        "x=$(which pip); $x install requests",
        "$(command -v pip) install requests",
        '"$(which pip)" install requests',
        "for t in pip; do $t install requests; done",
        "PIP=pip3; ${PIP} install requests",
        "${UV:-uv} add requests",
    ],
)
def test_forms_the_parser_cant_follow_are_never_silent(
    agent: str, decision: str, command: str, where: dict[str, str]
) -> None:
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    inner = spec(answer(agent, event(command, where["cwd"]), where, deps=deps(run)))
    assert inner["permissionDecision"] == decision


@pytest.mark.parametrize(("agent", "decision"), [("claude-code", "ask"), ("codex", "deny")])
@pytest.mark.parametrize(
    "command",
    ["uvx ruff", "uv tool install ruff", "uv run --with requests python", "poetry add x"],
)
def test_tools_that_install_unseen_packages_are_cant_check(
    agent: str, decision: str, command: str, where: dict[str, str]
) -> None:
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    inner = spec(answer(agent, event(command, where["cwd"]), where, deps=deps(run)))
    assert inner["permissionDecision"] == decision
    assert f"{command}: not checked." in inner["permissionDecisionReason"]


@pytest.mark.parametrize(("agent", "decision"), [("claude-code", "ask"), ("codex", "deny")])
@pytest.mark.parametrize(
    ("command", "shown"),
    [
        ("uv run http://example.invalid/s.py", "uv run http://example.invalid/s.py"),
        ("uv run - < sub/x.py", "uv run -"),
        ("cat sub/x.py | uv run -", "uv run -"),
        ("uv --directory sub run x.py", "uv --directory sub run x.py"),
        ("uv run --directory sub x.py", "uv run --directory sub x.py"),
        ("uv run sub/x.py", "uv run sub/x.py"),
        ("uv run -wsix python -c 1", "uv run -wsix python -c 1"),
        ("uv run -qw six python", "uv run -qw six python"),
    ],
)
def test_uv_run_scripts_and_with_are_cant_check_outside_a_project(
    agent: str, decision: str, command: str, shown: str, where: dict[str, str]
) -> None:
    sub = Path(where["cwd"], "sub")
    sub.mkdir()
    (sub / "x.py").write_text('# /// script\n# dependencies = ["six"]\n# ///\nprint(1)\n')
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    inner = spec(answer(agent, event(command, where["cwd"]), _uv_where(where), deps=deps(run)))
    assert inner["permissionDecision"] == decision
    assert f"{shown}: not checked." in inner["permissionDecisionReason"]


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("severity", [Severity.BLOCK, Severity.WARN])
def test_fail_on_never_still_shows_the_findings(
    agent: str, severity: Severity, where: dict[str, str]
) -> None:
    Path(where["cwd"], "garnet.toml").write_text('[garnet]\nversion = 1\nfail_on = "never"\n')
    out = answer(
        agent,
        event("pip install requests==2.32.3", where["cwd"]),
        where,
        evaluate=evaluator({"requests": ("GRN-T001", severity)}),
    )
    inner = spec(out)
    assert "permissionDecision" not in inner
    context = inner["additionalContext"]
    assert f"the verdict is {severity.label}, below fail_on = never" in context
    assert f"{severity.label} GRN-T001 requests 2.32.2 -> 2.32.3" in context
    assert "nothing at warn or above" not in context
    assert out is not None and "GRN-T001" in out["systemMessage"]


@pytest.mark.parametrize("agent", AGENTS)
def test_unsupported_tools_get_a_note_and_no_decision(agent: str, where: dict[str, str]) -> None:
    out = answer(agent, event("npm install left-pad", where["cwd"]), where)
    inner = spec(out)
    assert "permissionDecision" not in inner
    assert "npm install left-pad: not checked" in inner["additionalContext"]
    assert out is not None and out["systemMessage"].startswith(
        "Garnet Guard didn't check this install."
    )


@pytest.mark.parametrize("agent", AGENTS)
def test_block_wins_over_everything_else(agent: str, where: dict[str, str]) -> None:
    command = "npm i x; pip install requests==2.32.3; pip install $(y)"
    out = answer(
        agent,
        event(command, where["cwd"]),
        where,
        evaluate=evaluator({"requests": ("GRN-T001", Severity.BLOCK)}),
    )
    assert spec(out)["permissionDecision"] == "deny"


def test_codex_argv_command(where: dict[str, str]) -> None:
    inner = spec(
        answer("codex", event(["bash", "-lc", "pip install requests==2.32.3"], where["cwd"]), where)
    )
    assert (
        "permissionDecision" not in inner
        and "requests 2.32.2 -> 2.32.3" in inner["additionalContext"]
    )


def test_powershell_is_cant_tell(where: dict[str, str]) -> None:
    inner = spec(
        answer("claude-code", event("pip install x", where["cwd"], tool="PowerShell"), where)
    )
    assert (
        inner["permissionDecision"] == "ask" and "PowerShell" in inner["permissionDecisionReason"]
    )


def test_a_package_word_that_runs_nothing_gets_no_answer(where: dict[str, str]) -> None:
    assert answer("claude-code", event("echo pip install x", where["cwd"]), where) is None
    assert answer("claude-code", event("pip list", where["cwd"]), where) is None


def test_deadline_answers_before_the_agent_gives_up(where: dict[str, str]) -> None:
    release = threading.Event()

    def slow(argv: list[str], cwd: Path, env: dict[str, str]) -> Ran:
        release.wait(10)
        return Ran(1)

    try:
        for agent, decision in (("claude-code", "ask"), ("codex", "deny")):
            inner = spec(
                answer(
                    agent,
                    event("pip install x", where["cwd"]),
                    where,
                    deps=deps(FakeRunner(slow)),
                    deadline=1.0,
                )
            )
            assert inner["permissionDecision"] == decision
            assert "took longer than 1 seconds" in inner["permissionDecisionReason"]
    finally:
        release.set()
        for worker in threading.enumerate():
            if worker.name == hooks.WORKER:
                worker.join(10)  # it would write after the test's temp folder is gone


def test_deadline_leaves_no_temp_folder(where: dict[str, str]) -> None:
    release = threading.Event()

    def slow(argv: list[str], cwd: Path, env: dict[str, str]) -> Ran:
        release.wait(10)
        return Ran(1)

    try:
        answer(
            "codex",
            event("pip install x", where["cwd"]),
            where,
            deps=deps(FakeRunner(slow)),
            deadline=1.0,
        )
        # Removed before the process exits, though the worker still runs.
        assert not list(Path(tempfile.gettempdir()).glob("garnet-hook-*"))
    finally:
        release.set()
        for worker in threading.enumerate():
            if worker.name == hooks.WORKER:
                worker.join(10)
    assert not list(Path(tempfile.gettempdir()).glob("garnet-hook-*"))


def _uv_where(where: dict[str, str]) -> dict[str, str]:
    uv = Path(where["PATH"]) / "uv"
    uv.write_text("#!/bin/sh\n")
    uv.chmod(0o755)
    return where


def _uv_runner(check_ok: bool = True) -> FakeRunner:
    def run(argv: list[str], cwd: Path, env: dict[str, str]) -> Ran:
        assert argv[1:3] == ["lock", "--no-python-downloads"] and "--no-build" in argv
        if "--check" in argv:
            return Ran(0 if check_ok else 1)
        (cwd / "uv.lock").write_text(HEAD_LOCK)
        return Ran(0)

    return FakeRunner(run)


@pytest.mark.parametrize("agent", AGENTS)
def test_uv_run_with_nothing_new_to_sync_gets_no_answer(agent: str, where: dict[str, str]) -> None:
    uv_project(Path(where["cwd"]), lock=HEAD_LOCK)
    run = _uv_runner()
    payload = event("uv run pytest -k x", where["cwd"])
    out = answer(
        agent,
        payload,
        _uv_where(where),
        deps=deps(run, committed_lock=lambda p: HEAD_LOCK.encode()),
    )
    assert out is None
    assert run.calls and run.calls[0][0][1] == "lock"  # it was checked, as uv sync


@pytest.mark.parametrize("agent", AGENTS)
def test_uv_run_reports_what_its_sync_would_install(agent: str, where: dict[str, str]) -> None:
    uv_project(Path(where["cwd"]), lock=HEAD_LOCK)  # the working tree moved past HEAD
    run = _uv_runner()
    out = answer(
        agent,
        event("uv run pytest", where["cwd"]),
        _uv_where(where),
        deps=deps(
            run,
            committed_lock=lambda p: BASE_LOCK.encode(),
            evaluate=evaluator({"requests": ("GRN-T001", Severity.BLOCK)}),
        ),
    )
    inner = spec(out)
    assert inner["permissionDecision"] == "deny"
    assert "uv run pytest:" in inner["permissionDecisionReason"]
    assert "GRN-T001 requests 2.34.1 -> 2.34.2" in inner["permissionDecisionReason"]


def test_uv_run_outside_a_project_or_without_a_sync_gets_no_answer(where: dict[str, str]) -> None:
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    _uv_where(where)
    assert answer("codex", event("uv run python -c 1", where["cwd"]), where, deps=deps(run)) is None
    uv_project(Path(where["cwd"]))
    for command in ("uv run --no-sync pytest", "UV_NO_SYNC=1 uv run pytest"):
        assert answer("codex", event(command, where["cwd"]), where, deps=deps(run)) is None


def test_uv_run_in_a_project_garnet_cant_resolve_gets_a_note(where: dict[str, str]) -> None:
    Path(where["cwd"], "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndynamic = ["version"]\n'
        '[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n'
    )
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    out = answer("codex", event("uv run pytest", where["cwd"]), _uv_where(where), deps=deps(run))
    inner = spec(out)
    assert "permissionDecision" not in inner
    assert (
        "uv run pytest: not checked. uv run syncs the project first" in inner["additionalContext"]
    )


def test_long_reports_are_cut_and_saved(where: dict[str, str], tmp_path: Path) -> None:
    long = {"requests": ("GRN-T004", Severity.WARN)}
    out = answer(
        "claude-code",
        event("; ".join(["pip install requests==2.32.3"] * 60), where["cwd"]),
        where,
        evaluate=evaluator(long),
    )
    context = spec(out)["additionalContext"]
    assert len(context.encode()) <= hooks.MAX_FIELD and "(cut; the full report is in " in context
    report = Path(context.rsplit("(cut; the full report is in ", 1)[1].rstrip(")"))
    assert report.read_text().count("pip install requests==2.32.3") > 60


def test_fields_are_measured_in_bytes() -> None:
    # Codex counts 4 bytes as a token, so a field of 8,000 characters of "é" is too long.
    text = hooks._clip("é" * hooks.MAX_FIELD, lambda: None)
    assert len(text.encode()) <= hooks.MAX_FIELD and text.endswith(" ... (cut)")
    assert hooks._clip("é" * 100, lambda: pytest.fail("nothing was cut")) == "é" * 100


def test_package_text_is_escaped_in_answers(where: dict[str, str]) -> None:
    evil = {"requests": ("GRN-T004\x1b[2J‮", Severity.WARN)}
    out = answer(
        "claude-code",
        event("pip install requests==2.32.3", where["cwd"]),
        where,
        evaluate=evaluator(evil),
    )
    text = json.dumps(out)
    assert "\\u001b" not in text and "\\u202e" not in text and "\\\\x1b" in text


@pytest.mark.parametrize("agent", AGENTS)
def test_answers_never_repeat_url_credentials(
    agent: str, where: dict[str, str], tmp_path: Path
) -> None:
    index = "https://user:s3cret@example.invalid/simple"
    warn = evaluator({"requests": ("GRN-T004", Severity.WARN)})  # so a report is written
    for command in (
        f"pip install --index-url {index} requests==2.32.3",
        f"pip install --index-url {index} -e .",  # refused: can't check
        f"npm install --registry {index} left-pad",  # not checked yet
    ):
        payload = event(command, where["cwd"], scratchpad_dir=str(tmp_path))
        out = answer(agent, payload, where, evaluate=warn)
        text = json.dumps(out)
        assert "s3cret" not in text and "https://****@example.invalid/simple" in text, command
    reports = list(tmp_path.rglob("garnet-report-*.txt"))
    assert reports
    for report in reports:
        assert "s3cret" not in report.read_text()


def test_hook_tests_write_only_under_tmp_path(tmp_path: Path) -> None:
    # tests/conftest.py redirects the temp folder and fails a test that writes
    # a temp file elsewhere or leaves a hook check running.
    assert Path(tempfile.gettempdir()).is_relative_to(tmp_path)
    assert Path(os.environ["TMPDIR"]).is_relative_to(tmp_path)
    fd, path = tempfile.mkstemp()
    os.close(fd)
    assert Path(path).is_relative_to(tmp_path)


def test_a_crash_is_never_a_pass(where: dict[str, str]) -> None:
    def boom(argv: list[str], cwd: Path, env: dict[str, str]) -> Ran:
        raise RuntimeError("boom")

    for agent, decision in (("claude-code", "ask"), ("codex", "deny")):
        inner = spec(
            answer(agent, event("pip install x", where["cwd"]), where, deps=deps(FakeRunner(boom)))
        )
        assert inner["permissionDecision"] == decision
        assert "couldn't finish checking it (RuntimeError)" in inner["permissionDecisionReason"]


# --- the gate ---------------------------------------------------------------


def _gate(agent: str, raw: str) -> str:
    stdout = io.StringIO()
    assert gate.run(agent, io.StringIO(raw), stdout, io.StringIO()) == 0
    return stdout.getvalue()


@pytest.mark.parametrize(
    "payload",
    [
        {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "pip install x"},
        },
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"command": "pip install x"},
        },
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls; git status"},
        },
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "grep -r pipeline ."},
        },
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "PowerShell",
            "tool_input": {"command": "pip install x"},
        },
    ],
)
def test_gate_lets_other_events_through_silently(payload: dict[str, Any]) -> None:
    agent = "codex" if payload["tool_name"] == "PowerShell" else "claude-code"
    assert _gate(agent, json.dumps(payload)) == ""


@pytest.mark.parametrize(
    "command",
    [
        "python -mpip install x",
        "\\pip install x",
        "p\\ip install x",
        "p'i'p install x",
        "${UV:-uv} add x",
        "${PIP-pip} install x",
        "${UV:=uv} sync",
    ],
)
def test_gate_is_as_wide_as_the_parser(command: str) -> None:
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    assert gate.needs_a_look("claude-code", payload)


def test_gate_finds_a_package_word_past_the_first_megabyte() -> None:
    command = "true " + " " * gate.MAX_INPUT_BYTES + "; pip install requests"
    raw = json.dumps({"hook_event_name": "PreToolUse", "tool_input": {"command": command}})
    assert json.loads(_gate("codex", raw))["hookSpecificOutput"]["permissionDecision"] == "deny"
    quiet = json.dumps({"x": "true " + " " * (2 * gate.MAX_INPUT_BYTES) + "; ls"})
    assert _gate("codex", quiet) == ""


def test_gate_input_problems() -> None:
    assert _gate("claude-code", "not json") == ""
    cut = '{"hook_event_name": "PreToolUse", "tool_input": {"command": "pip install x"'
    for agent, decision in (("claude-code", "ask"), ("codex", "deny")):
        assert json.loads(_gate(agent, cut))["hookSpecificOutput"]["permissionDecision"] == decision
    huge = json.dumps({"x": "pip install " + "y" * gate.MAX_INPUT_BYTES})
    assert (
        json.loads(_gate("claude-code", huge))["hookSpecificOutput"]["permissionDecision"] == "ask"
    )
    assert json.loads(_gate("codex", huge))["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_fast_path_imports_only_the_standard_library() -> None:
    code = (
        "import io, json, sys\n"
        "sys.stdin = io.StringIO(json.dumps({'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',"
        " 'tool_input': {'command': 'ls -la'}}))\n"
        "from garnet_guard import console\n"
        "assert console.main(['hook', 'claude-code', 'run']) == 0\n"
        "loaded = sorted(m for m in sys.modules if m.startswith(('garnet_guard', 'httpx', 'packaging')))\n"
        "print(json.dumps(loaded))\n"
    )
    done = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, check=True, text=True
    )
    assert json.loads(done.stdout.splitlines()[-1]) == [
        "garnet_guard",
        "garnet_guard.console",
        "garnet_guard.install",
        "garnet_guard.install.gate",
    ]


# --- the printed configuration ------------------------------------------------


def test_claude_code_configuration() -> None:
    cfg = hooks.config("claude-code", "/home/me/.local/bin/garnet")
    (entry,) = cfg["hooks"]["PreToolUse"]
    assert entry["matcher"] == "Bash|PowerShell"
    (hook,) = entry["hooks"]
    assert hook == {
        "type": "command",
        "command": "/home/me/.local/bin/garnet",
        "args": ["hook", "claude-code", "run"],
        "timeout": 300,
        "onFailure": "block",
        "statusMessage": "Garnet Guard: checking dependency changes",
    }


def test_codex_configuration_quotes_the_path() -> None:
    cfg = hooks.config("codex", "/Users/me/my tools/garnet")
    (entry,) = cfg["hooks"]["PreToolUse"]
    assert entry["matcher"] == "^Bash$"
    (hook,) = entry["hooks"]
    assert hook["command"] == "'/Users/me/my tools/garnet' hook codex run"
    assert hook["timeout"] == 300 and "args" not in hook and "onFailure" not in hook


@pytest.mark.parametrize("agent", AGENTS)
def test_print_config(agent: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    exe = tmp_path / "garnet"
    exe.write_text("")
    monkeypatch.setattr(sys, "argv", [str(exe), "hook", agent])
    stdout, stderr = io.StringIO(), io.StringIO()
    assert hooks.print_config(agent, stdout=stdout, stderr=stderr) == 0
    printed = json.loads(stdout.getvalue())
    assert str(exe) in json.dumps(printed)
    notes = stderr.getvalue()
    assert notes.startswith("note: ") and "safe" not in notes.lower()


@pytest.mark.skipif(shutil.which("git") is None, reason="git isn't installed")
def test_a_committed_environment_is_not_run(tmp_path: Path) -> None:
    env_bin = tmp_path / "venv" / "bin"
    env_bin.mkdir(parents=True)
    (env_bin / "python").write_text("")
    (env_bin / "pip").write_text(f"#!{env_bin / 'python'}\n")
    (env_bin / "pip").chmod(0o755)
    git = ["git", "-C", str(tmp_path)]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "venv"], check=True)
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    where = {"PATH": "/nonexistent", "HOME": str(tmp_path), "cwd": str(tmp_path)}
    inner = spec(
        answer("claude-code", event("venv/bin/pip install x", str(tmp_path)), where, deps=deps(run))
    )
    assert inner["permissionDecision"] == "ask"
    assert "committed to the repository" in inner["permissionDecisionReason"]
    assert run.calls == []


@pytest.mark.skipif(shutil.which("git") is None, reason="git isn't installed")
@pytest.mark.parametrize(
    "command",
    [
        "pip install --python tools/python requests",
        "pip install --python=tools/python requests",
        "uv lock -p {root}/tools/python",
        "uv sync --python ./tools/python",
        "UV_PYTHON={root}/tools/python uv sync",
        "uv sync",  # .python-version names the committed interpreter
    ],
)
def test_a_committed_interpreter_is_not_run(command: str, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    tools = repo / "tools"
    tools.mkdir(parents=True)
    (tools / "python").write_text("#!/bin/sh\n")
    (tools / "python").chmod(0o755)
    (repo / "pyproject.toml").write_text('[project]\nname = "demo"\nversion = "0.1.0"\n')
    if command == "uv sync":
        (repo / ".python-version").write_text("./tools/python\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("pip", "uv", "python"):
        (bin_dir / name).write_text(f"#!{bin_dir / 'python'}\n")
        (bin_dir / name).chmod(0o755)
    git = ["git", "-C", str(repo)]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "tools", "pyproject.toml"], check=True)
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    where = {"PATH": str(bin_dir), "HOME": str(tmp_path), "cwd": str(repo)}
    payload = event(command.format(root=repo), str(repo))
    inner = spec(answer("codex", payload, where, deps=deps(run)))
    assert inner["permissionDecision"] == "deny"
    assert f"committed to the repository ({tools / 'python'})" in inner["permissionDecisionReason"]
    assert run.calls == []


# --- a loader preload set by the command ----------------------------------------


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize(
    ("command", "names"),
    [
        ("LD_PRELOAD=./pre.so pip install requests==2.32.3", "LD_PRELOAD"),
        ("LD_PRELOAD=./pre.so .venv/bin/pip install requests==2.32.3", "LD_PRELOAD"),
        ("LD_PRELOAD=./pre.so uv add six", "LD_PRELOAD"),
        ("LD_AUDIT=./a.so LD_LIBRARY_PATH=./lib uv sync", "LD_AUDIT, LD_LIBRARY_PATH"),
        ("env LD_PRELOAD=./pre.so pip install requests==2.32.3", "LD_PRELOAD"),
        ("sudo LD_PRELOAD=./pre.so pip install requests==2.32.3", "LD_PRELOAD"),
        ("export LD_PRELOAD=./pre.so; pip install requests==2.32.3", "LD_PRELOAD"),
        ("DYLD_INSERT_LIBRARIES=./p.dylib uv lock", "DYLD_INSERT_LIBRARIES"),
        ("DYLD_FRAMEWORK_PATH=./fw pip install requests==2.32.3", "DYLD_FRAMEWORK_PATH"),
        ("DYLD_SOME_LATER_NAME=./x uv add six", "DYLD_SOME_LATER_NAME"),
        # Changing a setting the hook's own environment has counts too.
        ("LD_LIBRARY_PATH=./lib pip install requests==2.32.3", "LD_LIBRARY_PATH"),
        (["env", "LD_PRELOAD=./pre.so", "uv", "add", "six"], "LD_PRELOAD"),
    ],
)
def test_a_loader_preload_on_the_command_asks_and_runs_nothing(
    agent: str, command: str | list[str], names: str, where: dict[str, str]
) -> None:
    cwd = Path(where["cwd"])
    uv_project(cwd)
    venv_bin = cwd / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").write_text("")
    (venv_bin / "pip").write_text(f"#!{venv_bin / 'python'}\n")
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    out = answer(
        agent,
        event(command, where["cwd"]),
        _uv_where(where),
        deps=deps(run),
        hook_env={"LD_LIBRARY_PATH": "/opt/python/lib"},
    )
    inner = spec(out)
    assert inner["permissionDecision"] == ("ask" if agent == "claude-code" else "deny")
    reason = inner["permissionDecisionReason"]
    assert f"not checked. The command sets {names}, which makes the system's loader" in reason
    assert "safe" not in reason.lower()
    assert run.calls == []


def test_a_loader_preload_the_shell_expands_is_cant_tell(where: dict[str, str]) -> None:
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    for command in ("LD_PRELOAD=$LIB pip install six", "export DYLD_LIBRARY_PATH=$D; uv sync"):
        inner = spec(answer("codex", event(command, where["cwd"]), where, deps=deps(run)))
        assert inner["permissionDecision"] == "deny"
        assert "can't tell" in inner["permissionDecisionReason"]
    assert run.calls == []


@pytest.mark.parametrize(
    "command",
    [
        "pip install requests==2.32.3",
        # The hook's own setting, unchanged or removed, is already loaded into Garnet.
        "LD_LIBRARY_PATH=/opt/python/lib pip install requests==2.32.3",
        "unset LD_LIBRARY_PATH; pip install requests==2.32.3",
        # Not a loader preload.
        "LD_BIND_NOW=1 pip install requests==2.32.3",
        "MY_LD_PRELOAD=./pre.so pip install requests==2.32.3",
        # On another command, not the install.
        "LD_PRELOAD=./pre.so ls; pip install requests==2.32.3",
    ],
)
def test_no_loader_preload_on_the_install_is_checked(command: str, where: dict[str, str]) -> None:
    out = answer(
        "claude-code",
        event(command, where["cwd"]),
        where,
        hook_env={"LD_LIBRARY_PATH": "/opt/python/lib"},
    )
    inner = spec(out)
    assert "permissionDecision" not in inner
    assert "requests 2.32.2 -> 2.32.3" in inner["additionalContext"]


# --- a pip or uv inside the project -------------------------------------------


def _program(path: Path, text: str = "#!/bin/sh\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)
    return path


@pytest.fixture
def project(tmp_path: Path) -> dict[str, str]:
    """A git project (nothing committed) and a pip, python and uv outside it, on PATH."""
    outside = tmp_path / "outside" / "bin"
    _program(outside / "python", "")
    _program(outside / "pip", f"#!{outside / 'python'}\n")
    _program(outside / "uv")
    repo = tmp_path / "repo"
    uv_project(repo)
    (repo / ".git").mkdir()
    return {"PATH": str(outside), "HOME": str(tmp_path), "cwd": str(repo)}


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize(
    ("command", "shown"),
    [
        ("bin/uv add --no-python-downloads --no-sync --no-build six", "bin/uv"),
        ("./bin/uv sync", "bin/uv"),
        ("bin/pip install requests==2.32.3", "bin/pip"),
        ("tools/pip install requests==2.32.3", "tools/pip"),
        ("bin/python -m pip install requests==2.32.3", "bin/python"),
        ("pip install --python bin/python requests==2.32.3", "bin/python"),
        ("uv sync --python ./bin/python", "bin/python"),
        ("{links}/uv lock", "{links}/uv (a link to {repo}/bin/uv)"),
        ("cd sub && ../bin/uv lock", "bin/uv"),
        # The project isn't its own venv, and a folder without pyvenv.cfg isn't one.
        ("VIRTUAL_ENV=. bin/python -m pip install requests==2.32.3", "bin/python"),
        ("VIRTUAL_ENV=tools tools/pip install requests==2.32.3", "tools/pip"),
        (
            ".venv/bin/python -m pip install requests==2.32.3",
            "{repo}/.venv/bin/python (a link to {repo}/bin/python)",
        ),
    ],
)
def test_a_pip_or_uv_inside_the_project_is_not_run(
    agent: str, command: str, shown: str, project: dict[str, str]
) -> None:
    repo = Path(project["cwd"])
    outside = Path(project["PATH"])
    _program(repo / "bin" / "uv")
    _program(repo / "bin" / "python", "")
    _program(repo / "bin" / "pip", f"#!{outside / 'python'}\n")  # pip itself is in the project
    _program(repo / "tools" / "python", "")
    _program(repo / "tools" / "pip", "")
    _program(repo / "tools" / "uv")
    (repo / "sub").mkdir()
    links = outside.parent / "links"
    links.mkdir()
    (links / "uv").symlink_to(repo / "bin" / "uv")
    (repo / ".venv" / "bin").mkdir(parents=True)
    (repo / ".venv" / "bin" / "python").symlink_to(repo / "bin" / "python")
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    payload = event(command.format(links=links), project["cwd"])
    inner = spec(answer(agent, payload, project, deps=deps(run)))
    assert inner["permissionDecision"] == ("ask" if agent == "claude-code" else "deny")
    where = shown.format(links=links, repo=repo)
    program = where if where.startswith("/") else str(repo / where)
    assert (
        f"not checked. {program} is inside the project ({repo}) and outside its virtual "
        "environment, so it is the project's own code" in inner["permissionDecisionReason"]
    )
    assert run.calls == []


def test_a_pip_or_uv_inside_a_project_without_git_is_not_run(project: dict[str, str]) -> None:
    repo = Path(project["cwd"])
    (repo / ".git").rmdir()  # pyproject.toml alone marks the project
    _program(repo / "bin" / "uv")
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    inner = spec(answer("codex", event("bin/uv lock", project["cwd"]), project, deps=deps(run)))
    assert inner["permissionDecision"] == "deny"
    assert (
        f"{repo / 'bin' / 'uv'} is inside the project ({repo})"
        in (inner["permissionDecisionReason"])
    )
    # uv --directory names the project from outside it.
    elsewhere = Path(project["HOME"]) / "elsewhere"
    elsewhere.mkdir()
    payload = event(f"{repo}/bin/uv --directory {repo} lock", str(elsewhere))
    inner = spec(answer("codex", payload, project, deps=deps(run)))
    assert f"is inside the project ({repo})" in inner["permissionDecisionReason"]
    assert run.calls == []


@pytest.mark.parametrize(
    "command",
    [
        "pip install requests==2.32.3",  # pip on PATH, outside the project
        ".venv/bin/pip install requests==2.32.3",
        ".venv/bin/python -m pip install requests==2.32.3",
        "venv/bin/pip install requests==2.32.3",  # VIRTUAL_ENV in the hook's environment
    ],
)
def test_pip_from_the_projects_virtual_environment_is_checked(
    command: str, project: dict[str, str]
) -> None:
    repo = Path(project["cwd"])
    for venv in (".venv", "venv"):
        bindir = repo / venv / "bin"
        _program(bindir / "python", "")
        _program(bindir / "pip", f"#!{bindir / 'python'}\n")
        (repo / venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    hook_env = {"VIRTUAL_ENV": str(repo / "venv")} if command.startswith("venv/") else {}
    out = answer("claude-code", event(command, project["cwd"]), project, hook_env=hook_env)
    inner = spec(out)
    assert "permissionDecision" not in inner
    assert "requests 2.32.2 -> 2.32.3" in inner["additionalContext"]


@pytest.mark.parametrize("agent", AGENTS)
def test_uv_outside_the_project_is_checked(agent: str, project: dict[str, str]) -> None:
    run = _uv_runner(check_ok=True)
    out = answer(
        agent,
        event("uv sync", project["cwd"]),
        project,
        deps=deps(run, committed_lock=lambda p: BASE_LOCK.encode()),
    )
    assert out is None or "permissionDecision" not in spec(out)
    assert run.calls and run.calls[0][0][0] == str(Path(project["PATH"]) / "uv")


def test_a_project_at_the_home_folder_doesnt_count(project: dict[str, str]) -> None:
    """With the home folder under git (dotfiles), ~/.local/bin/uv isn't the project's."""
    home = Path(project["HOME"])
    (home / ".git").mkdir()
    local = _program(home / ".local" / "bin" / "uv")
    plain = home / "notes"
    plain.mkdir()
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    where = {**project, "PATH": str(local.parent)}
    inner = spec(answer("codex", event("uv lock", str(plain)), where, deps=deps(run)))
    # Not the in-project answer: uv finds no pyproject.toml here, and says so.
    assert "inside the project" not in inner["permissionDecisionReason"]
    assert "there's no pyproject.toml" in inner["permissionDecisionReason"]
    # A command can't make the project its home folder.
    _program(Path(project["cwd"]) / "bin" / "uv")
    _program(Path(project["cwd"]) / "bin" / "python", "")
    payload = event(f"HOME={project['cwd']} bin/python -m pip install six", project["cwd"])
    inner = spec(answer("codex", payload, project, deps=deps(run)))
    assert "is inside the project" in inner["permissionDecisionReason"]


# --- settings that change where pip and uv find a Python -------------------------


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize(
    ("command", "names"),
    [
        ("UV_PYTHON_INSTALL_DIR=./py uv add six", "UV_PYTHON_INSTALL_DIR"),
        ("PATH={outside}:/usr/bin uv add six", "PATH"),
        ("UV_PROJECT_ENVIRONMENT=/tmp/env uv sync", "UV_PROJECT_ENVIRONMENT"),
        ("UV_PYTHON_PREFERENCE=only-system uv lock", "UV_PYTHON_PREFERENCE"),
        ("export UV_MANAGED_PYTHON=1; uv lock", "UV_MANAGED_PYTHON"),
        ("UV_NO_MANAGED_PYTHON=1 uv lock", "UV_NO_MANAGED_PYTHON"),
        ("XDG_DATA_HOME=./data uv lock", "XDG_DATA_HOME"),
        ("HOME=./fakehome uv lock", "HOME"),
        (
            "XDG_CONFIG_HOME=./cfg UV_CONFIG_FILE=./u.toml uv sync",
            "XDG_CONFIG_HOME, UV_CONFIG_FILE",
        ),
        ("CONDA_PREFIX=/tmp/conda uv lock", "CONDA_PREFIX"),
        ("VIRTUAL_ENV=/tmp/fake uv add --active six", "VIRTUAL_ENV"),
        # A real venv named by VIRTUAL_ENV alone, without activating it.
        ("VIRTUAL_ENV={repo}/.venv uv add --active six", "VIRTUAL_ENV"),
        # An activate script outside a virtual environment (no pyvenv.cfg).
        ("source notvenv/bin/activate && uv lock", "PATH, VIRTUAL_ENV"),
        ("PATH={outside}:/usr/bin pip install requests==2.32.3", "PATH"),
        ("unset PATH; pip install requests==2.32.3", "PATH"),
        ("source notvenv/bin/activate && pip install requests==2.32.3", "PATH"),
    ],
)
def test_a_command_that_moves_python_discovery_asks(
    agent: str, command: str, names: str, project: dict[str, str]
) -> None:
    repo = Path(project["cwd"])
    (repo / "notvenv" / "bin").mkdir(parents=True)
    (repo / "notvenv" / "bin" / "activate").write_text("")
    _program(repo / ".venv" / "bin" / "python", "")
    (repo / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\n")
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    payload = event(command.format(outside=project["PATH"], repo=repo), project["cwd"])
    inner = spec(answer(agent, payload, project, deps=deps(run)))
    assert inner["permissionDecision"] == ("ask" if agent == "claude-code" else "deny")
    assert (
        f"not checked. The command sets {names}, which changes where"
        in (inner["permissionDecisionReason"])
    )
    assert run.calls == []


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize(
    ("extra", "entry"), [(":bin", "bin"), (":.", "."), (":", "an empty entry")]
)
@pytest.mark.parametrize("command", ["uv lock", "pip install requests==2.32.3"])
def test_a_relative_path_entry_in_the_hooks_own_path_asks(
    agent: str, extra: str, entry: str, command: str, project: dict[str, str]
) -> None:
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    where = {**project, "PATH": project["PATH"] + extra}
    inner = spec(answer(agent, event(command, project["cwd"]), where, deps=deps(run)))
    assert inner["permissionDecision"] == ("ask" if agent == "claude-code" else "deny")
    assert f"PATH has a relative entry ({entry})" in inner["permissionDecisionReason"]
    assert run.calls == []


@pytest.mark.parametrize(
    "command",
    [
        "source .venv/bin/activate && uv lock",  # a real venv's activate is allowed
        "UV_PYTHON_PREFERENCE=only-system uv lock",  # the hook's own value, unchanged
        "HOME={home} uv lock",
        "UV_PYTHON=3.12 uv lock",  # not a path; -p and UV_PYTHON paths are checked as programs
    ],
)
def test_uv_with_its_discovery_unchanged_is_checked(command: str, project: dict[str, str]) -> None:
    repo = Path(project["cwd"])
    _program(repo / ".venv" / "bin" / "python", "")
    (repo / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\n")
    run = _uv_runner(check_ok=True)
    payload = event(command.format(home=project["HOME"]), project["cwd"])
    out = answer(
        "codex",
        payload,
        project,
        deps=deps(run, committed_lock=lambda p: BASE_LOCK.encode()),
        hook_env={"UV_PYTHON_PREFERENCE": "only-system"},
    )
    assert out is None or "permissionDecision" not in spec(out)
    assert run.calls


# --- builtins that set variables Garnet doesn't follow ----------------------------


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize(
    "command",
    [
        "declare -x LD_PRELOAD=./x.so; pip install six",
        "typeset -x PATH=./bin:/usr/bin; uv add six",
        "readonly UV_PYTHON=./p; uv sync",
        "f() { local -x LD_PRELOAD=./x.so; pip install six; }; f",
        "f() { pip install six; }; declare -x LD_PRELOAD=./x.so; f",  # declared after, runs first
        "builtin export LD_PRELOAD=./x.so; uv add six",
        "sudo declare -x A=1; pip install six",
        "set -a; LD_PRELOAD=./x.so; pip install six",
        "set -ea; LD_PRELOAD=./x.so; pip install six",
        "set -o allexport; LD_PRELOAD=x; pip install six",
        "export -n PATH; uv add six",
        "export -f f; pip install six",
        "bash -c 'declare -x LD_PRELOAD=./x.so; pip install six'",
    ],
)
def test_builtins_that_set_variables_make_the_command_cant_tell(
    agent: str, command: str, where: dict[str, str]
) -> None:
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    inner = spec(answer(agent, event(command, where["cwd"]), where, deps=deps(run)))
    assert inner["permissionDecision"] == ("ask" if agent == "claude-code" else "deny")
    assert (
        "Garnet Guard can't tell what this installs: it uses" in (inner["permissionDecisionReason"])
    )
    assert run.calls == []


@pytest.mark.parametrize(
    "command",
    [
        "set -e; pip install requests==2.32.3",
        "set -o pipefail; pip install requests==2.32.3",
        "declare -x A=1; ls",  # no package command: no answer either way
    ],
)
def test_other_set_options_are_still_checked(command: str, where: dict[str, str]) -> None:
    out = answer("claude-code", event(command, where["cwd"]), where)
    if "pip" not in command:
        assert out is None
        return
    inner = spec(out)
    assert "permissionDecision" not in inner
    assert "requests 2.32.2 -> 2.32.3" in inner["additionalContext"]


# --- a plain folder, with no .git or pyproject.toml -------------------------------


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize("command", ["bin/uv add six", "./bin/pip install requests==2.32.3"])
def test_a_program_in_a_plain_folder_is_the_folders_own(
    agent: str, command: str, tmp_path: Path
) -> None:
    plain = tmp_path / "plain"
    _program(plain / "bin" / "uv")
    _program(plain / "bin" / "pip", "#!/usr/bin/python3\n")
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    where = {"PATH": "/nonexistent", "HOME": str(tmp_path / "home"), "cwd": str(plain)}
    inner = spec(answer(agent, event(command, str(plain)), where, deps=deps(run)))
    assert inner["permissionDecision"] == ("ask" if agent == "claude-code" else "deny")
    program = plain / command.split()[0].removeprefix("./")
    assert f"{program} is inside the project ({plain})" in inner["permissionDecisionReason"]
    # uv --directory names the plain folder from somewhere else.
    if command.startswith("bin/uv"):
        payload = event(f"{plain}/bin/uv --directory {plain} lock", str(tmp_path))
        inner = spec(answer(agent, payload, where, deps=deps(run)))
        assert f"is inside the project ({plain})" in inner["permissionDecisionReason"]
    assert run.calls == []


def test_the_home_folder_and_root_are_not_a_plain_project(tmp_path: Path) -> None:
    home = tmp_path / "home"
    local = _program(home / "bin" / "uv")
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    for cwd in (str(home), str(tmp_path), "/"):
        where = {"PATH": str(local.parent), "HOME": str(home), "cwd": cwd}
        inner = spec(answer("codex", event("uv lock", cwd), where, deps=deps(run)))
        assert "inside the project" not in inner["permissionDecisionReason"]
        assert "there's no pyproject.toml" in inner["permissionDecisionReason"]


# --- GCONV_PATH and LOCPATH -----------------------------------------------------


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize(
    ("command", "names"),
    [
        ("GCONV_PATH=./g pip install requests==2.32.3", "GCONV_PATH"),
        ("LOCPATH=./loc LC_ALL=x.EBCDIC uv lock", "LOCPATH"),
        ("export GCONV_PATH=/tmp/g; uv add six", "GCONV_PATH"),
        ("GCONV_PATH=./g LOCPATH=./l uv sync", "GCONV_PATH, LOCPATH"),
        ("GCONV_PATH=/other pip install requests==2.32.3", "GCONV_PATH"),  # changed
    ],
)
def test_gconv_path_or_locpath_on_the_command_asks(
    agent: str, command: str, names: str, project: dict[str, str]
) -> None:
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    inner = spec(
        answer(
            agent,
            event(command, project["cwd"]),
            project,
            deps=deps(run),
            hook_env={"GCONV_PATH": "/usr/lib/gconv"},
        )
    )
    assert inner["permissionDecision"] == ("ask" if agent == "claude-code" else "deny")
    assert (
        f"not checked. The command sets {names}, which tells the C library"
        in (inner["permissionDecisionReason"])
    )
    assert run.calls == []


def test_gconv_path_the_shell_expands_is_cant_tell(project: dict[str, str]) -> None:
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    payload = event("GCONV_PATH=$G pip install six", project["cwd"])
    inner = spec(answer("codex", payload, project, deps=deps(run)))
    assert "can't tell the value of GCONV_PATH" in inner["permissionDecisionReason"]


def test_the_hooks_own_gconv_path_is_checked(project: dict[str, str]) -> None:
    for command in ("pip install requests==2.32.3", "GCONV_PATH=/g pip install requests==2.32.3"):
        out = answer(
            "claude-code", event(command, project["cwd"]), project, hook_env={"GCONV_PATH": "/g"}
        )
        inner = spec(out)
        assert "permissionDecision" not in inner
        assert "requests 2.32.2 -> 2.32.3" in inner["additionalContext"]


# --- a program the command names outside PATH and outside a venv -------------------


@pytest.fixture
def elsewhere(project: dict[str, str]) -> Path:
    """Programs outside the project and off PATH, as an agent could write them."""
    x = Path(project["HOME"]) / "x"
    outside = Path(project["PATH"])
    _program(x / "uv")
    _program(x / "python", "")
    _program(x / "bin" / "python", "")
    _program(x / "bin" / "pip", f"#!{outside / 'python'}\n")  # its Python is on PATH
    _program(x / "fakevenv" / "bin" / "python", "")
    _program(x / "fakevenv" / "bin" / "pip", f"#!{x / 'fakevenv' / 'bin' / 'python'}\n")
    return x


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize(
    ("command", "program", "finds"),
    [
        ("{x}/uv add six", "{x}/uv", "PATH finds {outside}/uv"),
        ("uv sync -p {x}/python", "{x}/python", "PATH finds {outside}/python"),
        ("UV_PYTHON={x}/python uv lock", "{x}/python", "PATH finds {outside}/python"),
        ("{x}/bin/pip install requests==2.32.3", "{x}/bin/pip", "PATH finds {outside}/pip"),
        ("{x}/bin/python -m pip install six", "{x}/bin/python", "PATH finds {outside}/python"),
        ("pip install --python {x}/python six", "{x}/python", "PATH finds {outside}/python"),
        # A bin folder without pyvenv.cfg isn't a virtual environment.
        ("{x}/fakevenv/bin/pip install six", "{x}/fakevenv/bin/pip", "PATH finds {outside}/pip"),
    ],
)
def test_a_program_the_command_chose_is_not_run(
    agent: str,
    command: str,
    program: str,
    finds: str,
    project: dict[str, str],
    elsewhere: Path,
) -> None:
    _uv_where(project)
    names = {"x": elsewhere, "outside": project["PATH"]}
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    inner = spec(
        answer(agent, event(command.format(**names), project["cwd"]), project, deps=deps(run))
    )
    assert inner["permissionDecision"] == ("ask" if agent == "claude-code" else "deny")
    assert (
        f"not checked. {program.format(**names)} isn't the "
        f"{os.path.basename(program)} your PATH finds ({finds.format(**names)}) or a program "
        "in a virtual environment" in inner["permissionDecisionReason"]
    )
    assert run.calls == []


def test_a_program_with_no_namesake_on_path_is_not_run(
    project: dict[str, str], elsewhere: Path
) -> None:
    _program(elsewhere / "python3.99", "")
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    payload = event(f"{elsewhere}/python3.99 -m pip install six", project["cwd"])
    inner = spec(answer("codex", payload, project, deps=deps(run)))
    assert "(PATH has no python3.99)" in inner["permissionDecisionReason"]


def test_a_venv_the_command_activates_inside_the_project_asks(project: dict[str, str]) -> None:
    """Only the project's .venv and the hook's own VIRTUAL_ENV count inside the project."""
    repo = Path(project["cwd"])
    bindir = repo / "venv" / "bin"
    _program(bindir / "python", "")
    _program(bindir / "pip", f"#!{bindir / 'python'}\n")
    (repo / "venv" / "pyvenv.cfg").write_text("home = /usr/bin\n")
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    payload = event("source venv/bin/activate && pip install six", project["cwd"])
    inner = spec(answer("codex", payload, project, deps=deps(run)))
    assert inner["permissionDecision"] == "deny"
    assert "or a program in a virtual environment" in inner["permissionDecisionReason"]
    # Not activated, it is the project's own code.
    inner = spec(answer("codex", event("venv/bin/pip install six", project["cwd"]), project))
    assert "is inside the project" in inner["permissionDecisionReason"]
    assert run.calls == []


@pytest.mark.parametrize(
    "command",
    [
        "pip install requests==2.32.3",
        "python -m pip install requests==2.32.3",
        "{outside}/python -m pip install requests==2.32.3",  # what PATH gives for python
        "{outside}/pip install requests==2.32.3",
        "{x}/venv/bin/pip install requests==2.32.3",  # a venv outside the project
        "{x}/venv/bin/python -m pip install requests==2.32.3",
        "pip install --python {x}/venv requests==2.32.3",
    ],
)
def test_pip_from_path_or_a_venv_is_checked(
    command: str, project: dict[str, str], elsewhere: Path
) -> None:
    bindir = elsewhere / "venv" / "bin"
    _program(bindir / "python", "")
    _program(bindir / "pip", f"#!{bindir / 'python'}\n")
    (elsewhere / "venv" / "pyvenv.cfg").write_text("home = /usr/bin\n")
    payload = event(command.format(x=elsewhere, outside=project["PATH"]), project["cwd"])
    inner = spec(answer("claude-code", payload, project))
    assert "permissionDecision" not in inner
    assert "requests 2.32.2 -> 2.32.3" in inner["additionalContext"]


def test_python_from_path_with_user_is_refused_for_user_not_for_the_program(
    project: dict[str, str],
) -> None:
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    payload = event(f"{project['PATH']}/python -m pip install --user six", project["cwd"])
    inner = spec(answer("codex", payload, project, deps=deps(run)))
    reason = inner["permissionDecisionReason"]
    assert "--user" in reason and "your PATH finds" not in reason


@pytest.mark.parametrize(
    "command",
    [
        "uv lock",
        "{local}/uv lock",  # the path PATH gives
        "{store}/uv lock",  # the same file, by its real path
        "uv lock -p {outside}/python",
        "uv lock -p python",
    ],
)
def test_uv_from_path_is_checked(command: str, project: dict[str, str]) -> None:
    """~/.local/bin/uv, often a link to where the installer put it, as PATH gives it."""
    home = Path(project["HOME"])
    store = home / "store"
    _program(store / "uv")
    local = home / ".local" / "bin"
    local.mkdir(parents=True)
    (local / "uv").symlink_to(store / "uv")
    where = {**project, "PATH": f"{local}{os.pathsep}{project['PATH']}"}
    run = _uv_runner(check_ok=True)
    payload = event(
        command.format(local=local, store=store, outside=project["PATH"]), project["cwd"]
    )
    out = answer(
        "codex", payload, where, deps=deps(run, committed_lock=lambda p: BASE_LOCK.encode())
    )
    assert out is None or "permissionDecision" not in spec(out)
    assert run.calls and os.path.realpath(run.calls[0][0][0]) == str((store / "uv").resolve())
