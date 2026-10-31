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
from tests.test_install_check import FIXTURES, FakeRunner, deps, evaluator, pip_answers, releases

AGENTS = ("claude-code", "codex")


@pytest.fixture
def where(tmp_path: Path) -> dict[str, str]:
    """A folder with stand-in pip, python and npm programs (never run)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "python").write_text("")
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
        env={"PATH": where["PATH"], "HOME": where["HOME"]},
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
    assert "OSV lookup failed (OSV lookup failed)" not in context
    assert "A new uploader (uploaded by mallory)" in context
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
    assert run.calls == []


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
