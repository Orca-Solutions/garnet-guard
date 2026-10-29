"""The Action's shell scripts, run against a local git repository.

``uv`` and ``gh`` are replaced with stubs on PATH: ``garnet check`` writes a
canned report (the real command is built in another change), the Markdown
renderer runs for real, and ``gh`` records its calls. No network.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(
    BASH is None or shutil.which("git") is None or shutil.which("jq") is None,
    reason="needs bash, git and jq",
)

REPORT = {
    "schema": "https://garnet.dev/schema/report/v1.json",
    "garnet_version": "0.1.0.dev0",
    "verdict": "warn",
    "policy": None,
    "changes": [
        {
            "ecosystem": "pypi",
            "package": "examplelib",
            "baseline": "2.6.1",
            "candidate": "2.6.2",
            "verdict": "warn",
            "findings": [
                {
                    "rule_id": "GRN-T004",
                    "name": "no-matching-tag",
                    "severity": "warn",
                    "title": "github.com/example/examplelib has a tag for 2.6.1 but none for 2.6.2",
                }
            ],
        }
    ],
}

UV_STUB = f"""#!/usr/bin/env bash
# Stub uv: record the call, fake `garnet check`, run the real renderer.
printf '%s\\n' "$*" >> "$STUB_LOG"
args=("$@")
for i in "${{!args[@]}}"; do
  if [[ "${{args[$i]}}" == garnet && "${{args[$((i+1))]}}" == check ]]; then
    out=""
    for j in "${{!args[@]}}"; do
      [[ "${{args[$j]}}" == --output ]] && out="${{args[$((j+1))]}}"
    done
    [[ -n "$STUB_REPORT" ]] && cp "$STUB_REPORT" "$out"
    exit "${{STUB_EXIT:-1}}"
  fi
  if [[ "${{args[$i]}}" == python ]]; then
    exec "{sys.executable}" "${{args[@]:$((i+1))}}"
  fi
done
exit 0
"""

GH_STUB = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$STUB_DIR/gh.log"
if [[ "$*" == *"--method"* ]]; then cat > "$STUB_DIR/gh-body.json"; exit "${GH_WRITE_EXIT:-0}"; fi
printf '%s' "${GH_EXISTING:-}"
"""


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    repo = tmp_path / "ws"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    _git(repo, "config", "commit.gpgsign", "false")
    (repo / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "examplelib"\nversion = "2.6.1"\n'
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "examplelib"\nversion = "2.6.2"\n'
    )
    # The pull request ships a module that would shadow Garnet Guard's if
    # Python ever put the checkout on sys.path.
    (repo / "garnet_guard").mkdir()
    (repo / "garnet_guard" / "__init__.py").write_text("raise SystemExit('ran PR code')\n")
    _git(repo, "commit", "-q", "-am", "head")

    stubs = tmp_path / "bin"
    stubs.mkdir()
    for name, body in (("uv", UV_STUB), ("gh", GH_STUB)):
        (stubs / name).write_text(body)
        (stubs / name).chmod(0o755)
    report = tmp_path / "canned.json"
    report.write_text(json.dumps(REPORT))
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 7, "base": {"sha": base}}}))
    runner = tmp_path / "runner"
    runner.mkdir()
    return {
        "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "STUB_DIR": str(tmp_path),
        "STUB_LOG": str(tmp_path / "uv.log"),
        "STUB_REPORT": str(report),
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_WORKSPACE": str(repo),
        "GITHUB_OUTPUT": str(runner / "output"),
        "GITHUB_STEP_SUMMARY": str(runner / "summary"),
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_REPOSITORY": "o/r",
        "GITHUB_RUN_ID": "99",
        "RUNNER_TEMP": str(runner),
        "GARNET_ACTION_PATH": str(ROOT),
        "GARNET_GITHUB_TOKEN": "t0ken",
        "BASE_SHA": base,
    }


def _run(script: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [BASH or "bash", str(ROOT / script)], env=env, capture_output=True, text=True
    )


def _outputs(env: dict[str, str]) -> dict[str, str]:
    path = Path(env["GITHUB_OUTPUT"])
    lines = path.read_text().splitlines() if path.exists() else []
    return dict(line.split("=", 1) for line in lines)


def test_check_renders_comment(env: dict[str, str]) -> None:
    proc = _run("action/run.sh", env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = _outputs(env)
    assert out["verdict"] == "warn" and out["exit-code"] == "1"
    assert out["pr-number"] == "7" and out["no-changes"] == "false"
    comment = Path(out["comment-path"]).read_text()
    assert comment.startswith("<!-- garnet:report -->\n")
    assert "1 of 1 update needs a look" in comment
    assert comment in Path(env["GITHUB_STEP_SUMMARY"]).read_text()

    calls = Path(env["STUB_LOG"]).read_text()
    assert "--no-config sync --quiet --frozen --no-dev" in calls
    assert f"check --git-base {env['BASE_SHA']} --format json" in calls
    assert "python -I -m garnet_guard.markdown" in calls
    assert "--github-token-env GARNET_GITHUB_TOKEN" in calls
    assert "--no-policy" in calls and "--fail-on" not in calls
    assert "--head" not in calls
    assert "t0ken" not in calls
    assert "ran PR code" not in proc.stdout + proc.stderr


def test_renderer_never_imports_from_the_working_directory(env: dict[str, str]) -> None:
    out_dir = Path(env["RUNNER_TEMP"]) / "garnet-guard"
    (out_dir / "garnet_guard").mkdir(parents=True)
    (out_dir / "garnet_guard" / "__init__.py").write_text("raise SystemExit('ran PR code')\n")
    proc = _run("action/run.sh", env)
    assert "ran PR code" not in proc.stdout + proc.stderr
    assert _outputs(env)["exit-code"] == "1"


def test_stale_report_is_never_reused(env: dict[str, str]) -> None:
    assert _run("action/run.sh", env).returncode == 0
    Path(env["GITHUB_OUTPUT"]).unlink()
    env |= {"STUB_EXIT": "0", "STUB_REPORT": ""}
    assert _run("action/run.sh", env).returncode == 0
    assert _outputs(env)["exit-code"] == "3"


@pytest.mark.parametrize("explicit", [False, True])
def test_symlinked_lockfile_is_refused(env: dict[str, str], explicit: bool) -> None:
    ws = Path(env["GITHUB_WORKSPACE"])
    (ws / "requirements.txt").symlink_to("/etc/hostname")
    if explicit:
        env |= {"GARNET_LOCKFILES": "requirements.txt"}
    assert _run("action/run.sh", env).returncode == 0
    out = _outputs(env)
    assert out["exit-code"] == "3"
    assert (
        "uv.log" not in os.listdir(env["STUB_DIR"])
        or "garnet check" not in Path(env["STUB_LOG"]).read_text()
    )


def test_explicit_lockfiles_and_no_footer(env: dict[str, str]) -> None:
    env |= {"GARNET_LOCKFILES": " uv.lock\n\nsub/requirements.txt \n", "GARNET_FOOTER": "false"}
    assert _run("action/run.sh", env).returncode == 0
    calls = Path(env["STUB_LOG"]).read_text()
    assert "--head uv.lock --head sub/requirements.txt" in calls
    assert "<sub>" not in Path(_outputs(env)["comment-path"]).read_text()


@pytest.mark.parametrize("bad", ["../etc/passwd", "/etc/passwd", "-x"])
def test_lockfile_paths_stay_in_the_repository(env: dict[str, str], bad: str) -> None:
    env |= {"GARNET_LOCKFILES": bad}
    assert _run("action/run.sh", env).returncode == 0
    out = _outputs(env)
    assert out["exit-code"] == "3"
    assert "couldn't check" in Path(out["comment-path"]).read_text()


def test_garnet_failure_is_never_a_pass(env: dict[str, str]) -> None:
    env |= {"STUB_EXIT": "3", "STUB_REPORT": ""}
    proc = _run("action/run.sh", env)
    assert proc.returncode == 0
    out = _outputs(env)
    assert out["exit-code"] == "3" and "verdict" not in out
    comment = Path(out["comment-path"]).read_text()
    assert comment.startswith("<!-- garnet:report -->\n")
    assert "not a pass" in comment and "https://github.com/o/r/actions/runs/99" in comment


@pytest.mark.parametrize("event", ["pull_request_target", "push"])
def test_refuses_other_events(env: dict[str, str], event: str) -> None:
    env |= {"GITHUB_EVENT_NAME": event}
    proc = _run("action/run.sh", env)
    assert proc.returncode == 3
    assert _outputs(env) == {"exit-code": "3"}


def test_bad_fail_on_is_refused(env: dict[str, str]) -> None:
    env |= {"GARNET_FAIL_ON": "sometimes"}
    assert _run("action/run.sh", env).returncode == 3


def test_fail_on_is_passed_through(env: dict[str, str]) -> None:
    env |= {"GARNET_FAIL_ON": "warn"}
    assert _run("action/run.sh", env).returncode == 0
    assert "--fail-on warn" in Path(env["STUB_LOG"]).read_text()


STRICT = "[garnet]\nversion = 1\nfail_on = 'warn'\n"
RELAXED = "[garnet]\nversion = 1\nfail_on = 'never'\n"


def _commit_at_base(env: dict[str, str], files: dict[str, str]) -> None:
    """Add files to a new base commit, and point the event at it."""
    ws = Path(env["GITHUB_WORKSPACE"])
    _git(ws, "checkout", "-q", "--detach", env["BASE_SHA"])
    for name, body in files.items():
        (ws / name).parent.mkdir(parents=True, exist_ok=True)
        (ws / name).write_text(body)
    _git(ws, "add", "-A")
    _git(ws, "commit", "-q", "-m", "base with policy")
    base = _git(ws, "rev-parse", "HEAD")
    _git(ws, "checkout", "-q", "main")
    env["BASE_SHA"] = base
    event = Path(env["GITHUB_EVENT_PATH"])
    event.write_text(json.dumps({"pull_request": {"number": 7, "base": {"sha": base}}}))


def _policy_passed(env: dict[str, str]) -> str | None:
    """The policy file garnet check was given, read back, or None for --no-policy."""
    calls = Path(env["STUB_LOG"]).read_text()
    m = re.search(r"--policy (\S+)", calls)
    if m is None:
        assert "--no-policy" in calls
        return None
    assert str(Path(env["RUNNER_TEMP"]) / "garnet-guard" / "policy") in m.group(1)
    return Path(m.group(1)).read_text()


@pytest.mark.parametrize("name", ["garnet.toml", "pyproject.toml"])
def test_policy_is_read_from_the_base_commit(env: dict[str, str], name: str) -> None:
    _commit_at_base(env, {name: STRICT})
    ws = Path(env["GITHUB_WORKSPACE"])
    (ws / name).write_text(RELAXED)  # the pull request relaxes it
    _git(ws, "add", name)
    _git(ws, "commit", "-q", "-m", "relax")
    assert _run("action/run.sh", env).returncode == 0
    assert _policy_passed(env) == STRICT


def test_pull_request_cannot_add_a_policy(env: dict[str, str]) -> None:
    (Path(env["GITHUB_WORKSPACE"]) / "garnet.toml").write_text(RELAXED)
    assert _run("action/run.sh", env).returncode == 0
    assert _policy_passed(env) is None


def test_garnet_toml_wins_over_pyproject(env: dict[str, str]) -> None:
    _commit_at_base(env, {"garnet.toml": STRICT, "pyproject.toml": "[tool.garnet]\nversion = 1\n"})
    assert _run("action/run.sh", env).returncode == 0
    assert _policy_passed(env) == STRICT


def test_explicit_policy_path(env: dict[str, str]) -> None:
    _commit_at_base(env, {"ci/garnet.toml": STRICT})
    env |= {"GARNET_POLICY": "ci/garnet.toml"}
    assert _run("action/run.sh", env).returncode == 0
    assert _policy_passed(env) == STRICT


@pytest.mark.parametrize("missing", ["ci/garnet.toml", "../garnet.toml"])
def test_explicit_policy_must_exist_at_the_base_commit(env: dict[str, str], missing: str) -> None:
    env |= {"GARNET_POLICY": missing}
    assert _run("action/run.sh", env).returncode == 0
    out = _outputs(env)
    assert out["exit-code"] == "3" and "verdict" not in out
    assert "couldn't check" in Path(out["comment-path"]).read_text()
    assert (
        not Path(env["STUB_LOG"]).exists()
        or "garnet check" not in Path(env["STUB_LOG"]).read_text()
    )


def _comment_env(env: dict[str, str], tmp_path: Path, **extra: str) -> dict[str, str]:
    body = tmp_path / "c.md"
    body.write_text("<!-- garnet:report -->\nhello\n")
    return env | {"GARNET_COMMENT": str(body), "GARNET_PR": "7"} | extra


def test_post_creates_then_updates(env: dict[str, str], tmp_path: Path) -> None:
    e = _comment_env(env, tmp_path)
    proc = _run("action/post-comment.sh", e)
    assert proc.returncode == 0, proc.stderr
    log = (tmp_path / "gh.log").read_text()
    assert 'select(.user.login == "github-actions[bot]"' in log
    assert "--method POST repos/o/r/issues/7/comments" in log
    assert json.loads((tmp_path / "gh-body.json").read_text())["body"].startswith("<!-- garnet")

    (tmp_path / "gh.log").unlink()
    proc = _run("action/post-comment.sh", e | {"GH_EXISTING": "123\n456\n"})
    assert "--method PATCH repos/o/r/issues/comments/123" in (tmp_path / "gh.log").read_text()


def test_post_update_only_and_refusals(env: dict[str, str], tmp_path: Path) -> None:
    e = _comment_env(env, tmp_path, GARNET_UPDATE_ONLY="true")
    assert _run("action/post-comment.sh", e).returncode == 0
    assert "--method" not in (tmp_path / "gh.log").read_text()

    proc = _run("action/post-comment.sh", e | {"GARNET_UPDATE_ONLY": "", "GH_WRITE_EXIT": "1"})
    assert proc.returncode == 0
    assert "::warning title=Garnet Guard::Couldn't post" in proc.stdout

    assert _run("action/post-comment.sh", e | {"GARNET_PR": "7; rm -rf /"}).returncode == 1
    bad = tmp_path / "bad.md"
    bad.write_text("no marker\n")
    assert _run("action/post-comment.sh", e | {"GARNET_COMMENT": str(bad)}).returncode == 1
    evil = 'x") | .id, ("'
    assert _run("action/post-comment.sh", e | {"GARNET_COMMENT_AUTHOR": evil}).returncode == 1


def _workflow_run_env(env: dict[str, str], tmp_path: Path, **extra: str) -> dict[str, str]:
    event = tmp_path / "wr.json"
    event.write_text(
        json.dumps(
            {
                "workflow_run": {
                    "event": "pull_request",
                    "head_sha": "a" * 40,
                    "head_branch": "dependabot/pip/x&y",
                    "head_repository": {"owner": {"login": "fork-owner"}},
                    "html_url": "https://github.com/o/r/actions/runs/5",
                }
            }
        )
    )
    return env | {"GITHUB_EVENT_NAME": "workflow_run", "GITHUB_EVENT_PATH": str(event)} | extra


def test_comment_job_finds_the_pull_request(env: dict[str, str], tmp_path: Path) -> None:
    e = _workflow_run_env(env, tmp_path, GH_EXISTING="12\n")
    proc = _run("action/comment/find-pr.sh", e)
    assert proc.returncode == 0, proc.stderr
    assert _outputs(e) == {"number": "12"}
    log = (tmp_path / "gh.log").read_text()
    assert "head=fork-owner%3Adependabot%2Fpip%2Fx%26y" in log
    assert f'select(.head.sha == "{"a" * 40}")' in log


def test_comment_job_skips_when_no_pull_request_matches(
    env: dict[str, str], tmp_path: Path
) -> None:
    e = _workflow_run_env(env, tmp_path)
    proc = _run("action/comment/find-pr.sh", e)
    assert proc.returncode == 0 and _outputs(e) == {}
    assert "nothing to comment on" in proc.stdout
    assert _run("action/comment/find-pr.sh", env).returncode == 1  # not workflow_run


def test_comment_job_renders_report_or_says_it_couldnt_check(
    env: dict[str, str], tmp_path: Path
) -> None:
    e = _workflow_run_env(env, tmp_path, GARNET_ROOT=str(ROOT))
    proc = _run("action/comment/render.sh", e)
    assert proc.returncode == 0, proc.stderr
    comment = Path(_outputs(e)["comment-path"]).read_text()
    assert "couldn't check" in comment and "https://github.com/o/r/actions/runs/5" in comment

    artifact = Path(env["RUNNER_TEMP"]) / "garnet-guard-artifact"
    artifact.mkdir()
    (artifact / "report.json").write_text(json.dumps(REPORT))
    Path(e["GITHUB_OUTPUT"]).unlink()
    proc = _run("action/comment/render.sh", e)
    assert proc.returncode == 0, proc.stderr
    out = _outputs(e)
    assert out["no-changes"] == "false"
    comment = Path(out["comment-path"]).read_text()
    assert "1 of 1 update needs a look" in comment
    assert "its fork controls" in comment  # head repository isn't o/r

    (artifact / "report.json").write_text('{"changes": [{"verdict": "evil"}]}')
    Path(e["GITHUB_OUTPUT"]).unlink()
    proc = _run("action/comment/render.sh", e)
    assert proc.returncode == 0, proc.stderr
    assert "couldn't check" in Path(_outputs(e)["comment-path"]).read_text()
