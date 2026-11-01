"""The resolve-and-check step and the wrapper, with recorded pip and uv
outputs in place of the programs, and stand-ins for PyPI and the checks."""

from __future__ import annotations

import io
import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import pytest

from garnet_guard.engine import Options
from garnet_guard.install import check, wrapper
from garnet_guard.install.check import Deps, Outcome
from garnet_guard.install.runner import LOADER_PRELOAD, Ran, loader_env, loader_preload
from garnet_guard.models import (
    Change,
    ChangeResult,
    Evidence,
    Finding,
    IndexFile,
    Policy,
    ProjectReleases,
    Severity,
    Verdict,
)

FIXTURES = Path(__file__).parent / "fixtures" / "install"
TODAY = date(2026, 10, 30)
PY = "/venv/bin/python"


@dataclass
class FakeRunner:
    """Answers each program by its arguments, and records every call."""

    answer: object  # Callable[[list[str], Path], Ran]
    calls: list[tuple[list[str], Path, bool]] = field(default_factory=list)

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        capture: bool = True,
        timeout: float | None = None,
    ) -> Ran:
        self.calls.append((list(argv), cwd, capture))
        assert callable(self.answer)
        result = self.answer(list(argv), cwd, dict(env))
        assert isinstance(result, Ran)
        return result


def finding(change: Change, rule: str, severity: Severity, title: str = "t") -> Finding:
    return Finding(
        rule,
        "name",
        severity,
        severity,
        change,
        title,
        (Evidence("file", "evidence line"),),
        "why",
        "what to do",
    )


def evaluator(rules: Mapping[str, tuple[str, Severity]] | None = None) -> check.Evaluate:
    """Checks that find ``rules[package]`` and nothing else."""

    def run(changes: list[Change], policy: Policy, options: Options) -> list[ChangeResult]:
        out = []
        for c in changes:
            hit = (rules or {}).get(c.package)
            found = (finding(c, hit[0], hit[1]),) if hit else ()
            worst = max((f.severity for f in found), default=Severity.OFF)
            out.append(ChangeResult(c, Verdict.from_severity(worst), found))
        return out

    return run


def releases(**projects: list[tuple[str, str]]) -> object:
    """A PyPI stand-in: name -> [(version, "wheel" | "sdist")]."""

    def lookup(name: str) -> ProjectReleases:
        if name not in projects:
            return ProjectReleases(name, on_registry=False)
        listed = tuple(
            (
                v,
                (IndexFile(f"{name}-{v}", "bdist_wheel" if kind == "wheel" else "sdist"),),
            )
            for v, kind in projects[name]
        )
        return ProjectReleases(name, True, listed)

    return lookup


def deps(run: FakeRunner, **kw: object) -> Deps:
    registry = kw.pop("registry", releases())
    return Deps(
        today=TODAY,
        run=run,
        registry=registry,  # type: ignore[arg-type]
        evaluate=kw.pop("evaluate", evaluator()),  # type: ignore[arg-type]
        committed_lock=kw.pop("committed_lock", lambda path: None),  # type: ignore[arg-type]
    )


# --- pip --------------------------------------------------------------------


def pip_answers(report: str | None, *, probe_err: str | None = None, fail: str | None = None):  # type: ignore[no-untyped-def]
    def answer(argv: list[str], cwd: Path, env: dict[str, str]) -> Ran:
        assert argv[1:4] == ["-I", "-m", "pip"]
        if argv[4:6] == ["config", "list"]:
            return Ran(0, b"global.index-url='https://user:pw@example.invalid/simple'\n")
        if argv[4] == "inspect":
            return Ran(0, (FIXTURES / "pip-inspect.json").read_bytes())
        assert "--dry-run" in argv and argv[-2:] == ["--only-binary", ":all:"]
        assert env["PIP_NO_INPUT"] == "1"
        if "-c" in argv:  # the probe for the newest release
            return Ran(1, b"", (probe_err or "").encode())
        if fail is not None:
            return Ran(1, b"", fail.encode())
        out = Path(argv[argv.index("--report") + 1])
        out.write_text((FIXTURES / report).read_text() if report else "")
        return Ran(0)

    return answer


def run_pip(tmp_path: Path, args: list[str], run: FakeRunner, **kw: object) -> Outcome:
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    return check.check_pip(
        PY,
        args,
        cwd=tmp_path,
        env={"PATH": "/venv/bin"},
        command="pip " + " ".join(args),
        deps=deps(run, **kw),
        workdir=work,
    )


def test_pip_pass_hands_off_the_checked_pins(tmp_path: Path) -> None:
    run = FakeRunner(pip_answers("pip-report-requests-2.32.3.json"))
    out = run_pip(tmp_path, ["install", "requests==2.32.3"], run)
    assert out.status == "pass" and out.exit_code == 0
    assert out.report is not None
    (result,) = out.report.results
    assert (result.change.package, result.change.baseline, result.change.candidate) == (
        "requests",
        "2.32.2",
        "2.32.3",
    )
    assert out.handoff is not None
    argv = list(out.handoff.argv)
    assert argv[:6] == [PY, "-I", "-m", "pip", "install", "requests==2.32.3"]
    assert argv[6:9] == ["--only-binary", ":all:", "-c"]
    pins = Path(argv[9]).read_text().splitlines()
    sha = "70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6"
    assert f"requests==2.32.3 --hash=sha256:{sha}" in pins
    assert "urllib3==2.8.0" in pins  # what's installed stays as it is
    assert out.handoff.shown == (
        f"{PY} -I -m pip install requests==2.32.3 --only-binary :all: -c <checked pins>"
    )
    assert "Garnet Guard checked 1 dependency change: nothing at warn or above." == check.summary(
        out
    )


def test_pip_warn_and_block(tmp_path: Path) -> None:
    run = FakeRunner(pip_answers("pip-report-requests-2.32.3.json"))
    warn = run_pip(
        tmp_path,
        ["install", "requests==2.32.3"],
        run,
        evaluate=evaluator({"requests": ("GRN-T004", Severity.WARN)}),
    )
    assert warn.status == "warn" and warn.exit_code == 0
    (tmp_path / "work2").mkdir()
    block = check.check_pip(
        PY,
        ["install", "requests==2.32.3"],
        cwd=tmp_path,
        env={},
        command="pip install requests==2.32.3",
        deps=deps(run, evaluate=evaluator({"requests": ("GRN-T001", Severity.BLOCK)})),
        workdir=tmp_path / "work2",
    )
    assert block.status == "stop" and block.exit_code == 2


def test_pip_fail_on_warn_from_the_policy(tmp_path: Path) -> None:
    (tmp_path / "garnet.toml").write_text('[garnet]\nversion = 1\nfail_on = "warn"\n')
    run = FakeRunner(pip_answers("pip-report-requests-2.32.3.json"))
    out = run_pip(
        tmp_path,
        ["install", "requests==2.32.3"],
        run,
        evaluate=evaluator({"requests": ("GRN-T004", Severity.WARN)}),
    )
    assert out.status == "stop" and out.exit_code == 1 and out.fail_on == Severity.WARN


def test_pip_newer_release_that_needs_a_build_is_cant_check(tmp_path: Path) -> None:
    stderr = (FIXTURES / "pip-num2words-0.5.14.stderr").read_text()
    run = FakeRunner(pip_answers("pip-report-num2words.json", probe_err=stderr))
    registry = releases(
        num2words=[("0.5.6", "wheel"), ("0.5.14", "wheel")], docopt=[("0.6.2", "sdist")]
    )
    out = run_pip(tmp_path, ["install", "num2words"], run, registry=registry)
    assert out.status == "cant_check" and out.exit_code == 3
    (b,) = out.blockers
    assert (b.package, b.needs, b.why, b.instead) == (
        "num2words 0.5.14",
        "docopt>=0.6.2",
        "is published only as source",
        "num2words 0.5.6",
    )
    assert check.blocker_lines(out) == [
        "num2words 0.5.14 needs docopt>=0.6.2, which is published only as source. Resolving "
        "docopt would run its build code, so Garnet Guard didn't. Without building, num2words "
        "resolves to 0.5.6."
    ]
    assert check.pins_to_try(out) == ["pip install num2words==0.5.6"]
    assert out.report is not None and out.changes == 1  # what could be checked is reported


def test_pip_lower_release_for_another_reason_is_not_flagged(tmp_path: Path) -> None:
    def answer(argv: list[str], cwd: Path, env: dict[str, str]) -> Ran:
        if "-c" in argv:
            return Ran(0)  # the newest resolves without building too
        return pip_answers("pip-report-num2words.json")(argv, cwd, env)

    registry = releases(num2words=[("0.5.6", "wheel"), ("0.5.14", "wheel")])
    out = run_pip(tmp_path, ["install", "num2words"], FakeRunner(answer), registry=registry)
    assert out.status == "pass" and not out.blockers


def test_pip_pinned_release_that_needs_a_build(tmp_path: Path) -> None:
    stderr = (FIXTURES / "pip-num2words-0.5.14.stderr").read_text()
    run = FakeRunner(pip_answers(None, fail=stderr))
    registry = releases(docopt=[("0.6.2", "sdist")])
    out = run_pip(tmp_path, ["install", "num2words==0.5.14"], run, registry=registry)
    assert out.status == "cant_check" and out.report is None
    assert check.blocker_lines(out)[0].startswith(
        "num2words needs docopt>=0.6.2, which is published only as source."
    )


def test_pip_resolution_failure_is_cant_check_without_credentials(tmp_path: Path) -> None:
    err = "ERROR: Could not fetch https://user:secret@example.invalid/simple/x/\nERROR: no\n"
    out = run_pip(tmp_path, ["install", "x"], FakeRunner(pip_answers(None, fail=err)))
    assert out.status == "cant_check"
    assert "secret" not in " ".join(out.reasons) and "****@" in " ".join(out.reasons)


@pytest.mark.parametrize("args", [["install", "-e", "."], ["install", "--no-binary", ":all:", "x"]])
def test_pip_refusals_run_nothing(args: list[str], tmp_path: Path) -> None:
    run = FakeRunner(pip_answers(None))
    out = run_pip(tmp_path, args, run)
    assert out.status == "cant_check" and run.calls == []
    assert out.original is not None and list(out.original.argv[4:]) == args


def test_pip_configuration_that_adds_files_is_refused(tmp_path: Path) -> None:
    def answer(argv: list[str], cwd: Path, env: dict[str, str]) -> Ran:
        if argv[4:6] == ["config", "list"]:
            return Ran(0, b"install.requirement='/etc/extra.txt'\n")
        raise AssertionError("nothing else runs")

    out = run_pip(tmp_path, ["install", "x"], FakeRunner(answer))
    assert out.status == "cant_check"
    assert out.reasons[0].startswith("pip configuration install.requirement")
    assert "/etc/extra.txt" not in out.reasons[0]


def test_pip_without_a_python(tmp_path: Path) -> None:
    out = check.check_pip(
        None,
        ["install", "x"],
        cwd=tmp_path,
        env={},
        command="pip install x",
        deps=deps(FakeRunner(pip_answers(None))),
        workdir=tmp_path,
    )
    assert out.status == "cant_check" and "can't find the Python" in out.reasons[0]


# --- uv ---------------------------------------------------------------------

HEAD_LOCK = (FIXTURES / "uv-head.lock").read_text()
BASE_LOCK = HEAD_LOCK.replace(
    'name = "requests"\nversion = "2.34.2"', 'name = "requests"\nversion = "2.34.1"'
)
UV = "/bin/uv"


def uv_project(root: Path, lock: str | None = BASE_LOCK) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n'
        'dependencies = ["requests>=2.34.1"]\n'
    )
    if lock is not None:
        (root / "uv.lock").write_text(lock)
    return root


def uv_answers(  # type: ignore[no-untyped-def]
    *,
    fail: str | None = None,
    probe_fail: str | None = None,
    check_ok: bool = False,
    head: str = HEAD_LOCK,
):
    def answer(argv: list[str], cwd: Path, env: dict[str, str]) -> Ran:
        if argv[1:3] == ["sync", "--frozen"]:  # the hand-off, after the check
            return Ran(0)
        assert argv[0] == UV and env["UV_NO_BUILD"] == "1"
        assert "--no-build" in argv and not (cwd / ".venv").exists()
        # Never a Python download, whatever the project's [tool.uv] says.
        assert argv[2] == "--no-python-downloads" and env["UV_PYTHON_DOWNLOADS"] == "never"
        argv = [*argv[:2], *argv[3:]]
        if "probe-" in str(cwd):
            return Ran(1, b"", (probe_fail or "").encode()) if probe_fail else Ran(0)
        if argv[1:3] == ["lock", "--check"]:
            return Ran(0 if check_ok else 1, b"", b"" if check_ok else b"needs updating")
        if fail:
            return Ran(1, b"", fail.encode())
        (cwd / "uv.lock").write_text(head)
        if argv[1] == "add":
            text = (cwd / "pyproject.toml").read_text()
            (cwd / "pyproject.toml").write_text(text.replace(">=2.34.1", ">=2.34.2"))
        return Ran(0)

    return answer


def run_uv(project: Path, sub: str, args: list[str], run: FakeRunner, **kw: object) -> Outcome:
    work = project.parent / f"work-{len(list(project.parent.glob('work-*')))}"
    work.mkdir()
    return check.check_uv(
        UV,
        sub,
        args,
        cwd=project,
        env={"UV_FROZEN": "0"},
        command=f"uv {sub} " + " ".join(args),
        deps=deps(run, **kw),
        workdir=work,
    )


def test_uv_add_pass_writes_back_and_syncs_frozen(tmp_path: Path) -> None:
    project = uv_project(tmp_path / "p")
    run = FakeRunner(uv_answers())
    out = run_uv(project, "add", ["requests", "--optional", "web"], run)
    assert out.status == "pass"
    assert run.calls[0][0] == [
        UV,
        "add",
        "--no-python-downloads",
        "--no-sync",
        "--no-build",
        "requests",
        "--optional",
        "web",
    ]
    assert run.calls[0][1] != project  # the copy, never the project
    assert out.report is not None
    assert [
        (r.change.package, r.change.baseline, r.change.candidate) for r in out.report.results
    ] == [("requests", "2.34.1", "2.34.2")]
    assert out.handoff is not None
    assert list(out.handoff.argv) == [
        UV,
        "sync",
        "--frozen",
        "--inexact",
        "--extra",
        "web",
        "--no-build-package",
        "requests",
    ]
    assert out.handoff.write_back == ("pyproject.toml", "uv.lock")
    assert (project / "uv.lock").read_text() == BASE_LOCK  # nothing written by the check
    stdout = io.StringIO()
    code = wrapper.act(out, force=False, deps=deps(run), stdout=stdout)
    assert code == 0
    assert (
        "Running: uv sync --frozen --inexact --extra web --no-build-package requests\n"
        in stdout.getvalue()
    )
    assert (project / "uv.lock").read_text() == HEAD_LOCK
    assert ">=2.34.2" in (project / "pyproject.toml").read_text()
    assert run.calls[-1] == (list(out.handoff.argv), project, False)


@pytest.mark.parametrize(
    "source",
    [
        '{ git = "https://example.invalid/r.git?rev=v1#abc" }',
        '{ path = "../r" }',
        '{ directory = "../r" }',
        '{ editable = "../r" }',
        '{ url = "https://example.invalid/r-1.0.tar.gz" }',
    ],
)
def test_uv_non_registry_packages_in_the_lock_are_cant_check(source: str, tmp_path: Path) -> None:
    # However it got into uv.lock (uv add -r, a direct reference, a source),
    # a package uv builds and Garnet can't compare is never a pass.
    head = HEAD_LOCK.replace(
        'name = "requests"\nversion = "2.34.2"\nsource = { registry = "https://pypi.org/simple" }',
        f'name = "requests"\nversion = "2.34.2"\nsource = {source}',
    )
    assert head != HEAD_LOCK
    run = FakeRunner(uv_answers(head=head))
    out = run_uv(uv_project(tmp_path / "p"), "lock", [], run)
    assert out.status == "cant_check" and out.handoff is None
    kind = source.split()[1]
    assert f"uv.lock requests: it comes from a {kind} source" in " ".join(out.reasons)


def test_uv_handoff_never_builds_an_unchecked_change(tmp_path: Path) -> None:
    head = HEAD_LOCK.replace(
        'name = "requests"\nversion = "2.34.2"\nsource = { registry = "https://pypi.org/simple" }',
        'name = "requests"\nversion = "2.34.2"\nsource = { registry = "https://example.invalid/simple" }',
    )
    run = FakeRunner(uv_answers(head=head, check_ok=False))
    out = run_uv(uv_project(tmp_path / "p"), "sync", [], run)
    assert out.handoff is not None
    argv = list(out.handoff.argv)
    assert ["--no-build-package", "requests"] == argv[
        argv.index("requests") - 1 : argv.index("requests") + 1
    ]


def test_uv_base_is_the_committed_lockfile(tmp_path: Path) -> None:
    project = uv_project(tmp_path / "p", lock=HEAD_LOCK)  # the working tree already moved
    run = FakeRunner(uv_answers(check_ok=True))
    out = run_uv(project, "sync", [], run, committed_lock=lambda p: BASE_LOCK.encode())
    assert run.calls[0][0] == [UV, "lock", "--no-python-downloads", "--check", "--no-build"]
    assert out.report is not None and len(out.report.results) == 1
    assert out.handoff is not None and out.handoff.write_back == ()
    assert list(out.handoff.argv) == [UV, "sync", "--frozen", "--no-build-package", "requests"]


def test_uv_sync_relocks_when_the_lockfile_is_stale(tmp_path: Path) -> None:
    run = FakeRunner(uv_answers(check_ok=False))
    out = run_uv(uv_project(tmp_path / "p"), "sync", ["--all-extras"], run)
    assert [c[0][1:4] for c in run.calls] == [
        ["lock", "--no-python-downloads", "--check"],
        ["lock", "--no-python-downloads", "--no-build"],
    ]
    assert out.handoff is not None and out.handoff.write_back == ("uv.lock",)
    assert "--all-extras" in out.handoff.argv


def test_uv_sync_locked_with_a_stale_lockfile_is_uvs_error(tmp_path: Path) -> None:
    run = FakeRunner(uv_answers(check_ok=False))
    out = run_uv(uv_project(tmp_path / "p"), "sync", ["--locked"], run)
    assert out.status == "uv_only" and out.exit_code == 1 and len(run.calls) == 1


def test_uv_lock_check_writes_nothing(tmp_path: Path) -> None:
    project = uv_project(tmp_path / "p")
    run = FakeRunner(uv_answers())
    out = run_uv(project, "lock", ["--check"], run)
    assert out.status == "uv_only" and (project / "uv.lock").read_text() == BASE_LOCK


def test_uv_lock_writes_the_lockfile_and_installs_nothing(tmp_path: Path) -> None:
    project = uv_project(tmp_path / "p")
    run = FakeRunner(uv_answers())
    out = run_uv(project, "lock", ["-U"], run)
    assert out.handoff is not None and out.handoff.argv == ()
    assert wrapper.act(out, force=False, deps=deps(run), stdout=io.StringIO()) == 0
    assert (project / "uv.lock").read_text() == HEAD_LOCK
    assert all(c[2] for c in run.calls)  # nothing ran outside the check


def test_uv_write_back_refuses_a_changed_project(tmp_path: Path) -> None:
    project = uv_project(tmp_path / "p")
    run = FakeRunner(uv_answers())
    out = run_uv(project, "add", ["requests"], run)
    (project / "uv.lock").write_text(BASE_LOCK + "\n# edited meanwhile\n")
    stdout = io.StringIO()
    assert wrapper.act(out, force=False, deps=deps(run), stdout=stdout) == 3
    assert "uv.lock changed while Garnet Guard was checking" in stdout.getvalue()
    assert (project / "uv.lock").read_text().endswith("# edited meanwhile\n")
    assert all(c[2] for c in run.calls)  # no hand-off


def test_uv_newer_release_that_needs_a_build(tmp_path: Path) -> None:
    project = uv_project(tmp_path / "p")
    stderr = (FIXTURES / "uv-add-num2words-0.5.14.stderr").read_text()
    registry = releases(
        requests=[("2.34.2", "wheel"), ("2.35.0", "wheel")], docopt=[("0.6.2", "sdist")]
    )
    out = run_uv(
        project, "add", ["requests"], FakeRunner(uv_answers(probe_fail=stderr)), registry=registry
    )
    assert out.status == "cant_check"
    (b,) = out.blockers
    assert (b.package, b.needs, b.why, b.instead) == (
        "requests 2.35.0",
        "docopt",
        "is published only as source",
        "requests 2.34.2",
    )
    assert check.pins_to_try(out) == ["uv add requests==2.34.2"]


def test_uv_failed_no_build_resolve(tmp_path: Path) -> None:
    stderr = (FIXTURES / "uv-add-num2words-0.5.14.stderr").read_text()
    out = run_uv(
        uv_project(tmp_path / "p"),
        "add",
        ["num2words==0.5.14"],
        FakeRunner(uv_answers(fail=stderr)),
        registry=releases(docopt=[("0.6.2", "sdist")]),
    )
    assert out.status == "cant_check" and out.report is None
    assert check.blocker_lines(out)[0].startswith(
        "num2words needs docopt, which is published only as source."
    )


@pytest.mark.parametrize(
    ("args", "pyproject_extra"),
    [
        (["--frozen", "x"], ""),
        (["x"], '[tool.uv.sources]\nx = { path = "../x" }\n'),
        (["x"], "[tool.uv.workspace]\nmembers = []\n"),
    ],
)
def test_uv_refusals_run_nothing(args: list[str], pyproject_extra: str, tmp_path: Path) -> None:
    project = uv_project(tmp_path / "p")
    with open(project / "pyproject.toml", "a") as fh:
        fh.write(pyproject_extra)
    run = FakeRunner(uv_answers())
    out = run_uv(project, "add", args, run)
    assert out.status == "cant_check" and run.calls == []


# --- the wrapper's verdicts -------------------------------------------------


def _outcome(
    tmp_path: Path, rules: Mapping[str, tuple[str, Severity]] | None
) -> tuple[Outcome, FakeRunner]:
    run = FakeRunner(pip_answers("pip-report-requests-2.32.3.json"))
    return run_pip(tmp_path, ["install", "requests==2.32.3"], run, evaluate=evaluator(rules)), run


def test_wrapper_stop_installs_nothing(tmp_path: Path) -> None:
    out, run = _outcome(tmp_path, {"requests": ("GRN-T001", Severity.BLOCK)})
    stdout = io.StringIO()
    assert wrapper.act(out, force=False, deps=deps(run), stdout=stdout) == 2
    assert all(c[2] for c in run.calls)  # only captured check runs, no install
    text = stdout.getvalue()
    assert "GRN-T001" in text and "Nothing was installed" in text and "safe" not in text.lower()


def test_wrapper_force_installs_after_a_block(tmp_path: Path) -> None:
    out, run = _outcome(tmp_path, {"requests": ("GRN-T001", Severity.BLOCK)})
    run.answer = lambda argv, cwd, env: Ran(0)
    assert wrapper.act(out, force=True, deps=deps(run), stdout=io.StringIO()) == 0
    assert out.handoff is not None and run.calls[-1][0] == list(out.handoff.argv)


def test_wrapper_package_manager_failure_exits_3(tmp_path: Path) -> None:
    # 1 and 2 say "findings, nothing installed"; a failed hand-off never reads as that.
    out, run = _outcome(tmp_path, None)
    for code in (1, 2, 7):
        run.answer = lambda argv, cwd, env, code=code: Ran(code)
        stdout = io.StringIO()
        assert wrapper.act(out, force=False, deps=deps(run), stdout=stdout) == 3
        assert f"pip exited with {code}. Garnet Guard exits 3." in stdout.getvalue()
    run.answer = lambda argv, cwd, env: Ran(0)
    assert wrapper.act(out, force=False, deps=deps(run), stdout=io.StringIO()) == 0


def test_wrapper_uv_sync_failure_says_the_files_were_written(tmp_path: Path) -> None:
    project = uv_project(tmp_path / "p")
    run = FakeRunner(uv_answers())
    out = run_uv(project, "add", ["requests"], run)
    assert out.status == "pass"
    run.answer = lambda argv, cwd, env: Ran(2)
    stdout = io.StringIO()
    assert wrapper.act(out, force=False, deps=deps(run), stdout=stdout) == 3
    text = stdout.getvalue()
    assert "Wrote the checked pyproject.toml and uv.lock." in text
    assert "uv exited with 2. Garnet Guard had already written the checked files" in text


@pytest.mark.parametrize("severity", [Severity.BLOCK, Severity.WARN])
def test_fail_on_never_still_reports_the_verdict(severity: Severity, tmp_path: Path) -> None:
    (tmp_path / "garnet.toml").write_text('[garnet]\nversion = 1\nfail_on = "never"\n')
    out, run = _outcome(tmp_path, {"requests": ("GRN-T001", severity)})
    assert out.status == "warn" and out.exit_code == 0
    worst = severity.label
    assert check.summary(out) == (
        f"Garnet Guard checked 1 dependency change: the verdict is {worst}, below fail_on = never."
    )
    run.answer = lambda argv, cwd, env: Ran(0)
    stdout = io.StringIO()
    assert wrapper.act(out, force=False, deps=deps(run), stdout=stdout) == 0
    assert "nothing at warn or above" not in stdout.getvalue()


def test_wrapper_force_with_nothing_to_run_says_so(tmp_path: Path) -> None:
    run = FakeRunner(lambda argv, cwd, env: pytest.fail("nothing runs"))
    out = check.check_uv(
        None, "sync", [], cwd=tmp_path, env={}, command="uv sync", deps=deps(run), workdir=tmp_path
    )
    stdout = io.StringIO()
    assert wrapper.act(out, force=True, deps=deps(run), stdout=stdout) == 3
    assert "--garnet-force: nothing to run" in stdout.getvalue()
    assert "not checked: uv sync" not in stdout.getvalue()


def test_pip_non_wheel_resolution_keeps_the_original_for_force(tmp_path: Path) -> None:
    report = json.loads((FIXTURES / "pip-report-requests-2.32.3.json").read_text())
    for item in report["install"]:
        item["download_info"]["url"] = item["download_info"]["url"].replace(".whl", ".tar.gz")
    (tmp_path / "sdist-report.json").write_text(json.dumps(report))
    run = FakeRunner(pip_answers(str(tmp_path / "sdist-report.json")))
    out = run_pip(tmp_path, ["install", "requests==2.32.3"], run)
    assert out.status == "cant_check" and out.original is not None


def test_wrapper_cant_check_installs_nothing_and_force_runs_the_original(tmp_path: Path) -> None:
    stderr = (FIXTURES / "pip-num2words-0.5.14.stderr").read_text()
    run = FakeRunner(pip_answers("pip-report-num2words.json", probe_err=stderr))
    registry = releases(
        num2words=[("0.5.6", "wheel"), ("0.5.14", "wheel")], docopt=[("0.6.2", "sdist")]
    )
    out = run_pip(tmp_path, ["install", "num2words"], run, registry=registry)
    stdout = io.StringIO()
    assert wrapper.act(out, force=False, deps=deps(run), stdout=stdout) == 3
    text = stdout.getvalue()
    assert "garnet pip install num2words==0.5.6" in text and "--garnet-force" in text
    assert all(c[2] for c in run.calls)
    run.answer = lambda argv, cwd, env: Ran(0)
    stdout = io.StringIO()
    assert wrapper.act(out, force=True, deps=deps(run), stdout=stdout) == 0
    assert run.calls[-1][0] == [PY, "-I", "-m", "pip", "install", "num2words"]
    assert "--garnet-force: not checked: num2words 0.5.14" in stdout.getvalue()


def test_wrapper_rejects_other_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert wrapper.main("pip", ["list"], cwd=tmp_path, env={}) == 3
    assert wrapper.main("uv", ["pip", "install", "x"], cwd=tmp_path, env={}) == 3
    assert wrapper.main("pip", ["install", "--garnet-typo", "x"], cwd=tmp_path, env={}) == 3
    assert "garnet pip checks pip install only" in capsys.readouterr().err


def test_redact() -> None:
    assert check.redact("https://user:p@ss@example.invalid/simple") == (
        "https://****@example.invalid/simple"
    )
    unchanged = "git+https://github.com/org/repo@v1 https://example.invalid/a@b"
    assert check.redact(unchanged) == unchanged


def test_nothing_printed_repeats_url_credentials(tmp_path: Path) -> None:
    index = "https://user:s3cret@example.invalid/simple"
    stdout = io.StringIO()
    # No pip on PATH: can't check, and the options repeat the command.
    args = ["install", "--index-url", index, "pkg>=1"]
    assert wrapper.main("pip", args, cwd=tmp_path, env={}, stdout=stdout) == 3
    text = stdout.getvalue()
    assert "s3cret" not in text
    assert (
        "garnet pip install --index-url https://****@example.invalid/simple 'pkg>=1' "
        "--garnet-force" in text
    )

    run = FakeRunner(pip_answers("pip-report-requests-2.32.3.json"))
    out = run_pip(tmp_path, ["install", "--index-url", index, "requests==2.32.3"], run)
    run.answer = lambda argv, cwd, env: Ran(0)
    stdout = io.StringIO()
    assert wrapper.act(out, force=False, deps=deps(run), stdout=stdout) == 0
    text = stdout.getvalue()
    assert "s3cret" not in text and "--index-url https://****@example.invalid/simple" in text
    assert index in run.calls[-1][0]  # pip itself gets the URL as written


def test_package_text_is_escaped(tmp_path: Path) -> None:
    out, run = _outcome(tmp_path, None)
    assert out.report is not None
    evil = Change("pypi", "x\x1b[31mred", None, "1‮0")
    out.report = check.report(
        [
            ChangeResult(
                evil, Verdict.WARN, (finding(evil, "GRN-T004", Severity.WARN, "t\x1b]0;x\x07"),)
            )
        ]
    )
    stdout = io.StringIO()
    wrapper.act(out, force=False, deps=deps(FakeRunner(lambda a, c, e: Ran(0))), stdout=stdout)
    text = stdout.getvalue()
    assert "\x1b" not in text and "‮" not in text and "\x07" not in text
    assert json.dumps(text)  # still printable


# --- the loader preload -------------------------------------------------------

PRELOADS = {
    "LD_PRELOAD": "./pre.so",
    "LD_AUDIT": "./audit.so",
    "LD_LIBRARY_PATH": "./lib",
    "DYLD_INSERT_LIBRARIES": "./pre.dylib",
    "DYLD_FRAMEWORK_PATH": "./fw",
    "DYLD_SOME_LATER_NAME": "./x",  # dyld reads more DYLD_ names than the constant lists
}


def test_loader_preload_names() -> None:
    assert {"LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"} <= LOADER_PRELOAD
    assert {"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"} <= LOADER_PRELOAD
    assert all(loader_preload(name) for name in PRELOADS)
    for name in ("LD_BIND_NOW", "PATH", "PYTHONPATH", "ld_preload", "MY_LD_PRELOAD", "DYLD"):
        assert not loader_preload(name)


def test_loader_env_keeps_only_garnets_own_loader_settings() -> None:
    env = {"PATH": "/usr/bin", "LD_BIND_NOW": "1", **PRELOADS}
    assert loader_env(env, own={}) == {"PATH": "/usr/bin", "LD_BIND_NOW": "1"}
    # What Garnet started with is already loaded into Garnet: it stays.
    own = {"LD_LIBRARY_PATH": "/opt/python/lib", "HOME": "/home/me"}
    assert loader_env(env, own=own) == {
        "PATH": "/usr/bin",
        "LD_BIND_NOW": "1",
        "LD_LIBRARY_PATH": "/opt/python/lib",
    }


def _recording(answer, seen: list[dict[str, str]]):  # type: ignore[no-untyped-def]
    def run(argv: list[str], cwd: Path, env: dict[str, str]) -> Ran:
        seen.append(env)
        return answer(argv, cwd, env)  # type: ignore[no-any-return]

    return run


def _no_own_loader_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if loader_preload(name):
            monkeypatch.delenv(name)


def test_pip_check_runs_without_the_commands_loader_preload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_own_loader_settings(monkeypatch)
    seen: list[dict[str, str]] = []
    run = FakeRunner(_recording(pip_answers("pip-report-requests-2.32.3.json"), seen))
    work = tmp_path / "work"
    work.mkdir()
    out = check.check_pip(
        PY,
        ["install", "requests==2.32.3"],
        cwd=tmp_path,
        env={"PATH": "/venv/bin", **PRELOADS},
        command="pip install requests==2.32.3",
        deps=deps(run),
        workdir=work,
    )
    assert out.status == "pass"
    # config list, inspect and the dry run: none of them gets a preload.
    assert len(seen) == 3
    assert all(not any(loader_preload(name) for name in env) for env in seen)
    assert all(env["PATH"] == "/venv/bin" for env in seen)
    # The install itself (the wrapper's hand-off) runs as the user wrote it.
    assert out.handoff is not None and out.handoff.env["LD_PRELOAD"] == "./pre.so"


def test_uv_check_runs_without_the_commands_loader_preload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_own_loader_settings(monkeypatch)
    monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/python/lib")  # Garnet's own: kept
    project = uv_project(tmp_path / "p")
    seen: list[dict[str, str]] = []
    run = FakeRunner(_recording(uv_answers(), seen))
    work = tmp_path / "work"
    work.mkdir()
    out = check.check_uv(
        UV,
        "add",
        ["requests"],
        cwd=project,
        env={"UV_FROZEN": "0", **PRELOADS},
        command="uv add requests",
        deps=deps(run),
        workdir=work,
    )
    assert out.status == "pass" and seen
    for env in seen:
        assert {name for name in env if loader_preload(name)} == {"LD_LIBRARY_PATH"}
        assert env["LD_LIBRARY_PATH"] == "/opt/python/lib"
    assert out.handoff is not None and out.handoff.env["DYLD_INSERT_LIBRARIES"] == "./pre.dylib"
