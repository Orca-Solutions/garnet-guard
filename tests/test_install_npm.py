"""``garnet npm install|ci|update`` and the hooks' npm commands, with recorded
npm answers in place of npm and stand-ins for the checks. No network."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
from typing import Any

import pytest

from garnet_guard.install import check, gate, hooks, npm, runner, shellwords, wrapper
from garnet_guard.install.check import Outcome
from garnet_guard.install.runner import Ran
from garnet_guard.models import Severity
from tests.test_install_check import FakeRunner, deps, evaluator
from tests.test_install_hooks import AGENTS, answer, event, spec, where  # noqa: F401

NPM = "/bin/npm"
CONFIG = "".join(f"{k}={v}\n" for k, v in npm.CONFIG_EXPECTED.items()) + "ignore-scripts=false\n"


def entry(name: str, version: str, **extra: Any) -> dict[str, Any]:
    tail = name.rpartition("/")[2]
    return {
        "version": version,
        "resolved": f"https://registry.npmjs.org/{name}/-/{tail}-{version}.tgz",
        "integrity": "sha512-AAAA",
        **extra,
    }


def lock(**entries: dict[str, Any]) -> str:
    """A package-lock.json (lockfileVersion 3) with these node_modules entries."""
    packages: dict[str, Any] = {"": {"name": "demo", "version": "1.0.0"}}
    for key, value in entries.items():
        packages[key if "/" in key else f"node_modules/{key}"] = value
    doc = {"name": "demo", "version": "1.0.0", "lockfileVersion": 3, "packages": packages}
    return json.dumps(doc, indent=2) + "\n"


BASE = lock(**{"left-pad": entry("left-pad", "1.2.0"), "esbuild": entry("esbuild", "0.25.0", hasInstallScript=True)})  # fmt: skip
HEAD = lock(
    **{
        "left-pad": entry("left-pad", "1.3.0", hasInstallScript=True),
        "esbuild": entry("esbuild", "0.25.0", hasInstallScript=True),
    }
)
MANIFEST = '{"name": "demo", "version": "1.0.0", "dependencies": {"left-pad": "1.2.0"}}\n'


def project(root: Path, manifest: str = MANIFEST, lockfile: str | None = BASE) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(manifest)
    if lockfile is not None:
        (root / "package-lock.json").write_text(lockfile)
    return root


def npm_answers(  # type: ignore[no-untyped-def]
    head: str = HEAD,
    *,
    config: str = CONFIG,
    fail: str | None = None,
    seen: list[Any] | None = None,
    version: str = "10.9.4",
):
    def answer(argv: list[str], cwd: Path, env: dict[str, str]) -> Ran:
        assert argv[0] == NPM
        if argv[1] not in ("ci", "rebuild"):  # every npm the check runs: no node preloads
            assert not {k for k in env if k.upper() in npm.NODE_PRELOAD}
            # nor a loader setting Garnet's own process didn't start with
            assert all(v == os.environ.get(k) for k, v in env.items() if runner.loader_preload(k))
        if argv[1:] == ["--version"]:
            return Ran(0, f"{version}\n".encode())
        if argv[1:3] == ["config", "get"]:
            assert argv[3:] == list(npm.CONFIG_KEYS)
            return Ran(0, config.encode())
        if argv[1] in ("ci", "rebuild"):  # the hand-off, after the check
            return Ran(0)
        # The resolve step: in the copy, with scripts and git off.
        assert argv[-len(npm.RESOLVE_TAIL) :] == list(npm.RESOLVE_TAIL)
        assert env["npm_config_ignore_scripts"] == "true"
        for key in ("npm_config_script_shell", "npm_config_git"):
            assert not Path(env[key]).exists() and Path(env[key]).is_absolute()
        assert not [k for k in env if k.lower() == "npm_config_ignore_scripts" and k != k.lower()]
        assert not (cwd / "node_modules").exists()
        if seen is not None:
            seen.append((argv, cwd, env))
        if fail is not None:
            return Ran(1, b"", fail.encode())
        (cwd / "package-lock.json").write_text(head)
        text = (cwd / "package.json").read_text()
        (cwd / "package.json").write_text(text.replace('"1.2.0"', '"^1.3.0"'))
        return Ran(0)

    return answer


def run_npm(root: Path, sub: str, args: list[str], run: FakeRunner, **kw: Any) -> Outcome:
    work = root.parent / f"work-{len(list(root.parent.glob('work-*')))}"
    work.mkdir()
    return check.check_npm(
        NPM,
        sub,
        args,
        cwd=root,
        env=kw.pop("env", {"PATH": "/bin", "NPM_CONFIG_IGNORE_SCRIPTS": "false"}),
        command=f"npm {sub} " + " ".join(args),
        deps=deps(run, **kw),
        workdir=work,
    )


# --- reading the command ----------------------------------------------------


def test_plan_splits_options_between_the_resolve_and_npm_ci() -> None:
    plan = npm.plan(
        "install",
        [
            "-D",
            "left-pad@^1.3.0",
            "--legacy-peer-deps",
            "--omit",
            "dev",
            "--registry=https://r.example/",
            "--no-audit",
        ],  # fmt: skip
    )
    assert not plan.refusals
    assert plan.specs == ["left-pad@^1.3.0"]
    assert plan.resolve == [
        "-D",
        "left-pad@^1.3.0",
        "--legacy-peer-deps",
        "--registry=https://r.example/",
        "--no-audit",
    ]
    assert plan.handoff == [
        "--legacy-peer-deps",
        "--omit=dev",
        "--registry=https://r.example/",
        "--no-audit",
    ]


@pytest.mark.parametrize(
    "args",
    [
        ["-g", "x"],
        ["--global", "x"],
        ["--glob", "x"],  # npm expands abbreviations; Garnet doesn't, and refuses
        ["--prefix", "web", "x"],
        ["--no-save", "x"],
        ["--no-package-lock"],
        ["--ignore-scripts=false"],
        ["--script-shell", "sh"],
        ["--install-links"],
        ["-w", "a", "x"],
        ["--workspaces"],
        ["-DE"],
        ["github:o/r"],
        ["o/r"],
        ["x@github:o/r#abc"],
        ["git+https://example.invalid/r.git"],
        ["https://example.invalid/x-1.0.0.tgz"],
        ["./vendor/x"],
        ["../x"],
        ["/abs/x"],
        ["x.tgz"],
        ["x@file:../x"],
        ["x@link:../x"],
        ["x@npm:y@file:../y"],
        ["--registry"],
    ],
)
def test_plan_refusals(args: list[str]) -> None:
    assert npm.plan("install", args).refusals


@pytest.mark.parametrize(
    "spec", ["x", "x@1", "x@^1.2.3 || 2", "@s/x@latest", "x@npm:@s/y@~1.0", "x@*", "x@1.x"]
)
def test_registry_specs(spec: str) -> None:
    assert npm.registry_spec(spec)
    assert not npm.plan("install", [spec]).refusals


def test_ci_takes_no_packages() -> None:
    assert npm.plan("ci", ["left-pad"]).refusals
    assert not npm.plan("ci", ["--omit=dev", "--no-audit"]).refusals


# --- install ----------------------------------------------------------------


def test_install_checks_in_a_copy_then_writes_back_and_runs_npm_ci(tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    seen: list[Any] = []
    run = FakeRunner(npm_answers(seen=seen))
    out = run_npm(root, "install", ["left-pad@1.3.0", "--no-audit"], run)
    assert out.status == "pass", out.reasons
    argv, cwd, _ = seen[0]
    assert argv[:4] == [NPM, "install", "left-pad@1.3.0", "--no-audit"]
    assert cwd != root and cwd.name == "demo"  # a copy; npm names the lockfile after it
    assert out.report is not None
    assert [
        (r.change.package, r.change.baseline, r.change.candidate) for r in out.report.results
    ] == [("left-pad", "1.2.0", "1.3.0")]
    assert (root / "package-lock.json").read_text() == BASE  # nothing written by the check
    handoff = out.handoff
    assert handoff is not None
    assert list(handoff.argv) == [NPM, "ci", "--ignore-scripts", "--no-audit"]
    assert handoff.write_back == ("package.json", "package-lock.json")
    # esbuild didn't change, so its install script runs again; left-pad's doesn't.
    assert handoff.then is not None and list(handoff.then.argv) == [
        NPM,
        "rebuild",
        "./node_modules/esbuild",
    ]
    stdout = io.StringIO()
    assert wrapper.act(out, force=False, deps=deps(run), stdout=stdout) == 0
    text = stdout.getvalue()
    assert "Wrote the checked package.json and package-lock.json." in text
    assert "Running: npm ci --ignore-scripts --no-audit\n" in text
    assert "Running: npm rebuild ./node_modules/esbuild\n" in text
    assert "because the package is new or changed: left-pad 1.3.0" in text
    assert "npm rebuild ./node_modules/left-pad" in text
    assert (root / "package-lock.json").read_text() == HEAD
    assert [c[0][1] for c in run.calls[-2:]] == ["ci", "rebuild"]
    assert all(c[1] == root for c in run.calls[-2:])


def test_users_ignore_scripts_runs_no_rebuild(tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    out = run_npm(
        root, "install", ["left-pad@1.3.0", "--ignore-scripts"], FakeRunner(npm_answers())
    )
    assert out.handoff is not None and out.handoff.then is None
    config = CONFIG.replace("ignore-scripts=false", "ignore-scripts=true")
    out = run_npm(root, "install", ["left-pad@1.3.0"], FakeRunner(npm_answers(config=config)))
    assert out.handoff is not None and out.handoff.then is None


def test_no_base_lockfile_runs_no_install_script(tmp_path: Path) -> None:
    root = project(tmp_path / "demo", lockfile=None)
    out = run_npm(root, "install", [], FakeRunner(npm_answers()))
    assert out.status == "pass" and out.report is not None
    assert {r.change.package for r in out.report.results} == {"left-pad", "esbuild"}
    assert out.handoff is not None and out.handoff.then is None
    assert any("esbuild 0.25.0, left-pad 1.3.0" in n for n in out.handoff.notes)


def test_base_is_the_committed_lockfile(tmp_path: Path) -> None:
    root = project(tmp_path / "demo", lockfile=HEAD)  # already changed on disk
    committed = BASE.encode()
    out = run_npm(
        root, "install", [], FakeRunner(npm_answers()), committed_lock=lambda path: committed
    )
    assert out.report is not None
    assert [(r.change.baseline, r.change.candidate) for r in out.report.results] == [
        ("1.2.0", "1.3.0")
    ]


def test_block_installs_and_writes_nothing(tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    run = FakeRunner(npm_answers())
    out = run_npm(
        root,
        "install",
        ["left-pad@1.3.0"],
        run,
        evaluate=evaluator({"left-pad": ("GRN-T001", Severity.BLOCK)}),
    )
    assert out.status == "stop"
    stdout = io.StringIO()
    assert wrapper.act(out, force=False, deps=deps(run), stdout=stdout) == 2
    assert "Nothing was installed" in stdout.getvalue()
    assert (root / "package-lock.json").read_text() == BASE
    assert all(c[2] for c in run.calls)  # captured check runs only


def test_package_lock_only_and_dry_run(tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    run = FakeRunner(npm_answers())
    out = run_npm(root, "install", ["left-pad@1.3.0", "--package-lock-only"], run)
    assert out.handoff is not None and not out.handoff.argv
    assert wrapper.act(out, force=False, deps=deps(run), stdout=io.StringIO()) == 0
    assert (root / "package-lock.json").read_text() == HEAD
    assert not [c for c in run.calls if c[0][1] in ("ci", "rebuild")]

    root = project(tmp_path / "dry")
    out = run_npm(root, "install", ["left-pad@1.3.0", "--dry-run"], FakeRunner(npm_answers()))
    assert out.status == "pass" and out.handoff is None
    assert wrapper.act(out, force=False, deps=deps(run), stdout=io.StringIO()) == 0
    assert (root / "package-lock.json").read_text() == BASE


def test_update_resolves_with_npm_update(tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    seen: list[Any] = []
    out = run_npm(root, "update", ["left-pad"], FakeRunner(npm_answers(seen=seen)))
    assert out.status == "pass"
    assert seen[0][0][:3] == [NPM, "update", "left-pad"]


def test_failed_resolve_is_cant_check_without_credentials(tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    err = "npm error code E401\nnpm error 401 https://user:s3cret@r.example/x\n"
    out = run_npm(root, "install", ["x"], FakeRunner(npm_answers(fail=err)))
    assert out.status == "cant_check" and out.exit_code == 3
    text = " ".join(check.reason_lines(out))
    assert "scripts and git turned off" in text and "E401" in text and "s3cret" not in text


# --- what makes it "can't check" --------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        {"version": "1.0.0", "resolved": "git+ssh://git@github.com/o/r.git#" + "a" * 40},
        {"version": "1.0.0", "resolved": "file:../x-1.0.0.tgz"},
        {"version": "1.0.0", "resolved": "https://example.invalid/x-1.0.0.tgz"},
        {"version": "1.0.0", "resolved": "http://registry.npmjs.org/x/-/x-1.0.0.tgz"},
        {"version": "1.0.0"},
    ],
)
def test_non_registry_lockfile_entries_are_cant_check(bad: dict[str, Any], tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    head = lock(**{"left-pad": entry("left-pad", "1.3.0"), "x": bad})
    run = FakeRunner(npm_answers(head))
    out = run_npm(root, "install", [], run)
    assert out.status == "cant_check", out.reasons
    assert any("package-lock.json x:" in r for r in out.reasons)
    assert out.handoff is None


def test_a_link_in_the_lockfile_is_cant_check(tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    head = lock(
        **{"node_modules/x": {"resolved": "../x", "link": True}, "../x": {"version": "1.0.0"}}
    )
    out = run_npm(root, "install", [], FakeRunner(npm_answers(head)))
    assert out.status == "cant_check"
    assert any("a link to a folder" in r for r in out.reasons)


def test_a_private_registry_is_a_finding_not_cant_check(tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    private = {"version": "1.0.0", "resolved": "https://npm.example/x/-/x-1.0.0.tgz"}
    head = lock(**{"left-pad": entry("left-pad", "1.3.0"), "x": private})
    out = run_npm(root, "install", [], FakeRunner(npm_answers(head)))
    assert out.status != "cant_check" and out.report is not None
    found = [f for r in out.report.results for f in r.findings]
    assert [(f.rule_id, f.change.package) for f in found] == [("GRN-E005", "x")]


@pytest.mark.parametrize(
    "manifest",
    [
        '{"dependencies": {"x": "github:o/r#' + "a" * 40 + '"}}',
        '{"devDependencies": {"x": "file:../x"}}',
        '{"optionalDependencies": {"x": "https://example.invalid/x.tgz"}}',
        '{"dependencies": {"x": "npm:y@git+https://example.invalid/y.git"}}',
        '{"overrides": {"x": {"y": "o/r"}}}',
        '{"workspaces": ["packages/*"]}',
    ],
)
def test_project_refusals_run_nothing(manifest: str, tmp_path: Path) -> None:
    root = project(tmp_path / "demo", manifest=manifest)
    run = FakeRunner(npm_answers())
    out = run_npm(root, "install", [], run)
    assert out.status == "cant_check" and not run.calls


def test_a_folder_inside_a_workspace_is_refused(tmp_path: Path) -> None:
    project(tmp_path / "mono", manifest='{"workspaces": ["demo"]}')
    root = project(tmp_path / "mono" / "demo")
    run = FakeRunner(npm_answers())
    out = run_npm(root, "install", [], run)
    assert out.status == "cant_check" and not run.calls
    assert any("workspaces" in r for r in out.reasons)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("package-lock", "false"),
        ("save", "false"),
        ("global", "true"),
        ("location", "global"),
        ("install-links", "true"),
        ("workspace", "a"),
        ("omit-lockfile-registry-resolved", "true"),
    ],
)
def test_npm_settings_that_hide_what_is_installed(key: str, value: str, tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    config = CONFIG.replace(f"{key}={npm.CONFIG_EXPECTED[key]}\n", f"{key}={value}\n")
    run = FakeRunner(npm_answers(config=config))
    out = run_npm(root, "install", [], run)
    assert out.status == "cant_check"
    assert [c[0][1] for c in run.calls] == ["--version", "config"]  # nothing resolved
    assert any(f"npm setting {key}" in r for r in out.reasons)


def test_resolve_env_overrides_the_users_spellings(tmp_path: Path) -> None:
    env = npm.resolve_env(
        {"NPM_CONFIG_IGNORE_SCRIPTS": "false", "npm_config_Script_Shell": "sh", "HOME": "/h"},
        tmp_path,
    )
    assert env["HOME"] == "/h" and env["npm_config_ignore_scripts"] == "true"
    assert "NPM_CONFIG_IGNORE_SCRIPTS" not in env and "npm_config_Script_Shell" not in env
    assert env["npm_config_script_shell"] == str(tmp_path / "no-scripts")


# --- ci ---------------------------------------------------------------------


def test_ci_checks_the_lockfile_on_disk_against_head(tmp_path: Path) -> None:
    root = project(tmp_path / "demo", lockfile=HEAD)
    run = FakeRunner(npm_answers())
    out = run_npm(root, "ci", [], run, committed_lock=lambda path: BASE.encode())
    assert [c[0][1] for c in run.calls] == ["--version", "config"]  # no resolve
    assert out.report is not None and len(out.report.results) == 1
    assert out.handoff is not None and out.handoff.write_back == ()
    assert list(out.handoff.argv) == [NPM, "ci", "--ignore-scripts"]


def test_ci_refuses_a_lockfile_changed_after_the_check(tmp_path: Path) -> None:
    root = project(tmp_path / "demo", lockfile=HEAD)
    run = FakeRunner(npm_answers())
    out = run_npm(root, "ci", [], run)
    (root / "package-lock.json").write_text(BASE)
    stdout = io.StringIO()
    assert wrapper.act(out, force=False, deps=deps(run), stdout=stdout) == 3
    assert "package-lock.json changed while Garnet Guard was checking" in stdout.getvalue()
    assert not [c for c in run.calls if c[0][1] == "ci"]


def test_ci_without_a_lockfile_is_cant_check(tmp_path: Path) -> None:
    root = project(tmp_path / "demo", lockfile=None)
    out = run_npm(root, "ci", [], FakeRunner(npm_answers()))
    assert out.status == "cant_check" and "there's no package-lock.json." in out.reasons


def test_shrinkwrap_is_the_lockfile_when_present(tmp_path: Path) -> None:
    root = project(tmp_path / "demo", lockfile=None)
    (root / "npm-shrinkwrap.json").write_text(HEAD)
    out = run_npm(
        root, "ci", [], FakeRunner(npm_answers()), committed_lock=lambda path: BASE.encode()
    )
    assert out.report is not None
    assert {r.change.lockfile for r in out.report.results} == {"npm-shrinkwrap.json"}


def test_wrapper_main_routes_npm_aliases(tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "npm").write_text("#!/bin/sh\n")
    (tmp_path / "bin" / "npm").chmod(0o755)
    seen: list[Any] = []

    def answer(argv: list[str], cwd: Path, env: dict[str, str]) -> Ran:
        seen.append(argv[1:3])
        return Ran(1, b"", b"npm error offline")

    run = FakeRunner(answer)
    code = wrapper.main(
        "npm",
        ["isntall", "left-pad"],
        deps=deps(run),
        cwd=root,
        env={"PATH": str(tmp_path / "bin")},
        stdout=io.StringIO(),
    )
    assert code == 3 and seen == [["--version"]]
    assert wrapper.main("npm", ["run", "build"], deps=deps(run), cwd=root, env={}) == 3


# --- the hooks --------------------------------------------------------------


def _shape(command: str, cwd: str) -> list[str]:
    found = shellwords.find_commands(command, cwd=cwd, env={"PATH": "/nonexistent"})
    out = []
    for f in found:
        if isinstance(f, shellwords.NpmCommand):
            out.append(f"npm {f.subcommand} " + " ".join(f.args))
        elif isinstance(f, shellwords.Unsupported):
            out.append(f"unsupported {f.tool}")
        elif isinstance(f, shellwords.Unclear):
            out.append("unclear")
        else:
            out.append(type(f).__name__)
    return [s.strip() for s in out]


@pytest.mark.parametrize(
    ("command", "shape"),
    [
        ("npm install left-pad", ["npm install left-pad"]),
        ("npm i -D x", ["npm install -D x"]),
        ("npm add x", ["npm install x"]),
        ("npm ci", ["npm ci"]),
        ("npm clean-install --omit=dev", ["npm ci --omit=dev"]),
        ("npm up x", ["npm update x"]),
        ("npm --loglevel=warn i x", ["npm install --loglevel=warn x"]),
        ("npm -s ci", ["npm ci -s"]),
        ("npm --prefix web install", ["unclear"]),
        ("npm --loglevel warn install", ["unclear"]),
        ("cd web && npm ci", ["npm ci"]),
        ("npm install $PKG", ["unclear"]),
        ("npm_config_registry=$R npm ci", ["unclear"]),
        ("npm exec x", ["unsupported npm exec"]),
        ("npm cit", ["unsupported npm cit"]),
        ("npx x", ["unsupported npx"]),
        ("pnpm add x", ["unsupported pnpm add"]),
        ("npm run build", []),
        ("npm test", []),
        ("npm -v", []),
        ("echo npm install x", []),
    ],
)
def test_npm_command_shapes(command: str, shape: list[str], tmp_path: Path) -> None:
    (tmp_path / "web").mkdir()
    assert _shape(command, str(tmp_path)) == shape


@pytest.mark.parametrize("agent", AGENTS)
def test_hook_checks_npm_install_and_installs_nothing(
    agent: str,
    where: dict[str, str],  # noqa: F811
) -> None:
    root = project(Path(where["cwd"]) / "demo")
    npm_exe = str(Path(where["PATH"]) / "npm")

    def answers(argv: list[str], cwd: Path, env: dict[str, str]) -> Ran:
        assert argv[1] not in ("ci", "rebuild")  # the hook never installs
        return npm_answers()([NPM, *argv[1:]], cwd, env)

    run = FakeRunner(answers)
    out = answer(agent, event("npm install left-pad@1.3.0", str(root)), where, deps=deps(run))
    inner = spec(out)
    assert "permissionDecision" not in inner
    assert "left-pad 1.2.0 -> 1.3.0" in inner["additionalContext"]
    assert run.calls[0][0][0] == npm_exe
    assert (root / "package-lock.json").read_text() == BASE

    git = FakeRunner(answers)
    out = answer(agent, event("npm i github:o/r", str(root)), where, deps=deps(git))
    inner = spec(out)
    assert inner["permissionDecision"] == ("ask" if agent == "claude-code" else "deny")
    assert "github:o/r: it installs from git" in inner["permissionDecisionReason"]
    assert not git.calls


@pytest.mark.parametrize("agent", AGENTS)
def test_hook_npm_registry_credentials_never_shown(
    agent: str,
    where: dict[str, str],  # noqa: F811
) -> None:
    root = project(Path(where["cwd"]) / "demo")
    err = "npm error 401 https://user:s3cret@r.example/x\n"
    run = FakeRunner(lambda argv, cwd, env: npm_answers(fail=err)([NPM, *argv[1:]], cwd, env))
    command = "npm install --registry https://user:s3cret@r.example/ x"
    text = json.dumps(answer(agent, event(command, str(root)), where, deps=deps(run)))
    assert "s3cret" not in text and "https://****@r.example/" in text


# --- review findings (2026-10-31) -------------------------------------------


def test_rebuild_needs_the_same_entry_at_the_same_path(tmp_path: Path) -> None:
    # Same name and version, but another tarball: it changed, so it isn't rebuilt.
    other = entry("esbuild", "0.25.0", hasInstallScript=True)
    other["resolved"] = "https://npm.example/esbuild/-/esbuild-0.25.0.tgz"
    other["integrity"] = "sha512-BBBB"
    head = lock(**{"left-pad": entry("left-pad", "1.2.0"), "esbuild": other})
    root = project(tmp_path / "demo")
    out = run_npm(root, "install", [], FakeRunner(npm_answers(head)))
    assert out.handoff is not None and out.handoff.then is None
    assert any("esbuild 0.25.0" in n and "./node_modules/esbuild" in n for n in out.handoff.notes)


def test_rebuild_never_names_a_package_npm_could_match_elsewhere(tmp_path: Path) -> None:
    # node_modules/bar/node_modules/esbuild is another package (an alias of
    # evil) at the trusted name and version. npm rebuild esbuild@0.25.0 would
    # run it; the rebuild is given the trusted entry's exact path instead.
    nested = {**entry("evil", "0.25.0", hasInstallScript=True), "name": "evil"}
    head = json.loads(HEAD)
    head["packages"]["node_modules/bar"] = entry("bar", "1.0.0")
    head["packages"]["node_modules/bar/node_modules/esbuild"] = nested
    root = project(tmp_path / "demo")
    out = run_npm(root, "install", [], FakeRunner(npm_answers(json.dumps(head))))
    assert out.handoff is not None and out.handoff.then is not None
    assert list(out.handoff.then.argv)[1:] == ["rebuild", "./node_modules/esbuild"]
    assert not any("@" in a for a in out.handoff.then.argv[2:])
    note = " ".join(out.handoff.notes)
    assert "evil 0.25.0" in note and "./node_modules/bar/node_modules/esbuild" in note


def test_entries_key_on_path_name_version_resolved_and_integrity() -> None:
    found = npm.entries(BASE.encode())
    assert found["node_modules/esbuild"] == npm.Scripted(
        "node_modules/esbuild",
        "esbuild",
        "0.25.0",
        "https://registry.npmjs.org/esbuild/-/esbuild-0.25.0.tgz",
        "sha512-AAAA",
    )
    no_integrity = lock(
        x={"version": "1.0.0", "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz"}
    )
    assert npm.entries(no_integrity.encode()) == {}


# npm's own deref (lib/utils/cmd-list.js) gave these for npm 10.9.4 and
# 11.21.1; the port matched it on all 458 prefixes of every command and alias.
@pytest.mark.parametrize(
    ("word", "commands"),
    [
        ("upd", {"update"}),
        ("ud", {"update"}),
        ("upgr", {"update"}),
        ("u", {"update"}),  # npm 11 only; npm 10 says "Unknown command"
        ("install-cl", {"ci"}),
        ("installClean", {"ci"}),
        ("cleanInstall", {"ci"}),
        ("isntall-c", {"ci"}),
        ("insta", {"install"}),
        ("run", {"run", "run-script"}),
        ("x", {"exec"}),
        ("cit", {"install-ci-test"}),
        ("I", set()),
        ("ru", set()),
    ],
)
def test_deref_reads_subcommands_as_npm_does(word: str, commands: set[str]) -> None:
    assert npm.deref(word) == commands


@pytest.mark.parametrize(
    ("command", "shape"),
    [
        ("npm upd left-pad", ["npm update left-pad"]),
        ("npm upgr", ["npm update"]),
        ("npm install-cl", ["npm ci"]),
        ("npm installClean", ["npm ci"]),
        ("npm cleanInstall", ["npm ci"]),
        ("npm isntall-c", ["npm ci"]),
        ("npm -- install left-pad", ["npm install -- left-pad"]),
        ("npm --no-audit false install x", ["unclear"]),
        ("npm uninstall x", ["unsupported npm uninstall"]),  # may install: asks
        ("npm dedupe", ["unsupported npm dedupe"]),
        ("npm rb", ["unsupported npm rb"]),
        ("npm I x", ["unsupported npm I"]),  # unknown to npm: asks rather than guess
        ("npm init -y", []),
        ("npm init vite", ["unsupported npm init"]),
        ("npm audit", []),
        ("npm audit fix", ["unsupported npm audit"]),
        ("npm view left-pad versions", []),
        ("npm view github:o/r", ["unsupported npm view"]),
        ("npm run build", []),
        ("npm t", []),
        ("npx npm i x", ["unsupported npx"]),
        ("npx -y npm@10 i x", ["unsupported npx"]),
        ("npx --package=pnpm pnpm add x", ["unsupported npx"]),
        ("npm exec -- npm i x", ["unsupported npm exec"]),
        ("npm x npm i", ["unsupported npm x"]),
        ("node /usr/lib/node_modules/npm/bin/npm-cli.js i x", ["unclear"]),
        ("corepack npm i x", ["unclear"]),
    ],
)
def test_npm_spellings_are_checked_or_asked(command: str, shape: list[str], tmp_path: Path) -> None:
    assert _shape(command, str(tmp_path)) == shape


@pytest.mark.parametrize(
    ("command", "ask"),
    [
        ("npm uninstall x", True),
        ("npx npm i x", True),
        ("npm exec -- npm i x", True),
        ("npx -y npm@8 i x", True),
        ("npx prettier --check .", False),
        ("npm exec tsc", False),
    ],
)
def test_ask_or_note(command: str, ask: bool, tmp_path: Path) -> None:
    found = shellwords.find_commands(command, cwd=str(tmp_path), env={"PATH": "/nonexistent"})
    assert len(found) == 1 and isinstance(found[0], shellwords.Unsupported)
    assert found[0].ask is ask


def test_wrapper_reads_npm_spellings(tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    seen: list[str] = []
    real = check.check_npm

    def spy(npm_exe: str | None, subcommand: str, args: Any, **kw: Any) -> Outcome:
        seen.append(subcommand)
        return real(npm_exe, subcommand, args, **kw)

    for words in (["upd"], ["installClean"], ["--", "install", "x"]):
        check.check_npm = spy  # type: ignore[assignment]
        try:
            wrapper.main("npm", words, deps=deps(FakeRunner(npm_answers())), cwd=root, env={})
        finally:
            check.check_npm = real  # type: ignore[assignment]
    assert seen == ["update", "ci", "install"]
    assert (
        wrapper.main(
            "npm", ["uninstall", "x"], deps=deps(FakeRunner(npm_answers())), cwd=root, env={}
        )
        == 3
    )


@pytest.mark.parametrize(
    "args", [["x", "--ignore-scripts", "false"], ["-D", "true", "x"], ["--save", "false"]]
)
def test_a_bare_true_or_false_after_a_flag_is_refused(args: list[str]) -> None:
    plan = npm.plan("install", args)
    assert plan.refusals and "flag's value" in plan.refusals[0].why


def test_node_preloads_never_reach_the_check(tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    run = FakeRunner(npm_answers())  # asserts no NODE_OPTIONS on every check run
    env = {"PATH": "/bin", "NODE_OPTIONS": "--require=./x.js", "node_path": "/x"}
    out = run_npm(root, "install", ["left-pad@1.3.0"], run, env=env)
    assert out.status == "pass"
    assert [c[0][1] for c in run.calls] == ["--version", "config", "install"]
    assert npm.check_env(env) == {"PATH": "/bin", "npm_config_update_notifier": "false"}


def _program(path: Path, first_line: str = "#!/bin/sh\n") -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(first_line)
    path.chmod(0o755)
    return str(path)


@pytest.mark.parametrize(
    "where_",
    [
        "demo/bin/npm",
        "demo/node_modules/.bin/npm",
        "elsewhere/node_modules/.bin/npm",
        "repo/tools/npm",
    ],
)
def test_an_npm_from_the_project_or_node_modules_is_never_started(
    where_: str, tmp_path: Path
) -> None:
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    root = project(tmp_path / ("repo/demo" if where_.startswith("repo") else "demo"))
    exe = _program(tmp_path / where_)
    run = FakeRunner(npm_answers())
    work = tmp_path / "work"
    work.mkdir()
    out = check.check_npm(
        exe, "install", [], cwd=root, env={"PATH": str(Path(exe).parent)}, command="npm install",
        deps=deps(run), workdir=work,
    )  # fmt: skip
    assert out.status == "cant_check" and not run.calls
    assert any("doesn't start this npm" in r for r in out.reasons)


def test_the_node_npm_starts_with_is_checked_too(tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    node = _program(tmp_path / "demo" / "node_modules" / ".bin" / "node")
    exe = _program(tmp_path / "bin" / "npm", "#!/usr/bin/env node\n")
    run = FakeRunner(npm_answers())
    work = tmp_path / "work"
    work.mkdir()
    path = f"{Path(node).parent}:{Path(exe).parent}"
    out = check.check_npm(
        exe, "install", [], cwd=root, env={"PATH": path}, command="npm install",
        deps=deps(run), workdir=work,
    )  # fmt: skip
    assert out.status == "cant_check" and not run.calls
    assert any("the node npm starts with" in r for r in out.reasons)


def test_corepacks_shim_is_never_started(tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    shim = _program(tmp_path / "lib" / "corepack" / "dist" / "npm.js")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "npm").symlink_to(shim)
    run = FakeRunner(npm_answers())
    work = tmp_path / "work"
    work.mkdir()
    out = check.check_npm(
        str(tmp_path / "bin" / "npm"), "install", [], cwd=root, env={"PATH": str(tmp_path / "bin")},
        command="npm install", deps=deps(run), workdir=work,
    )  # fmt: skip
    assert out.status == "cant_check" and not run.calls
    assert any("corepack" in r for r in out.reasons)


@pytest.mark.parametrize("version", ["8.19.4", "9.9.4", "12.0.0", "garbage"])
def test_untested_npm_versions_are_cant_check(version: str, tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    run = FakeRunner(npm_answers(version=version))
    out = run_npm(root, "install", [], run)
    assert out.status == "cant_check" and [c[0][1] for c in run.calls] == ["--version"]
    assert any("checks with npm 10 and 11" in r for r in out.reasons)


# --- re-review findings (2026-10-31) ----------------------------------------

SHA = "0123456789abcdef0123456789abcdef01234567"
GIT = f"github:o/r#{SHA}"
# Each ran the git dependency's prepare script on npm 10.9.4 (WORKING_RECORD.md),
# and so did their aliases (home, issues, author, info).
FETCHING = ["docs", "bugs", "repo", "fund", "owner ls", "publish --dry-run", "view", "home",
            "issues", "author ls", "info"]  # fmt: skip


@pytest.mark.parametrize("command", FETCHING)
@pytest.mark.parametrize("form", ["npm {c} {spec}", "npm -- {c} {spec}", "npm {c} -- {spec}"])
def test_a_quiet_command_given_a_spec_npm_would_fetch_asks(
    command: str, form: str, tmp_path: Path
) -> None:
    text = form.format(c=command, spec=GIT)
    found = shellwords.find_commands(text, cwd=str(tmp_path), env={"PATH": "/nonexistent"})
    assert len(found) == 1 and isinstance(found[0], shellwords.Unsupported)
    assert found[0].ask and GIT in found[0].why and "isn't a registry package" in found[0].why


@pytest.mark.parametrize("command", FETCHING)
@pytest.mark.parametrize(
    "form", ["npm {c}", "npm {c} left-pad", "npm -- {c} left-pad@1.3.0", "npm {c} -- @scope/x@^2"]
)
def test_a_quiet_command_given_registry_specs_gets_no_answer(
    command: str, form: str, tmp_path: Path
) -> None:
    assert _shape(form.format(c=command), str(tmp_path)) == []


@pytest.mark.parametrize(
    "command",
    [
        "npm explain ./vendor/x",
        "npm ls git+https://example.com/x.git",
        "npm star github:o/r",
        "npm unpublish ./x.tgz",
        "npm dist-tag add github:o/r beta",
        "npm deprecate https://example.com/x.tgz old",
        "npm access get status ./x",
        "npm docs --registry https://r.example/ x",  # a value counts: asks rather than guess
    ],
)
def test_every_command_that_takes_specs_asks_for_one_npm_would_fetch(
    command: str, tmp_path: Path
) -> None:
    assert _shape(command, str(tmp_path)) == [f"unsupported npm {command.split()[1]}"]


@pytest.mark.parametrize(
    "command",
    [
        "npm run test:unit",
        "npm test -- src/x.test.js",
        "npm run build -- --out ./dist",
        "npm start ./server.js",
        "npm config set registry https://r.example/",
        "npm help install",
        "npm search github:o/r",
        "npm version patch",
    ],
)
def test_commands_whose_arguments_are_never_specs_stay_quiet(command: str, tmp_path: Path) -> None:
    assert _shape(command, str(tmp_path)) == []


def test_quiet_command_tests_every_word_for_spec_commands() -> None:
    assert npm.quiet_command({"docs"}, ["left-pad", "@scope/x@1.0.0"])
    assert not npm.quiet_command({"docs"}, ["left-pad", GIT])
    assert npm.quiet_command({"run", "run-script"}, ["./anything", "github:o/r"])
    assert not npm.quiet_command({"run", "docs"}, ["github:o/r"])
    assert npm.fetched_spec({"owner"}, ["ls", GIT]) == GIT
    assert npm.fetched_spec({"run"}, [GIT]) is None


@pytest.fixture
def no_own_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    """Garnet's own process started with no loader setting."""
    for name in [k for k in os.environ if runner.loader_preload(k)]:
        monkeypatch.delenv(name)


@pytest.mark.parametrize(
    "name",
    [
        "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH", "DYLD_FALLBACK_LIBRARY_PATH", "DYLD_PRINT_LIBRARIES",
    ],
)  # fmt: skip
def test_loader_preload_names(name: str) -> None:
    assert runner.loader_preload(name)


@pytest.mark.parametrize("name", ["PATH", "LDFLAGS", "LD_DEBUG", "LD_BIND_NOW", "NODE_OPTIONS"])
def test_other_names_are_not_loader_preloads(name: str) -> None:
    assert not runner.loader_preload(name)


@pytest.mark.usefixtures("no_own_loader")
def test_loader_preloads_never_reach_the_check(tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    run = FakeRunner(npm_answers())  # asserts no loader preload on every check run
    loader = {
        "LD_PRELOAD": "./pre.so",
        "LD_AUDIT": "./a.so",
        "LD_LIBRARY_PATH": "./lib",
        "DYLD_INSERT_LIBRARIES": "./pre.dylib",
        "DYLD_FRAMEWORK_PATH": "./fw",
    }
    env = {"PATH": "/bin", **loader}
    out = run_npm(root, "install", ["left-pad@1.3.0"], run, env=env)
    assert out.status == "pass"
    assert [c[0][1] for c in run.calls] == ["--version", "config", "install"]
    assert npm.check_env(env) == {"PATH": "/bin", "npm_config_update_notifier": "false"}
    assert not set(loader) & set(npm.resolve_env(env, tmp_path))
    assert out.handoff is not None and out.handoff.env == env  # the hand-off keeps them


def test_the_check_keeps_the_loader_settings_garnet_started_with(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Already loaded into Garnet, so they still apply (runner.loader_env); a
    # value the command changes is replaced by Garnet's own.
    monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/lib")
    env = {"PATH": "/bin", "LD_LIBRARY_PATH": "./lib", "LD_PRELOAD": "./pre.so"}
    assert npm.check_env(env) == {
        "PATH": "/bin",
        "LD_LIBRARY_PATH": "/opt/lib",
        "npm_config_update_notifier": "false",
    }


@pytest.mark.parametrize("agent", AGENTS)
@pytest.mark.parametrize(
    "command",
    [
        "LD_PRELOAD=./pre.so npm i left-pad@1.3.0",
        "env DYLD_INSERT_LIBRARIES=./pre.dylib npm install left-pad@1.3.0",
        "export LD_AUDIT=./a.so; npm ci",
        "sudo LD_LIBRARY_PATH=./lib npm update",
    ],
)
def test_hook_asks_when_the_command_sets_a_loader_preload(
    agent: str,
    command: str,
    where: dict[str, str],  # noqa: F811
) -> None:
    root = project(Path(where["cwd"]) / "demo")
    run = FakeRunner(npm_answers())
    inner = spec(answer(agent, event(command, str(root)), where, deps=deps(run)))
    assert inner["permissionDecision"] == ("ask" if agent == "claude-code" else "deny")
    name = command.split("=")[0].split()[-1]
    reason = inner["permissionDecisionReason"]
    assert f"sets {name}" in reason and "loader" in reason
    assert not run.calls  # npm never started before approval


@pytest.mark.parametrize("agent", AGENTS)
def test_hook_asks_when_a_loader_preload_value_expands(
    agent: str,
    where: dict[str, str],  # noqa: F811
) -> None:
    root = project(Path(where["cwd"]) / "demo")
    run = FakeRunner(npm_answers())
    inner = spec(answer(agent, event("LD_PRELOAD=$X npm i x", str(root)), where, deps=deps(run)))
    assert inner["permissionDecision"] == ("ask" if agent == "claude-code" else "deny")
    assert "LD_PRELOAD" in inner["permissionDecisionReason"] and not run.calls


@pytest.mark.usefixtures("no_own_loader")
def test_hook_checks_without_a_loader_preload_the_command_doesnt_set(
    where: dict[str, str],  # noqa: F811
) -> None:
    # Already in the agent's environment, not set by the command: checked as
    # usual, and npm runs with the loader settings of Garnet's own process
    # only (npm_answers asserts that on each run).
    root = project(Path(where["cwd"]) / "demo")
    npm_exe = str(Path(where["PATH"]) / "npm")

    def answers(argv: list[str], cwd: Path, env: dict[str, str]) -> Ran:
        assert argv[0] == npm_exe
        return npm_answers()([NPM, *argv[1:]], cwd, env)

    run = FakeRunner(answers)
    stdout, stderr = io.StringIO(), io.StringIO()
    env = {"PATH": where["PATH"], "HOME": where["HOME"], "LD_LIBRARY_PATH": "/opt/lib"}
    hooks.handle(
        "claude-code",
        event("npm install left-pad@1.3.0", str(root)),
        stdout=stdout,
        stderr=stderr,
        env=env,
        deps=deps(run),
        exit_now=lambda code: None,
    )
    inner = spec(json.loads(stdout.getvalue()))
    assert "permissionDecision" not in inner
    assert "left-pad 1.2.0 -> 1.3.0" in inner["additionalContext"]
    assert [c[0][1] for c in run.calls] == ["--version", "config", "install"]


def _link(path: Path, target: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target)
    return str(path)


def _check_with(exe: str, root: Path, tmp_path: Path, run: FakeRunner) -> Outcome:
    work = tmp_path / f"work-{len(list(tmp_path.glob('work-*')))}"
    work.mkdir()
    return check.check_npm(
        exe, "install", ["left-pad@1.3.0"], cwd=root, env={"PATH": str(Path(exe).parent)},
        command="npm install left-pad@1.3.0", deps=deps(run), workdir=work,
    )  # fmt: skip


def test_an_npm_linked_into_another_projects_node_modules_is_never_started(
    tmp_path: Path,
) -> None:
    root = project(tmp_path / "demo")
    cli = Path(_program(tmp_path / "other" / "node_modules" / "npm" / "bin" / "npm-cli.js"))
    exe = _link(tmp_path / "home" / "bin" / "npm", cli)
    run = FakeRunner(npm_answers())
    out = _check_with(exe, root, tmp_path, run)
    assert out.status == "cant_check" and not run.calls
    assert any("a link to" in r and "in a node_modules folder" in r for r in out.reasons)


def test_an_npm_linked_into_another_prefixs_lib_is_never_started(tmp_path: Path) -> None:
    # The installers' layout, but the link leaves its own prefix.
    root = project(tmp_path / "demo")
    cli = Path(_program(tmp_path / "other" / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js"))
    exe = _link(tmp_path / "prefix" / "bin" / "npm", cli)
    run = FakeRunner(npm_answers())
    out = _check_with(exe, root, tmp_path, run)
    assert out.status == "cant_check" and not run.calls


def test_the_npm_node_installs_in_its_prefix_is_started(tmp_path: Path) -> None:
    # <prefix>/bin/npm -> ../lib/node_modules/npm/bin/npm-cli.js: node's
    # tarballs, nvm and Homebrew install npm this way.
    root = project(tmp_path / "demo")
    _program(tmp_path / "prefix" / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js")
    exe = _link(tmp_path / "prefix" / "bin" / "npm", Path("../lib/node_modules/npm/bin/npm-cli.js"))

    def answers(argv: list[str], cwd: Path, env: dict[str, str]) -> Ran:
        assert argv[0] == exe
        return npm_answers()([NPM, *argv[1:]], cwd, env)

    run = FakeRunner(answers)
    out = _check_with(exe, root, tmp_path, run)
    assert out.status == "pass", out.reasons


def test_a_node_linked_into_node_modules_is_never_started(tmp_path: Path) -> None:
    root = project(tmp_path / "demo")
    real_node = Path(_program(tmp_path / "other" / "node_modules" / "node" / "bin" / "node"))
    node = _link(tmp_path / "bin" / "node", real_node)
    exe = _program(tmp_path / "bin" / "npm", "#!/usr/bin/env node\n")
    run = FakeRunner(npm_answers())
    work = tmp_path / "work"
    work.mkdir()
    out = check.check_npm(
        exe, "install", [], cwd=root, env={"PATH": str(Path(node).parent)},
        command="npm install", deps=deps(run), workdir=work,
    )  # fmt: skip
    assert out.status == "cant_check" and not run.calls
    assert any("the node npm starts with" in r and "a link to" in r for r in out.reasons)


@pytest.mark.parametrize(
    "command",
    [
        "node ./node_modules/npm/index.js i x",
        "node node_modules/npm i x",
        "node /opt/x/lib/node_modules/npm/lib/cli.js install x",
        "nodejs ./node_modules/npx/bin/x.js npm i x",
        "node22 ./vendor/npm-cli.js i x",
        "node ./tools/npx-cli.mjs npm i x",
        "node --no-warnings ./node_modules/npm/bin/npm-cli.js ci",
    ],
)
def test_node_running_npms_own_files_is_cant_tell(command: str, tmp_path: Path) -> None:
    assert gate.has_pm_word(command)  # the hook's fast path passes it on
    assert _shape(command, str(tmp_path)) == ["unclear"]


def test_node_running_npms_files_from_an_argument_list_is_cant_tell(tmp_path: Path) -> None:
    found = shellwords.find_commands(
        ["node", "C:\\p\\node_modules\\npm\\index.js", "i", "x"],
        cwd=str(tmp_path),
        env={"PATH": "/nonexistent"},
    )
    assert len(found) == 1 and isinstance(found[0], shellwords.Unclear)


@pytest.mark.parametrize(
    "command",
    [
        "node build.js",
        "node ./node_modules/vite/bin/vite.js build",
        "node ./node_modules/npm-run-all/bin/run-p/index.js a b",
        "node ./scripts/npmrc-check.js",
    ],
)
def test_node_running_other_files_gets_no_answer(command: str, tmp_path: Path) -> None:
    assert _shape(command, str(tmp_path)) == []


@pytest.mark.parametrize("agent", AGENTS)
def test_hook_asks_for_node_running_npms_files(
    agent: str,
    where: dict[str, str],  # noqa: F811
) -> None:
    root = project(Path(where["cwd"]) / "demo")
    run = FakeRunner(npm_answers())
    command = "node ./node_modules/npm/index.js i left-pad@1.3.0"
    inner = spec(answer(agent, event(command, str(root)), where, deps=deps(run)))
    assert inner["permissionDecision"] == ("ask" if agent == "claude-code" else "deny")
    assert "can't tell which npm this runs" in inner["permissionDecisionReason"]
    assert not run.calls
