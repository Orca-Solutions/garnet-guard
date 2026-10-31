"""The resolve step really runs no build code: real pip and uv against a local
folder of "canary" source distributions, offline.

Each canary's ``build-backend`` names a module that doesn't exist, with no
build requirements, so any attempt to build one fails with an import error
naming ``garnet_canary_backend_missing``. Each test first shows that the
plain command does try the build, then that Garnet's resolve step doesn't.
Skipped where uv, or a venv with pip, isn't available.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import venv
from datetime import date
from pathlib import Path

import pytest

from garnet_guard.install import check
from garnet_guard.install.runner import Ran
from tests.builders import sdist
from tests.test_install_check import deps, evaluator, releases

BACKEND = "garnet_canary_backend_missing"
UV = shutil.which("uv")


def canary_index(root: Path) -> Path:
    """A find-links folder with one sdist whose dependencies are dynamic."""
    index = root / "index"
    index.mkdir()
    pyproject = (
        f'[build-system]\nrequires = []\nbuild-backend = "{BACKEND}"\n\n'
        '[project]\nname = "canary-dynamic"\nversion = "1.0.0"\ndynamic = ["dependencies"]\n'
    )
    pkg_info = "Metadata-Version: 2.1\nName: canary-dynamic\nVersion: 1.0.0\n"
    data = sdist("canary_dynamic-1.0.0", {"pyproject.toml": pyproject, "PKG-INFO": pkg_info})
    (index / "canary_dynamic-1.0.0.tar.gz").write_bytes(data)
    return index


def _env(tmp_path: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("UV_", "PIP_"))}
    env.update(HOME=str(tmp_path), UV_CACHE_DIR=str(tmp_path / "uv-cache"), PIP_NO_CACHE_DIR="1")
    env["PIP_CONFIG_FILE"] = os.devnull
    env["UV_NO_CONFIG"] = "1"
    return env


SOURCE_ONLY = releases(**{"canary-dynamic": [("1.0.0", "sdist")]})


@pytest.mark.skipif(UV is None, reason="uv isn't installed")
def test_uv_resolve_step_never_builds(tmp_path: Path) -> None:
    assert UV is not None
    index = canary_index(tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n'
        'dependencies = ["canary-dynamic"]\n\n[tool.uv]\npackage = false\nno-build = false\n'
    )
    env = _env(tmp_path)
    flags = ["--offline", "--no-index", "--find-links", str(index)]

    plain = tmp_path / "plain"
    shutil.copytree(project, plain)
    tried = subprocess.run([UV, "lock", *flags], cwd=plain, env=env, capture_output=True, text=True)
    assert tried.returncode != 0 and BACKEND in tried.stderr  # the canary works

    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    out = check.check_uv(
        UV,
        "lock",
        flags,
        cwd=project,
        env=env,
        command="uv lock",
        deps=deps(check.run_program, registry=SOURCE_ONLY, evaluate=evaluator()),  # type: ignore[arg-type]
        workdir=work,
    )
    assert out.status == "cant_check"
    (b,) = out.blockers
    assert (b.needs, b.why) == ("canary-dynamic", "is published only as source")
    assert not (project / "uv.lock").exists()


def _pip_venv(root: Path) -> Path:
    try:
        venv.create(root / "venv", with_pip=True)
    except Exception as err:  # noqa: BLE001
        pytest.skip(f"can't create a venv with pip here: {err}")
    python = root / "venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    return python


def test_pip_resolve_step_never_builds(tmp_path: Path) -> None:
    index = canary_index(tmp_path)
    python = _pip_venv(tmp_path)
    env = _env(tmp_path)
    flags = ["--no-index", "--find-links", str(index)]

    tried = subprocess.run(
        [str(python), "-I", "-m", "pip", "install", "--dry-run", *flags, "canary-dynamic"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert tried.returncode != 0 and BACKEND in tried.stdout + tried.stderr  # the canary works

    (tmp_path / "reqs.txt").write_text("--no-binary :all:\ncanary-dynamic\n")
    for args in (["install", *flags, "canary-dynamic"], ["install", *flags, "-r", "reqs.txt"]):
        work = tmp_path / f"work-{len(args)}"
        work.mkdir(mode=0o700)
        out = check.check_pip(
            str(python),
            args,
            cwd=tmp_path,
            env=env,
            command="pip " + " ".join(args),
            deps=deps(check.run_program, registry=SOURCE_ONLY, evaluate=evaluator()),  # type: ignore[arg-type]
            workdir=work,
        )
        assert out.status == "cant_check", args
        text = " ".join(check.reason_lines(out))
        assert BACKEND not in text
        if "-r" in args:  # refused before pip runs
            assert "reqs.txt line 1: --no-binary :all:" in text
        else:
            assert out.blockers[0].why == "is published only as source"


def test_pip_local_archive_spellings_are_refused_before_pip_runs(tmp_path: Path) -> None:
    # pip takes "; markers" and "[extras]" off before it asks whether a word
    # is an archive file, and builds a named local sdist even with
    # --only-binary :all:. Garnet reads the words the same way.
    index = canary_index(tmp_path)
    python = _pip_venv(tmp_path)
    env = _env(tmp_path)
    archive = "canary_dynamic-1.0.0.tar.gz"
    shutil.copy(index / archive, tmp_path / archive)
    spellings = [f"{archive}[x]", f'{archive};python_version>"0"', f"{archive} ; extra == 'a'"]
    tried = subprocess.run(
        [str(python), "-I", "-m", "pip", "install", "--dry-run", "--no-index"]
        + ["--only-binary", ":all:", spellings[0]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert tried.returncode != 0 and BACKEND in tried.stdout + tried.stderr  # the canary works

    nothing = check.Deps(today=date(2026, 10, 30), run=_never_run)
    for n, spec in enumerate(spellings):
        (tmp_path / "reqs.txt").write_text(spec + "\n")
        for args in (["install", "--no-index", spec], ["install", "--no-index", "-r", "reqs.txt"]):
            work = tmp_path / f"work-{n}-{len(args)}"
            work.mkdir(mode=0o700)
            out = check.check_pip(
                str(python), args, cwd=tmp_path, env=env, command="pip", deps=nothing, workdir=work
            )
            assert out.status == "cant_check", args
            assert "it installs a local file or folder" in " ".join(check.reason_lines(out))


def _never_run(argv: object, **kw: object) -> Ran:
    raise AssertionError(f"Garnet ran {argv} for a command it refuses")


@pytest.mark.skipif(UV is None, reason="uv isn't installed")
@pytest.mark.skipif(
    not (sys.platform == "linux" and platform.machine() in ("x86_64", "aarch64")),
    reason="the fake Python download is built for Linux",
)
def test_uv_resolve_step_never_downloads_a_python(tmp_path: Path) -> None:
    # A project's [tool.uv] python-downloads-json-url names where uv gets a
    # Python from; uv runs what it downloads to query it.
    assert UV is not None
    marker = tmp_path / "FAKE_PYTHON_RAN"
    fake = tmp_path / "fakepy"
    (fake / "python" / "bin").mkdir(parents=True)
    (fake / "python" / "lib" / "python3.10").mkdir(parents=True)
    sysconfig = f"_sysconfigdata__linux_{platform.machine()}-linux-gnu.py"
    (fake / "python" / "lib" / "python3.10" / sysconfig).write_text(
        "# system configuration generated and used by the sysconfig module\nbuild_time_vars = {}\n"
    )
    for name in ("python3.10", "python3", "python"):
        script = fake / "python" / "bin" / name
        script.write_text(f'#!/bin/sh\ntouch "{marker}"\nexit 1\n')
        script.chmod(0o755)
    archive = tmp_path / "fakepy.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(fake / "python", arcname="python")
    arch = platform.machine()
    key = f"cpython-3.10.99-linux-{arch}-gnu"
    downloads = {
        key: {
            "name": "cpython",
            "arch": {"family": arch, "variant": None},
            "os": "linux",
            "libc": "gnu",
            "major": 3,
            "minor": 10,
            "patch": 99,
            "prerelease": "",
            "url": archive.as_uri(),
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "variant": None,
            "build": "1",
        }
    }
    (tmp_path / "downloads.json").write_text(json.dumps(downloads))
    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = "==3.10.99"\n'
        'dependencies = []\n\n[tool.uv]\npackage = false\npython-preference = "only-managed"\n'
        f'python-downloads-json-url = "{tmp_path / "downloads.json"}"\n'
    )
    env = _env(tmp_path)
    del env["UV_NO_CONFIG"]  # the project's [tool.uv] is read, as in a real run
    env["UV_PYTHON_INSTALL_DIR"] = str(tmp_path / "pythons")
    env["UV_PYTHON_DOWNLOADS"] = "automatic"

    plain = tmp_path / "plain"
    shutil.copytree(project, plain)
    # --no-index, not --offline: offline mode would stop the download too.
    subprocess.run([UV, "lock", "--no-index"], cwd=plain, env=env, capture_output=True)
    assert marker.exists()  # the canary works: plain uv ran the downloaded "Python"
    marker.unlink()
    shutil.rmtree(tmp_path / "pythons", ignore_errors=True)

    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    out = check.check_uv(
        UV,
        "lock",
        ["--no-index"],
        cwd=project,
        env=env,
        command="uv lock",
        deps=deps(check.run_program, registry=SOURCE_ONLY, evaluate=evaluator()),  # type: ignore[arg-type]
        workdir=work,
    )
    assert out.status == "cant_check"
    assert not marker.exists() and not (tmp_path / "pythons").exists()


# --- npm ----------------------------------------------------------------------

NPM = shutil.which("npm")


def _marker_package(
    folder: Path,
    name: str,
    markers: Path,
    events: tuple[str, ...] = ("preinstall", "install", "postinstall", "prepare", "prepack"),
    **extra: object,
) -> None:
    """A package.json whose every lifecycle script writes a marker file."""
    folder.mkdir(parents=True, exist_ok=True)
    scripts = {
        e: f"node -e \"require('fs').writeFileSync('{markers / f'{name}-{e}'}', '')\""
        for e in events
    }
    doc = {"name": name, "version": "1.0.0", "scripts": scripts, **extra}
    (folder / "package.json").write_text(json.dumps(doc))


def _npm_env(tmp_path: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.lower().startswith("npm_config_")}
    env.update(
        HOME=str(tmp_path),
        npm_config_cache=str(tmp_path / "npm-cache"),
        npm_config_userconfig=str(tmp_path / "npmrc"),
        npm_config_offline="true",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=str(tmp_path / "gitconfig"),
    )
    return env


def _git_repo(folder: Path) -> str:
    git = ["git", "-c", "user.email=c@example.invalid", "-c", "user.name=c", "-C", str(folder)]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "c"], check=True)
    sha = subprocess.run([*git, "rev-parse", "HEAD"], check=True, capture_output=True)
    return sha.stdout.decode().strip()


@pytest.mark.skipif(NPM is None, reason="npm isn't installed")
def test_npm_resolve_step_runs_no_scripts(tmp_path: Path) -> None:
    """The project's own lifecycle scripts don't run, the project isn't
    written, and the resolve really writes a lockfile (offline: no deps)."""
    assert NPM is not None
    markers = tmp_path / "markers"
    markers.mkdir()
    project = tmp_path / "demo"
    _marker_package(project, "demo", markers)
    before = (project / "package.json").read_bytes()
    work = tmp_path / "work"
    work.mkdir()
    out = check.check_npm(
        NPM,
        "install",
        [],
        cwd=project,
        env=_npm_env(tmp_path),
        command="npm install",
        deps=deps(check.run_program, evaluate=evaluator()),  # type: ignore[arg-type]
        workdir=work,
    )
    assert out.status == "pass", out.reasons
    assert not list(markers.iterdir())
    assert (project / "package.json").read_bytes() == before
    assert not (project / "package-lock.json").exists()
    assert out.handoff is not None and out.handoff.copy is not None
    assert out.handoff.copy.head("package-lock.json") is not None


@pytest.mark.skipif(NPM is None, reason="npm isn't installed")
def test_npm_resolve_env_never_runs_git_or_a_git_dependencys_scripts(tmp_path: Path) -> None:
    """A git dependency (refused before npm runs, so npm is called directly
    here) fails to resolve under Garnet's environment: npm can't start git."""
    assert NPM is not None
    markers = tmp_path / "markers"
    markers.mkdir()
    _marker_package(tmp_path / "gitdep", "gitdep", markers)
    _git_repo(tmp_path / "gitdep")
    project = tmp_path / "demo"
    project.mkdir()
    spec = f"git+file://{tmp_path / 'gitdep'}"
    (project / "package.json").write_text(json.dumps({"dependencies": {"gitdep": spec}}))
    work = tmp_path / "work"
    work.mkdir()
    env = check.npm.resolve_env(_npm_env(tmp_path), work)
    done = subprocess.run(
        [NPM, "install", *check.npm.RESOLVE_TAIL],
        cwd=project,
        env=env,
        capture_output=True,
        check=False,
    )
    assert done.returncode != 0
    assert not list(markers.iterdir()) and not (project / "package-lock.json").exists()


@pytest.mark.network
@pytest.mark.skipif(NPM is None, reason="npm isn't installed")
def test_npm_hosted_git_dependency_prepare_is_stopped(tmp_path: Path) -> None:
    """npm 10 packs a git-host dependency pinned to a commit to read its
    manifest, which runs its prepare script even with --ignore-scripts.
    git's url.insteadOf points the host at a local repository. Plain npm runs
    the script when it falls back to cloning (this needs codeload.github.com
    to answer with an HTTP error); under Garnet's environment it never does."""
    assert NPM is not None
    markers = tmp_path / "markers"
    markers.mkdir()
    repo = tmp_path / "gitdep"
    _marker_package(repo, "gitdep", markers)
    sha = _git_repo(repo)
    (tmp_path / "gitconfig").write_text(
        f'[url "file://{repo}"]\n\tinsteadOf = https://github.com/garnet-canary/gitdep.git\n'
        "\tinsteadOf = git@github.com:garnet-canary/gitdep.git\n"
        "\tinsteadOf = ssh://git@github.com/garnet-canary/gitdep.git\n"
    )
    spec = f"github:garnet-canary/gitdep#{sha}"
    work = tmp_path / "work"
    work.mkdir()
    env = _npm_env(tmp_path)
    env.pop("npm_config_offline")
    for n, run_env in enumerate((env, check.npm.resolve_env(env, work))):
        project = tmp_path / f"demo-{n}"
        project.mkdir()
        (project / "package.json").write_text(json.dumps({"dependencies": {"gitdep": spec}}))
        subprocess.run(
            [NPM, "install", *check.npm.RESOLVE_TAIL],
            cwd=project,
            env=run_env,
            capture_output=True,
            check=False,
            timeout=240,
        )
        ran = list(markers.iterdir())
        if n == 0 and not ran:
            pytest.skip("this npm (or network) doesn't reach the prepare step")
        if n == 1:
            assert not ran
        for path in ran:
            path.unlink()


@pytest.mark.skipif(NPM is None, reason="npm isn't installed")
def test_npm_rebuild_by_path_runs_only_that_folder(tmp_path: Path) -> None:
    """npm rebuild foo@1.0.0 also runs an alias installed as foo deeper in the
    tree (here bar's foo, which is the package evil); npm rebuild
    ./node_modules/foo, what the hand-off passes, runs only that folder.
    Offline: the packages are local tarballs."""
    assert NPM is not None
    markers = tmp_path / "markers"
    markers.mkdir()
    env = _npm_env(tmp_path)
    src = tmp_path / "src"
    for name in ("foo", "evil"):
        # Install scripts only: npm 10 runs prepare while packing, --ignore-scripts or not.
        _marker_package(src / name, name, markers, ("preinstall", "install", "postinstall"))
        subprocess.run(
            [NPM, "pack", "--silent", "--ignore-scripts"],
            cwd=src / name,
            env=env,
            check=True,
            capture_output=True,
        )
    bar = src / "bar"
    bar.mkdir()
    evil = f"file:{src / 'evil' / 'evil-1.0.0.tgz'}"
    (bar / "package.json").write_text(
        json.dumps({"name": "bar", "version": "1.0.0", "dependencies": {"foo": evil}})
    )
    subprocess.run(
        [NPM, "pack", "--silent", "--ignore-scripts"],
        cwd=bar,
        env=env,
        check=True,
        capture_output=True,
    )
    project = tmp_path / "demo"
    project.mkdir()
    deps_ = {"foo": f"file:{src / 'foo' / 'foo-1.0.0.tgz'}", "bar": f"file:{bar / 'bar-1.0.0.tgz'}"}
    (project / "package.json").write_text(
        json.dumps({"name": "demo", "version": "1.0.0", "dependencies": deps_})
    )
    subprocess.run(
        [NPM, "install", "--ignore-scripts", "--no-audit", "--no-fund"],
        cwd=project,
        env=env,
        check=True,
        capture_output=True,
    )
    assert (project / "node_modules" / "bar" / "node_modules" / "foo").is_dir()
    assert not list(markers.iterdir())

    def rebuild(spec: str) -> set[str]:
        subprocess.run(
            [NPM, "rebuild", spec], cwd=project, env=env, check=True, capture_output=True
        )
        ran = {p.name.split("-")[0] for p in markers.iterdir()}
        for p in markers.iterdir():
            p.unlink()
        return ran

    assert rebuild("foo@1.0.0") == {"foo", "evil"}  # the canary: a name matches both
    assert rebuild("./node_modules/foo") == {"foo"}
