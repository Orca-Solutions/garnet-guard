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
