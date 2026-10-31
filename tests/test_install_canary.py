"""The resolve step really runs no build code: real pip and uv against a local
folder of "canary" source distributions, offline.

Each canary's ``build-backend`` names a module that doesn't exist, with no
build requirements, so any attempt to build one fails with an import error
naming ``garnet_canary_backend_missing``. Each test first shows that the
plain command does try the build, then that Garnet's resolve step doesn't.
Skipped where uv, or a venv with pip, isn't available.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

import pytest

from garnet_guard.install import check
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
