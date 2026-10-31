"""Reading install commands without running them: the shell parser, pip's and
uv's arguments, and the requirement files they name. No network, no programs."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import cast

import pytest
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from garnet_guard.ecosystems import pypi
from garnet_guard.ecosystems.github import TagLookup
from garnet_guard.ecosystems.gittree import TreeLookup
from garnet_guard.install import pip, shellwords, uv
from garnet_guard.install.check import newest_release
from garnet_guard.install.shellwords import PipCommand, Unclear, Unsupported, UvCommand
from garnet_guard.models import Limits
from garnet_guard.net import Http, NetError, Response


@pytest.fixture
def tools(tmp_path: Path) -> dict[str, str]:
    """A PATH with stand-in pip, uv and npm programs (never run) and a venv."""
    bin_dir = tmp_path / "bin"
    venv = tmp_path / "venv" / "bin"
    for folder in (bin_dir, venv):
        folder.mkdir(parents=True)
        (folder / "python").write_text("")
    (bin_dir / "pip").write_text(f"#!{bin_dir / 'python'}\n")
    (venv / "pip").write_text(f"#!{venv / 'python'}\n")
    for name in ("uv", "npm", "pnpm", "yarn", "uvx", "poetry", "pip3"):
        (bin_dir / name).write_text("#!/bin/sh\n")
    for path in (*bin_dir.iterdir(), *venv.iterdir()):
        path.chmod(0o755)
    (tmp_path / "proj").mkdir()
    return {"PATH": str(bin_dir), "HOME": str(tmp_path), "root": str(tmp_path)}


def _find(command: str | list[str], tools: dict[str, str]) -> list[shellwords.Found]:
    env = {"PATH": tools["PATH"], "HOME": tools["HOME"]}
    return shellwords.find_commands(command, cwd=tools["root"], env=env)


def _shape(found: list[shellwords.Found]) -> list[str]:
    out = []
    for f in found:
        if isinstance(f, PipCommand):
            out.append("pip " + " ".join(f.args))
        elif isinstance(f, UvCommand):
            out.append(f"uv {f.subcommand} " + " ".join(f.args))
        elif isinstance(f, Unsupported):
            out.append(f"unsupported {f.tool}")
        else:
            out.append("unclear")
    return [s.strip() for s in out]


# (command, what Garnet reads in it). "unclear" is can't tell; it never runs.
SHAPES = [
    ("ls -la", []),
    ("echo pip install x", []),
    ('echo "pip install x" && ls', []),
    ("pip install requests", ["pip install requests"]),
    ("pip3 install -U requests", ["pip install -U requests"]),
    ("python -m pip install 'requests>=2'", ["pip install requests>=2"]),
    ("python3 -I -m pip install x", ["pip install x"]),
    ("cd proj && pip install x", ["pip install x"]),
    ("FOO=1 pip install x; uv add y", ["pip install x", "uv add y"]),
    ("sudo -H pip install x", ["pip install x"]),
    ("env PIP_NO_INPUT=1 pip install x", ["pip install x"]),
    ("time nice -n 5 pip install x", ["pip install x"]),
    ("command pip install x", ["pip install x"]),
    ("pip install x 2>&1 | tee log", ["pip install x"]),
    ("pip install x > /dev/null", ["pip install x"]),
    ("bash -c 'pip install x'", ["pip install x"]),
    ("bash -lc 'cd proj && uv lock'", ["uv lock"]),
    ("pip install x \\\n  y", ["pip install x y"]),
    ("pip install x\nuv sync", ["pip install x", "uv sync"]),
    ("uv --directory proj add requests", ["uv add --directory proj requests"]),
    ("uv remove requests", ["uv remove requests"]),
    ("pip list", []),
    ("pip download x", []),
    ("uv run pytest", []),
    ("uv pip install x", ["unsupported uv pip"]),
    ("uv tool install ruff", ["unsupported uv tool"]),
    ("uvx ruff", ["unsupported uvx"]),
    ("uv run --with requests python", ["unsupported uv run --with"]),
    ("npm install left-pad", ["unsupported npm install"]),
    ("npm i", ["unsupported npm i"]),
    ("npm test", []),
    ("pnpm add x", ["unsupported pnpm add"]),
    ("yarn", ["unsupported yarn"]),
    ("yarn add x", ["unsupported yarn add"]),
    ("poetry add x", ["unsupported poetry add"]),
    ("pip install $(cat reqs.txt)", ["unclear"]),
    ("pip install `cat reqs.txt`", ["unclear"]),
    ("pip install $PKG", ["unclear"]),
    ('pip install "${PKG}"', ["unclear"]),
    ("eval pip install x", ["unclear"]),
    ("xargs pip install < reqs.txt", ["unclear"]),
    ("cat <<EOF | sh\npip install x\nEOF", ["unclear"]),
    ("pip install 'x", ["unclear"]),
    ('bash -c "$CMD pip install x"', ["unclear"]),
    ("cd $DIR && pip install x", ["unclear"]),
    ("PIP_INDEX_URL=$U pip install x", ["unclear"]),
    ("bash -c 'bash -c \"pip install x\"'", ["unclear"]),
    ("uv run pip install x", ["unclear"]),
    ("source venv/bin/activate && pip install x", ["pip install x"]),
    ("source ./env.sh && pip install x", ["unclear"]),
    ("pip install '$HOME'", ["pip install $HOME"]),  # single quotes: literal
]


@pytest.mark.parametrize(("command", "expected"), SHAPES)
def test_command_shapes(command: str, expected: list[str], tools: dict[str, str]) -> None:
    assert _shape(_find(command, tools)) == expected


def test_codex_argv_lists(tools: dict[str, str]) -> None:
    assert _shape(_find(["bash", "-lc", "pip install x && uv add y"], tools)) == [
        "pip install x",
        "uv add y",
    ]
    # An argv list reaches the program as is: "$(x)" is a literal argument there.
    assert _shape(_find(["pip", "install", "$(x)"], tools)) == ["pip install $(x)"]


def test_programs_and_folders_are_located(tools: dict[str, str]) -> None:
    root = Path(tools["root"])
    (found,) = _find("cd proj && venv/bin/pip install x", tools)
    assert isinstance(found, PipCommand)
    assert found.python is None  # proj/venv doesn't exist
    (found,) = _find("venv/bin/pip install x", tools)
    assert isinstance(found, PipCommand)
    assert found.python == str(root / "venv" / "bin" / "python")
    assert found.cwd == tools["root"]
    (found,) = _find("source venv/bin/activate && pip install x", tools)
    assert isinstance(found, PipCommand) and found.python == str(root / "venv/bin/python")
    (found,) = _find("cd proj && uv add y", tools)
    assert isinstance(found, UvCommand)
    assert found.cwd == str(root / "proj") and found.uv == str(Path(tools["PATH"]) / "uv")
    (found,) = _find("PIP_NO_INPUT=1 pip install x", tools)
    assert isinstance(found, PipCommand) and found.env["PIP_NO_INPUT"] == "1"


def test_unclear_never_names_a_program_to_run(tools: dict[str, str]) -> None:
    for command, expected in SHAPES:
        if expected == ["unclear"]:
            (found,) = _find(command, tools)
            assert isinstance(found, Unclear) and found.why.startswith("Garnet Guard can't tell")


# --- pip --------------------------------------------------------------------


def _plan(args: list[str], cwd: Path, env: dict[str, str] | None = None) -> pip.Plan:
    return pip.plan(args, cwd=cwd, env=env or {})


def _refused(p: pip.Plan) -> list[str]:
    return [r.what for r in p.refusals]


def test_pip_plan_reads_requirements(tmp_path: Path) -> None:
    p = _plan(["install", "-U", "requests>=2", "Django==5.1", "--pre"], tmp_path)
    assert {k: str(v) for k, v in p.requested.items()} == {"requests": ">=2", "django": "==5.1"}
    assert p.pre and not p.refusals and p.compare_newest
    p = _plan(["--python", "/x/python", "install", "x"], tmp_path)
    assert p.python == "/x/python" and p.args == ["install", "x"]
    p = _plan(["install", "--python=/x/python", "x", "--", "y"], tmp_path)
    assert p.args == ["install", "x", "--", "y"] and p.insert_at == 2
    assert (
        _plan(["install", "x", "--uploaded-prior-to", "2026-01-01"], tmp_path).compare_newest
        is False
    )


@pytest.mark.parametrize(
    "args",
    [
        ["install", "-e", "."],
        ["install", "--editable=."],
        ["install", "."],
        ["install", "./pkg"],
        ["install", "dist/x-1.0-py3-none-any.whl"],
        ["install", "x-1.0.tar.gz"],
        ["install", "git+https://example.invalid/x.git"],
        ["install", "x @ https://example.invalid/x.whl"],
        ["install", "https://example.invalid/x.whl"],
        ["install", "--no-binary", ":all:", "x"],
        ["install", "--no-bin=x", "x"],  # pip takes unique prefixes
        ["install", "--target", "t", "x"],
        ["install", "--user", "x"],
        ["install", "--prefix=/p", "x"],
        ["install", "--platform", "win_amd64", "x"],
        ["install", "-r", "https://example.invalid/reqs.txt"],
        ["install", "-r", "missing.txt"],
    ],
)
def test_pip_plan_refuses(args: list[str], tmp_path: Path) -> None:
    assert _plan(args, tmp_path).refusals


def test_pip_requirement_files_are_read_recursively(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "reqs.txt").write_text(
        "# comment\nrequests>=2 \\\n  --hash=sha256:" + "0" * 64 + "\n-r sub/more.txt\n-c c.txt\n"
    )
    (tmp_path / "sub" / "more.txt").write_text("idna==3.20\n--pre\n")
    (tmp_path / "c.txt").write_text("urllib3<3\n")
    p = _plan(["install", "-r", "reqs.txt"], tmp_path)
    assert not p.refusals
    assert sorted(p.requested) == ["idna", "requests"]
    assert str(p.constraints["urllib3"]) == "<3" and p.pre


@pytest.mark.parametrize(
    "line",
    [
        "--no-binary :all:",
        "x --no-binary x",
        "--only-binary :none:",
        "--only-bin=:none:",
        "-e .",
        "-e git+https://example.invalid/x.git#egg=x",
        "./local",
        "x @ file:///tmp/x.whl",
        "${PKG}",
        "--unknown-option",
        "-r nested-missing.txt",
        "-r https://example.invalid/r.txt",
    ],
)
def test_pip_requirement_file_lines_that_are_refused(line: str, tmp_path: Path) -> None:
    (tmp_path / "reqs.txt").write_text(f"requests\n{line}\n")
    p = _plan(["install", "-r", "reqs.txt"], tmp_path)
    assert p.refusals, line
    named = ("reqs.txt line 2", "nested-missing.txt", "https://example.invalid/r.txt")
    assert all(r.what.startswith(named) for r in p.refusals)


def test_pip_requirement_file_limits(tmp_path: Path) -> None:
    (tmp_path / "big.txt").write_bytes(b"x\n" * (pip.MAX_REQUIREMENTS_BYTES // 2 + 1))
    assert _refused(_plan(["install", "-r", "big.txt"], tmp_path)) == ["big.txt"]
    (tmp_path / "bad.txt").write_bytes(b"\xff\xfe")
    assert _refused(_plan(["install", "-r", "bad.txt"], tmp_path)) == ["bad.txt"]
    (tmp_path / "loop.txt").write_text("-r loop.txt\nx\n")  # read once, no recursion error
    assert not _plan(["install", "-r", "loop.txt"], tmp_path).refusals


def test_pip_settings_that_add_files_or_move_the_install(tmp_path: Path) -> None:
    env = {
        "PIP_REQUIREMENT": "r.txt",
        "PIP_CONSTRAINT": "c.txt",
        "PIP_USER": "0",
        "PIP_TARGET": "t",
    }
    assert sorted(r.what for r in pip.env_refusals(env)) == [
        "PIP_CONSTRAINT",
        "PIP_REQUIREMENT",
        "PIP_TARGET",
    ]
    listed = (
        "global.index-url='https://user:secret@example.invalid/simple'\n"
        "install.requirement='/etc/r.txt'\ninstall.user='false'\nglobal.no-binary=':all:'\n"
    )
    refused = pip.config_refusals(listed)
    assert [r.what for r in refused] == ["pip configuration install.requirement"]
    assert "secret" not in repr(refused) and "/etc/r.txt" not in repr(refused)


FIXTURES = Path(__file__).parent / "fixtures" / "install"


def test_pip_report_and_inspect() -> None:
    (r,) = pip.parse_report((FIXTURES / "pip-report-requests-2.32.3.json").read_bytes())
    assert (r.name, r.version, r.from_pypi, r.wheel, r.requested) == (
        "requests",
        "2.32.3",
        True,
        True,
        True,
    )
    assert r.sha256 == "70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6"
    installed = pip.parse_inspect((FIXTURES / "pip-inspect.json").read_bytes())
    assert installed.pins["requests"] == "2.32.2" and installed.python_version == "3.13.17"
    with pytest.raises(pip.PipError):
        pip.parse_report(b'{"version": "2"}')
    with pytest.raises(pip.PipError):
        pip.parse_report(b"not json")


def test_pip_errors_name_what_needs_a_build() -> None:
    text = (FIXTURES / "pip-num2words-0.5.14.stderr").read_text()
    (u,) = pip.unresolvable(text)
    assert (u.requirement, u.wanted_by, u.versions) == ("docopt>=0.6.2", "num2words", "none")


def test_pins_text() -> None:
    assert pip.pins_text({"b": ("1", None), "a": ("2", "f" * 64)}) == (
        f"a==2 --hash=sha256:{'f' * 64}\nb==1\n"
    )


# --- uv ---------------------------------------------------------------------


def test_uv_plan(tmp_path: Path) -> None:
    p = uv.plan(
        "add",
        ["requests", "-qU", "--optional", "web", "-r", "r.txt", "--index-url", "https://x"],
        cwd=tmp_path,
        env={},
    )
    assert not p.refusals and p.upgrade and set(p.requested) == {"requests"}
    assert p.resolve == [
        "requests",
        "-q",
        "-U",
        "--optional",
        "web",
        "--requirements",
        str(tmp_path / "r.txt"),
        "--index-url",
        "https://x",
    ]
    assert p.handoff == ["-q", "--extra", "web", "--index-url", "https://x"]

    p = uv.plan(
        "sync", ["-U", "--extra", "a", "--locked", "--directory", "sub"], cwd=tmp_path, env={}
    )
    assert p.start == tmp_path / "sub" and p.locked and p.upgrade
    assert p.lock_args == ["-U"]
    assert p.handoff == ["--extra", "a", "--directory", "sub"]

    p = uv.plan("lock", ["--check"], cwd=tmp_path, env={"UV_PROJECT": "proj"})
    assert p.check_only and p.start == tmp_path / "proj"
    p = uv.plan("add", ["x"], cwd=tmp_path, env={"UV_NO_SYNC": "1"})
    assert p.no_sync


@pytest.mark.parametrize(
    ("sub", "args"),
    [
        ("add", ["--frozen", "x"]),
        ("add", ["git+https://example.invalid/x"]),
        ("add", ["./local"]),
        ("add", ["--editable", "x"]),
        ("add", ["x", "--branch", "main"]),
        ("add", ["--script", "s.py", "x"]),
        ("add", ["--package", "member", "x"]),
        ("sync", ["--build"]),
        ("lock", ["--no-binary"]),
        ("sync", ["--no-binary-package", "x"]),
        ("sync", ["--all-packages"]),
        ("lock", ["--some-new-option"]),
        ("add", ["-qr", "f"]),
        ("lock", ["requests"]),
    ],
)
def test_uv_plan_refuses(sub: str, args: list[str], tmp_path: Path) -> None:
    assert uv.plan(sub, args, cwd=tmp_path, env={}).refusals


def test_uv_resolve_env_turns_builds_off() -> None:
    env = uv.resolve_env({"UV_PROJECT": "p", "UV_FROZEN": "1", "UV_NO_SYNC": "1", "KEEP": "1"})
    assert env == {"KEEP": "1", "UV_NO_BUILD": "1"}


def _project(root: Path, extra: str = "") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n'
        f"dependencies = []\n{extra}"
    )
    return root


@pytest.mark.parametrize(
    "extra",
    [
        "[tool.uv.workspace]\nmembers = []\n",
        '[tool.uv.sources]\nlib = { path = "../lib" }\n',
        '[tool.uv.sources]\nlib = { git = "https://example.invalid/lib" }\n',
        '[tool.uv.sources]\nlib = [{ index = "x" }, { url = "https://example.invalid/l.whl" }]\n',
        '[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n'
        "[tool.garnet-test]\n",
    ],
)
def test_uv_project_refusals(extra: str, tmp_path: Path) -> None:
    if "build-system" in extra:  # only dynamic metadata in a packaged project is refused
        project = tmp_path / "p"
        project.mkdir()
        (project / "pyproject.toml").write_text(
            '[project]\nname = "demo"\ndynamic = ["version"]\n' + extra
        )
    else:
        project = _project(tmp_path / "p", extra)
    assert uv.project_refusals(project)


def test_uv_member_of_a_workspace_is_refused(tmp_path: Path) -> None:
    _project(tmp_path, "[tool.uv.workspace]\nmembers = ['m']\n")
    assert uv.project_refusals(_project(tmp_path / "m"))
    assert not uv.project_refusals(_project(tmp_path / "other" / "x"))[1:]


def test_uv_requires_python_floor(tmp_path: Path) -> None:
    assert str(uv.requires_python_floor(_project(tmp_path))) == "3.11"


def test_uv_copy_and_write_back(tmp_path: Path) -> None:
    project = _project(tmp_path / "p")
    (project / "uv.lock").write_text("old\n")
    (project / ".venv").mkdir()
    into = tmp_path / "copy"
    into.mkdir(mode=0o700)
    copy = uv.copy_project(project, into)
    assert sorted(os.listdir(into)) == ["pyproject.toml", "uv.lock"]
    (into / "uv.lock").write_text("new\n")
    assert uv.write_back(copy, ("pyproject.toml", "uv.lock")) == ["uv.lock"]
    assert (project / "uv.lock").read_text() == "new\n"


def test_uv_write_back_refuses_when_the_project_changed(tmp_path: Path) -> None:
    project = _project(tmp_path / "p")
    (project / "uv.lock").write_text("old\n")
    into = tmp_path / "copy"
    into.mkdir(mode=0o700)
    copy = uv.copy_project(project, into)
    (into / "uv.lock").write_text("checked\n")
    (project / "pyproject.toml").write_text("edited meanwhile\n")
    with pytest.raises(uv.Changed, match="pyproject.toml"):
        uv.write_back(copy, ("uv.lock",))
    assert (project / "uv.lock").read_text() == "old\n"


def test_uv_copy_refuses_symlinks(tmp_path: Path) -> None:
    project = _project(tmp_path / "p")
    (tmp_path / "elsewhere").write_text("secret")
    (project / "uv.lock").symlink_to(tmp_path / "elsewhere")
    into = tmp_path / "copy"
    into.mkdir()
    with pytest.raises(uv.UvError, match="symlink"):
        uv.copy_project(project, into)


def test_uv_errors_name_what_needs_a_build() -> None:
    text = (FIXTURES / "uv-add-num2words-0.5.14.stderr").read_text()
    assert uv.no_wheel_packages(text) == ["docopt"]


# --- PyPI's release list (the newest-release check) ---------------------------


def test_pypi_project_releases() -> None:
    body = {
        "releases": {
            "0.5.6": [{"filename": "n-0.5.6-py3-none-any.whl", "packagetype": "bdist_wheel"}],
            "0.5.14": [
                {
                    "filename": "n-0.5.14.tar.gz",
                    "packagetype": "sdist",
                    "requires_python": ">=3.12",
                }
            ],
            "0.6.0rc1": [{"filename": "n-0.6.0rc1.tar.gz", "packagetype": "sdist"}],
            "0.7.0": [{"filename": "n-0.7.0.tar.gz", "packagetype": "sdist", "yanked": True}],
            "0.0.1": [],
        }
    }

    class FakeHttp:
        def __init__(self, status: int) -> None:
            self.status = status

        def get(self, url: str, **kwargs: object) -> Response:
            assert url == "https://pypi.org/pypi/num2words/json"
            return Response(status=self.status, content=json.dumps(body).encode(), url=url)

    def ctx(status: int) -> pypi.FetchContext:
        h = cast(Http, FakeHttp(status))
        return pypi.FetchContext(http=h, limits=Limits(), tags=TagLookup(h), trees=TreeLookup(h))

    listed = pypi.project_releases(ctx(200), "Num2Words")
    assert listed.on_registry and [v for v, _ in listed.releases] == sorted(body["releases"])
    newest = newest_release(listed, SpecifierSet(), pre=False, python=Version("3.13"))
    assert newest == Version("0.5.14")
    assert newest_release(listed, SpecifierSet(), pre=False, python=Version("3.11")) == Version(
        "0.5.6"
    )
    assert newest_release(listed, SpecifierSet(), pre=True, python=None) == Version("0.6.0rc1")
    assert newest_release(listed, SpecifierSet("<0.5.10"), pre=False, python=None) == Version(
        "0.5.6"
    )
    assert pypi.project_releases(ctx(404), "num2words").on_registry is False
    with pytest.raises(NetError):
        pypi.project_releases(ctx(503), "num2words")
