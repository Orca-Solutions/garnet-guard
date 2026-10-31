"""Requirements files brought in with -r and -c: Garnet follows them inside the
directory it checks, as pip reads them, and applies the index options of the
whole include tree to every pin in it. Local files and a local git repository
only; no network."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from garnet_guard.cli import main
from garnet_guard.lockfiles import parse
from garnet_guard.lockfiles.requirements import Included
from garnet_guard.workspace import (
    MAX_INCLUDE_DEPTH,
    changes_for,
    disk_reader,
    git_reader,
    requirement_includes,
)

PRIVATE = b"--index-url https://user:s3cret@nexus.example/simple\n"


def _write(root: Path, files: dict[str, bytes]) -> dict[str, bytes]:
    for rel, body in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(body)
    return files


def _pins(root: Path, files: dict[str, bytes], name: str) -> list[tuple[str, str, str | None]]:
    included = requirement_includes(files, disk_reader(root))
    return [
        (p.package, p.source, p.detail)
        for p in parse(name, files[name], included=included[name])
        if p.version
    ]


def test_a_followed_include_that_sets_nothing_keeps_pins_checked(tmp_path: Path) -> None:
    files = _write(
        tmp_path,
        {
            "requirements.txt": b"-r requirements/base.txt\n-c constraints.txt\nflask==3.0\n",
            "requirements/base.txt": b"requests==2.32.5\n-r more.txt\n",
            "requirements/more.txt": b"idna==3.7 --hash=sha256:abc\n",
            "constraints.txt": b"urllib3==2.2\n",
        },
    )
    assert _pins(tmp_path, files, "requirements.txt") == [("flask", "registry", None)]


def test_an_included_index_applies_to_the_including_file(tmp_path: Path) -> None:
    files = _write(
        tmp_path,
        {
            "requirements-dev.txt": b"-r requirements/base.txt\npytest==8.3\n",
            "requirements/base.txt": b"-r more.txt\nrequests==2.32.5\n",
            "requirements/more.txt": PRIVATE,
        },
    )
    files = {k: v for k, v in files.items() if k != "requirements/more.txt"}
    why = "private index, set with --index-url in requirements/more.txt, which this file brings in"
    assert _pins(tmp_path, files, "requirements-dev.txt") == [("pytest", "unsupported", why)]
    assert _pins(tmp_path, files, "requirements/base.txt") == [("requests", "unsupported", why)]
    included = requirement_includes(files, disk_reader(tmp_path))
    assert all("s3cret" not in (i.why or "") for i in included.values())


def test_an_including_files_index_applies_to_the_included_file(tmp_path: Path) -> None:
    # pip install -r requirements-dev.txt installs base.txt's pins from the
    # extra index too, so base.txt's pins aren't checked against PyPI either.
    files = _write(
        tmp_path,
        {
            "requirements-dev.txt": b"--extra-index-url https://nexus.example/simple\n"
            b"-r requirements/base.txt\npytest==8.3\n",
            "requirements/base.txt": b"requests==2.32.5\n",
            "requirements/other.txt": b"-r ../requirements-dev.txt\nidna==3.7\n",
        },
    )
    assert _pins(tmp_path, files, "requirements/base.txt") == [
        (
            "requests",
            "unsupported",
            "extra index, set with --extra-index-url in requirements-dev.txt, which brings in "
            "this file",
        )
    ]
    assert _pins(tmp_path, files, "requirements/other.txt") == [
        (
            "idna",
            "unsupported",
            "extra index, set with --extra-index-url in requirements-dev.txt, which this file "
            "brings in",
        )
    ]
    # a file outside every tree that sets an index stays checked
    lone = _write(tmp_path, {"requirements-docs.txt": b"sphinx==8.0\n"})
    assert _pins(tmp_path, {**files, **lone}, "requirements-docs.txt") == [
        ("sphinx", "registry", None)
    ]


@pytest.mark.parametrize(
    ("include", "why"),
    [
        ("-r missing.txt", "it doesn't exist"),
        ("-r ../outside.txt", "it is outside the directory Garnet checks"),
        ("-r /etc/passwd", "it is outside the directory Garnet checks"),
        ("-r sub/../../outside.txt", "it is outside the directory Garnet checks"),
        ("-r https://user:tok@example.com/r.txt", "it is a URL"),
        ("-r file:///srv/r.txt", "it is a URL"),
        ("-r ${REQS}/base.txt", "it uses an environment variable"),
        ("-r linked.txt", "it is a symlink or not a regular file"),
        ("-r linkdir/base.txt", "it is a symlink or not a regular file"),
        ("-r sub", "it is a symlink or not a regular file"),
        ("-c latin1.txt", "it isn't UTF-8"),
    ],
)
def test_an_include_that_cant_be_followed_leaves_pins_unchecked(
    tmp_path: Path, include: str, why: str
) -> None:
    root = tmp_path / "repo"
    (root / "sub").mkdir(parents=True)
    (tmp_path / "outside.txt").write_bytes(b"x==1\n")
    (root / "real.txt").write_bytes(b"x==1\n")
    (root / "linked.txt").symlink_to(root / "real.txt")
    (root / "linkdir").symlink_to(root / "sub", target_is_directory=True)
    (root / "sub" / "base.txt").write_bytes(b"x==1\n")
    (root / "latin1.txt").write_bytes(b"caf\xe9==1\n")
    files = _write(root, {"requirements.txt": f"{include}\nflask==3.0\n".encode()})
    short = include[:2]
    assert _pins(root, files, "requirements.txt") == [
        (
            "flask",
            "unsupported",
            f"{short} in this file brings in a file Garnet can't follow ({why}), which can set "
            "another index",
        )
    ]


def test_include_cycles_and_depth(tmp_path: Path) -> None:
    files = _write(
        tmp_path,
        {"requirements.txt": b"-r a.txt\nflask==3.0\n", "a.txt": b"-r requirements.txt\n"},
    )
    (_, _, why) = _pins(tmp_path, files, "requirements.txt")[0]
    assert why == (
        "-r in a.txt, which this file brings in, brings in a file Garnet can't follow (the files "
        "include each other), which can set another index"
    )
    chain = {f"l{i}.txt": f"-r l{i + 1}.txt\n".encode() for i in range(MAX_INCLUDE_DEPTH)}
    chain[f"l{MAX_INCLUDE_DEPTH}.txt"] = b"x==1\n"
    deep = _write(tmp_path, {"requirements.txt": b"-r l0.txt\nflask==3.0\n", **chain})
    deep = {"requirements.txt": deep["requirements.txt"]}
    (_, source, why) = _pins(tmp_path, deep, "requirements.txt")[0]
    assert source == "unsupported" and f"more than {MAX_INCLUDE_DEPTH} includes deep" in why
    # one level less is followed
    chain[f"l{MAX_INCLUDE_DEPTH - 1}.txt"] = b"x==1\n"
    _write(tmp_path, chain)
    assert _pins(tmp_path, deep, "requirements.txt") == [("flask", "registry", None)]
    # the same file reached twice is no cycle
    diamond = _write(
        tmp_path,
        {
            "requirements.txt": b"-r b.txt\n-r c.txt\nflask==3.0\n",
            "b.txt": b"-r d.txt\n",
            "c.txt": b"-r d.txt\n",
            "d.txt": b"x==1\n",
        },
    )
    diamond = {"requirements.txt": diamond["requirements.txt"]}
    assert _pins(tmp_path, diamond, "requirements.txt") == [("flask", "registry", None)]


def test_without_include_context_an_include_is_still_unchecked() -> None:
    pins = parse("requirements.txt", b"-r base.txt\nflask==3.0\n")
    assert pins[0].source == "unsupported"
    pins = parse("requirements.txt", b"-r base.txt\nflask==3.0\n", included=Included())
    assert pins[0].source == "registry"


def _git(cwd: Path, *args: str) -> None:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, env=env)


def test_git_reader_reads_the_base_and_refuses_symlinks(tmp_path: Path) -> None:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.invalid")
    _git(tmp_path, "config", "user.name", "t")
    _write(tmp_path, {"base.txt": PRIVATE + b"x==1\n", "real.txt": b"y==1\n"})
    (tmp_path / "link.txt").symlink_to("real.txt")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "base")
    # the working tree has moved on; the reader sees the commit
    (tmp_path / "base.txt").write_bytes(b"x==1\n")
    read = git_reader("HEAD", tmp_path)
    assert read("base.txt") == PRIVATE + b"x==1\n"
    assert read("missing.txt") is None
    files = {"requirements.txt": b"-r base.txt\nflask==3.0\n"}
    got = requirement_includes(files, read)["requirements.txt"]
    assert got.why == ("private index, set with --index-url in base.txt, which this file brings in")
    linked = requirement_includes({"requirements.txt": b"-r link.txt\n"}, read)
    assert "it is a symlink or not a regular file" in (linked["requirements.txt"].why or "")


def test_changes_for_reports_pins_an_included_index_moves(tmp_path: Path) -> None:
    head = b"-r base.txt\nflask==3.0\n"
    moved = Included("private index, set with --index-url in base.txt, which this file brings in")
    changes, unchecked = changes_for(
        "requirements.txt", head, head, included=moved, base_included=Included()
    )
    assert changes == []
    assert [(u.change.package, u.rule_id) for u in unchecked] == [("flask", "GRN-E005")]


def test_check_follows_includes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    # The included file moves to a private index; the pin itself didn't
    # change, so nothing is fetched, and the pin is reported as not checked.
    # The --base file's includes are read beside it.
    _write(tmp_path, {"old/base.txt": b"", "old/requirements.txt": b"-r base.txt\nflask==3.0\n"})
    _write(tmp_path, {"base.txt": b"", "requirements.txt": b"-r base.txt\nflask==3.0\n"})
    monkeypatch.chdir(tmp_path)
    args = [
        "check",
        "--base",
        "old/requirements.txt",
        "--head",
        "requirements.txt",
        "--format",
        "json",
    ]
    assert main(args) == 0
    clean = json.loads(capsys.readouterr().out)
    assert clean["changes"] == []
    (tmp_path / "base.txt").write_bytes(PRIVATE)
    assert main(args) == 0
    out = capsys.readouterr().out
    assert "GRN-E005" in out and "s3cret" not in out
    assert "set with --index-url in base.txt, which this file brings in" in out
