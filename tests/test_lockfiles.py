import subprocess
from pathlib import Path

import pytest

from garnet_guard.lockfiles import LockfileError, Pin, detect, diff_pins, parse
from garnet_guard.workspace import changes_for, discover, git_show, plain_file

UV = b"""version = 1
requires-python = ">=3.11"

[[package]]
name = "Requests"
version = "2.32.5"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
]

[[package]]
name = "mylib"
version = "0.1.0"
source = { git = "https://github.com/x/mylib?rev=abc#abc" }

[[package]]
name = "internal"
version = "1.0"
source = { registry = "https://pypi.internal.example/simple" }

[[package]]
name = "myproject"
version = "0.0.0"
source = { editable = "." }
"""

POETRY = b"""[[package]]
name = "idna"
version = "3.10"
description = "x"
optional = false

[[package]]
name = "private"
version = "2.0"

[package.source]
type = "legacy"
url = "https://nexus.example/simple"
reference = "nexus"

[metadata]
lock-version = "2.1"
"""

PYLOCK = b"""lock-version = "1.0"
created-by = "uv"

[[packages]]
name = "attrs"
version = "25.4.0"
index = "https://pypi.org/simple"

[[packages]]
name = "local"
directory = { path = "./local" }

[[packages]]
name = "certifi"
version = "2025.8.3"
wheels = [{ url = "https://files.pythonhosted.org/packages/x/certifi-2025.8.3-py3-none-any.whl", hashes = {sha256 = "00"} }]
"""


def test_uv_lock() -> None:
    pins = parse("uv.lock", UV)
    assert pins == [
        Pin("requests", "2.32.5", 6),
        Pin("mylib", "0.1.0", 14, "unsupported", "git source"),
        Pin("internal", "1.0", 19, "unsupported", "registry source"),
    ]


def test_poetry_lock() -> None:
    pins = parse("poetry.lock", POETRY)
    assert pins == [
        Pin("idna", "3.10", 3),
        Pin("private", "2.0", 9, "unsupported", "private index"),
    ]


def test_pylock() -> None:
    pins = parse("pylock.toml", PYLOCK)
    assert [(p.package, p.source) for p in pins] == [
        ("attrs", "registry"),
        ("local", "unsupported"),
        ("certifi", "registry"),
    ]


def test_requirements() -> None:
    text = b"""# comment
requests==2.32.5 \\
    --hash=sha256:abc
flask>=2
foo[bar]==1.0 ; python_version < "3.12"  # trailing
-e ./local
-r other.txt
baz @ https://example.com/baz.whl
"""
    pins = parse("requirements.txt", text)
    assert [(p.package, p.version, p.line, p.source) for p in pins] == [
        ("requests", "2.32.5", 2, "registry"),
        ("flask", None, 4, "unpinned"),
        ("foo", "1.0", 5, "registry"),
        ("(editable)", None, 6, "unsupported"),
        ("baz", None, 8, "unsupported"),
    ]


def test_requirements_private_index() -> None:
    pins = parse("requirements.txt", b"--index-url https://nexus.example/simple\nx==1\n")
    assert pins[0].source == "unsupported"


def test_detect() -> None:
    assert detect("requirements-dev.txt", b"") == "requirements.txt"
    assert detect("pylock.prod.toml", b"") == "pylock.toml"
    with pytest.raises(LockfileError):
        detect("Gemfile.lock", b"GEM")


def test_diff_pins_semantics() -> None:
    base = [Pin("a", "1.0", 1), Pin("b", "2.0", 2), Pin("gone", "1.0", 3)]
    head = [Pin("a", "1.1", 1), Pin("b", "2.0", 2), Pin("new", "0.1", 3)]
    changes = diff_pins(base, head)
    assert [(c.package, c.baseline, c.candidate) for c in changes] == [
        ("a", "1.0", "1.1"),
        ("new", None, "0.1"),
    ]


def test_diff_pins_multiple_versions_picks_highest_lower() -> None:
    base = [Pin("a", "1.0", 1), Pin("a", "2.0", 2)]
    head = [Pin("a", "1.5", 1), Pin("a", "2.0", 2), Pin("a", "0.5", 3)]
    got = {(c.baseline, c.candidate) for c in diff_pins(base, head)}
    assert got == {("1.0", "1.5"), ("2.0", "0.5")}


def test_changes_for_reports_new_unchecked_only() -> None:
    base = b"flask>=2\nrequests==2.32.4\n"
    head = b"flask>=2\nrequests==2.32.5\ndjango>=5\n"
    changes, unchecked = changes_for("requirements.txt", head, base)
    assert [(c.package, c.baseline, c.candidate, c.line) for c in changes] == [
        ("requests", "2.32.4", "2.32.5", 2)
    ]
    assert [(u.change.package, u.rule_id) for u in unchecked] == [("django", "GRN-E004")]


def test_discover_and_git_show(tmp_path: Path) -> None:
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    (tmp_path / "uv.lock").write_bytes(UV)
    git("add", "uv.lock")
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base")
    (tmp_path / "requirements-dev.txt").write_text("pytest==8\n")
    assert [p.name for p in discover(tmp_path)] == ["uv.lock", "requirements-dev.txt"]
    assert git_show("HEAD", tmp_path / "uv.lock", cwd=tmp_path) == UV
    assert git_show("HEAD", tmp_path / "requirements-dev.txt", cwd=tmp_path) is None
    with pytest.raises(LockfileError):
        git_show("no-such-ref", tmp_path / "uv.lock", cwd=tmp_path)
    with pytest.raises(LockfileError):
        git_show("--output=/tmp/x", tmp_path / "uv.lock", cwd=tmp_path)


def test_symlinked_lockfiles_are_listed_but_not_plain(tmp_path: Path) -> None:
    secret = tmp_path / "outside" / "secret.txt"
    secret.parent.mkdir()
    secret.write_text("TOKEN=hunter2\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").symlink_to(secret)
    (repo / "requirements").symlink_to(secret.parent, target_is_directory=True)
    (repo / "uv.lock").write_bytes(UV)
    found = discover(repo)
    assert [p.relative_to(repo).as_posix() for p in found] == [
        "uv.lock",
        "requirements.txt",
        "requirements/secret.txt",
    ]
    assert [plain_file(p, repo) for p in found] == [True, False, False]
    assert not plain_file(Path("requirements/secret.txt"), repo)
    assert not plain_file(Path("missing.txt"), repo)


def test_toml_errors_do_not_quote_the_file() -> None:
    with pytest.raises(LockfileError) as err:
        parse("uv.lock", b"version = 1\n[hunter2]\n[hunter2]\n")
    assert "hunter2" not in str(err.value)
    assert "line 3" in str(err.value)
