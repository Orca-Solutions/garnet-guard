import subprocess
from pathlib import Path

import pytest

from garnet_guard.lockfiles import LockfileError, Pin, detect, diff_pins, parse
from garnet_guard.lockfiles.requirements import logical_lines
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
baz @ https://example.com/baz.whl
"""
    pins = parse("requirements.txt", text)
    assert [(p.package, p.version, p.line, p.source) for p in pins] == [
        ("requests", "2.32.5", 2, "registry"),
        ("flask", None, 4, "unpinned"),
        ("foo", "1.0", 5, "registry"),
        ("(editable)", None, 6, "unsupported"),
        ("baz", None, 7, "unsupported"),
    ]
    # An included file can set another index for this one, and Garnet
    # doesn't follow it, so the == pins aren't checked against PyPI.
    pins = parse("requirements.txt", text + b"-r other.txt\n")
    assert [(p.package, p.version, p.line, p.source, p.detail) for p in pins] == [
        ("requests", "2.32.5", 2, "unsupported", INCLUDE),
        ("flask", None, 4, "unpinned", ">=2"),
        ("foo", "1.0", 5, "unsupported", INCLUDE),
        ("(editable)", None, 6, "unsupported", "editable install"),
        ("baz", None, 7, "unsupported", "direct URL or path"),
    ]


def test_requirements_private_index() -> None:
    pins = parse("requirements.txt", b"--index-url https://nexus.example/simple\nx==1\n")
    assert pins[0].source == "unsupported"


INCLUDE = "-r in this file brings in a file Garnet doesn't follow, which can set another index"
SECRET = "https://user:s3cret@nexus.example/simple"


@pytest.mark.parametrize(
    ("line", "detail"),
    [
        (f"--index-url {SECRET}", "private index, set with --index-url in this file"),
        (f"--index-url={SECRET}", "private index, set with --index-url in this file"),
        (f"-i {SECRET}", "private index, set with --index-url in this file"),
        (f"-i{SECRET}", "private index, set with --index-url in this file"),
        (f"--index={SECRET}", "private index, set with --index-url in this file"),
        (f"--ind {SECRET}", "private index, set with --index-url in this file"),
        (f"--pypi-url {SECRET}", "private index, set with --pypi-url in this file"),
        ("-i ${PRIVATE_INDEX}", "private index, set with --index-url in this file"),
        (f"--extra-index-url {SECRET}", "extra index, set with --extra-index-url in this file"),
        (f"--extra-ind {SECRET}", "extra index, set with --extra-index-url in this file"),
        (f"--extra={SECRET}", "extra index, set with --extra-index-url in this file"),
        ("-f/srv/wheels", "--find-links in this file, so pip can install it from elsewhere"),
        ("-f /srv/wheels", "--find-links in this file, so pip can install it from elsewhere"),
        ("--find-l=/x", "--find-links in this file, so pip can install it from elsewhere"),
        ("--no-ind", "--no-index in this file, so pip doesn't install it from PyPI"),
        ("--no-index", "--no-index in this file, so pip doesn't install it from PyPI"),
        ("-r base.txt", INCLUDE),
        ("-rbase.txt", INCLUDE),
        ("--requirem=base.txt", INCLUDE),
        (
            "-c constraints.txt",
            "-c in this file brings in a file Garnet doesn't follow, which can set another index",
        ),
        (
            "--constr constraints.txt",
            "-c in this file brings in a file Garnet doesn't follow, which can set another index",
        ),
        (
            f"--nonsense={SECRET}",
            "an option Garnet can't read (--nonsense), so the index is unknown",
        ),
        ("--req=base.txt", "an option Garnet can't read (--req), so the index is unknown"),
        ("--no x", "an option Garnet can't read (--no), so the index is unknown"),
        ("-x secret", "an option Garnet can't read (-x), so the index is unknown"),
        ("--no-index=yes", "an option Garnet can't read (--no-index), so the index is unknown"),
        ("--index-url", "an option Garnet can't read (--index-url), so the index is unknown"),
        (
            "--trusted-host 'unclosed",
            "an option Garnet can't read (an option line), so the index is unknown",
        ),
    ],
)
def test_requirements_index_options_apply_to_the_whole_file(line: str, detail: str) -> None:
    # pip applies index options to every requirement in the file, before or
    # after the option line, and reads them with optparse: unambiguous long
    # prefixes and attached short values count.
    text = f"before==1.0\n{line}\nafter==2.0 --hash=sha256:abc\nloose>=1\n".encode()
    pins = parse("requirements.txt", text)
    assert [(p.package, p.version, p.source, p.detail) for p in pins] == [
        ("before", "1.0", "unsupported", detail),
        ("after", "2.0", "unsupported", detail),
        ("loose", None, "unpinned", ">=1"),
    ]
    # The value can hold credentials: it's never in what a report shows.
    assert all("s3cret" not in (p.detail or "") and "secret" not in (p.detail or "") for p in pins)


@pytest.mark.parametrize(
    ("line", "shown"),
    [
        ("--extra-index-urlhttps://bob:s3cret@evil.example/simple", "--extra-index-url…"),
        ("--index-urlbobs3cret@evil.example", "--index-url…"),
        ("--weirdbobsecret:hunter2@evil", "--weirdbobsecret…"),
        ("--abcdefghijklmnopqrstuvwxyzsecret", "--abcdefghijklmnopqrstuv…"),
        ("-/user:s3cret@evil", "-…"),
    ],
)
def test_requirements_unreadable_option_never_shows_its_value(line: str, shown: str) -> None:
    (pin,) = parse("requirements.txt", f"x==1\n{line}\n".encode())
    assert pin.detail == f"an option Garnet can't read ({shown}), so the index is unknown"
    assert "s3cret" not in pin.detail and "hunter2" not in pin.detail


@pytest.mark.parametrize(
    ("text", "lines"),
    [
        # pip 24.0's join_lines and ignore_comments
        (b"a==1 \\\n  --hash=sha256:x\n", [(1, "a==1   --hash=sha256:x")]),
        (b"--\\\nindex-url u\n", [(1, "--index-url u")]),
        (b"\\--index-url u\\\n\n", [(1, "--index-url u")]),
        (b"# note \\\na==1\n", [(2, "a==1")]),  # a comment line doesn't continue
        (b"a==1 # note \\\nb==2\n", [(1, "a==1")]),  # the comment eats the join
        (b"a==1 \\ \nb==2\n", [(1, "a==1 \\"), (2, "b==2")]),  # space after \\
        (b"a==1#x\n", [(1, "a==1#x")]),  # no space before #: not a comment
    ],
)
def test_logical_lines_match_pip(text: bytes, lines: list[tuple[int, str]]) -> None:
    assert logical_lines(text.decode()) == lines


def test_requirements_index_option_on_a_requirement_line_counts() -> None:
    pins = parse("requirements.txt", f"a==1\nb==2 --extra-index-url {SECRET}\n".encode())
    assert {p.source for p in pins} == {"unsupported"}


@pytest.mark.parametrize(
    "line",
    [
        "--index-url https://pypi.org/simple",
        "-ihttps://pypi.org/simple/",
        "--extra-index-url https://pypi.python.org/simple",
        "--hash=sha256:abc",
        "--hash sha256:abc",
        "--require-hashes",
        "--prefer-binary",
        "--pre",
        "--only-binary :all:",
        "--only-b=:all:",
        "--no-binary :none:",
        "--trusted-host internal.example",
        "--use-feature=truststore",
        "-C key=value",
        "--config-settings=key=value",
        "--global-option=--quiet",
        "-- -r ignored.txt",
    ],
)
def test_requirements_harmless_options_keep_pins_checked(line: str) -> None:
    text = f"before==1.0\n{line}\nafter==2.0 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\n"
    pins = parse("requirements.txt", text.encode())
    assert [(p.package, p.version, p.source) for p in pins] == [
        ("before", "1.0", "registry"),
        ("after", "2.0", "registry"),
    ]


def test_requirements_attached_editable_is_unsupported() -> None:
    pins = parse("requirements.txt", b"-e.\n--editable=./x\nok==1\n")
    assert [(p.package, p.source, p.detail) for p in pins] == [
        ("(editable)", "unsupported", "editable install"),
        ("(editable)", "unsupported", "editable install"),
        ("ok", "registry", None),
    ]


def test_requirements_new_index_reports_unchanged_pins() -> None:
    # Adding an extra index to a file moves every pin in it off PyPI, so the
    # unchanged pins are reported as not checked.
    base = b"requests==2.32.5\n"
    head = b"requests==2.32.5\n--extra-index-url https://nexus.example/simple\n"
    changes, unchecked = changes_for("requirements.txt", head, base)
    assert changes == []
    assert [(u.change.package, u.rule_id, u.detail) for u in unchecked] == [
        ("requests", "GRN-E005", "extra index, set with --extra-index-url in this file")
    ]
    # and a change of index value counts as a change, though it isn't shown
    moved = head.replace(b"nexus", b"other")
    _, unchecked = changes_for("requirements.txt", moved, head)
    assert [u.rule_id for u in unchecked] == ["GRN-E005"]
    assert all("other" not in u.detail for u in unchecked)


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
