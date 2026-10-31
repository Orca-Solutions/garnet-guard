"""pnpm-lock.yaml, Yarn 2+ (Berry) yarn.lock, and the YAML reader they share.

The fixtures in tests/fixtures/npm were written by the tools themselves,
with no install scripts run: pnpm-lock-base.yaml by pnpm 10.28.0
(``pnpm install --lockfile-only --ignore-scripts``) and pnpm-lock-head.yaml
from it by ``pnpm add debug@4.3.7 --lockfile-only --ignore-scripts``;
pnpm-lock-v6.yaml by pnpm 8.15.9 the same way; yarn-berry-base.lock by
Yarn 4.9.2 (``yarn install --mode=update-lockfile`` with
``YARN_ENABLE_SCRIPTS=0``) and yarn-berry-head.lock from it by
``yarn add debug@4.3.7``; yarn-berry-v6.lock by Yarn 3.8.7. The lockfiles
written here by hand follow the formats those tools write. No test here
touches the network.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
import yaml

from garnet_guard import markdown, sarif
from garnet_guard.cli import main
from garnet_guard.engine import report, run_checks, unchecked_result
from garnet_guard.lockfiles import LockfileError, Pin, berry, detect, parse, pnpm, yamldoc
from garnet_guard.lockfiles import base as lock_base
from garnet_guard.lockfiles.npm import INVALID_NAME
from garnet_guard.lockfiles.registries import NONE, Registries, npmrc, pnpm_workspace, yarnrc
from garnet_guard.lockfiles.yarn import is_berry, is_berry_text
from garnet_guard.models import Change
from garnet_guard.report import to_json, to_text
from garnet_guard.workspace import changes_for, discover, registry_settings
from tests.builders import release

FIXTURES = Path(__file__).parent / "fixtures" / "npm"


def fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def rows(pins: list[Pin]) -> list[tuple[str, str | None, int, str, str | None]]:
    return [(p.package, p.version, p.line, p.source, p.detail) for p in pins]


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _repo(path: Path) -> None:
    _git(path, "init", "-q")
    _git(path, "config", "user.email", "t@example.com")
    _git(path, "config", "user.name", "t")
    _git(path, "config", "commit.gpgsign", "false")


@pytest.fixture(params=["libyaml", "python"])
def yaml_parser(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> str:
    """Each test runs with PyYAML's C parser and with its pure-Python one,
    which is what PyYAML uses where libyaml isn't built in."""
    if request.param == "libyaml":
        if not hasattr(yaml, "CSafeLoader"):
            pytest.skip("this PyYAML has no libyaml")
    else:
        monkeypatch.delattr(yaml, "CSafeLoader", raising=False)
    return str(request.param)


# --- the YAML reader ---------------------------------------------------------------------


def test_the_reader_keeps_the_line_of_every_key(yaml_parser: str) -> None:
    doc = yamldoc.load("a:\n  b: x\n\n  'c': {d: y}\nl: [1, z]\n", schema="core")
    assert isinstance(doc, yamldoc.Mapping)
    assert doc == {"a": {"b": "x", "c": {"d": "y"}}, "l": [yamldoc.Scalar("1"), "z"]}
    assert (doc.lines, doc["a"].lines, doc["a"]["c"].lines) == (
        {"a": 1, "l": 5},
        {"b": 2, "c": 4},
        {"d": 4},
    )


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("a: x\nb: *x\n", "line 2: a YAML alias, which Garnet refuses"),
        ("a: &x hunter2\nb: *x\n", "line 1: a YAML anchor, which Garnet refuses"),
        ("a: &x {b: 1}\n", "line 1: a YAML anchor, which Garnet refuses"),
        ("a: &x [1]\n", "line 1: a YAML anchor, which Garnet refuses"),
        (
            "a: &a [x, x]\nb: &b [*a, *a]\nc: [*b, *b]\n",
            "line 1: a YAML anchor, which Garnet refuses",
        ),
        (
            "a: !!python/object/apply:os.system [hunter2]\n",
            "line 1: a YAML tag Garnet doesn't read",
        ),
        ("a: !!python/name:os.system hunter2\n", "line 1: a YAML tag Garnet doesn't read"),
        ("a: !secret hunter2\n", "line 1: a YAML tag Garnet doesn't read"),
        ("a: !!binary aHVudGVyMg==\n", "line 1: a YAML tag Garnet doesn't read"),
        ("a: !!timestamp 2001-01-01\n", "line 1: a YAML tag Garnet doesn't read"),
        ("a: !!set {x}\n", "line 1: a YAML tag Garnet doesn't read"),
        ("a: !!omap [x: 1]\n", "line 1: a YAML tag Garnet doesn't read"),
        ("%TAG !e! tag:example.com,2000:\n---\na: !e!x 1\n", "line 3: a YAML tag"),
        ("a: 1\nb: 2\na: 3\n", "line 3: a key repeated in one mapping"),
        ("null: 1\n'null': 2\n", "line 2: a key repeated in one mapping"),
        ("'true': 1\ntrue: 2\n", "line 2: a key repeated in one mapping"),
        ("1: x\n'1': y\n", "line 2: a key repeated in one mapping"),
        ("? [a]\n: 1\n", "line 1: a key that isn't a scalar"),
        ("{a: 1}: 2\n", "line 1: a key that isn't a scalar"),
        ("a: [" + "[" * 40 + "]" * 41 + "\n", "line 1: nested deeper than Garnet reads"),
        ("[" * 100_000 + "]" * 100_000, "line 1: nested deeper than Garnet reads"),
        ("a: x\nb: x\x85y\n", "line 2: a NEL, LS or PS character"),
        ("a: 'x\u2028y'\n", "line 1: a NEL, LS or PS character"),
        ("a: x\u2029\n", "line 1: a NEL, LS or PS character"),
        ("a: 1\n---\nb: 2\n", "line 2: a second YAML document"),
        ("a: 1\nb: hunter2\x01\n", "line 2: a character YAML doesn't allow"),
        ("a: [hunter2\nb: 2\n", "invalid YAML at line 2, column 2"),
        ("a: 'hunter2\n", "invalid YAML at line 2, column 1"),
        ("a:\n\t- hunter2\n", "invalid YAML at line 2, column 1"),
    ],
)
def test_the_reader_refuses_what_it_might_read_differently(
    yaml_parser: str, text: str, message: str
) -> None:
    for schema in ("core", "failsafe"):
        with pytest.raises(LockfileError) as err:
            yamldoc.load(text, schema=schema)  # type: ignore[arg-type]
        assert message in str(err.value)
        assert "hunter2" not in str(err.value) and "aHVudGVyMg" not in str(err.value)


def test_a_merge_key_is_refused_where_js_yaml_would_merge(yaml_parser: str) -> None:
    with pytest.raises(LockfileError, match="line 3: a YAML merge key, which Garnet refuses"):
        yamldoc.load("a: {b: 1}\nc:\n  <<: {d: 2}\n", schema="core")
    # Yarn's failsafe schema has no merge key: ``<<`` is a key like any other.
    assert yamldoc.load("c:\n  <<: {d: 2}\n", schema="failsafe") == {"c": {"<<": {"d": "2"}}}


def test_a_lone_surrogate_is_refused_by_either_parser(yaml_parser: str) -> None:
    with pytest.raises(LockfileError, match="line 1"):
        yamldoc.load('a: "\\ud800"\n', schema="failsafe")


def test_core_scalars_follow_js_yaml_and_anything_unclear_isnt_text(yaml_parser: str) -> None:
    text = (
        "a: foo\nb: 'yes'\nc: yes\nd: 1.0\ne: 2001-01-01\nf: 0o17\ng: 1_000\nh: true\n"
        "i: ~\nj: '9.0'\nk: 9.0\nl: .inf\nm: 0x1F\nn: '1:20'\no: 1:20\np: 4.3.7\nq: !!str 1\n"
        "r: !!int 1\ns: ''\nt:\nu: =\nv: NULL\nw: False\nx: 'null'\n"
    )
    doc = yamldoc.load(text, schema="core")
    s = yamldoc.Scalar
    assert doc == {
        "a": "foo",
        "b": "yes",
        "c": s("yes"),
        "d": s("1.0"),
        "e": s("2001-01-01"),
        "f": s("0o17"),
        "g": s("1_000"),
        "h": True,
        "i": None,
        "j": "9.0",
        "k": s("9.0"),
        "l": s(".inf"),
        "m": s("0x1F"),
        "n": "1:20",
        "o": s("1:20"),
        "p": "4.3.7",
        "q": "1",
        "r": s("1"),
        "s": "",
        "t": None,
        "u": s("="),
        "v": None,
        "w": False,
        "x": "null",
    }


def test_failsafe_reads_every_scalar_as_text(yaml_parser: str) -> None:
    doc = yamldoc.load(
        "a: yes\nb: 1.0\nc: ~\nd: true\ne: <<\n<<: x\nf:\ng: ''\n", schema="failsafe"
    )
    assert doc == {
        "a": "yes",
        "b": "1.0",
        "c": "~",
        "d": "true",
        "e": "<<",
        "<<": "x",
        "f": None,
        "g": "",
    }
    with pytest.raises(LockfileError, match="a YAML tag"):
        yamldoc.load("a: !!int 1\n", schema="failsafe")


def test_a_key_longer_than_1024_characters_reads_as_js_yaml_writes_it(yaml_parser: str) -> None:
    key = "a@1.0.0" + "(b@1.0.0)" * 150
    doc = yamldoc.load(f"? '{key}'\n: x\n", schema="core")
    assert doc == {key: "x"} and isinstance(doc, yamldoc.Mapping) and doc.lines == {key: 1}


def test_an_empty_document_is_none() -> None:
    assert yamldoc.load("", schema="core") is None
    assert yamldoc.load("# only a comment\n", schema="failsafe") is None


def test_a_settings_file_is_held_to_the_rules_only_in_the_keys_read(yaml_parser: str) -> None:
    read = frozenset({"registries"})
    text = (
        "catalog: &c\n  a: !!binary aGk=\n  a: 2\nother: *c\nscalar: &s x\n"
        "registries:\n  default: x\n"
        "deep: " + "[" * 31 + "]" * 31 + "\nlast: 1\nlast: 2\n"
    )
    doc = yamldoc.load(text, schema="core", read=read)
    assert isinstance(doc, yamldoc.Mapping)
    assert doc == {"registries": {"default": "x"}} and doc.lines == {"registries": 6}
    with pytest.raises(LockfileError, match="line 1: nested deeper than Garnet reads"):
        yamldoc.load("deep: " + "[" * 32 + "]" * 32 + "\n", schema="core", read=read)
    with pytest.raises(LockfileError, match="line 1: a NEL, LS or PS"):
        yamldoc.load("catalog: 'a\u2028b'\n", schema="core", read=read)
    with pytest.raises(LockfileError, match="line 2: a YAML anchor"):
        yamldoc.load("catalog: 1\n&k registries: x\n", schema="core", read=read)
    # Without read, every key is held to them.
    with pytest.raises(LockfileError, match="line 1: a YAML anchor"):
        yamldoc.load(text, schema="core")


# --- pnpm-lock.yaml: the generated fixtures ----------------------------------------------

PNPM_BASE_PINS = [
    # scoped; a dev dependency (is-odd) and its is-number 6; the git
    # dependency (is-number 7); a patched one (left-pad); a file: folder; the
    # alias my-ms (ms 2.1.2) and the workspace's ms 2.1.3; a peer-dependent
    # package (react-dom). The link: and workspace: dependencies have no entry.
    ("@isaacs/string-locale-compare", "1.1.0", 56, "registry", None),
    ("debug", "4.3.6", 59, "registry", None),
    ("is-number", "6.0.0", 68, "registry", None),
    ("is-number", "7.0.0", 72, "unsupported", "git source"),
    ("is-odd", "3.0.1", 77, "registry", None),
    ("js-tokens", "4.0.0", 81, "registry", None),
    ("left-pad", "1.3.0", 84, "registry", None),
    ("local-dir", None, 88, "unsupported", "file: source"),
    ("loose-envify", "1.4.0", 91, "registry", None),
    ("ms", "2.1.2", 95, "registry", None),
    ("ms", "2.1.3", 98, "registry", None),
    ("react-dom", "18.3.1", 101, "registry", None),
    ("react", "18.3.1", 106, "registry", None),
    ("scheduler", "0.23.2", 110, "registry", None),
]


def _key_line(data: bytes, pin: Pin) -> str:
    return data.decode().splitlines()[pin.line - 1]


def test_pnpm_v9_pins_every_package_at_its_key_line() -> None:
    data = fixture("pnpm-lock-base.yaml")
    pins = parse("pnpm-lock.yaml", data)
    assert rows(pins) == PNPM_BASE_PINS
    assert {p.ecosystem for p in pins} == {"npm"}
    for pin in pins:
        line = _key_line(data, pin).strip().strip("'")
        assert line.startswith(f"{pin.package}@") and line.endswith(":")


def test_pnpm_v6_gives_the_same_packages() -> None:
    """pnpm 8 wrote this one from the same project, without the git
    dependency, after the debug update."""
    data = fixture("pnpm-lock-v6.yaml")
    pins = parse("pnpm-lock.yaml", data)
    assert rows(pins) == [
        ("@isaacs/string-locale-compare", "1.1.0", 53, "registry", None),
        ("debug", "4.3.7", 57, "registry", None),
        ("is-number", "6.0.0", 69, "registry", None),
        ("is-odd", "3.0.1", 74, "registry", None),
        ("js-tokens", "4.0.0", 81, "registry", None),
        ("left-pad", "1.3.0", 85, "registry", None),
        ("loose-envify", "1.4.0", 91, "registry", None),
        ("ms", "2.1.2", 98, "registry", None),
        ("ms", "2.1.3", 102, "registry", None),
        ("react-dom", "18.3.1", 106, "registry", None),
        ("react", "18.3.1", 116, "registry", None),
        ("scheduler", "0.23.2", 123, "registry", None),
        ("local-dir", None, 129, "unsupported", "file: source"),
    ]
    for pin in pins:
        assert pin.package in _key_line(data, pin)


def test_a_pnpm_bump_is_one_npm_change_at_its_line() -> None:
    changes, unchecked = changes_for(
        "pnpm-lock.yaml", fixture("pnpm-lock-head.yaml"), fixture("pnpm-lock-base.yaml")
    )
    assert [(c.ecosystem, c.package, c.baseline, c.candidate, c.line) for c in changes] == [
        ("npm", "debug", "4.3.6", "4.3.7", 59)
    ]
    assert unchecked == []


def test_a_new_pnpm_lockfile_reports_git_and_file_sources() -> None:
    changes, unchecked = changes_for("pnpm-lock.yaml", fixture("pnpm-lock-base.yaml"), None)
    assert len(changes) == 12
    assert [(u.change.package, u.change.line, u.rule_id, u.detail) for u in unchecked] == [
        ("is-number", 72, "GRN-E005", "git source"),
        ("local-dir", 88, "GRN-E005", "file: source"),
    ]


def test_pnpm_is_detected_by_name_and_by_content() -> None:
    data = fixture("pnpm-lock-base.yaml")
    assert detect("pnpm-lock.yaml", data) == "pnpm-lock.yaml"
    assert detect("lock.yaml", data) == "pnpm-lock.yaml"
    assert detect("old", b"\xef\xbb\xbf" + data) == "pnpm-lock.yaml"
    assert rows(parse("old", b"\xef\xbb\xbf" + data)) == PNPM_BASE_PINS


# --- pnpm-lock.yaml: entries --------------------------------------------------------------


def pnpm9(key: str, fields: str, snapshot: str | None = None) -> bytes:
    """A lockfileVersion 9.0 file with one package, at line 9, and its snapshot."""
    snap = key if snapshot is None else snapshot
    return (
        "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\npackages:\n\n"
        f"  '{key}':\n{fields}\nsnapshots:\n\n  '{snap}': {{}}\n"
    ).encode()


INTEGRITY = "    resolution: {integrity: sha512-AAAA}\n"
NPM = "https://registry.npmjs.org"


@pytest.mark.parametrize(
    ("key", "fields", "expected"),
    [
        ("ms@2.1.3", INTEGRITY, ("ms", "2.1.3", "registry", None)),
        ("@scope/x@1.0.0", INTEGRITY, ("@scope/x", "1.0.0", "registry", None)),
        (
            "ms@2.1.3",
            f"    resolution: {{integrity: sha512-AAAA, tarball: {NPM}/ms/-/ms-2.1.3.tgz}}\n",
            ("ms", "2.1.3", "registry", None),
        ),
        (
            "ms@2.1.3",
            f"    resolution: {{tarball: {NPM}/ms/-/ms-2.1.2.tgz}}\n",
            ("ms", "2.1.3", "unsupported", "resolved URL isn't this package's registry tarball"),
        ),
        (
            "ms@2.1.3",
            "    resolution: {tarball: 'https://user:hunter2@npm.corp.example/ms/-/ms-2.1.3.tgz'}\n",
            ("ms", "2.1.3", "unsupported", "private registry"),
        ),
        (
            "ms@https://example.com/ms.tgz",
            "    resolution: {tarball: https://example.com/ms.tgz}\n    version: 2.1.3\n",
            ("ms", "2.1.3", "unsupported", "tarball URL outside the npm registry"),
        ),
        (
            "ms@http://example.com/ms.tgz",
            "    resolution: {tarball: http://example.com/ms.tgz}\n    version: 2.1.3\n",
            ("ms", "2.1.3", "unsupported", "plain HTTP URL"),
        ),
        (
            "ms@file:vendor/ms-2.1.3.tgz",
            "    resolution: {integrity: sha512-AAAA, tarball: file:vendor/ms-2.1.3.tgz}\n"
            "    version: 2.1.3\n",
            ("ms", "2.1.3", "unsupported", "file: source"),
        ),
        (
            "ms@https://codeload.github.com/o/ms/tar.gz/0123abc",
            "    resolution: {tarball: https://codeload.github.com/o/ms/tar.gz/0123abc}\n"
            "    version: 2.1.3\n",
            ("ms", "2.1.3", "unsupported", "git source"),
        ),
        (
            "ms@git+https://github.com/o/ms.git#0123abc",
            "    resolution: {commit: 0123abc, repo: https://github.com/o/ms.git, type: git}\n"
            "    version: 2.1.3\n",
            ("ms", "2.1.3", "unsupported", "git source"),
        ),
        (
            "ms@file:vendor/ms",
            "    resolution: {directory: vendor/ms, type: directory}\n    version: 2.1.3\n",
            ("ms", "2.1.3", "unsupported", "file: source"),
        ),
        (
            "node@runtime:22.0.0",
            "    resolution: {type: variations, variants: []}\n    version: 22.0.0\n",
            ("node", "22.0.0", "unsupported", "unsupported source"),
        ),
        (
            "ms@2.1.3",
            "    resolution: {tarball: ms/-/ms-2.1.3.tgz}\n",
            ("ms", "2.1.3", "unsupported", "unsupported source"),
        ),
        (
            "@jsr/std__path@1.0.8",
            INTEGRITY,
            (
                "@jsr/std__path",
                "1.0.8",
                "unsupported",
                "JSR registry, pnpm's default for @jsr packages",
            ),
        ),
        (
            "Evil\u202e@1.0.0",
            INTEGRITY,
            (INVALID_NAME, "1.0.0", "unsupported", "not a valid npm package name"),
        ),
    ],
)
def test_pnpm_sources(key: str, fields: str, expected: tuple[str, str, str, str | None]) -> None:
    (pin,) = parse("pnpm-lock.yaml", pnpm9(key, fields))
    assert (pin.package, pin.version, pin.source, pin.detail) == expected
    assert pin.line == 9 and pin.ecosystem == "npm"


def test_pnpm_peer_and_patch_suffixes_are_removed() -> None:
    assert pnpm.remove_suffix("react-dom@18.3.1(react@18.3.1)") == "react-dom@18.3.1"
    assert pnpm.remove_suffix("a@1.0.0(b@2.0.0(c@3.0.0))(d@1.0.0)") == "a@1.0.0"
    assert pnpm.remove_suffix("left-pad@1.3.0(patch_hash=b471fb)") == "left-pad@1.3.0"
    assert pnpm.remove_suffix("@s/a@1.0.0") == "@s/a@1.0.0"
    assert pnpm.split_key("@s/a@1.0.0") == ("@s/a", "1.0.0")
    data = pnpm9("a@1.0.0", INTEGRITY, snapshot="a@1.0.0(b@2.0.0(c@3.0.0))(d@1.0.0)")
    assert rows(parse("pnpm-lock.yaml", data)) == [("a", "1.0.0", 9, "registry", None)]


def test_a_git_dependency_moving_to_another_commit_is_reported() -> None:
    def at(sha: str) -> bytes:
        return pnpm9(
            f"lib@git+https://github.com/o/lib.git#{sha}",
            f"    resolution: {{commit: {sha}, repo: https://github.com/o/lib.git, type: git}}\n"
            "    version: 1.0.0\n",
        )

    assert changes_for("pnpm-lock.yaml", at("aaa"), at("aaa")) == ([], [])
    _, unchecked = changes_for("pnpm-lock.yaml", at("bbb"), at("aaa"))
    assert [(u.change.package, u.rule_id, u.detail) for u in unchecked] == [
        ("lib", "GRN-E005", "git source")
    ]


def test_a_new_pnpm_tarball_behind_the_same_url_is_reported() -> None:
    def with_integrity(integrity: str) -> bytes:
        return pnpm9(
            "x@https://example.com/x.tgz",
            f"    resolution: {{integrity: {integrity}, tarball: https://example.com/x.tgz}}\n"
            "    version: 1.0.0\n",
        )

    old, new = with_integrity("sha512-AAAA"), with_integrity("sha512-BBBB")
    assert changes_for("pnpm-lock.yaml", old, old) == ([], [])
    _, unchecked = changes_for("pnpm-lock.yaml", new, old)
    assert [(u.change.package, u.detail) for u in unchecked] == [
        ("x", "tarball URL outside the npm registry")
    ]


# Written by pnpm 10.28.0 (pnpm install --lockfile-only --ignore-scripts) for
# "pnpm": {"patchedDependencies": {"lodash@4.17.21": "../outside-lodash.patch"}}.
OUTSIDE_PATCH_LOCK = """lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

patchedDependencies:
  lodash@4.17.21:
    hash: 3915e3468fb28e75d74657df0f51fd6084c8cce7eca09ee4cd46b0f10f6e581a
    path: ../outside-lodash.patch

importers:

  .:
    dependencies:
      lodash:
        specifier: 4.17.21
        version: 4.17.21(patch_hash=3915e3468fb28e75d74657df0f51fd6084c8cce7eca09ee4cd46b0f10f6e581a)

packages:

  lodash@4.17.21:
    resolution: {integrity: sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==}

snapshots:

  lodash@4.17.21(patch_hash=3915e3468fb28e75d74657df0f51fd6084c8cce7eca09ee4cd46b0f10f6e581a): {}
"""
LODASH = "    path: ../outside-lodash.patch\n"


def _patched(key: str = "lodash@4.17.21", path: str = "../outside-lodash.patch") -> bytes:
    return (
        OUTSIDE_PATCH_LOCK.replace("  lodash@4.17.21:\n    hash", f"  '{key}':\n    hash", 1)
        .replace(LODASH, f"    path: '{path}'\n")
        .encode()
    )


@pytest.mark.parametrize(
    ("key", "path", "expected"),
    [
        ("lodash@4.17.21", "../outside-lodash.patch", ("unsupported", pnpm.OUTSIDE_PATCH)),
        ("lodash@4.17.21", "patches/lodash.patch", ("registry", None)),
        ("lodash@4.17.21", "./patches/../lodash.patch", ("registry", None)),
        ("lodash@4.17.21", "patches/../../lodash.patch", ("unsupported", pnpm.OUTSIDE_PATCH)),
        ("lodash@4.17.21", "/tmp/lodash.patch", ("unsupported", pnpm.OUTSIDE_PATCH)),
        ("lodash@4.17.21", "C:/x/lodash.patch", ("unsupported", pnpm.OUTSIDE_PATCH)),
        ("lodash@4.17.21", "..\\lodash.patch", ("unsupported", pnpm.OUTSIDE_PATCH)),
        # A bare name or a range patches every version pnpm matches it with.
        ("lodash", "../x.patch", ("unsupported", pnpm.OUTSIDE_PATCH)),
        ("lodash@^4.0.0", "../x.patch", ("unsupported", pnpm.OUTSIDE_PATCH)),
        ("lodash@4.17.20", "../x.patch", ("registry", None)),
        ("other", "../x.patch", ("registry", None)),
    ],
)
def test_a_pnpm_patch_file_outside_the_project_is_reported(
    key: str, path: str, expected: tuple[str, str | None]
) -> None:
    (pin,) = parse("pnpm-lock.yaml", _patched(key, path))
    assert (pin.package, pin.version, pin.line) == ("lodash", "4.17.21", 22)
    assert (pin.source, pin.detail) == expected


def test_a_new_patch_file_outside_the_project_is_reported_each_time() -> None:
    inside, outside = _patched(path="patches/lodash.patch"), _patched()
    _, unchecked = changes_for("pnpm-lock.yaml", outside, inside)
    assert [(u.change.package, u.change.line, u.rule_id, u.detail) for u in unchecked] == [
        ("lodash", 22, "GRN-E005", pnpm.OUTSIDE_PATCH)
    ]
    assert changes_for("pnpm-lock.yaml", outside, outside) == ([], [])
    rehashed = outside.replace(b"hash: 3915e3", b"hash: 000000", 1)
    assert len(changes_for("pnpm-lock.yaml", rehashed, outside)[1]) == 1


def test_a_pnpm_8_patch_file_outside_the_project_is_reported() -> None:
    data = fixture("pnpm-lock-v6.yaml").replace(
        b"path: patches/left-pad@1.3.0.patch", b"path: ../left-pad.patch"
    )
    (pin,) = [p for p in parse("pnpm-lock.yaml", data) if p.package == "left-pad"]
    assert (pin.version, pin.source, pin.detail) == ("1.3.0", "unsupported", pnpm.OUTSIDE_PATCH)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (pnpm9("ms@2.1.3", INTEGRITY + "    version: 2.1.4\n"), "line 9: a name or version"),
        (pnpm9("ms@2.1.3", INTEGRITY + "    name: other\n"), "line 9: a name or version"),
        (pnpm9("ms@latest", INTEGRITY), "line 9: a registry entry whose key has no SemVer"),
        (pnpm9("ms", INTEGRITY, snapshot="ms"), "line 9: a packages key that isn't name@version"),
        (pnpm9("ms@2.1.3", "    version: 2.1.3\n"), "line 9: an entry with no resolution"),
        (pnpm9("ms@2.1.3", "    resolution: [x]\n"), "line 9: an entry with no resolution"),
        (pnpm9("ms@2.1.3", "    resolution: {tarball: [x]}\n"), "line 9: a tarball that isn't"),
        (pnpm9("ms@2.1.3", "    resolution: {type: ''}\n"), "line 9: a resolution type that"),
        (pnpm9("ms@2.1.3", INTEGRITY + "    version: 2.1\n"), "line 9: a version that isn't"),
        (pnpm9("ms@2.1.3", INTEGRITY, snapshot="ms@9.9.9"), "line 14: a snapshot with no"),
        (
            pnpm9("ms@2.1.3(x@1.0.0)", INTEGRITY),
            "line 9: a packages key with a peer or patch suffix",
        ),
        (
            pnpm9("ms@2.1.3", INTEGRITY).replace(
                b"'ms@2.1.3': {}", b"'ms@2.1.3': {resolution: {integrity: x}}"
            ),
            "line 14: a snapshot with its own resolution",
        ),
        (
            pnpm9("ms@2.1.3", INTEGRITY).replace(b"'ms@2.1.3': {}", b"'ms@2.1.3': x"),
            "line 14: a snapshot that isn't a mapping",
        ),
        (b"lockfileVersion: '9.0'\npackages: []\n", "line 2: packages isn't a mapping"),
        (b"lockfileVersion: '9.0'\nimporters: x\n", "line 2: importers isn't a mapping"),
        (
            OUTSIDE_PATCH_LOCK.replace(LODASH, "").encode(),
            "line 8: a patchedDependencies entry with no path",
        ),
        (
            OUTSIDE_PATCH_LOCK.replace(LODASH, "    path: [hunter2]\n").encode(),
            "line 8: a path that isn't text",
        ),
        (
            b"lockfileVersion: '9.0'\npatchedDependencies:\n  x@1.0.0: hunter2\n",
            "line 3: a patchedDependencies entry pnpm doesn't write",
        ),
        (b"- lockfileVersion\n", "the top level isn't a mapping"),
        (b"packages: {}\n", "no lockfileVersion; Garnet reads lockfileVersion 9.0 and 6.x"),
        (
            b"lockfileVersion: 5.4\n",
            "lockfileVersion 5.4 is from pnpm 7 or earlier, which Garnet doesn't read; "
            "regenerate the lockfile with pnpm 8 or later",
        ),
        (b"lockfileVersion: '5.3'\n", "lockfileVersion 5.3 is from pnpm 7 or earlier"),
        (b"lockfileVersion: '10.0'\n", "lockfileVersion 10.0 isn't one Garnet reads (9.0 or 6.x)"),
        (b"lockfileVersion: 'hunter2'\n", "a lockfileVersion isn't one Garnet reads"),
        ("lockfileVersion: '\u00b2.0'\n".encode(), "a lockfileVersion isn't one Garnet reads"),
        ("lockfileVersion: '\u0663.0'\n".encode(), "a lockfileVersion isn't one Garnet reads"),
        (b"lockfileVersion: '" + b"9" * 5000 + b".0'\n", "a lockfileVersion isn't one Garnet"),
        (b"lockfileVersion: '9.0'\npackages:\n  a@1.0.0: &x\n", "line 3: a YAML anchor"),
    ],
)
def test_malformed_pnpm_lockfiles_are_lockfile_errors(data: bytes, message: str) -> None:
    with pytest.raises(LockfileError) as err:
        parse("pnpm-lock.yaml", data)
    assert message in str(err.value)
    assert "hunter2" not in str(err.value)


def test_an_unquoted_lockfile_version_is_read_as_pnpm_reads_it() -> None:
    data = pnpm9("ms@2.1.3", INTEGRITY).replace(b"'9.0'", b"9.0")
    assert rows(parse("pnpm-lock.yaml", data)) == [("ms", "2.1.3", 9, "registry", None)]


V6 = """lockfileVersion: '6.0'

packages:

  /react-dom@18.3.1(react@18.3.1):
    resolution: {integrity: sha512-AAAA}
    dev: false

  /react-dom@18.3.1(react@18.2.0):
    resolution: {integrity: sha512-AAAA}
    dev: false

  /@scope/x@1.0.0_y@2.0.0:
    resolution: {integrity: sha512-BBBB}
    dev: true

  github.com/jonschlinkert/is-number/98e8ff1da1a89f93d1397a24d7413ed15421c139:
    resolution: {tarball: https://codeload.github.com/jonschlinkert/is-number/tar.gz/98e8ff1da1a89f93d1397a24d7413ed15421c139}
    name: is-number
    version: 7.0.0
    dev: false
"""


def test_pnpm_v6_peers_git_entries_and_one_pin_per_version() -> None:
    assert rows(parse("pnpm-lock.yaml", V6.encode())) == [
        ("react-dom", "18.3.1", 5, "registry", None),
        ("@scope/x", "1.0.0", 13, "registry", None),
        ("is-number", "7.0.0", 17, "unsupported", "git source"),
    ]


def test_pnpm_v6_entries_pnpm_8_doesnt_write_are_refused() -> None:
    nameless = V6.replace("    name: is-number\n", "")
    (*_, pin) = parse("pnpm-lock.yaml", nameless.encode())
    assert (pin.package, pin.source) == (INVALID_NAME, "unsupported")
    registry_only = V6.replace(
        "{tarball: https://codeload.github.com/jonschlinkert/is-number/tar.gz/98e8ff1da1a89f93d1397a24d7413ed15421c139}",
        "{integrity: sha512-CCCC}",
    )
    with pytest.raises(LockfileError, match="line 17: a registry entry whose key has no SemVer"):
        parse("pnpm-lock.yaml", registry_only.encode())
    with pytest.raises(LockfileError, match="line 5: a name or version"):
        parse("pnpm-lock.yaml", V6.replace("dev: false\n", "version: 1.0.0\n", 1).encode())


# --- registries -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "default", "scopes"),
    [
        ("", None, {}),
        ("registry=https://registry.npmjs.org/\n", True, {}),
        ("registry = https://registry.npmjs.org\n", True, {}),
        ('registry="https://registry.npmjs.org/"\n', True, {}),
        ("registry='https://registry.yarnpkg.com/'\n", True, {}),
        ("registry=https://registry.npmjs.org/ ; a comment\n", True, {}),
        ("registry=https://npm.corp.example/\n", False, {}),
        ("registry=http://registry.npmjs.org/\n", False, {}),
        ("registry=https://registry.npmjs.org:8443/\n", False, {}),
        ("registry=https://user:hunter2@registry.npmjs.org/\n", False, {}),
        ("registry=${NPM_REGISTRY}\n", False, {}),
        ("registry=https://npm.corp.example/\nregistry=https://registry.npmjs.org/\n", True, {}),
        ("@corp:registry=https://npm.corp.example/\n", None, {"@corp": False}),
        ("@pub:registry=https://registry.npmjs.org/\n", None, {"@pub": True}),
        ("//npm.corp.example/:_authToken=hunter2\n", None, {}),
        ("; registry=https://npm.corp.example/\n# registry=x\n", None, {}),
        ("[section]\nregistry=https://npm.corp.example/\n", None, {}),
        ("@corp/x:registry=https://npm.corp.example/\n", None, {}),
        # A registry that isn't text: pnpm stops ("`registry` should be a string").
        ("registry\n", False, {}),
        ("registry=null\n", False, {}),
        ("registry[]=https://registry.npmjs.org/\n", False, {}),
        # Read as pnpm 10.28.0 reads them (its ini 1.x parser): each line below
        # was given to pnpm, and it fetched from the registry the line names.
        # A section header only when the line is exactly [name] ...
        (" [x]\nregistry=https://npm.corp.example/\n", False, {}),
        ("\t[x]\nregistry=https://npm.corp.example/\n", False, {}),
        ("[x] \nregistry=https://npm.corp.example/\n", False, {}),
        ("[x]]\nregistry=https://npm.corp.example/\n", False, {}),
        ("[x\\]]\nregistry=https://npm.corp.example/\n", False, {}),
        ("\ufeff[x]\nregistry=https://npm.corp.example/\n", False, {}),
        # ... a byte order mark is trimmed from a key, and a line ends only at
        # CR or LF ...
        ("\ufeffregistry=https://npm.corp.example/\n", False, {}),
        ("\u00a0registry\u00a0=https://npm.corp.example/\n", False, {}),
        ("foo=bar\x0b[x]\nregistry=https://npm.corp.example/\n", False, {}),
        ("[x]\r\nregistry=https://npm.corp.example/\r\n", None, {}),
        # ... a line whose value holds a line separator is skipped ...
        (
            "registry=https://npm.corp.example/\nregistry=https://registry.npmjs.org/\u2028\n",
            False,
            {},
        ),
        ("registry=https://npm.corp.example/\u2028\n", None, {}),
        # ... a backslash before anything but \\, ; or # is kept ...
        ("registry=https://registry.npmjs\\.org/\n", False, {}),
        # ... a quoted key is decoded, a JSON list to its JavaScript name ...
        ("'registry'=https://npm.corp.example/\n", False, {}),
        ('"registry"=https://npm.corp.example/\n', False, {}),
        ("'[\"registry\"]'=https://npm.corp.example/\n", False, {}),
        # ... and these are a comment, and a key that isn't registry.
        ("\ufeff#registry=https://npm.corp.example/\n", None, {}),
        ("\x1fregistry=https://npm.corp.example/\n", None, {}),
        ("REGISTRY=https://npm.corp.example/\n", None, {}),
        # A scope runs to the first colon, as in pnpm's getNetworkConfigs.
        ("@corp:x:registry=https://npm.corp.example/\n", None, {"@corp": False}),
        ("@corp:x/y:registry=https://npm.corp.example/\n", None, {"@corp": False}),
    ],
)
def test_npmrc_registry_settings(text: str, default: bool | None, scopes: dict[str, bool]) -> None:
    settings = npmrc(text)
    assert (settings.source, settings.default, dict(settings.scopes)) == (".npmrc", default, scopes)


def test_an_npmrc_registry_reports_the_packages_it_serves() -> None:
    settings = npmrc(
        "registry=https://npm.corp.example/\n@pub:registry=https://registry.npmjs.org/\n"
    )
    assert settings.other_registry("ms") == ".npmrc"
    assert settings.other_registry("@corp/x") == ".npmrc"
    assert settings.other_registry("@pub/x") is None
    scoped = npmrc("@corp:registry=https://npm.corp.example/\n")
    assert scoped.other_registry("ms") is None and scoped.other_registry("@corp/x") == ".npmrc"
    assert NONE.other_registry("@corp/x") is None
    data = fixture("pnpm-lock-base.yaml")
    pins = parse("pnpm-lock.yaml", data, registries=npmrc("registry=https://npm.corp.example\n"))
    assert {(p.source, p.detail) for p in pins} == {
        ("unsupported", "private registry, set in .npmrc"),
        ("unsupported", "git source"),
        ("unsupported", "file: source"),
    }
    jsr = npmrc("@jsr:registry=https://registry.npmjs.org/\n")
    (pin,) = parse("pnpm-lock.yaml", pnpm9("@jsr/std__path@1.0.8", INTEGRITY), registries=jsr)
    assert pin.source == "registry"


@pytest.mark.parametrize(
    ("text", "default", "scopes"),
    [
        ("", None, {}),
        ("# nothing\n", None, {}),
        ('npmRegistryServer: "https://registry.yarnpkg.com"\n', True, {}),
        ("npmRegistryServer: https://registry.npmjs.org/\nnpmAuthToken: hunter2\n", True, {}),
        ("npmRegistryServer: https://npm.corp.example\n", False, {}),
        ("npmRegistryServer: ${NPM_REGISTRY_SERVER}\n", False, {}),
        (
            "npmScopes:\n  corp:\n    npmRegistryServer: https://npm.corp.example\n"
            "  pub:\n    npmAlwaysAuth: true\n",
            None,
            {"@corp": False, "@pub": None},
        ),
        # Yarn 4.9.2 and 3.8.7 look scopes up without the @: Yarn 4.9.2 fetched
        # @isaacs/string-locale-compare from npm's registry with this entry.
        (
            "npmRegistryServer: https://npm.corp.example\n"
            "npmScopes:\n  '@corp':\n    npmRegistryServer: https://registry.npmjs.org\n",
            False,
            {},
        ),
        ("yarnPath: .yarn/releases/yarn-4.9.2.cjs\nnodeLinker: node-modules\n", None, {}),
        # Keys Garnet doesn't read may use anything YAML has, and repeat, as
        # Yarn's js-yaml (json: true) lets them; only their names are checked.
        (
            "packageExtensions: &ext\n  'x@*': {dependencies: {y: '*'}}\nother: *ext\n"
            "nodeLinker: pnp\nnodeLinker: node-modules\ntag: !custom {a: 1}\n"
            "npmRegistryServer: https://npm.corp.example\n",
            False,
            {},
        ),
    ],
)
def test_yarnrc_registry_settings(text: str, default: bool | None, scopes: dict[str, bool]) -> None:
    settings = yarnrc(text)
    assert (settings.source, settings.default, dict(settings.scopes)) == (
        ".yarnrc.yml",
        default,
        scopes,
    )


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("npmRegistryServer: [hunter2]\n", "line 1: the npmRegistryServer setting isn't text"),
        ("npmScopes: hunter2\n", "line 1: npmScopes isn't a mapping"),
        ("npmScopes:\n  corp: hunter2\n", "line 2: an npmScopes entry Garnet can't read"),
        (
            "npmScopes:\n  corp:\n    npmRegistryServer: {a: hunter2}\n",
            "line 3: an npmRegistryServer isn't text",
        ),
        ("- hunter2\n", "the top level isn't a mapping"),
        ("npmAuthToken: 'hunter2\n", "invalid YAML at line 2"),
        ("npmRegistryServer: &a hunter2\n", "line 1: a YAML anchor"),
        ("x: &a hunter2\nnpmRegistryServer: *a\n", "line 2: a YAML alias"),
        (
            "npmScopes:\n  corp: &a {npmRegistryServer: hunter2}\n",
            "line 2: a YAML anchor",
        ),
        ("npmRegistryServer: x\nnpmRegistryServer: hunter2\n", "line 2: a key repeated"),
        ("&a npmRegistryServer: hunter2\n", "line 1: a YAML anchor"),
        ("*a : hunter2\n", "line 1: a YAML alias"),
        ("--- &a\nnpmAuthToken: hunter2\n", "a YAML anchor"),
    ],
)
def test_unreadable_yarnrc_files_are_lockfile_errors(text: str, message: str) -> None:
    with pytest.raises(LockfileError) as err:
        yarnrc(text)
    assert message in str(err.value) and "hunter2" not in str(err.value)


@pytest.mark.parametrize(
    ("text", "default", "scopes"),
    [
        ("", None, {}),
        ("packages:\n  - 'packages/*'\nonlyBuiltDependencies: [esbuild]\n", None, {}),
        # pnpm has read the registries before it reads this file's settings.
        ("registry: https://npm.corp.example/\n", None, {}),
        ("registries:\n  default: https://registry.npmjs.org/\n", True, {}),
        (
            "registries:\n  default: https://npm.corp.example/\n"
            "  '@pub': https://registry.npmjs.org/\n",
            False,
            {"@pub": True},
        ),
        # With no default, pnpm 10.28.0 installs unscoped packages from npm's
        # public registry.
        ("registries:\n  '@corp': https://npm.corp.example/\n", None, {"@corp": False}),
        # A catalog with anchors, aliases and a merge key, as pnpm reads one.
        (
            "packages: [.]\ncatalogs:\n  a: &shared\n    debug: 4.3.6\n  b: *shared\n"
            "  c:\n    <<: *shared\n    ms: 2.1.3\n"
            "registries:\n  default: https://npm.corp.example/\n",
            False,
            {},
        ),
    ],
)
def test_pnpm_workspace_registry_settings(
    text: str, default: bool | None, scopes: dict[str, bool]
) -> None:
    settings = pnpm_workspace(text)
    assert (settings.source, settings.default, dict(settings.scopes)) == (
        "pnpm-workspace.yaml",
        default,
        scopes,
    )


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("registries: hunter2\n", "line 1: registries isn't a mapping"),
        ("registries:\n  default: [hunter2]\n", "line 2: a registries entry Garnet can't read"),
        ("registries:\n  default: &r hunter2\n", "line 2: a YAML anchor, which Garnet refuses"),
        ("catalog: &c {a: 1}\nregistries: *c\n", "line 2: a YAML alias, which Garnet refuses"),
        ("catalog: &c {a: 1}\n<<: *c\n", "line 2: a YAML merge key, which Garnet refuses"),
        ("registries: {}\nregistries: {default: hunter2}\n", "line 2: a key repeated"),
        ("- hunter2\n", "the top level isn't a mapping"),
        ("catalog: '\n", "invalid YAML"),
    ],
)
def test_unreadable_pnpm_workspace_files_are_lockfile_errors(text: str, message: str) -> None:
    with pytest.raises(LockfileError) as err:
        pnpm_workspace(text)
    assert message in str(err.value) and "hunter2" not in str(err.value)


def test_npmrc_and_pnpm_workspace_both_count(tmp_path: Path) -> None:
    """pnpm 10 takes registries from pnpm-workspace.yaml over .npmrc, and a
    pnpm that doesn't read that file's settings uses .npmrc's; a package
    either sends elsewhere is reported."""
    head = tmp_path / "pnpm-lock.yaml"
    head.write_bytes(fixture("pnpm-lock-base.yaml"))
    data = head.read_bytes()
    (tmp_path / "pnpm-workspace.yaml").write_text(
        "packages: ['packages/*']\nregistries:\n  default: https://registry.npmjs.org/\n"
        "  '@isaacs': https://npm.corp.example/\n"
    )
    settings = registry_settings(head, data, tmp_path)
    assert settings.other_registry("@isaacs/string-locale-compare") == "pnpm-workspace.yaml"
    assert settings.other_registry("debug") is None
    (tmp_path / ".npmrc").write_text("registry=https://npm.corp.example/\n")
    settings = registry_settings(head, data, tmp_path)
    assert settings.other_registry("debug") == ".npmrc"
    assert settings.other_registry("@isaacs/string-locale-compare") == ".npmrc"
    (tmp_path / ".npmrc").write_text("@jsr:registry=https://registry.npmjs.org/\n")
    settings = registry_settings(head, data, tmp_path)
    assert settings.public_scope("@jsr") and not NONE.public_scope("@jsr")
    pins = parse("pnpm-lock.yaml", data, registries=settings)
    assert [(p.package, p.detail) for p in pins if p.source != "registry"] == [
        ("@isaacs/string-locale-compare", "private registry, set in pnpm-workspace.yaml"),
        ("is-number", "git source"),
        ("local-dir", "file: source"),
    ]
    (tmp_path / "pnpm-workspace.yaml").unlink()
    (tmp_path / "pnpm-workspace.yaml").symlink_to(tmp_path / ".npmrc")
    with pytest.raises(LockfileError, match="^pnpm-workspace.yaml is not a regular file"):
        registry_settings(head, data, tmp_path)


def test_registry_settings_come_from_the_lockfile_folder(tmp_path: Path) -> None:
    head = tmp_path / "pnpm-lock.yaml"
    head.write_bytes(fixture("pnpm-lock-base.yaml"))
    data = head.read_bytes()
    assert registry_settings(head, data, tmp_path) == NONE
    (tmp_path / ".npmrc").write_text("registry=https://npm.corp.example/\n")
    assert registry_settings(head, data, tmp_path) == Registries(".npmrc", False, {})
    sub = tmp_path / "web"
    sub.mkdir()
    (sub / ".yarnrc.yml").write_text("npmRegistryServer: https://npm.corp.example\n")
    yarn_lock = sub / "yarn.lock"
    yarn_lock.write_bytes(fixture("yarn-berry-base.lock"))
    assert registry_settings(yarn_lock, yarn_lock.read_bytes(), tmp_path) == Registries(
        ".yarnrc.yml", False, {}
    )
    # Formats that record the registry, and Yarn 1, read no settings file.
    yarn_lock.write_bytes(fixture("yarn-base.lock"))
    assert registry_settings(yarn_lock, yarn_lock.read_bytes(), tmp_path) == NONE
    (sub / ".npmrc").write_text("registry=https://npm.corp.example/\n")
    package_lock = sub / "package-lock.json"
    package_lock.write_bytes(fixture("package-lock-base.json"))
    assert registry_settings(package_lock, package_lock.read_bytes(), tmp_path) == NONE


def test_registry_settings_follow_the_parser_on_a_long_comment_header(tmp_path: Path) -> None:
    """The parser looks at the first 65,536 characters; 81,200 bytes of
    comments in 41,200 characters still leave __metadata inside them."""
    (tmp_path / ".yarnrc.yml").write_text("npmRegistryServer: https://npm.corp.example\n")
    lock = tmp_path / "yarn.lock"
    padding = "".join("# " + "\u00e9" * 100 + "\n" for _ in range(400))
    lock.write_bytes(padding.encode() + fixture("yarn-berry-head.lock"))
    data = lock.read_bytes()
    assert len(data) - len(fixture("yarn-berry-head.lock")) > 65536
    assert is_berry_text(data.decode())
    settings = registry_settings(lock, data, tmp_path)
    assert settings == Registries(".yarnrc.yml", False, {})
    pins = parse("yarn.lock", data, registries=settings)
    assert "private registry, set in .yarnrc.yml" in {p.detail for p in pins}
    assert not any(p.source == "registry" for p in pins)
    # Past 65,536 characters neither reads it as Yarn 2+.
    lock.write_bytes(("#\n" * 40000).encode() + fixture("yarn-berry-head.lock"))
    assert registry_settings(lock, lock.read_bytes(), tmp_path) == NONE
    with pytest.raises(LockfileError, match="isn't a Yarn 1 lockfile"):
        parse("yarn.lock", lock.read_bytes())


def test_registry_settings_files_are_read_like_lockfiles(tmp_path: Path) -> None:
    head = tmp_path / "pnpm-lock.yaml"
    head.write_bytes(fixture("pnpm-lock-base.yaml"))
    data = head.read_bytes()
    secret = tmp_path / "secret"
    secret.write_text(
        "registry=https://npm.corp.example/\n//npm.corp.example/:_authToken=hunter2\n"
    )
    (tmp_path / ".npmrc").symlink_to(secret)
    with pytest.raises(LockfileError) as err:
        registry_settings(head, data, tmp_path)
    assert str(err.value) == (
        ".npmrc is not a regular file, so Garnet can't tell which registry "
        "pnpm-lock.yaml installs from"
    )
    (tmp_path / ".npmrc").unlink()
    (tmp_path / ".npmrc").mkdir()
    with pytest.raises(LockfileError, match="is not a regular file"):
        registry_settings(head, data, tmp_path)
    (tmp_path / ".npmrc").rmdir()
    (tmp_path / ".npmrc").write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(LockfileError, match="larger than 1 MiB"):
        registry_settings(head, data, tmp_path)
    (tmp_path / ".npmrc").write_bytes(b"registry=\xff\n")
    with pytest.raises(LockfileError, match="is not UTF-8"):
        registry_settings(head, data, tmp_path)
    berry_lock = tmp_path / "yarn.lock"
    berry_lock.write_bytes(fixture("yarn-berry-base.lock"))
    (tmp_path / ".yarnrc.yml").write_text("npmAuthToken: 'hunter2\n")
    with pytest.raises(LockfileError) as err:
        registry_settings(berry_lock, berry_lock.read_bytes(), tmp_path)
    assert str(err.value).endswith(".yarnrc.yml: invalid YAML at line 2, column 1")
    assert "hunter2" not in str(err.value)


# --- Yarn 2+ yarn.lock: the generated fixtures --------------------------------------------

BERRY_BASE_PINS = [
    # The project and the @fixture/lib workspace, the link: and the portal:
    # are the project's own code and have no pin. left-pad and resolve are
    # each listed as the release and as that release patched.
    ("@isaacs/string-locale-compare", "1.1.0", 17, "registry", None),
    ("debug", "4.3.6", 24, "registry", None),
    ("function-bind", "1.1.2", 56, "registry", None),
    ("hasown", "2.0.4", 63, "registry", None),
    ("is-core-module", "2.17.0", 72, "registry", None),
    ("is-number", "7.0.0", 81, "unsupported", "git source"),
    ("is-number", "6.0.0", 88, "registry", None),
    ("is-odd", "3.0.1", 95, "registry", None),
    ("js-tokens", "4.0.0", 104, "registry", None),
    ("left-pad", "1.3.0", 111, "registry", None),
    ("left-pad", "1.3.0", 118, "registry", None),
    ("local-dir", "1.0.0", 131, "unsupported", "file: source"),
    ("loose-envify", "1.4.0", 138, "registry", None),
    ("ms", "2.1.2", 149, "registry", None),
    ("ms", "2.1.3", 156, "registry", None),
    ("path-parse", "1.0.7", 163, "registry", None),
    ("react-dom", "18.3.1", 178, "registry", None),
    ("resolve", "1.22.8", 190, "registry", None),
    ("resolve", "1.22.8", 203, "registry", None),
    ("scheduler", "0.23.2", 216, "registry", None),
    ("supports-preserve-symlinks-flag", "1.0.0", 225, "registry", None),
    (
        "tarball-ms",
        "2.0.0",
        232,
        "unsupported",
        "resolved URL isn't this package's registry tarball",
    ),
    ("vendored", "1.0.0", 239, "unsupported", "file: source"),
]


def test_berry_pins_every_entry_at_its_key_line() -> None:
    data = fixture("yarn-berry-base.lock")
    pins = parse("yarn.lock", data)
    assert rows(pins) == BERRY_BASE_PINS
    assert {p.ecosystem for p in pins} == {"npm"}
    for pin in pins:
        assert _key_line(data, pin).startswith(f'"{pin.package}@')


def test_berry_metadata_version_6_from_yarn_3() -> None:
    assert rows(parse("yarn.lock", fixture("yarn-berry-v6.lock"))) == [
        ("@isaacs/string-locale-compare", "1.1.0", 8, "registry", None),
        ("debug", "4.3.6", 15, "registry", None),
        ("ms", "2.1.2", 37, "registry", None),
    ]


def test_a_berry_bump_is_one_npm_change_at_its_line() -> None:
    changes, unchecked = changes_for(
        "yarn.lock", fixture("yarn-berry-head.lock"), fixture("yarn-berry-base.lock")
    )
    assert [(c.ecosystem, c.package, c.baseline, c.candidate, c.line) for c in changes] == [
        ("npm", "debug", "4.3.6", "4.3.7", 24)
    ]
    assert unchecked == []


def test_a_new_berry_lockfile_reports_git_file_and_url_sources() -> None:
    _, unchecked = changes_for("yarn.lock", fixture("yarn-berry-base.lock"), None)
    assert [(u.change.package, u.change.line, u.detail) for u in unchecked] == [
        ("is-number", 81, "git source"),
        ("local-dir", 131, "file: source"),
        ("tarball-ms", 232, "resolved URL isn't this package's registry tarball"),
        ("vendored", 239, "file: source"),
    ]


def test_berry_is_detected_and_read_by_name_and_by_content() -> None:
    data = fixture("yarn-berry-base.lock")
    assert is_berry(data) and is_berry(fixture("yarn-berry-v6.lock"))
    assert detect("yarn.lock", data) == detect("old.lock", data) == "yarn.lock"
    assert rows(parse("old.lock", data)) == BERRY_BASE_PINS
    assert rows(parse("yarn.lock", b"\xef\xbb\xbf" + data)) == BERRY_BASE_PINS


# --- Yarn 2+ yarn.lock: entries -----------------------------------------------------------

METADATA = "__metadata:\n  version: 8\n  cacheKey: 10c0\n"


def berry_lock(*entries: str, metadata: str = METADATA) -> bytes:
    """A Yarn 4 lockfile; the first entry's key is at line 5."""
    return (metadata + "".join("\n" + e for e in entries)).encode()


def entry(key: str, resolution: str, version: str = "1.0.0", checksum: str = "10c0/aaaa") -> str:
    fields = [f'"{key}":', f"  version: {version}", f'  resolution: "{resolution}"']
    if checksum:
        fields.append(f"  checksum: {checksum}")
    return "\n".join([*fields, "  languageName: node", "  linkType: hard"]) + "\n"


ROOT = "locator=app%40workspace%3A."
JSR_YARN = "JSR registry, Yarn's default for @jsr packages"
LIB = "locator=%40app%2Flib%40workspace%3Apackages%2Flib"
PATCH = "x@patch:x@npm%3A1.0.0"
OUTSIDE = ("x", "1.0.0", "unsupported", "patch file outside the project")
REGISTRY = ("x", "1.0.0", "registry", None)


@pytest.mark.parametrize(
    ("resolution", "expected"),
    [
        ("x@npm:1.0.0", REGISTRY),
        ("@s/x@npm:1.0.0", ("@s/x", "1.0.0", "registry", None)),
        ("x@npm:^1.0.0", ("x", "1.0.0", "unsupported", "unsupported source")),
        (
            "x@npm:1.0.0::__archiveUrl=https%3A%2F%2Fregistry.npmjs.org%2Fx%2F-%2Fx-1.0.0.tgz",
            REGISTRY,
        ),
        (
            "x@npm:1.0.0::__archiveUrl=https%3A%2F%2Fnpm.corp.example%2Fx%2F-%2Fx-1.0.0.tgz",
            ("x", "1.0.0", "unsupported", "private registry"),
        ),
        (
            "x@npm:1.0.0::__archiveUrl=https%3A%2F%2Fregistry.npmjs.org%2Fx%2F-%2Fx-1.0.0.tgz&a=b",
            ("x", "1.0.0", "unsupported", "unsupported source"),
        ),
        ("x@workspace:packages/x", None),
        (f"x@link:./vendor/x::{ROOT}", None),
        (f"x@portal:../../vendor/x::{LIB}", None),
        (f"x@link:../x::{ROOT}", ("x", "1.0.0", "unsupported", "link: outside the project")),
        (
            f"x@portal:../../../x::{LIB}",
            ("x", "1.0.0", "unsupported", "portal: outside the project"),
        ),
        (f"x@link:/opt/x::{ROOT}", ("x", "1.0.0", "unsupported", "link: outside the project")),
        ("x@link:./x", ("x", "1.0.0", "unsupported", "link: outside the project")),
        (
            "x@link:./x::locator=y%40npm%3A1.0.0",
            ("x", "1.0.0", "unsupported", "link: outside the project"),
        ),
        (f"{PATCH}#~/patches/x.patch::version=1.0.0&hash=abc", REGISTRY),
        (f"{PATCH}#./patches/x.patch::version=1.0.0&hash=abc&{ROOT}", REGISTRY),
        (f"{PATCH}#../../patches/x.patch::version=1.0.0&hash=abc&{LIB}", REGISTRY),
        (f"{PATCH}#optional!builtin<compat/x>::version=1.0.0&hash=abc", REGISTRY),
        (f"{PATCH}#~/a.patch&./b.patch::version=1.0.0&hash=abc&{ROOT}", REGISTRY),
        (f"{PATCH}#../x.patch::version=1.0.0&hash=abc&{ROOT}", OUTSIDE),
        (f"{PATCH}#../../../x.patch::version=1.0.0&hash=abc&{LIB}", OUTSIDE),
        (f"{PATCH}#/tmp/x.patch::version=1.0.0&hash=abc&{ROOT}", OUTSIDE),
        (f"{PATCH}#C:/x.patch::version=1.0.0&hash=abc&{ROOT}", OUTSIDE),
        (f"{PATCH}#~/../x.patch::version=1.0.0&hash=abc", OUTSIDE),
        (f"{PATCH}#./x.patch::version=1.0.0&hash=abc", OUTSIDE),
        (f"{PATCH}#~/a.patch&../b.patch::version=1.0.0&hash=abc&{ROOT}", OUTSIDE),
        (f"{PATCH}#.\\\\..\\\\x.patch::version=1.0.0&hash=abc&{ROOT}", OUTSIDE),
        (
            "x@patch:x@https%3A%2F%2Fgithub.com%2Fo%2Fx.git%23commit%3Dabc#~/x.patch::hash=abc",
            ("x", "1.0.0", "unsupported", "git source"),
        ),
        ("x@patch:x@workspace%3Apackages%2Fx#~/x.patch::version=1.0.0&hash=abc", None),
        # A patch file outside the project counts even on the project's own code.
        (
            f"x@patch:x@workspace%3Apackages%2Fx#../../../x.patch::version=1.0.0&hash=abc&{LIB}",
            OUTSIDE,
        ),
        (
            "x@patch:x@portal%3A./vendor/x%3A%3Alocator=app%2540workspace%253A.#../outside.patch"
            f"::version=1.0.0&hash=abc&{ROOT}",
            OUTSIDE,
        ),
        # Yarn 4 reads Yarn 3's optional flag as part of a relative path.
        (f"{PATCH}#~builtin<compat/x>::version=1.0.0&hash=abc", OUTSIDE),
        (f"x@file:./x.tgz#./x.tgz::hash=abc&{ROOT}", ("x", "1.0.0", "unsupported", "file: source")),
        (f"x@file:./x#./x::hash=abc&{ROOT}", ("x", "1.0.0", "unsupported", "file: source")),
        (
            f"x@exec:./gen.js#./gen.js::hash=abc&{ROOT}",
            ("x", "1.0.0", "unsupported", "exec: source"),
        ),
        ("x@https://github.com/o/x.git#commit=abc", ("x", "1.0.0", "unsupported", "git source")),
        (
            "x@git+ssh://git@github.com/o/x.git#commit=abc",
            ("x", "1.0.0", "unsupported", "git source"),
        ),
        ("x@github:o/x#commit=abc", ("x", "1.0.0", "unsupported", "git source")),
        ("x@https://registry.npmjs.org/x/-/x-1.0.0.tgz", REGISTRY),
        (
            "x@https://example.com/x.tgz",
            ("x", "1.0.0", "unsupported", "tarball URL outside the npm registry"),
        ),
        ("x@other:thing", ("x", "1.0.0", "unsupported", "unsupported source")),
        ("@jsr/x@npm:1.0.0", ("@jsr/x", "1.0.0", "unsupported", JSR_YARN)),
        (
            "Evil\u202e@npm:1.0.0",
            (INVALID_NAME, "1.0.0", "unsupported", "not a valid npm package name"),
        ),
    ],
)
def test_berry_sources(resolution: str, expected: tuple[str, str, str, str | None] | None) -> None:
    pins = parse("yarn.lock", berry_lock(entry("x@whatever", resolution)))
    if expected is None:
        assert pins == []
        return
    (pin,) = pins
    assert (pin.package, pin.version, pin.source, pin.detail) == expected
    assert pin.line == 5 and pin.ecosystem == "npm"


YARN3 = "__metadata:\n  version: 6\n  cacheKey: 8\n"


@pytest.mark.parametrize(
    ("resolution", "version", "expected"),
    [
        # Written by Yarn 3.8.7 (yarn install, YARN_ENABLE_SCRIPTS=0) for
        # typescript 5.5.4, resolve 1.22.8 and a patch in .yarn/patches.
        (
            "typescript@patch:typescript@npm%3A5.5.4#~builtin<compat/typescript>"
            "::version=5.5.4&hash=379a07",
            "5.5.4",
            ("typescript", "5.5.4", "registry", None),
        ),
        (
            "resolve@patch:resolve@npm%3A1.22.8#~builtin<compat/resolve>"
            "::version=1.22.8&hash=c3c19d",
            "1.22.8",
            ("resolve", "1.22.8", "registry", None),
        ),
        (
            "lodash@patch:lodash@npm%3A4.17.21#./.yarn/patches/lodash.patch"
            "::version=4.17.21&hash=172044&locator=y3%40workspace%3A.",
            "4.17.21",
            ("lodash", "4.17.21", "registry", None),
        ),
        # Yarn 3 has no project paths: ~/x.patch is optional /x.patch.
        (f"{PATCH}#~/patches/x.patch::version=1.0.0&hash=abc", "1.0.0", OUTSIDE),
        (f"{PATCH}#~./x.patch::version=1.0.0&hash=abc&{ROOT}", "1.0.0", REGISTRY),
        (f"{PATCH}#~../x.patch::version=1.0.0&hash=abc&{ROOT}", "1.0.0", OUTSIDE),
        # Nor Yarn 4's flags: this is a relative path, with no workspace to start from.
        (f"{PATCH}#optional!builtin<compat/x>::version=1.0.0&hash=abc", "1.0.0", OUTSIDE),
        # Yarn 3 has no JSR default; it fetches @jsr packages from its registry.
        ("@jsr/x@npm:1.0.0", "1.0.0", ("@jsr/x", "1.0.0", "registry", None)),
    ],
)
def test_berry_yarn_3_patch_paths(
    resolution: str, version: str, expected: tuple[str, str, str, str | None]
) -> None:
    data = berry_lock(entry("x@whatever", resolution, version=version), metadata=YARN3)
    (pin,) = parse("yarn.lock", data)
    assert (pin.package, pin.version, pin.source, pin.detail) == expected


def test_a_berry_jsr_package_is_checked_when_yarnrc_configures_the_scope() -> None:
    data = berry_lock(entry("@jsr/x@npm:1.0.0", "@jsr/x@npm:1.0.0"))
    public = yarnrc("npmScopes:\n  jsr:\n    npmRegistryServer: https://registry.npmjs.org\n")
    assert rows(parse("yarn.lock", data, registries=public)) == [
        ("@jsr/x", "1.0.0", 5, "registry", None)
    ]
    # A scope without a server uses npmRegistryServer, as in Yarn's getScopeRegistry.
    token_only = yarnrc("npmScopes:\n  jsr:\n    npmAuthToken: hunter2\n")
    assert rows(parse("yarn.lock", data, registries=token_only)) == [
        ("@jsr/x", "1.0.0", 5, "registry", None)
    ]
    corp = yarnrc("npmScopes:\n  jsr:\n    npmRegistryServer: https://npm.corp.example\n")
    assert [p.detail for p in parse("yarn.lock", data, registries=corp)] == [
        "private registry, set in .yarnrc.yml"
    ]
    other = yarnrc("npmScopes:\n  corp:\n    npmRegistryServer: https://npm.corp.example\n")
    assert [p.detail for p in parse("yarn.lock", data, registries=other)] == [JSR_YARN]
    # Yarn never reads an '@jsr' entry, so the JSR default still applies.
    at_jsr = yarnrc("npmScopes:\n  '@jsr':\n    npmRegistryServer: https://registry.npmjs.org\n")
    assert [p.detail for p in parse("yarn.lock", data, registries=at_jsr)] == [JSR_YARN]


def test_an_alias_is_checked_as_the_package_it_resolves_to() -> None:
    data = berry_lock(entry("my-ms@npm:ms@2.1.3", "ms@npm:2.1.3", version="2.1.3"))
    assert rows(parse("yarn.lock", data)) == [("ms", "2.1.3", 5, "registry", None)]


def test_a_berry_git_dependency_moving_to_another_commit_is_reported() -> None:
    def at(sha: str, checksum: str = "10c0/aaaa") -> bytes:
        res = f"lib@https://github.com/o/lib.git#commit={sha}"
        return berry_lock(entry(res, res, checksum=checksum))

    assert changes_for("yarn.lock", at("aaa"), at("aaa")) == ([], [])
    _, unchecked = changes_for("yarn.lock", at("bbb"), at("aaa"))
    assert [(u.change.package, u.detail) for u in unchecked] == [("lib", "git source")]
    # The same commit with new content (a new checksum) is reported too.
    _, unchecked = changes_for("yarn.lock", at("aaa", "10c0/bbbb"), at("aaa"))
    assert [(u.change.package, u.detail) for u in unchecked] == [("lib", "git source")]


def test_a_berry_private_registry_is_reported_with_the_file_that_set_it() -> None:
    corp = yarnrc("npmScopes:\n  corp:\n    npmRegistryServer: https://npm.corp.example\n")
    data = berry_lock(
        entry("ms@npm:2.1.3", "ms@npm:2.1.3", version="2.1.3"),
        entry("@corp/x@npm:1.0.0", "@corp/x@npm:1.0.0"),
    )
    assert rows(parse("yarn.lock", data, registries=corp)) == [
        ("ms", "2.1.3", 5, "registry", None),
        ("@corp/x", "1.0.0", 12, "unsupported", "private registry, set in .yarnrc.yml"),
    ]
    everything = yarnrc("npmRegistryServer: https://npm.corp.example\n")
    pins = parse("yarn.lock", data, registries=everything)
    assert {p.detail for p in pins} == {"private registry, set in .yarnrc.yml"}


def test_a_line_break_in_a_berry_version_is_escaped_in_the_report() -> None:
    res = "lib@https://github.com/o/lib.git#commit=abc"
    data = berry_lock(entry(res, res, version='"1.0.0\\n# Approved"'))
    _, unchecked = changes_for("yarn.lock", data, None)
    (u,) = unchecked
    out = to_text(report([unchecked_result(u.change, u.rule_id, u.detail)]))
    assert "1.0.0\\x0a# Approved" in out and "\n# Approved" not in out


def test_an_invalid_berry_name_is_reported_without_echoing_it() -> None:
    hostile = "evil\u202e[x](javascript:hunter2.example)"
    data = berry_lock(entry(f"{hostile}@npm:1.0.0", f"{hostile}@npm:1.0.0"))
    _, unchecked = changes_for("yarn.lock", data, None)
    (u,) = unchecked
    assert (u.change.package, u.rule_id, u.change.line) == (INVALID_NAME, "GRN-E005", 5)
    rep = report([unchecked_result(u.change, u.rule_id, u.detail)])
    doc = json.loads(to_json(rep))
    for out in (to_json(rep), to_text(rep), markdown.render(doc), sarif.dumps(sarif.render(doc))):
        assert "hunter2" not in out


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (berry_lock(entry("x@npm:1.0.0", "x@npm:1.0.1")), "line 5: a version that doesn't match"),
        (
            berry_lock(entry("x@virtual:abc#npm:1.0.0", "x@virtual:abc#npm:1.0.0")),
            "line 5: a virtual:",
        ),
        (
            berry_lock(entry("x@patch:x", f"{PATCH}#~/x%ZZ.patch")),
            "line 5: a resolution Yarn can't",
        ),
        (berry_lock(entry("x@patch:x", "x@patch:hunter2")), "line 5: a patch: resolution with no"),
        (
            berry_lock(entry("x@patch:x", "x@patch:x@patch%3Ax%40npm%253A1.0.0%23~%2Fa.patch#~/b")),
            "line 5: a patch: resolution of a patch: resolution",
        ),
        (berry_lock(entry("x@npm:1.0.0", "hunter2")), "line 5: a resolution that isn't name@ref"),
        (berry_lock('"x@npm:1.0.0":\n  version: 1.0.0\n'), "line 5: an entry with no resolution"),
        (berry_lock('"x@npm:1.0.0": hunter2\n'), "line 5: an entry that isn't"),
        (berry_lock(entry("x@npm:1.0.0", "x@npm:1.0.0", version="[1]")), "line 5: a version that"),
        (
            berry_lock(entry("x@npm:1.0.0", "x@npm:1.0.0", checksum="{a: b}")),
            "line 5: a checksum that",
        ),
        (berry_lock(metadata="__metadata:\n  version: 3\n"), "line 1: __metadata version 3 isn't"),
        (berry_lock(metadata="__metadata:\n  version: 9\n"), "line 1: __metadata version 9 isn't"),
        (
            berry_lock(metadata="# c\n__metadata:\n  version: hunter2\n"),
            "line 2: __metadata a version isn't one Garnet reads (4 to 8)",
        ),
        (
            berry_lock(metadata="__metadata:\n  version: \u00b3\n"),
            "line 1: __metadata a version isn't one Garnet reads (4 to 8)",
        ),
        (
            berry_lock(metadata="__metadata:\n  version: \u0668\n"),
            "line 1: __metadata a version isn't one Garnet reads (4 to 8)",
        ),
        (
            berry_lock(metadata="__metadata:\n  version: " + "9" * 5000 + "\n"),
            "line 1: __metadata a version isn't one Garnet reads (4 to 8)",
        ),
        (
            berry_lock(metadata="__metadata:\n  version: 8\n  version: 8\n"),
            "line 3: a key repeated",
        ),
        (
            berry_lock(metadata="__metadata:\n  version: 8\n") + b"x: &a 1\n",
            "line 3: a YAML anchor",
        ),
        (
            berry_lock(metadata="__metadata:\n  version: 8\n") + b"x:\n  - *a\n",
            "line 4: a YAML alias",
        ),
    ],
)
def test_malformed_berry_lockfiles_are_lockfile_errors(data: bytes, message: str) -> None:
    with pytest.raises(LockfileError) as err:
        parse("yarn.lock", data)
    assert message in str(err.value)
    assert "hunter2" not in str(err.value)


def test_berry_metadata_versions_4_to_8_are_read() -> None:
    for version in berry.METADATA_VERSIONS:
        data = berry_lock(
            entry("x@npm:1.0.0", "x@npm:1.0.0"),
            metadata=f"__metadata:\n  version: {version}\n  cacheKey: 8\n",
        )
        assert rows(parse("yarn.lock", data)) == [("x", "1.0.0", 5, "registry", None)]
    assert list(berry.METADATA_VERSIONS) == [4, 5, 6, 7, 8]


def test_a_berry_parse_needs_metadata() -> None:
    with pytest.raises(LockfileError, match="no __metadata entry"):
        berry.parse('"x@npm:1.0.0":\n  version: 1.0.0\n  resolution: "x@npm:1.0.0"\n')


@pytest.mark.parametrize("name", ["pnpm-lock.yaml", "yarn.lock"])
def test_oversized_yaml_lockfiles_are_refused_before_parsing(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.setattr(lock_base, "MAX_LOCKFILE_BYTES", 100)
    data = fixture("pnpm-lock-base.yaml" if name == "pnpm-lock.yaml" else "yarn-berry-base.lock")
    with pytest.raises(LockfileError, match="larger than 64 MiB"):
        parse(name, data)


# --- discovery and the CLI ---------------------------------------------------------------


def test_discover_lists_pnpm_and_berry_lockfiles(tmp_path: Path) -> None:
    (tmp_path / "pnpm-lock.yaml").write_bytes(fixture("pnpm-lock-base.yaml"))
    (tmp_path / "yarn.lock").write_bytes(fixture("yarn-berry-base.lock"))
    (tmp_path / "uv.lock").write_bytes(b"version = 1\n")
    assert [p.name for p in discover(tmp_path)] == ["uv.lock", "yarn.lock", "pnpm-lock.yaml"]


def _fake_evaluate(seen: list[Change]):  # type: ignore[no-untyped-def]
    def evaluate(changes, *, policy=None, options=None):  # type: ignore[no-untyped-def]
        seen.extend(changes)
        return [
            run_checks(c, release(c.baseline or "0"), release(c.candidate, tag=False))
            for c in changes
        ]

    return evaluate


@pytest.mark.parametrize(
    ("name", "base", "head", "line"),
    [
        ("pnpm-lock.yaml", "pnpm-lock-base.yaml", "pnpm-lock-head.yaml", 59),
        ("yarn.lock", "yarn-berry-base.lock", "yarn-berry-head.lock", 24),
    ],
)
def test_check_reads_pnpm_and_berry_lockfiles_from_git(
    tmp_path, monkeypatch, capsys, name, base, head, line
) -> None:
    from garnet_guard import cli

    _repo(tmp_path)
    (tmp_path / name).write_bytes(fixture(base))
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    (tmp_path / name).write_bytes(fixture(head))
    seen: list[Change] = []
    monkeypatch.setattr(cli, "evaluate", _fake_evaluate(seen))
    monkeypatch.chdir(tmp_path)
    assert main(["check", "--git-base", "HEAD", "--format", "json", "--no-policy"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert [
        (c.ecosystem, c.package, c.baseline, c.candidate, c.lockfile, c.line) for c in seen
    ] == [("npm", "debug", "4.3.6", "4.3.7", name, line)]
    (result,) = sarif.render(doc)["runs"][0]["results"]
    location = result["locations"][0]["physicalLocation"]
    assert (location["artifactLocation"]["uri"], location["region"]["startLine"]) == (name, line)


def test_check_reads_a_yarn_lock_that_became_berry(tmp_path, monkeypatch, capsys) -> None:
    from garnet_guard import cli

    _repo(tmp_path)
    (tmp_path / "yarn.lock").write_bytes(fixture("yarn-base.lock"))
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    (tmp_path / "yarn.lock").write_bytes(fixture("yarn-berry-base.lock"))
    seen: list[Change] = []
    monkeypatch.setattr(cli, "evaluate", _fake_evaluate(seen))
    monkeypatch.chdir(tmp_path)
    assert main(["check", "--git-base", "HEAD", "--format", "json", "--no-policy"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert ("debug", "2.6.9", "4.3.6", 24) in [
        (c.package, c.baseline, c.candidate, c.line) for c in seen
    ]
    assert {
        (r["package"], r["findings"][0]["rule_id"])
        for r in doc["changes"]
        if r["findings"] and r["findings"][0]["rule_id"] == "GRN-E005"
    } == {
        ("is-number", "GRN-E005"),
        ("local-dir", "GRN-E005"),
        ("tarball-ms", "GRN-E005"),
        ("vendored", "GRN-E005"),
    }


def test_check_reports_a_private_registry_without_naming_it(tmp_path, monkeypatch, capsys) -> None:
    from garnet_guard import cli

    monkeypatch.chdir(tmp_path)
    (tmp_path / "base.yaml").write_bytes(fixture("pnpm-lock-base.yaml"))
    (tmp_path / "pnpm-lock.yaml").write_bytes(fixture("pnpm-lock-head.yaml"))
    (tmp_path / ".npmrc").write_text(
        "registry=https://npm.corp.example/\n//npm.corp.example/:_authToken=hunter2\n"
    )
    seen: list[Change] = []
    monkeypatch.setattr(cli, "evaluate", _fake_evaluate(seen))
    args = ["check", "--base", "base.yaml", "--head", "pnpm-lock.yaml", "--no-policy"]
    assert main([*args, "--format", "json"]) == 0
    out = capsys.readouterr().out
    assert seen == []
    doc = json.loads(out)
    assert [(r["package"], r["candidate"]) for r in doc["changes"]] == [("debug", "4.3.7")]
    assert main([*args, "--format", "sarif"]) == 0
    out += capsys.readouterr().out
    assert main(args) == 0
    text = capsys.readouterr().out
    assert "debug was not checked: private registry, set in .npmrc" in text
    for shown in (out, text, markdown.render(doc)):
        assert "hunter2" not in shown and "corp.example" not in shown


def test_check_refuses_a_symlinked_npmrc(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "base.yaml").write_bytes(fixture("pnpm-lock-base.yaml"))
    (tmp_path / "pnpm-lock.yaml").write_bytes(fixture("pnpm-lock-head.yaml"))
    (tmp_path / "token").write_text("//npm.corp.example/:_authToken=hunter2\n")
    (tmp_path / ".npmrc").symlink_to(tmp_path / "token")
    assert main(["check", "--base", "base.yaml", "--head", "pnpm-lock.yaml", "--no-policy"]) == 3
    err = capsys.readouterr().err
    assert err == (
        "garnet: .npmrc is not a regular file, so Garnet can't tell which registry "
        "pnpm-lock.yaml installs from\n"
    )


def test_cli_reports_hostile_yaml_as_exit_3_without_quoting_it(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "base.yaml").write_bytes(fixture("pnpm-lock-base.yaml"))
    bomb = b"lockfileVersion: '9.0'\na: &a [hunter2, hunter2]\nb: &b [*a, *a]\nc: [*b, *b]\n"
    (tmp_path / "pnpm-lock.yaml").write_bytes(bomb)
    args = ["check", "--base", "base.yaml", "--head", "pnpm-lock.yaml", "--no-policy"]
    assert main(args) == 3
    err = capsys.readouterr().err
    assert err == "garnet: pnpm-lock.yaml: line 2: a YAML anchor, which Garnet refuses\n"
    (tmp_path / "pnpm-lock.yaml").write_bytes(fixture("pnpm-lock-head.yaml"))
    (tmp_path / "base.yaml").write_bytes(b"lockfileVersion: '5.4'\n")
    assert main(args) == 3
    err = capsys.readouterr().err
    assert "regenerate the lockfile with pnpm 8 or later (in the base version)" in err
