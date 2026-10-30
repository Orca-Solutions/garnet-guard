"""npm lockfiles: package-lock.json, yarn.lock (classic and Berry), pnpm-lock.yaml."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from garnet_guard.cli import main
from garnet_guard.engine import run_checks
from garnet_guard.lockfiles import ECOSYSTEM, LockfileError, detect, parse
from garnet_guard.lockfiles.pnpm import split_key
from garnet_guard.models import Change
from garnet_guard.workspace import changes_for, dedupe, discover
from tests.builders import release


def _line(text: str, needle: str) -> int:
    """1-based number of the first line containing ``needle``."""
    for i, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return i
    raise AssertionError(f"{needle!r} not in text")


def _summary(text: str, name: str) -> list[tuple[str, str | None, str, str | None]]:
    return [(p.package, p.version, p.source, p.detail) for p in parse(name, text.encode())]


# package-lock.json ----------------------------------------------------------------

PACKAGE_LOCK = {
    "name": "demo",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {"name": "demo", "version": "1.0.0", "dependencies": {"chalk": "^5.6.0"}},
        "node_modules/@ctrl/tinycolor": {
            "version": "4.1.0",
            "resolved": "https://registry.npmjs.org/@ctrl/tinycolor/-/tinycolor-4.1.0.tgz",
            "integrity": "sha512-aaa",
            "license": "MIT",
        },
        "node_modules/chalk": {
            "version": "5.6.0",
            "resolved": "https://registry.npmjs.org/chalk/-/chalk-5.6.0.tgz",
            "integrity": "sha512-bbb",
            "dependencies": {"supports-color": "^7.1.0"},
        },
        "node_modules/chalk/node_modules/supports-color": {
            "version": "7.2.0",
            "resolved": "https://registry.npmjs.org/supports-color/-/supports-color-7.2.0.tgz",
            "integrity": "sha512-ccc",
        },
        "node_modules/supports-color": {
            "version": "9.4.0",
            "resolved": "https://registry.npmjs.org/supports-color/-/supports-color-9.4.0.tgz",
            "integrity": "sha512-ddd",
        },
        "node_modules/string-width-cjs": {
            "name": "string-width",
            "version": "4.2.3",
            "resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz",
            "integrity": "sha512-eee",
        },
        "node_modules/mylib": {
            "version": "1.0.0",
            "resolved": "git+ssh://git@github.com/x/mylib.git#abc",
            "license": "MIT",
        },
        "node_modules/tarball-dep": {
            "version": "1.0.0",
            "resolved": "file:vendor/tarball-dep-1.0.0.tgz",
        },
        "node_modules/private-pkg": {
            "version": "2.0.0",
            "resolved": "https://npm.pkg.github.com/download/@x/private-pkg/2.0.0/abc",
            "integrity": "sha512-fff",
        },
        "node_modules/npm/node_modules/abbrev": {
            "version": "1.1.1",
            "inBundle": True,
            "license": "ISC",
        },
        "node_modules/no-version": {
            "resolved": "https://registry.npmjs.org/no-version/-/no-version-0.0.0.tgz",
        },
        "packages/app": {"name": "app", "version": "0.0.1"},
        "node_modules/app": {"resolved": "packages/app", "link": True},
    },
}
PACKAGE_LOCK_TEXT = json.dumps(PACKAGE_LOCK, indent=2) + "\n"


def test_package_lock_v3() -> None:
    pins = parse("package-lock.json", PACKAGE_LOCK_TEXT.encode())
    assert [(p.package, p.version, p.source, p.detail) for p in pins] == [
        ("@ctrl/tinycolor", "4.1.0", "npm", None),
        ("chalk", "5.6.0", "npm", None),
        ("supports-color", "7.2.0", "npm", None),  # nested copy, its own version
        ("supports-color", "9.4.0", "npm", None),
        ("string-width", "4.2.3", "npm", None),  # aliased: the real name wins
        ("mylib", "1.0.0", "unsupported", "git source"),
        ("tarball-dep", "1.0.0", "unsupported", "local path"),
        ("private-pkg", "2.0.0", "unsupported", "URL outside the registry"),
        ("abbrev", "1.1.1", "unsupported", "bundled with another package"),
        ("no-version", None, "unsupported", "no version"),
    ]
    by_name = {(p.package, p.version): p.line for p in pins}
    assert by_name[("@ctrl/tinycolor", "4.1.0")] == _line(PACKAGE_LOCK_TEXT, '"version": "4.1.0"')
    assert by_name[("supports-color", "7.2.0")] == _line(PACKAGE_LOCK_TEXT, '"version": "7.2.0"')
    assert by_name[("no-version", None)] == _line(PACKAGE_LOCK_TEXT, '"node_modules/no-version"')


def test_package_lock_v2_and_shrinkwrap() -> None:
    v2 = dict(PACKAGE_LOCK, lockfileVersion=2)
    v2["dependencies"] = {"chalk": {"version": "5.6.0"}}  # the v1 section v2 keeps
    text = json.dumps(v2, indent=2)
    assert detect("npm-shrinkwrap.json", b"") == "package-lock.json"
    names = {p.package for p in parse("npm-shrinkwrap.json", text.encode())}
    assert "chalk" in names and "@ctrl/tinycolor" in names


def test_package_lock_v1_is_refused() -> None:
    v1 = {"name": "demo", "lockfileVersion": 1, "dependencies": {"chalk": {"version": "4.0.0"}}}
    with pytest.raises(LockfileError, match="lockfileVersion 1"):
        parse("package-lock.json", json.dumps(v1).encode())
    with pytest.raises(LockfileError, match="not a JSON object"):
        parse("package-lock.json", b"[]")


def test_package_lock_json_errors_do_not_quote_the_file() -> None:
    with pytest.raises(LockfileError) as err:
        parse("package-lock.json", b'{\n  "hunter2": }\n')
    assert "hunter2" not in str(err.value)
    assert "line 2" in str(err.value)


def test_package_lock_refuses_names_that_are_not_packages() -> None:
    doc = {
        "lockfileVersion": 3,
        "packages": {
            "node_modules/../etc": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0.tgz",
            }
        },
    }
    (pin,) = parse("package-lock.json", json.dumps(doc).encode())
    assert pin.source == "unsupported"
    assert pin.detail == "not an npm package name"


# yarn.lock ------------------------------------------------------------------------

YARN_CLASSIC = """\
# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.10.4"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.10.4.tgz#168da1a36e90da68ae8d49c0f1b48c7c6249213a"
  integrity sha512-aaa
  dependencies:
    "@babel/highlight" "^7.10.4"

chalk@^4.1.0:
  version "4.1.2"
  resolved "https://registry.yarnpkg.com/chalk/-/chalk-4.1.2.tgz#aac4e2b7734a740867aeb16bf02aad556a1e7a01"
  integrity sha512-bbb

"string-width-cjs@npm:string-width@^4.2.0", string-width@^4.2.0:
  version "4.2.3"
  resolved "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz#269c7117d27b05ad2e536830a8ec895ef9c6d010"
  integrity sha512-ccc

"mylib@git+ssh://git@github.com/x/mylib.git#abc":
  version "1.0.0"
  resolved "git+ssh://git@github.com/x/mylib.git#abc123"

"local-thing@file:../local-thing":
  version "0.0.1"

private-pkg@^2.0.0:
  version "2.0.0"
  resolved "https://npm.pkg.github.com/download/@x/private-pkg/2.0.0/abc#deadbeef"
  integrity sha512-ddd
"""


def test_yarn_classic() -> None:
    assert _summary(YARN_CLASSIC, "yarn.lock") == [
        ("@babel/code-frame", "7.10.4", "npm", None),
        ("chalk", "4.1.2", "npm", None),
        ("string-width", "4.2.3", "npm", None),  # name from the tarball URL, not the alias
        ("mylib", "1.0.0", "unsupported", "git source"),
        ("local-thing", "0.0.1", "unsupported", "local path"),
        ("private-pkg", "2.0.0", "unsupported", "URL outside the registry"),
    ]
    pins = parse("yarn.lock", YARN_CLASSIC.encode())
    assert pins[1].line == _line(YARN_CLASSIC, 'version "4.1.2"')


YARN_BERRY = """\
# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"@babel/core@npm:^7.0.0, @babel/core@npm:^7.10.4":
  version: 7.24.0
  resolution: "@babel/core@npm:7.24.0"
  dependencies:
    "@babel/code-frame": "npm:^7.24.0"
  checksum: 10c0/aaa
  languageName: node
  linkType: hard

"chalk@npm:^5.3.0":
  version: 5.3.0
  resolution: "chalk@npm:5.3.0"
  checksum: 10c0/bbb
  languageName: node
  linkType: hard

"string-width-cjs@npm:string-width@^4.2.0, string-width@npm:^4.2.0":
  version: 4.2.3
  resolution: "string-width@npm:4.2.3"
  checksum: 10c0/ccc
  languageName: node
  linkType: hard

"demo@workspace:.":
  version: 0.0.0-use.local
  resolution: "demo@workspace:."
  dependencies:
    chalk: "npm:^5.3.0"
  languageName: unknown
  linkType: soft

"typescript@patch:typescript@npm%3A5.3.3#optional!builtin<compat/typescript>":
  version: 5.3.3
  resolution: "typescript@patch:typescript@npm%3A5.3.3#optional!builtin<compat/typescript>::version=5.3.3&hash=e012d7"
  checksum: 10c0/ddd
  languageName: node
  linkType: hard

"mylib@https://github.com/x/mylib.git#commit=abc":
  version: 1.0.0
  resolution: "mylib@https://github.com/x/mylib.git#commit=abc"
  checksum: 10c0/eee
  languageName: node
  linkType: hard

"local-thing@portal:../local-thing::locator=demo%40workspace%3A.":
  version: 0.0.1
  resolution: "local-thing@portal:../local-thing::locator=demo%40workspace%3A."
  languageName: node
  linkType: soft
"""


def test_yarn_berry() -> None:
    assert _summary(YARN_BERRY, "yarn.lock") == [
        ("@babel/core", "7.24.0", "npm", None),
        ("chalk", "5.3.0", "npm", None),
        ("string-width", "4.2.3", "npm", None),
        ("typescript", "5.3.3", "unsupported", "patched package"),
        ("mylib", "1.0.0", "unsupported", "git source or URL"),
        ("local-thing", "0.0.1", "unsupported", "local path"),
    ]
    pins = parse("yarn.lock", YARN_BERRY.encode())
    assert pins[0].line == _line(YARN_BERRY, "version: 7.24.0")


def test_yarn_entry_without_version_is_not_passed() -> None:
    text = 'chalk@^4.1.0:\n  resolved "https://registry.yarnpkg.com/chalk/-/chalk-4.1.2.tgz"\n'
    (pin,) = parse("yarn.lock", text.encode())
    assert (pin.package, pin.version, pin.source, pin.detail) == (
        "chalk",
        None,
        "unsupported",
        "no version",
    )


# pnpm-lock.yaml -------------------------------------------------------------------

PNPM_V9 = """\
lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      '@ctrl/tinycolor':
        specifier: ^4.1.0
        version: 4.1.0
      chalk:
        specifier: ^5.6.0
        version: 5.6.0

packages:

  '@ctrl/tinycolor@4.1.0':
    resolution: {integrity: sha512-aaa}
    engines: {node: '>=14'}

  chalk@5.6.0:
    resolution: {integrity: sha512-bbb}
    engines: {node: ^12.17.0 || ^14.13 || >=16.0.0}

  '@babel/core@7.24.0(supports-color@5.5.0)':
    resolution: {integrity: sha512-ccc}

  'mylib@git+ssh://git@github.com/x/mylib.git#abc':
    resolution: {commit: abc, repo: git+ssh://git@github.com/x/mylib.git, type: git}
    version: 1.0.0

  'local-thing@file:../local-thing':
    resolution: {directory: ../local-thing, type: directory}
    version: 0.0.1

  'private-pkg@https://npm.pkg.github.com/download/@x/private-pkg/2.0.0/abc':
    resolution: {tarball: https://npm.pkg.github.com/download/@x/private-pkg/2.0.0/abc}
    version: 2.0.0

  'mirrored@https://registry.npmjs.org/mirrored/-/mirrored-3.0.0.tgz':
    resolution: {tarball: https://registry.npmjs.org/mirrored/-/mirrored-3.0.0.tgz}
    version: 3.0.0

snapshots:

  '@ctrl/tinycolor@4.1.0': {}

  chalk@5.6.0: {}
"""

PNPM_V6 = """\
lockfileVersion: '6.0'

settings:
  autoInstallPeers: true

dependencies:
  chalk:
    specifier: ^5.3.0
    version: 5.3.0

packages:

  /chalk@5.3.0:
    resolution: {integrity: sha512-aaa}
    engines: {node: ^12.17.0 || ^14.13 || >=16.0.0}
    dev: false

  /@babel/core@7.0.0(supports-color@5.5.0):
    resolution: {integrity: sha512-bbb}
    dev: true
"""


def test_pnpm_v9() -> None:
    assert _summary(PNPM_V9, "pnpm-lock.yaml") == [
        ("@ctrl/tinycolor", "4.1.0", "npm", None),
        ("chalk", "5.6.0", "npm", None),
        ("@babel/core", "7.24.0", "npm", None),  # peer suffix stripped
        ("mylib", "1.0.0", "unsupported", "git source"),
        ("local-thing", "0.0.1", "unsupported", "local path"),
        ("private-pkg", "2.0.0", "unsupported", "URL outside the registry"),
        ("mirrored", "3.0.0", "npm", None),
    ]
    pins = parse("pnpm-lock.yaml", PNPM_V9.encode())
    assert pins[0].line == _line(PNPM_V9, "  '@ctrl/tinycolor@4.1.0':")
    assert pins[1].line == _line(PNPM_V9, "  chalk@5.6.0:")
    assert pins[3].line == _line(PNPM_V9, "  'mylib@git+ssh")


def test_pnpm_v6() -> None:
    assert _summary(PNPM_V6, "pnpm-lock.yaml") == [
        ("chalk", "5.3.0", "npm", None),
        ("@babel/core", "7.0.0", "npm", None),
    ]


def test_pnpm_split_key() -> None:
    assert split_key("/chalk@5.3.0") == ("chalk", "5.3.0")
    assert split_key("@babel/core@7.24.0(supports-color@5.5.0)") == ("@babel/core", "7.24.0")
    assert split_key("/@babel/core@7.0.0") == ("@babel/core", "7.0.0")
    assert split_key("mylib@git+ssh://git@github.com/x/mylib.git#abc") == (
        "mylib",
        "git+ssh://git@github.com/x/mylib.git#abc",
    )
    assert split_key("@scope/only") == ("@scope/only", "")


def test_pnpm_refuses_old_versions_aliases_and_bad_yaml() -> None:
    with pytest.raises(LockfileError, match="lockfileVersion 5.4"):
        parse("pnpm-lock.yaml", b"lockfileVersion: 5.4\npackages: {}\n")
    bomb = "lockfileVersion: '9.0'\nx: &a [1, 2]\npackages:\n  chalk@5.6.0:\n    resolution: *a\n"
    with pytest.raises(LockfileError, match="alias"):
        parse("pnpm-lock.yaml", bomb.encode())
    with pytest.raises(LockfileError) as err:
        parse("pnpm-lock.yaml", b"lockfileVersion: '9.0'\npackages:\n  hunter2: [\n")
    assert "hunter2" not in str(err.value)
    assert "invalid YAML at line" in str(err.value)
    with pytest.raises(LockfileError, match="not a mapping"):
        parse("pnpm-lock.yaml", b"- 1\n")


# detection, changes and the CLI ---------------------------------------------------


def test_detect_npm_lockfiles_by_name_and_content() -> None:
    assert detect("web/package-lock.json", b"") == "package-lock.json"
    assert detect("npm-shrinkwrap.json", b"") == "package-lock.json"
    assert detect("yarn.lock", b"") == "yarn.lock"
    assert detect("pnpm-lock.yaml", b"") == "pnpm-lock.yaml"
    assert detect("deps.lock", b'{\n  "name": "x",\n  "lockfileVersion": 3') == "package-lock.json"
    assert detect("deps.lock", b"lockfileVersion: '9.0'\n") == "pnpm-lock.yaml"
    assert detect("deps.lock", b"# yarn lockfile v1\n") == "yarn.lock"
    assert detect("deps.lock", b"__metadata:\n  version: 8\n") == "yarn.lock"
    assert {ECOSYSTEM[f] for f in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")} == {"npm"}


def test_changes_for_npm_lockfile() -> None:
    head_doc = json.loads(PACKAGE_LOCK_TEXT)
    head_doc["packages"]["node_modules/chalk"]["version"] = "5.6.1"
    head_doc["packages"]["node_modules/chalk"]["resolved"] = (
        "https://registry.npmjs.org/chalk/-/chalk-5.6.1.tgz"
    )
    head_doc["packages"]["node_modules/left-pad"] = {
        "version": "1.3.0",
        "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
    }
    head = json.dumps(head_doc, indent=2)
    changes, unchecked = changes_for("package-lock.json", head.encode(), PACKAGE_LOCK_TEXT.encode())
    assert [(c.ecosystem, c.package, c.baseline, c.candidate, c.lockfile) for c in changes] == [
        ("npm", "chalk", "5.6.0", "5.6.1", "package-lock.json"),
        ("npm", "left-pad", None, "1.3.0", "package-lock.json"),
    ]
    assert changes[0].line == _line(head, '"version": "5.6.1"')
    assert unchecked == []  # the git, path, private and bundled entries were already in base

    changes, unchecked = changes_for("package-lock.json", head.encode(), None)
    assert len(changes) == 6  # a new lockfile: every registry package is a change
    assert [(u.change.ecosystem, u.change.package, u.rule_id, u.detail) for u in unchecked] == [
        ("npm", "mylib", "GRN-E005", "git source"),
        ("npm", "tarball-dep", "GRN-E005", "local path"),
        ("npm", "private-pkg", "GRN-E005", "URL outside the registry"),
        ("npm", "abbrev", "GRN-E005", "bundled with another package"),
        ("npm", "no-version", "GRN-E005", "no version"),
    ]


def test_dedupe_keeps_ecosystems_apart() -> None:
    a = Change("pypi", "chalk", None, "1.0.0", lockfile="uv.lock")
    b = Change("npm", "chalk", None, "1.0.0", lockfile="package-lock.json")
    c = Change("npm", "chalk", None, "1.0.0", lockfile="yarn.lock")
    assert dedupe([a, b, c]) == [a, b]


def test_discover_lists_npm_lockfiles(tmp_path: Path) -> None:
    for name in ("pnpm-lock.yaml", "yarn.lock", "package-lock.json", "uv.lock"):
        (tmp_path / name).write_text("")
    assert [p.name for p in discover(tmp_path)] == [
        "uv.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    ]


def test_check_reads_a_package_lock_without_network(tmp_path, monkeypatch, capsys) -> None:
    from garnet_guard import cli

    base = tmp_path / "base.json"
    head = tmp_path / "package-lock.json"
    base.write_text(PACKAGE_LOCK_TEXT)
    head_doc = json.loads(PACKAGE_LOCK_TEXT)
    head_doc["packages"]["node_modules/@ctrl/tinycolor"]["version"] = "4.1.1"
    head_doc["packages"]["node_modules/mylib"]["version"] = "1.1.0"  # still from git
    head.write_text(json.dumps(head_doc, indent=2) + "\n")

    def fake_evaluate(changes, *, policy=None, options=None):
        assert [(c.ecosystem, c.package, c.baseline, c.candidate) for c in changes] == [
            ("npm", "@ctrl/tinycolor", "4.1.0", "4.1.1")
        ]
        return [run_checks(changes[0], release("4.1.0"), release("4.1.1", provenance="none"))]

    monkeypatch.setattr(cli, "evaluate", fake_evaluate)
    monkeypatch.chdir(tmp_path)
    code = main(["check", "--base", str(base), "--head", str(head), "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert code == 0
    assert [(c["ecosystem"], c["package"], c["verdict"]) for c in doc["changes"]] == [
        ("npm", "@ctrl/tinycolor", "warn"),
        ("npm", "mylib", "pass"),
    ]
    assert doc["changes"][0]["lockfile"] == "package-lock.json"
    assert doc["changes"][1]["findings"][0]["rule_id"] == "GRN-E005"
