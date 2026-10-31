"""Seed inputs for the fuzz targets, built in memory from the test fixtures.

``python -m tests.fuzz.seeds TARGET DIR`` writes one file per seed into DIR
for Atheris to start from. ``seeds(TARGET)`` returns them for the unit tests.
Building them here keeps binary archives out of the repository.
"""

from __future__ import annotations

import bz2
import io
import lzma
import sys
import tarfile
from pathlib import Path

from tests.builders import sdist, wheel
from tests.fuzz import fuzz_lockfiles, fuzz_safe_archive

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"

_PACKAGE = {
    "demo/__init__.py": "import os\nVALUE = os.environ.get('HOME')\n",
    "demo-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
    "demo-1.0.dist-info/entry_points.txt": "[console_scripts]\ndemo = demo:main\n",
}

_JS = (
    "const cp = require('child_process');\ncp.exec('id');\n",
    "import { request } from 'node:https';\nexport default () => fetch(`https://x/${a}`);\n",
    "!function () { eval(atob('YQ==')) }();\nvar re = /[/]\\//g, s = 'a\\'b';\n",
    "var _0x1a = ['x'], _0x1b = _0x1a[0];\n// comment\n/* block */ module.exports = _0x1b;\n",
    "const w = new Worker(new URL('./w.js', import.meta.url)); require('./lib/a');\n",
)


def _tar(compress: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, body in sorted(_PACKAGE.items()):
            data = body.encode()
            info = tarfile.TarInfo(f"demo-1.0/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    if compress == "bz2":
        return bz2.compress(raw)
    if compress == "xz":
        return lzma.compress(raw, format=lzma.FORMAT_XZ)
    return raw


def _prefixed(suffixes: tuple[str, ...], suffix: str, data: bytes) -> bytes:
    return bytes([suffixes.index(suffix)]) + data


def seeds(target: str) -> list[bytes]:
    if target == "safe_archive":
        s = fuzz_safe_archive.SUFFIXES
        return [
            _prefixed(s, ".whl", wheel(_PACKAGE)),
            _prefixed(s, ".zip", wheel({"README": "x"})),
            _prefixed(s, ".tar.gz", sdist("demo-1.0", _PACKAGE)),
            _prefixed(s, ".tar.bz2", _tar("bz2")),
            _prefixed(s, ".tar.xz", _tar("xz")),
            _prefixed(s, ".tar", _tar("none")),
        ]
    if target == "jsscan":
        return [js.encode() for js in _JS]
    if target == "lockfiles":
        names = fuzz_lockfiles.NAMES
        files = {
            "uv.lock": [FIXTURES / "install" / "uv-head.lock"],
            "package-lock.json": sorted((FIXTURES / "npm").glob("package-lock-*.json")),
            "pnpm-lock.yaml": sorted((FIXTURES / "npm").glob("pnpm-lock-*.yaml")),
            "yarn.lock": sorted((FIXTURES / "npm").glob("yarn-*.lock")),
        }
        out = [
            _prefixed(names, name, path.read_bytes())
            for name, paths in files.items()
            for path in paths
        ]
        out.append(
            _prefixed(names, "requirements.txt", b"requests==2.32.3 \\\n    --hash=sha256:00\n")
        )
        out.append(_prefixed(names, "poetry.lock", b'[[package]]\nname = "a"\nversion = "1"\n'))
        return out
    raise SystemExit(f"unknown fuzz target: {target}")


def main() -> None:
    target, directory = sys.argv[1], Path(sys.argv[2])
    directory.mkdir(parents=True, exist_ok=True)
    for i, data in enumerate(seeds(target)):
        (directory / f"seed-{i:02d}").write_bytes(data)


if __name__ == "__main__":
    main()
