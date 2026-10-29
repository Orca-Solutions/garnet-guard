import tomllib
from pathlib import Path

import garnet_guard


def test_version_matches_pyproject() -> None:
    # The release workflow tags from pyproject.toml; reports and `garnet version` use __version__.
    pyproject = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text())
    assert garnet_guard.__version__ == pyproject["project"]["version"]
