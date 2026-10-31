import tomllib
from pathlib import Path

import garnet_guard


def test_version_matches_pyproject() -> None:
    # The release workflow tags from pyproject.toml; reports and `garnet version` use __version__.
    pyproject = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text())
    assert garnet_guard.__version__ == pyproject["project"]["version"]


def test_both_commands_are_the_same_entry_point() -> None:
    # `uvx garnet-guard` runs the script named after the package (ADR-0007).
    pyproject = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text())
    scripts = pyproject["project"]["scripts"]
    assert scripts["garnet-guard"] == scripts["garnet"] == "garnet_guard.console:main"
