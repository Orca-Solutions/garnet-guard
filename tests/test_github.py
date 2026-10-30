from typing import cast

from garnet_guard.ecosystems.github import TagLookup, match_tag
from garnet_guard.net import Http, Response

TAGS = {"2026.01.04": "a", "v1.18.0": "b", "lightning-2.6.1": "c", "1.0": "d", "1.0.0": "e"}


def test_exact_tag_wins() -> None:
    assert match_tag(TAGS, "x", "1.0").name == "1.0"


def test_zero_padded_tag_matches_normalized_version() -> None:
    tag = match_tag(TAGS, "certifi", "2026.1.4", "certifi/python-certifi")
    assert tag is not None and tag.name == "2026.01.04" and tag.repo == "certifi/python-certifi"


def test_prefixed_tags() -> None:
    assert match_tag(TAGS, "scipy", "1.18.0").name == "v1.18.0"
    assert match_tag(TAGS, "lightning", "2.6.1").name == "lightning-2.6.1"


def test_no_match() -> None:
    assert match_tag(TAGS, "lightning", "2.6.2") is None
    assert match_tag(TAGS, "x", "1.18.1") is None
    assert match_tag({"other-2.6.2": "z"}, "lightning", "2.6.2") is None
    assert match_tag(TAGS, "x", "not a version") is None


def test_monorepo_directory_tags() -> None:
    # Real tag names: open-telemetry/opentelemetry-js and import-js/eslint-plugin-import.
    tags = {"api/v1.4.1": "a", "v1.4.0": "b", "utils/v2.8.1": "c", "resolvers/node/v0.3.3": "d"}
    assert match_tag(tags, "@opentelemetry/api", "1.4.1", npm=True).name == "api/v1.4.1"
    assert match_tag(tags, "eslint-module-utils", "2.8.1", npm=True).name == "utils/v2.8.1"
    assert match_tag(tags, "eslint-import-resolver-node", "0.3.3").name == "resolvers/node/v0.3.3"
    assert match_tag({"pkgs/demo/1.0": "e"}, "demo", "1.0.0").name == "pkgs/demo/1.0"


def test_release_word_and_monorepo_separators() -> None:
    # Real tag names: explosion/confection, langchain-ai/langgraph, Azure/azure-sdk-for-python.
    tags = {"release-v1.0.0": "a", "prebuilt==1.0.11": "b", "azure-mgmt-core_1.1.0": "c"}
    assert match_tag(tags, "confection", "1.0.0").name == "release-v1.0.0"
    assert match_tag(tags, "langgraph-prebuilt", "1.0.11").name == "prebuilt==1.0.11"
    assert match_tag(tags, "azure-mgmt-core", "1.1.0").name == "azure-mgmt-core_1.1.0"
    assert match_tag({"Release-1.0": "d"}, "x", "1.0.0").name == "Release-1.0"


def test_prefix_must_name_the_package_or_a_release() -> None:
    tags = {"checkpoint==1.0.11": "a", "azure-core_1.1.0": "b", "nightly-v1.0.0": "c"}
    assert match_tag(tags, "langgraph-prebuilt", "1.0.11") is None
    assert match_tag(tags, "azure-mgmt-core", "1.1.0") is None
    assert match_tag(tags, "x", "1.0.0") is None


def test_monorepo_directory_tag_must_name_the_package() -> None:
    tags = {"api/v1.4.1": "a", "sdk-metrics/v2.0.0": "b", "utils/v2.8.1": "c"}
    assert match_tag(tags, "@opentelemetry/sdk-trace", "1.4.1", npm=True) is None
    assert match_tag(tags, "@opentelemetry/api", "2.0.0", npm=True) is None
    assert match_tag(tags, "eslint-module-utils", "2.8.2") is None
    assert match_tag(tags, "utils-extra", "2.8.1") is None


def _pkt(line: str) -> bytes:
    data = line.encode() + b"\n"
    return f"{len(data) + 4:04x}".encode() + data


class _RefsHttp:
    """Serves one ref advertisement for any repository."""

    def __init__(self, refs: dict[str, str]) -> None:
        self.body = b"".join(_pkt(f"{sha} refs/tags/{name}") for name, sha in refs.items())
        self.body += b"0000"

    def get(self, url: str, **kwargs: object) -> Response:
        return Response(status=200, content=self.body, url=url)


def test_tag_overrides_restore_and_hide_tags() -> None:
    http = cast(Http, _RefsHttp({"v0.23.2": "a" * 40, "v4.87.1": "b" * 40}))
    tags = TagLookup(
        http, {"Example/Repo": {"v0.23.3": "c" * 40, "v4.87.1": None, "never-there": None}}
    ).tags("example/repo")
    assert tags == {"v0.23.2": "a" * 40, "v0.23.3": "c" * 40}


def test_tag_overrides_apply_only_to_their_repository() -> None:
    http = cast(Http, _RefsHttp({"v1.0": "a" * 40}))
    lookup = TagLookup(http, {"example/other": {"v1.0": None}})
    assert lookup.tags("example/repo") == {"v1.0": "a" * 40}
