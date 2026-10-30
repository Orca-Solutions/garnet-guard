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
