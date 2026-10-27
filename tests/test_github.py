from garnet_guard.ecosystems.github import match_tag

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
