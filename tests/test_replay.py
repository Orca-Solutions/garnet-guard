"""Incident replay: release facts built from recorded registry data."""

import hashlib
from typing import cast

import pytest

from garnet_guard.ecosystems.github import TagLookup
from garnet_guard.ecosystems.pypi import FetchContext, RegistryFile, ReplayRelease, release_facts
from garnet_guard.models import FileProvenance, Limits
from garnet_guard.net import Http, Response

from .builders import wheel

WHEEL = wheel({"demo/__init__.py": "x = 1\n"})
URL = "https://files.pythonhosted.org/packages/aa/bb/demo-1.0.1-py3-none-any.whl"


class _ReplayHttp:
    """Serves the wheel and an empty tag list; nothing else is expected."""

    def get(self, url: str, **kwargs: object) -> Response:
        if url == URL:
            return Response(status=200, content=WHEEL, url=url)
        if url.endswith("/info/refs?service=git-upload-pack"):
            return Response(status=200, content=b"0000", url=url)
        raise AssertionError(f"unexpected request: {url}")


def _facts(attested: bool | None) -> list[FileProvenance | None]:
    http = cast(Http, _ReplayHttp())
    ctx = FetchContext(http=http, limits=Limits(), tags=TagLookup(http))
    replay = ReplayRelease(
        files=(
            RegistryFile(
                filename="demo-1.0.1-py3-none-any.whl",
                url=URL,
                sha256=hashlib.sha256(WHEEL).hexdigest(),
                packagetype="bdist_wheel",
                uploaded_at=None,
            ),
        ),
        source_repo="example/demo",
        note="replayed",
        attested=attested,
    )
    facts = release_facts("demo", "1.0.1", ctx, replay=replay, advisories=False)
    return [a.provenance for a in facts.artifacts]


def test_replay_records_confirmed_missing_attestations() -> None:
    (prov,) = _facts(attested=False)
    assert prov is not None and prov.present is False and prov.verified is False


@pytest.mark.parametrize("attested", [None, True])
def test_replay_leaves_provenance_unknown_otherwise(attested: bool | None) -> None:
    assert _facts(attested=attested) == [None]
