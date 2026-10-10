import gzip

import httpx
import pytest

from garnet_guard.net import Http, NetError


def client(handler, token: str | None = None) -> Http:
    return Http(github_token=token, retries=0, transport=httpx.MockTransport(handler))


def test_allowlist_scheme_and_credentials() -> None:
    h = client(lambda r: httpx.Response(200))
    for url in ("http://pypi.org/x", "https://evil.example/x", "https://u:p@pypi.org/x"):
        with pytest.raises(NetError) as exc:
            h.get(url)
        assert "u:p" not in str(exc.value)


def test_redirect_to_other_host_is_rechecked_and_token_dropped() -> None:
    seen: list[tuple[str, str | None]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.url.host, req.headers.get("authorization")))
        if req.url.host == "api.github.com":
            return httpx.Response(302, headers={"location": "https://pypi.org/ok"})
        return httpx.Response(200, stream=httpx.ByteStream(b"ok"))

    assert client(handler, token="sekret").get("https://api.github.com/x").content == b"ok"
    assert seen == [("api.github.com", "Bearer sekret"), ("pypi.org", None)]

    def evil(req: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/"})

    with pytest.raises(NetError):
        client(evil).get("https://pypi.org/x")


def test_redirect_without_location_raises() -> None:
    with pytest.raises(NetError):
        client(lambda r: httpx.Response(302)).get("https://pypi.org/x")


def test_size_cap_without_content_length() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=iter([b"x" * 1000] * 10))

    with pytest.raises(NetError):
        client(handler).get("https://pypi.org/x", max_bytes=5000)


def test_encoded_body_refused() -> None:
    body = gzip.compress(b"\0" * 1_000_000)

    def handler(req: httpx.Request) -> httpx.Response:
        assert req.headers["accept-encoding"] == "identity"
        return httpx.Response(
            200, stream=httpx.ByteStream(body), headers={"content-encoding": "gzip"}
        )

    with pytest.raises(NetError):
        client(handler).get("https://pypi.org/x", max_bytes=10_000)
