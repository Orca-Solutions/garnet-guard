"""The only module that talks to the network.

HTTPS only, TLS verification always on, a hosts allowlist, timeouts, a
response size cap and retries with backoff for 429 and 5xx. Tokens are
attached only to api.github.com and never logged.
"""

from __future__ import annotations

import os
import ssl
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

ALLOWED_HOSTS = frozenset(
    {
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "github.com",
        "api.github.com",
        "api.osv.dev",
    }
)

DEFAULT_MAX_BYTES = 200 * 1024 * 1024
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})


class NetError(Exception):
    """A request could not be completed. Callers turn this into GRN-E001."""


@dataclass(frozen=True)
class Response:
    status: int
    content: bytes
    url: str

    def json(self) -> Any:
        import json

        return json.loads(self.content)


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        path = os.environ.get(var)
        if path and os.path.isfile(path):
            ctx.load_verify_locations(cafile=path)
    return ctx


class Http:
    def __init__(
        self,
        *,
        github_token: str | None = None,
        retries: int = 3,
        user_agent: str = "garnet-guard",
    ) -> None:
        self._token = github_token
        self._retries = retries
        self._client = httpx.Client(
            verify=_ssl_context(),
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=False,
            headers={"User-Agent": user_agent},
            trust_env=True,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Http:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> Response:
        return self._request("GET", url, headers=headers, max_bytes=max_bytes)

    def post_json(self, url: str, body: Any, *, max_bytes: int = 16 * 1024 * 1024) -> Response:
        return self._request("POST", url, json_body=body, max_bytes=max_bytes)

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        max_bytes: int,
        redirects: int = 5,
    ) -> Response:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise NetError(f"refusing non-HTTPS URL: {url}")
        host = (parts.hostname or "").lower()
        if host not in ALLOWED_HOSTS:
            raise NetError(f"host not in allowlist: {host}")
        hdrs = dict(headers or {})
        if host == "api.github.com" and self._token:
            hdrs["Authorization"] = f"Bearer {self._token}"

        delay = 1.0
        for attempt in range(self._retries + 1):
            try:
                with self._client.stream(method, url, headers=hdrs, json=json_body) as resp:
                    if resp.status_code in (301, 302, 307, 308) and redirects > 0:
                        location = resp.headers.get("location", "")
                        target = str(httpx.URL(url).join(location))
                        return self._request(
                            method,
                            target,
                            headers=headers,
                            json_body=json_body,
                            max_bytes=max_bytes,
                            redirects=redirects - 1,
                        )
                    if resp.status_code in _RETRY_STATUSES and attempt < self._retries:
                        retry_after = resp.headers.get("retry-after", "")
                        wait = float(retry_after) if retry_after.isdigit() else delay
                        time.sleep(min(wait, 30.0))
                        delay *= 2
                        continue
                    declared = resp.headers.get("content-length")
                    if declared and declared.isdigit() and int(declared) > max_bytes:
                        raise NetError(f"response from {host} exceeds {max_bytes} bytes")
                    buf = bytearray()
                    for chunk in resp.iter_bytes():
                        buf += chunk
                        if len(buf) > max_bytes:
                            raise NetError(f"response from {host} exceeds {max_bytes} bytes")
                    return Response(resp.status_code, bytes(buf), url)
            except httpx.HTTPError as err:
                if attempt < self._retries:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise NetError(f"{method} {host}{parts.path} failed: {type(err).__name__}") from err
        raise NetError(f"{method} {host}{parts.path} failed after retries")
