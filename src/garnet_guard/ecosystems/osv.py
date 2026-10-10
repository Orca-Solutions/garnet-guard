"""OSV lookup for malicious-package advisories (``MAL-`` ids)."""

from __future__ import annotations

from ..net import Http, NetError

_ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm"}


def malicious_advisories(http: Http, ecosystem: str, package: str, version: str) -> tuple[str, ...]:
    body = {"package": {"name": package, "ecosystem": _ECOSYSTEMS[ecosystem]}, "version": version}
    resp = http.post_json("https://api.osv.dev/v1/query", body)
    if resp.status != 200:
        raise NetError(f"OSV query returned HTTP {resp.status}")
    data = resp.json()
    vulns = data.get("vulns", []) if isinstance(data, dict) else []
    ids = {v.get("id", "") for v in vulns if isinstance(v, dict)}
    return tuple(sorted(i for i in ids if isinstance(i, str) and i.startswith("MAL-")))
