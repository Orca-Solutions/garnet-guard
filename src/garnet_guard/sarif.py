"""The SARIF report (SPEC §9.3), rendered from a JSON report (SPEC §9.2).

GitHub code scanning reads SARIF, so this is how findings reach a repository's
Security tab and the pull request's changed lines.

Like ``markdown``, rendering works on the JSON document, and every value in it
is treated as untrusted: rule IDs must name a known rule, severities are
validated, lockfile paths must stay inside the repository, and every
package-supplied string loses its control characters and can't form a SARIF
embedded link. Rule metadata comes from Garnet's own rule docs, never from the
document.

``render`` is pure and works on plain data. ``to_sarif`` is the entry point
``garnet check --format sarif`` calls with a ``Report``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote

from . import __version__
from .checks import DOCS
from .checks.docs import rule_url
from .markdown import ReportFormatError, load
from .models import Severity

SCHEMA_URI = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
INFO_URI = "https://github.com/orca-solutions/garnet-guard"
FINGERPRINT = "garnetFinding/v1"
_MAX_FIELD = 300
_MAX_EVIDENCE = 10
_MAX_PATH = 1024

# SPEC §9.3: block → error, warn → warning, info → note. "off" findings are
# left out, as they are from the PR comment.
_LEVELS = {"block": "error", "warn": "warning", "info": "note"}
_SEVERITY_LABELS = (*_LEVELS, "off")
_FAMILIES = {"T": "trust", "C": "content", "K": "known-bad", "E": "couldnt-check"}

_CTRL = re.compile("[\\x00-\\x1f\\x7f-\\x9f\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u2069\\ufeff]")
# SARIF plain-text messages turn "[text](target)" into a link (SARIF §3.11.6).
# A backslash before a bracket makes it literal, so brackets and backslashes
# from packages are escaped.
_LINK_CHARS = re.compile(r"([\\\[\]])")
_URL = re.compile(r"https://[^\s<>\"]{1,500}")
_DRIVE = re.compile(r"^[A-Za-z]:")
_MD_SPECIAL = re.compile(r"([\\`*_\[\]])")


def to_sarif(report: Any) -> str:
    """The SARIF log for an ``engine.Report``, rendered through its JSON form."""
    from .report import to_json

    return dumps(render(json.loads(to_json(report))))


def dumps(log: Mapping[str, Any]) -> str:
    return json.dumps(log, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def text(value: object) -> str:
    """A package-supplied string as SARIF message text: one line, no links."""
    s = _CTRL.sub(" ", value if isinstance(value, str) else str(value))
    if len(s) > _MAX_FIELD:
        s = s[: _MAX_FIELD - 1] + "…"
    return _LINK_CHARS.sub(r"\\\1", s)


def _md(value: str) -> str:
    """Garnet's own rule text as literal Markdown, so ``<name>-X`` isn't read as HTML."""
    s = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _MD_SPECIAL.sub(r"\\\1", s)


def _level(severity: Severity) -> str:
    return _LEVELS.get(severity.label, "none")


def _rule(rule_id: str) -> dict[str, Any]:
    doc = DOCS[rule_id]
    url = rule_url(rule_id)
    return {
        "id": rule_id,
        "name": doc.name,
        "shortDescription": {"text": doc.summary},
        "fullDescription": {"text": doc.explanation},
        "help": {
            "text": f"{doc.explanation}\n\nWhat to do: {doc.remediation}\n\nMore: {url}",
            "markdown": f"{_md(doc.explanation)}\n\n**What to do:** {_md(doc.remediation)}\n\n"
            f"[{rule_id}]({url})",
        },
        "helpUri": url,
        "defaultConfiguration": {"level": _level(doc.default)},
        "properties": {"tags": ["security", "supply-chain", _FAMILIES[rule_id[4]]]},
    }


def _location(change: Mapping[str, Any]) -> dict[str, Any]:
    """The lockfile line that pins the candidate, as a repository-relative URI."""
    path = change.get("lockfile")
    if not isinstance(path, str) or not path:
        raise ReportFormatError("a change has no lockfile, so SARIF can't place its findings")
    posix = path.replace("\\", "/")
    parts = [p for p in posix.split("/") if p not in ("", ".")]
    if (
        not parts
        or len(posix) > _MAX_PATH
        or _CTRL.search(posix)
        or posix.startswith("/")
        or _DRIVE.match(posix)
        or ".." in parts
    ):
        raise ReportFormatError(
            f"lockfile {text(path)!r} isn't a path inside the repository, "
            "so SARIF can't place its findings"
        )
    uri = quote("/".join(parts), safe="/")
    line = change.get("line")
    # Code scanning needs a line. When the pin's line isn't known, use the first.
    start = line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else 1
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": start},
        }
    }


def _update(change: Mapping[str, Any]) -> str:
    pkg = text(change.get("package", "?"))
    cand = text(change.get("candidate", "?"))
    base = change.get("baseline")
    return f"{pkg} {text(base)} → {cand}" if base else f"{pkg} new at {cand}"


def _evidence(f: Mapping[str, Any]) -> list[str]:
    items = f.get("evidence")
    lines: list[str] = []
    for e in items if isinstance(items, list) else []:
        if not isinstance(e, Mapping) or not e.get("summary"):
            continue
        line = f"- {text(e['summary'])}"
        url = e.get("url")
        if isinstance(url, str) and _URL.fullmatch(url):
            line += f" <{text(url)}>"
        lines.append(line)
    if len(lines) > _MAX_EVIDENCE:
        more = len(lines) - _MAX_EVIDENCE
        lines = lines[:_MAX_EVIDENCE] + [f"- and {more} more in the JSON report"]
    return lines


def _suppressions(f: Mapping[str, Any]) -> list[dict[str, Any]]:
    """A ``suppressed_by`` ignore (SPEC §7) as a SARIF suppression."""
    by = f.get("suppressed_by")
    if not by:
        return []
    reason = by.get("reason") if isinstance(by, Mapping) else by
    entry: dict[str, Any] = {"kind": "external", "status": "accepted"}
    if reason:
        entry["justification"] = text(reason)
    return [entry]


def _fingerprint(change: Mapping[str, Any], f: Mapping[str, Any], rule_id: str) -> str:
    """Stable across runs, so code scanning keeps one alert per finding."""
    key = [
        str(change.get("ecosystem", "")),
        str(change.get("package", "")),
        str(change.get("candidate", "")),
        rule_id,
        str(f.get("release") or ""),
        str(f.get("title", "")),
    ]
    return hashlib.sha256(json.dumps(key).encode()).hexdigest()


def _result(
    change: Mapping[str, Any], f: Mapping[str, Any], index: Mapping[str, int]
) -> dict[str, Any] | None:
    rule_id = f.get("rule_id")
    if not isinstance(rule_id, str) or rule_id not in index:
        raise ReportFormatError(f"unknown rule {text(rule_id)!r}")
    severity = f.get("severity")
    if severity not in _SEVERITY_LABELS:
        raise ReportFormatError(f"unknown severity {text(severity)!r}")
    if severity == "off":
        return None
    title = text(f.get("title", ""))
    if f.get("release"):
        title += f" (in {text(f['release'])})"
    lines = [f"{_update(change)}: {title}"]
    if evidence := _evidence(f):
        lines += ["", "Evidence:", *evidence]
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": index[rule_id],
        "level": _LEVELS[str(severity)],
        "message": {"text": "\n".join(lines)},
        "locations": [_location(change)],
        "partialFingerprints": {FINGERPRINT: _fingerprint(change, f, rule_id)},
    }
    if suppressions := _suppressions(f):
        result["suppressions"] = suppressions
    return result


def render(doc: Mapping[str, Any]) -> dict[str, Any]:
    """Render a JSON report as a SARIF 2.1.0 log. Deterministic for a given document."""
    if not isinstance(doc, Mapping) or not isinstance(doc.get("changes"), list):
        raise ReportFormatError("not a Garnet report: missing 'changes'")
    rule_ids = sorted(DOCS)
    index = {r: i for i, r in enumerate(rule_ids)}
    results: list[dict[str, Any]] = []
    for change in doc["changes"]:
        if not isinstance(change, Mapping):
            raise ReportFormatError("not a Garnet report: a change isn't an object")
        findings = change.get("findings")
        for f in findings if isinstance(findings, list) else []:
            if not isinstance(f, Mapping):
                raise ReportFormatError("not a Garnet report: a finding isn't an object")
            if (r := _result(change, f, index)) is not None:
                results.append(r)
    return {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "garnet",
                        "fullName": "Garnet Guard",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": [_rule(r) for r in rule_ids],
                    }
                },
                "results": results,
            }
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m garnet_guard.sarif",
        description="Render a Garnet JSON report as SARIF for GitHub code scanning.",
    )
    p.add_argument("report", type=Path, help="JSON report written by garnet --format json")
    p.add_argument("--output", type=Path, help="write the SARIF log here instead of stdout")
    args = p.parse_args(argv)
    try:
        out = dumps(render(load(args.report)))
    except (OSError, ReportFormatError) as err:
        print(f"garnet: couldn't render SARIF: {err}", file=sys.stderr)
        return 3
    if args.output:
        args.output.write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
