"""Text and JSON reporters. Package-supplied strings are escaped here."""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from datetime import date
from typing import Any

from .engine import Report
from .models import Finding, Ignore, Severity
from .policy import describe

_CTRL = re.compile("[\\x00-\\x08\\x0b-\\x1f\\x7f-\\x9f\\u202a-\\u202e\\u2066-\\u2069]")


def escape(text: str) -> str:
    """Neutralize control characters and bidi overrides for terminals."""
    return _CTRL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


_SEV_LABEL = {
    Severity.BLOCK: "BLOCK",
    Severity.WARN: "WARN ",
    Severity.INFO: "info ",
    Severity.OFF: "off  ",
}
_COLORS = {Severity.BLOCK: "\x1b[1;31m", Severity.WARN: "\x1b[33m", Severity.INFO: "\x1b[2m"}


def to_text(report: Report, *, color: bool = False) -> str:
    """The terminal report (SPEC §9.1)."""
    lines: list[str] = []
    for r in report.results:
        c = r.change
        head = f"{c.package} {c.baseline or '(new)'} → {c.candidate}: {r.verdict.value.upper()}"
        lines.append(escape(head))
        if not r.findings:
            lines.append("  no findings")
        for f in r.findings:
            lines.extend(_finding_text(f, color))
        lines.append("")
    if report.policy.source:
        lines.append(escape(f"policy: {report.policy.source}"))
    for ignore in report.expired:
        lines.append(escape(f"note: this ignore expired and no longer applies: {describe(ignore)}"))
    lines.append(f"verdict: {report.verdict.value}")
    return "\n".join(lines) + "\n"


def _finding_text(f: Finding, color: bool) -> list[str]:
    label = "ignored" if f.suppressed_by else _SEV_LABEL[f.severity]
    if color and f.suppressed_by:
        label = f"\x1b[2m{label}\x1b[0m"
    elif color and f.severity in _COLORS:
        label = f"{_COLORS[f.severity]}{label}\x1b[0m"
    rel = f" [in {f.release}]" if f.release else ""
    out = [f"  {label} {f.rule_id} {f.name}{escape(rel)}: {escape(f.title)}"]
    if f.suppressed_by:
        i = f.suppressed_by
        out.append(f"           - ignored until {i.until.isoformat()}: {escape(i.reason)}")
    for e in f.evidence:
        extra = f" <{e.url}>" if e.url else ""
        out.append(f"           - {escape(e.summary)}{escape(extra)}")
    return out


def _clean(obj: Any) -> Any:
    """Drop None values and turn severities into their labels."""
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, (list, tuple)):
        return [_clean(v) for v in obj]
    if isinstance(obj, Severity):
        return obj.label
    if isinstance(obj, date):
        return obj.isoformat()
    return obj


def _ignore(ignore: Ignore) -> dict[str, Any]:
    out: dict[str, Any] = _clean(asdict(ignore))
    out["rules"] = list(ignore.rules)
    return out


def to_json(report: Report) -> str:
    """The JSON report (SPEC §9.2), with sorted keys so output is stable."""
    changes = []
    for r in report.results:
        findings = []
        for f in r.findings:
            d = asdict(f)
            d.pop("change")
            d["severity"] = f.severity.label
            d["default_severity"] = f.default_severity.label
            d.pop("suppressed_by")
            if f.suppressed_by:
                d["suppressed_by"] = _ignore(f.suppressed_by)
            findings.append(_clean(d))
        changes.append(
            {
                "ecosystem": r.change.ecosystem,
                "package": r.change.package,
                "baseline": r.change.baseline,
                "candidate": r.change.candidate,
                "lockfile": r.change.lockfile,
                "line": r.change.line,
                "verdict": r.verdict.value,
                "findings": findings,
            }
        )
    policy = None
    if report.policy.source:
        policy = {
            "source": report.policy.source,
            "sha256": report.policy.sha256,
            "expired": [_ignore(i) for i in report.expired],
        }
    doc = {
        "schema": "https://garnetguard.dev/schema/report/v1.json",
        "garnet_version": report.garnet_version,
        "verdict": report.verdict.value,
        "policy": policy,
        "changes": changes,
    }
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
