"""The PR comment (SPEC §9.4), rendered from a JSON report (SPEC §9.2).

Rendering works on the JSON document, not on ``Report``, so the comment job of
the two-workflow Action pattern can render a report it downloaded as an
artifact. That artifact may come from a fork's workflow run, so every value in
the document is treated as untrusted: rule IDs and verdicts are validated, and
every other string is escaped so it can't create markup, links or mentions.

``render`` is pure and works on plain data. ``to_markdown`` is the entry point
``garnet check --format markdown`` calls with a ``Report``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

MARKER = "<!-- garnet:report -->"
REPO_URL = "https://github.com/orca-solutions/garnet-guard"
RULES_URL = f"{REPO_URL}/blob/main/docs/rules/"
WHAT_URL = f"{REPO_URL}#readme"
FAVICON_URL = (
    "https://raw.githubusercontent.com/orca-solutions/garnet-guard/main/"
    "docs/brand/favicon/favicon-16.svg"
)
# GitHub rejects comments over 65,536 characters; leave room for the footer.
MAX_CHARS = 60_000
MAX_REPORT_BYTES = 5 * 1024 * 1024
_MAX_FIELD = 300

_RULE_ID = re.compile(r"GRN-[TCKE]\d{3}")
_VERDICTS = ("pass", "warn", "block")
_SEVERITIES = ("off", "info", "warn", "block")

_CTRL = re.compile("[\\x00-\\x1f\\x7f-\\x9f\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u2069\\ufeff]")
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|~:])")
_ZWSP = "\u200b"
# Text GitHub turns into links or notifications even when Markdown-escaped:
# URLs, www. autolinks, @mentions, #123 and GH-123 references, commit SHAs.
_AUTOLINK = re.compile(r"(?i)(?<=:)(?=//)|(?<=@)(?=\w)|(?<=#)(?=\d)|(?<=gh-)(?=\d)|(?<=www)(?=\.)")
# Hex runs that could be read as commit SHAs (7 or more characters, at least
# one digit). They are split every 6 characters so no piece is long enough.
_HEX_RUN = re.compile(r"(?i)\b(?=[a-f]*\d)[0-9a-f]{7,}\b")


def _break_hex(m: re.Match[str]) -> str:
    run = m.group(0)
    return _ZWSP.join(run[i : i + 6] for i in range(0, len(run), 6))


def to_markdown(report: Any, *, footer: bool = True, max_chars: int = MAX_CHARS) -> str:
    """The PR comment for an ``engine.Report``, rendered through its JSON form."""
    from .report import to_json

    return render(json.loads(to_json(report)), footer=footer, max_chars=max_chars)


class ReportFormatError(ValueError):
    """The JSON document isn't a Garnet report this renderer can trust."""


def _plain(value: object) -> str:
    text = value if isinstance(value, str) else str(value)
    text = _CTRL.sub(" ", text)
    if len(text) > _MAX_FIELD:
        text = text[: _MAX_FIELD - 1] + "…"
    return text


def text(value: object) -> str:
    """Escape a package-supplied string for Markdown prose.

    The result renders as the literal text: no emphasis, HTML, links, autolinks,
    @mentions, issue references or commit references.
    """
    s = _HEX_RUN.sub(_break_hex, _AUTOLINK.sub(_ZWSP, _plain(value)))
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _MD_SPECIAL.sub(r"\\\1", s)


def code(value: object, *, in_table: bool = False) -> str:
    """Render a package-supplied string as an inline code span."""
    s = _plain(value).strip() or " "
    run = max((len(m) for m in re.findall(r"`+", s)), default=0)
    fence = "`" * (run + 1)
    if in_table:
        s = s.replace("|", "\\|")
    pad = " " if run or s.startswith(("`", " ")) or s.endswith(("`", " ")) else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def rule_link(rule_id: str) -> str:
    return f"[`{rule_id}`]({RULES_URL}{rule_id}.md)"


def _rule(value: object) -> str | None:
    return value if isinstance(value, str) and _RULE_ID.fullmatch(value) else None


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _version(value: object) -> str:
    return code(value) if value else "(new)"


def _update(change: Mapping[str, Any], *, in_table: bool = False) -> str:
    base = change.get("baseline")
    cand = code(change.get("candidate", "?"), in_table=in_table)
    if not base:
        return f"new at {cand}"
    return f"{code(base, in_table=in_table)} → {cand}"


def _verdict(change: Mapping[str, Any]) -> str:
    v = change.get("verdict")
    if v not in _VERDICTS:
        raise ReportFormatError(f"unknown verdict {_plain(v)!r}")
    return str(v)


def _active(change: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Findings that apply, worst first; suppressed and "off" findings are left out."""
    found = [
        f
        for f in _list(change.get("findings"))
        if isinstance(f, Mapping) and not f.get("suppressed_by") and f.get("severity") != "off"
    ]
    rank = {s: i for i, s in enumerate(_SEVERITIES)}
    return sorted(found, key=lambda f: -rank.get(str(f.get("severity")), 0))


def _ignored(change: Mapping[str, Any]) -> list[str]:
    """Rule IDs of findings a policy ignore suppressed, sorted and unique."""
    return sorted(
        {
            r
            for f in _list(change.get("findings"))
            if isinstance(f, Mapping) and f.get("suppressed_by") and (r := _rule(f.get("rule_id")))
        }
    )


def _finding_line(f: Mapping[str, Any]) -> str:
    rid = _rule(f.get("rule_id"))
    label = rule_link(rid) if rid else code(f.get("rule_id", "?"))
    line = f"> - {label} {text(f.get('title', ''))}"
    if f.get("release"):
        line += f" (in {code(f['release'])})"
    if f.get("severity") == "block":
        line += " · **block**"
    elif f.get("severity") == "info":
        line += " · info"
    return line


def _flagged_block(change: Mapping[str, Any]) -> list[str]:
    name = code(change.get("package", "?"))
    lines = ["> [!WARNING]", f"> **{name} {_update(change)}**"]
    lines += [_finding_line(f) for f in _active(change)]
    ignored = _ignored(change)
    if ignored:
        lines.append(f"> - ignored by the policy: {', '.join(f'`{r}`' for r in ignored)}")
    return lines


def _pass_row(change: Mapping[str, Any]) -> str:
    infos = sorted({r for f in _active(change) if (r := _rule(f.get("rule_id")))})
    ignored = _ignored(change)
    parts = []
    if infos:
        parts.append("info: " + ", ".join(f"`{r}`" for r in infos))
    if ignored:
        parts.append("ignored by the policy: " + ", ".join(f"`{r}`" for r in ignored))
    checks = " · ".join(parts) or "no findings"
    return (
        f"| {code(change.get('package', '?'), in_table=True)} "
        f"| {_update(change, in_table=True)} | {checks} |"
    )


def _header(flagged: int, total: int) -> str:
    icon = f'<img src="{FAVICON_URL}" width="16" height="16" alt="">'
    if total == 0:
        title = "no dependency updates to check"
    elif flagged == 0:
        title = f"{total} update{'s' if total != 1 else ''}, nothing worth a look"
    else:
        title = (
            f"{flagged} of {total} update{'s' if total != 1 else ''} "
            f"need{'s' if flagged == 1 else ''} a look"
        )
    return f"{icon} **Garnet Guard: {title}**"


def _footer(cited: Sequence[str]) -> str:
    links = [f"[what is this?]({WHAT_URL})"]
    links += [f"[{r}]({RULES_URL}{r}.md)" for r in cited]
    return "<sub>Garnet Guard · " + " · ".join(links) + "</sub>"


def _expired_lines(doc: Mapping[str, Any]) -> list[str]:
    """One line per policy ignore past its until date, so nobody misses it."""
    policy = doc.get("policy")
    expired = _list(policy.get("expired")) if isinstance(policy, Mapping) else []
    lines = []
    for e in expired:
        if not isinstance(e, Mapping):
            continue
        rules = ", ".join(f"`{r}`" for x in _list(e.get("rules")) if (r := _rule(x)))
        lines.append(
            f"- The policy's ignore for {code(e.get('package', '?'))} ({rules}) expired on "
            f"{code(e.get('until', '?'))} and no longer applies. Review it again, then renew "
            "or remove it."
        )
    return lines + [""] if lines else []


def render(doc: Mapping[str, Any], *, footer: bool = True, max_chars: int = MAX_CHARS) -> str:
    """Render a JSON report as the PR comment. Deterministic for a given document."""
    if not isinstance(doc, Mapping) or not isinstance(doc.get("changes"), list):
        raise ReportFormatError("not a Garnet report: missing 'changes'")
    changes = [c for c in doc["changes"] if isinstance(c, Mapping)]
    if len(changes) != len(doc["changes"]):
        raise ReportFormatError("not a Garnet report: a change isn't an object")
    for c in changes:
        _verdict(c)

    def order(c: Mapping[str, Any]) -> tuple[int, str, str]:
        return (-_VERDICTS.index(_verdict(c)), str(c.get("package", "")), str(c.get("candidate")))

    flagged = sorted((c for c in changes if _verdict(c) != "pass"), key=order)
    passing = sorted((c for c in changes if _verdict(c) == "pass"), key=order)
    cited = sorted({r for c in flagged for f in _active(c) if (r := _rule(f.get("rule_id")))})

    head = [MARKER, _header(len(flagged), len(changes)), ""]
    tail = ["", _footer(cited)] if footer else []

    body: list[str] = []
    for c in flagged:
        body += _flagged_block(c) + [""]
    body += _expired_lines(doc)

    def assemble(rows: list[str], dropped: int) -> str:
        parts = list(head) + body
        if rows or dropped:
            label = f"{len(passing)} update{'s' if len(passing) != 1 else ''}"
            parts += [f"<details><summary>{label} with nothing worth a look</summary>", ""]
            if rows:
                parts += ["| Package | Update | Checks |", "|---|---|---|", *rows]
            if dropped:
                parts += [
                    "",
                    f"{dropped} more not shown here. The full report is in the job summary.",
                ]
            parts += ["", "</details>"]
        return "\n".join(parts + tail).rstrip("\n") + "\n"

    rows = [_pass_row(c) for c in passing]
    out = assemble(rows, 0)
    # Truncate passing changes first (SPEC §9.4).
    while len(out) > max_chars and rows:
        cut = max(1, len(rows) // 4)
        rows = rows[:-cut]
        out = assemble(rows, len(passing) - len(rows))
    if len(out) > max_chars:
        note = "\n\nThis comment was cut to fit GitHub's size limit. The full report is in the job summary.\n"
        keep = max_chars - len(note) - sum(len(x) + 1 for x in tail)
        out = out[:keep].rsplit("\n", 1)[0] + note + "\n".join(tail) + ("\n" if tail else "")
    return out


def load(path: Path) -> Mapping[str, Any]:
    data = path.read_bytes()
    if len(data) > MAX_REPORT_BYTES:
        raise ReportFormatError(f"report is larger than {MAX_REPORT_BYTES} bytes")
    try:
        doc = json.loads(data)
    except (ValueError, UnicodeDecodeError) as err:
        raise ReportFormatError(f"report isn't valid JSON: {err}") from err
    if not isinstance(doc, Mapping):
        raise ReportFormatError("not a Garnet report: top level isn't an object")
    return doc


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m garnet_guard.markdown",
        description="Render a Garnet JSON report as the pull request comment.",
    )
    p.add_argument("report", type=Path, help="JSON report written by garnet --format json")
    p.add_argument("--output", type=Path, help="write the comment here instead of stdout")
    p.add_argument("--no-footer", action="store_true", help="leave out the footer line")
    args = p.parse_args(argv)
    try:
        out = render(load(args.report), footer=not args.no_footer)
    except (OSError, ReportFormatError) as err:
        print(f"garnet: couldn't render the comment: {err}", file=sys.stderr)
        return 3
    if args.output:
        args.output.write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
