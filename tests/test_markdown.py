import json
import re

import pytest

from garnet_guard import markdown as md
from garnet_guard.cli import main
from garnet_guard.engine import report, run_checks
from garnet_guard.models import Change
from garnet_guard.report import to_json, to_markdown
from tests.builders import release


def _change(pkg: str, base: str | None, cand: str, verdict: str, *findings: dict) -> dict:
    return {
        "ecosystem": "pypi",
        "package": pkg,
        "baseline": base,
        "candidate": cand,
        "verdict": verdict,
        "findings": list(findings),
    }


def _finding(rule: str, title: str, severity: str = "warn", **extra: object) -> dict:
    return {"rule_id": rule, "title": title, "severity": severity, **extra}


def _doc(*changes: dict) -> dict:
    return {"verdict": "warn", "changes": list(changes)}


def test_comment_follows_the_design() -> None:
    doc = _doc(
        _change("requests", "2.32.4", "2.32.5", "pass"),
        _change(
            "examplelib",
            "2.6.1",
            "2.6.2",
            "warn",
            _finding("GRN-T004", "github.com/example/examplelib has no tag for 2.6.2"),
            _finding("GRN-C003", "2.6.2 adds import-time calls to sensitive APIs in 1 module(s)"),
        ),
        _change("idna", "3.10", "3.11", "pass"),
    )
    out = md.render(doc)
    lines = out.splitlines()
    assert lines[0] == md.MARKER
    assert lines[1].endswith("**Garnet Guard: 1 of 3 updates needs a look**")
    assert "> [!WARNING]" in out and "[!CAUTION]" not in out
    assert "> **`examplelib` `2.6.1` → `2.6.2`**" in out
    assert f"> - [`GRN-T004`]({md.RULES_URL}GRN-T004.md) github\\.com/" in out
    assert "<details><summary>2 updates with nothing worth a look</summary>" in out
    assert out.index("`idna`") < out.index("`requests`")
    assert lines[-1].startswith("<sub>Garnet Guard · [what is this?]")
    assert "[GRN-C003]" in lines[-1] and "[GRN-T004]" in lines[-1]
    assert "garnet-guard.dev" not in out
    assert md.render(doc) == out


def test_headers() -> None:
    assert "no dependency updates to check" in md.render(_doc())
    one = md.render(_doc(_change("a", "1", "2", "pass")))
    assert "1 update, nothing worth a look" in one
    assert "[!WARNING]" not in one
    two = md.render(
        _doc(
            _change("a", "1", "2", "warn", _finding("GRN-T001", "x")),
            _change("b", "1", "2", "block", _finding("GRN-K001", "y", "block")),
        )
    )
    assert "2 of 2 updates need a look" in two
    # block sorts before warn and is labelled
    assert two.index("`b`") < two.index("`a`")
    assert "y · **block**" in two


def test_footer_can_be_removed() -> None:
    out = md.render(_doc(_change("a", "1", "2", "warn", _finding("GRN-T001", "x"))), footer=False)
    assert "<sub>" not in out
    assert out.rstrip().endswith("x")


def test_added_package_and_intermediate_release() -> None:
    out = md.render(
        _doc(
            _change("new", None, "1.0", "pass"),
            _change("a", "1.0", "1.3", "warn", _finding("GRN-T001", "lost", release="1.2")),
        )
    )
    assert "new at `1.0`" in out
    assert "lost (in `1.2`)" in out


def test_suppressed_and_info_findings() -> None:
    out = md.render(
        _doc(
            _change(
                "a",
                "1",
                "2",
                "pass",
                _finding("GRN-C004", "binary", suppressed_by={"reason": "ok"}),
                _finding("GRN-E004", "unpinned", "info"),
            )
        )
    )
    assert "binary" not in out and "info: `GRN-E004`" in out


@pytest.mark.parametrize(
    "hostile",
    [
        "<img src=x onerror=alert(1)>",
        "[click](https://evil.example)",
        "see https://evil.example now",
        "ping @octocat and @org/team",
        "closes #1 and GH-2",
        "commit 1a2b3c4d5e6f",
        "www.evil.example",
        "**bold** _em_ `code`",
        "line\nbreak\r> [!CAUTION]",
        "bidi ‮evil⁦",
        "| a | b |",
    ],
)
def test_package_strings_cannot_inject(hostile: str) -> None:
    doc = _doc(
        _change(
            hostile,
            hostile,
            hostile,
            "warn",
            _finding(hostile, hostile, release=hostile),
            _finding("GRN-T001", hostile),
        ),
        _change(hostile, "1", hostile, "pass"),
    )
    out = md.render(doc)
    body = out.split("\n", 2)[2]  # skip marker and header, which carry no package text
    body = body.rsplit("\n<sub>", 1)[0]
    body = re.sub(re.escape(md.RULES_URL) + r"GRN-[A-Z]\d{3}\.md", "RULE", body)
    # Code spans render literally; everything outside them must be inert.
    prose = re.sub(r"(`+).*?\1", "", body)
    assert "<img" not in prose and "<sub" not in prose
    assert "](" not in prose.replace("](RULE)", "")
    for token in ("https://", "@octocat", "#1", "GH-2", "1a2b3c4d5e6f", "www.evil"):
        assert token not in prose
    assert not any("[!CAUTION]" in line.split("`")[0] for line in out.splitlines())
    assert "‮" not in out and "⁦" not in out
    for line in body.splitlines():
        assert line == "" or line.startswith(("> ", "<details>", "</details>", "|", "1 update"))


def test_untrusted_document_is_validated() -> None:
    with pytest.raises(md.ReportFormatError):
        md.render({"changes": [_change("a", "1", "2", "evil")]})
    with pytest.raises(md.ReportFormatError):
        md.render({"changes": "nope"})
    with pytest.raises(md.ReportFormatError):
        md.render({"changes": ["nope"]})


def test_length_limit_truncates_passing_changes_first() -> None:
    flagged = _change("bad", "1", "2", "warn", _finding("GRN-T001", "lost provenance"))
    passing = [_change(f"pkg{i:04d}", "1.0", "1.1", "pass") for i in range(2000)]
    out = md.render(_doc(flagged, *passing), max_chars=20_000)
    assert len(out) <= 20_000
    assert "lost provenance" in out
    assert "more not shown here" in out
    assert out.rstrip().endswith("</sub>")


def test_length_limit_with_many_flagged_changes() -> None:
    flagged = [
        _change(f"p{i}", "1", "2", "warn", _finding("GRN-T001", "x" * 200)) for i in range(500)
    ]
    out = md.render(_doc(*flagged), max_chars=10_000)
    assert len(out) <= 10_000
    assert "cut to fit" in out
    assert out.rstrip().endswith("</sub>")


def test_report_to_markdown_and_cli_round_trip(tmp_path) -> None:
    change = Change("pypi", "demo", "1.0", "1.1")
    rep = report([run_checks(change, release("1.0"), release("1.1", provenance="none", tag=False))])
    out = to_markdown(rep)
    assert "1 of 1 update needs a look" in out and "GRN-T001" in out
    path = tmp_path / "report.json"
    path.write_text(to_json(rep))
    dest = tmp_path / "comment.md"
    assert md.main([str(path), "--output", str(dest)]) == 0
    assert dest.read_text() == out
    assert md.main([str(path), "--no-footer"]) == 0


def test_cli_render_rejects_bad_input(tmp_path, capsys) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps([1, 2]))
    assert md.main([str(bad)]) == 3
    assert "couldn't render" in capsys.readouterr().err
    assert main(["diff", "x", "1", "2", "--format", "nope"]) == 3
