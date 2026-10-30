"""Evidence a reviewer needs that is not a warning (issue #50)."""

from __future__ import annotations

import json
from dataclasses import replace

from garnet_guard.checks.trust import coverage_notes
from garnet_guard.engine import report, run_checks
from garnet_guard.markdown import render, to_markdown
from garnet_guard.models import Change, FactError
from garnet_guard.report import to_json, to_text
from tests.builders import release

CHANGE = Change("pypi", "demo", "1.0", "1.1")


def test_note_when_the_trusted_release_has_no_attestation_and_no_tag() -> None:
    base = release("1.0", provenance="none", tag=False)
    (note,) = coverage_notes(base)
    assert note == (
        "1.0 has no attestation and no git tag in github.com/o/r, so GRN-T001 to GRN-T005, "
        "which compare how releases were published, had nothing to compare with"
    )
    bare = replace(base, source_repo=None, tag_checked=False)
    (note,) = coverage_notes(bare)
    assert "links no GitHub repository to look for a tag in" in note


def test_no_note_when_a_trust_rule_has_something_to_compare() -> None:
    assert coverage_notes(release("1.0", provenance="none", tag=True)) == ()
    assert coverage_notes(release("1.0", provenance="ok", tag=False)) == ()
    assert coverage_notes(None) == ()


def test_no_note_when_garnet_could_not_look() -> None:
    # Provenance not fetched, or a failed tag lookup: GRN-E001 reports those,
    # and the note would claim something Garnet didn't see.
    assert coverage_notes(release("1.0", provenance=None, tag=False)) == ()
    failed = replace(
        release("1.0", provenance="none", tag=False),
        tag_checked=False,
        tag_repos=("o/r",),
        errors=(FactError("GRN-E001", "tag lookup: HTTP 503", ("GRN-T004",)),),
    )
    assert coverage_notes(failed) == ()


def test_note_reaches_every_output_without_changing_the_verdict() -> None:
    base = release("1.0", provenance="none", tag=False)
    result = run_checks(CHANGE, base, release("1.1", provenance="none", tag=False))
    assert result.verdict.value == "pass" and result.findings == ()
    assert result.notes == coverage_notes(base)
    rep = report([result])
    assert "  note: 1.0 has no attestation and no git tag" in to_text(rep)
    doc = json.loads(to_json(rep))
    assert doc["changes"][0]["notes"] == list(result.notes)
    assert "publishing not compared (no attestation or tag)" in to_markdown(rep)


def test_late_wheels_garnet_left_out_are_a_finding_not_a_note() -> None:
    """GRN-C012 not comparing a late wheel is a check it couldn't run, so it
    is GRN-E003 and never a pass; it isn't about how 1.0 was published.
    (This was a note, and the update passed.)"""
    left = ("demo-1.1-cp314-cp314-win32.whl",)
    cand = replace(release("1.1"), wheels_not_compared=left)
    result = run_checks(CHANGE, release("1.0"), cand)
    assert result.verdict.value == "warn" and result.notes == ()
    assert [f.rule_id for f in result.findings] == ["GRN-E003"]
    rep = report([result])
    assert "demo-1.1-cp314-cp314-win32.whl" in to_text(rep)
    assert "GRN-E003" in to_markdown(rep) and "publishing not compared" not in to_markdown(rep)


def test_json_has_no_notes_key_when_there_is_nothing_to_say() -> None:
    result = run_checks(CHANGE, release("1.0"), release("1.1"))
    assert result.notes == ()
    assert "notes" not in json.loads(to_json(report([result])))["changes"][0]


def test_note_in_a_flagged_change_is_escaped() -> None:
    doc = {
        "verdict": "warn",
        "changes": [
            {
                "ecosystem": "pypi",
                "package": "demo",
                "baseline": "1.0",
                "candidate": "1.1",
                "verdict": "warn",
                "findings": [{"rule_id": "GRN-C003", "title": "t", "severity": "warn"}],
                "notes": ["1.0 has no tag in github.com/[x](https://evil.example) @someone"],
            }
        ],
    }
    out = render(doc)
    (line,) = [x for x in out.splitlines() if x.startswith("> - note: ")]
    assert "](https://evil.example)" not in line and "@someone" not in line


# Credential and CI reads at import (GRN-C003, info)


def _reads(src: str) -> list[tuple[int, str]]:
    from garnet_guard.facts.pyindex import scan_module

    return [(c.line, c.name) for c in scan_module(src.encode()).calls if c.read]


def test_reads_of_credentials_and_ci_settings_are_indexed() -> None:
    src = (
        "import os, json\n"
        "from os import environ, getenv\n"
        "a = os.environ['GITHUB_TOKEN']\n"
        "b = os.getenv('AWS_SECRET_ACCESS_KEY')\n"
        "c = environ.get('npm_token')\n"
        "if 'CI' in os.environ:\n"
        "    pass\n"
        "d = json.dumps(dict(os.environ))\n"
        "e = {**environ}\n"
        "f = os.environ.copy()\n"
        "URL = 'http://169.254.169.254/latest/meta-data/iam/'\n"
        "g = getenv('ACTIONS_ID_TOKEN_REQUEST_URL')\n"
    )
    assert _reads(src) == [
        (3, "environment variable GITHUB_TOKEN"),
        (4, "environment variable AWS_SECRET_ACCESS_KEY"),
        (5, "environment variable npm_token"),
        (6, "environment variable CI"),
        (8, "the whole environment (os.environ)"),
        (9, "the whole environment (os.environ)"),
        (10, "the whole environment (os.environ)"),
        (11, "cloud metadata address 169.254.169.254"),
        (12, "environment variable ACTIONS_ID_TOKEN_REQUEST_URL"),
    ]


def test_ordinary_environment_use_is_not_a_read() -> None:
    src = (
        "import os, subprocess\n"
        "home = os.environ['HOME']\n"
        "debug = os.getenv('DEMO_DEBUG')\n"
        "os.environ['GITHUB_TOKEN'] = 'x'\n"  # a write, not a read
        "subprocess.run(['true'], env=os.environ)\n"  # hands the environment on
        "environ = {}\n"
        "environ.get('GITHUB_TOKEN')\n"  # a local dict of that name
        "def later():\n"
        "    return os.environ['GITHUB_TOKEN']\n"  # never called at import
    )
    assert _reads(src) == []


def _c003(base_src: str, cand_src: str, path: str = "demo/__init__.py") -> list:
    from garnet_guard.checks.content import new_import_time_exec

    base = release("1.0", {path: base_src})
    cand = release("1.1", {path: cand_src})
    return list(new_import_time_exec(CHANGE, base, cand))


def test_new_read_at_import_is_info_with_its_own_finding() -> None:
    from garnet_guard.models import Severity

    (f,) = _c003("import os\n", "import os\nTOKEN = os.environ.get('GITHUB_TOKEN')\n")
    assert f.rule_id == "GRN-C003" and f.lowered_to == Severity.INFO
    assert f.title == "1.1 reads credentials or CI settings at import in 1 module(s)"
    assert f.evidence[0].summary == "demo/__init__.py:2 reads environment variable GITHUB_TOKEN"
    assert "how credential stealers stay quiet" in f.evidence[1].summary


def test_read_beside_a_new_call_keeps_the_call_at_warn() -> None:
    cand = (
        "import os, subprocess\n"
        "if os.environ.get('CI'):\n"
        "    subprocess.Popen(['sh', '-c', 'true'])\n"
    )
    findings = _c003("import os\n", cand)
    assert sorted((f.lowered_to is None, f.title) for f in findings) == [
        (False, "1.1 reads credentials or CI settings at import in 1 module(s)"),
        (True, "1.1 adds import-time calls to sensitive APIs in 1 module(s)"),
    ]


def test_read_the_trusted_version_had_or_only_tests_make_is_quiet() -> None:
    src = "import os\nTOKEN = os.getenv('GITHUB_TOKEN')\n"
    assert _c003(src, src + "x = 1\n") == []
    assert _c003("import os\n", src, path="tests/test_env.py") == []
