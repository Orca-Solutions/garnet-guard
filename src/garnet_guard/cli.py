"""The ``garnet`` command."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from . import __version__
from .checks import DOCS
from .engine import Options, compare, report
from .facts.pyindex import SENSITIVE_SET_VERSION, sensitive_set
from .models import Severity
from .report import to_json, to_text

_FAIL_ON = {"warn": Severity.WARN, "block": Severity.BLOCK, "never": Severity.OFF}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="garnet", description="Release-diff guard for dependency updates."
    )
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("diff", help="compare two releases of one package")
    d.add_argument(
        "package", help="package name, optionally prefixed with the ecosystem (pypi:requests)"
    )
    d.add_argument("old", help="the version you trust")
    d.add_argument("new", help="the version you are updating to")
    d.add_argument("--format", choices=("text", "json"), default="text")
    d.add_argument("--output", help="write the report to this file instead of stdout")
    d.add_argument("--fail-on", choices=tuple(_FAIL_ON), default="block")
    d.add_argument("--github-token-env", default="GITHUB_TOKEN", metavar="NAME")

    e = sub.add_parser("explain", help="describe a rule")
    e.add_argument("rule_id")

    sub.add_parser("version", help="print the version")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 3
    try:
        if args.command == "version":
            print(f"garnet {__version__}")
            return 0
        if args.command == "explain":
            return _explain(args.rule_id)
        return _diff(args)
    except KeyboardInterrupt:
        return 3
    except Exception as err:  # Garnet itself failed
        print(f"garnet: internal error: {type(err).__name__}: {err}", file=sys.stderr)
        return 3


def _diff(args: argparse.Namespace) -> int:
    eco, _, name = args.package.rpartition(":")
    eco = eco or "pypi"
    if eco != "pypi":
        print(f"garnet: unsupported ecosystem {eco!r}; 0.1 supports pypi", file=sys.stderr)
        return 3
    token = os.environ.get(args.github_token_env) or None
    result = compare(eco, name, args.old, args.new, options=Options(github_token=token))
    rep = report([result])
    if args.format == "json":
        out = to_json(rep)
    else:
        tty = args.output is None and sys.stdout.isatty()
        out = to_text(rep, color=tty)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
    else:
        sys.stdout.write(out)
    return rep.exit_code(_FAIL_ON[args.fail_on])


def _explain(rule_id: str) -> int:
    doc = DOCS.get(rule_id.upper())
    if doc is None:
        print(
            f"garnet: unknown rule {rule_id!r}. Known: {', '.join(sorted(DOCS))}", file=sys.stderr
        )
        return 3
    print(f"{doc.rule_id} {doc.name} ({doc.kind} rule, default {doc.default.label})\n")
    print(doc.summary + "\n")
    print("Why it matters: " + doc.explanation + "\n")
    print("What to do: " + doc.remediation)
    if doc.rule_id in ("GRN-C002", "GRN-C003"):
        print(f"\nSensitive calls (set {SENSITIVE_SET_VERSION}):")
        for s in sensitive_set():
            print(f"  {s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
