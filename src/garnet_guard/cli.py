"""The ``garnet`` command."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .checks import DOCS
from .checks.docs import rule_url
from .engine import Options, Report, compare, evaluate, report, unchecked_result
from .facts.pyindex import SENSITIVE_SET_VERSION, sensitive_set
from .lockfiles import LockfileError
from .models import Change, Severity
from .report import to_json, to_text
from .workspace import Unchecked, changes_for, dedupe, discover, git_show, plain_file

_FAIL_ON = {"warn": Severity.WARN, "block": Severity.BLOCK, "never": Severity.OFF}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="garnet", description="Release-diff guard for dependency updates."
    )
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", help="check every dependency change between two lockfiles")
    c.add_argument("--base", metavar="PATH", help="the lockfile you trust")
    c.add_argument(
        "--head",
        metavar="PATH",
        action="append",
        help="the updated lockfile; repeat for several (default: lockfiles found here)",
    )
    c.add_argument("--git-base", metavar="REF", help="read each base lockfile from this git ref")
    c.add_argument("--format", choices=("text", "json", "sarif", "markdown"), default="text")
    c.add_argument("--output", help="write the report to this file instead of stdout")
    c.add_argument("--policy", metavar="PATH")
    c.add_argument("--fail-on", choices=tuple(_FAIL_ON), default="block")
    c.add_argument("--offline", action="store_true")
    c.add_argument("--cache-dir", metavar="PATH")
    c.add_argument("--github-token-env", default="GITHUB_TOKEN", metavar="NAME")

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
        if args.command == "check":
            return _check(args)
        return _diff(args)
    except (UsageError, LockfileError) as err:
        print(f"garnet: {err}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        return 3
    except Exception as err:  # Garnet itself failed
        print(f"garnet: internal error: {type(err).__name__}: {err}", file=sys.stderr)
        return 3


class UsageError(Exception):
    pass


def _not_yet(flag: str) -> UsageError:
    return UsageError(f"{flag} isn't supported in this preview yet")


def _check(args: argparse.Namespace) -> int:
    if args.policy:
        raise _not_yet("--policy")
    if args.offline or args.cache_dir:
        raise _not_yet("--offline/--cache-dir")
    if args.format == "sarif":
        raise _not_yet("--format sarif")
    if args.base and args.git_base:
        raise UsageError("use --base or --git-base, not both")
    if not args.base and not args.git_base:
        raise UsageError("give the trusted lockfile with --base PATH or --git-base REF")
    cwd = Path.cwd()
    heads = [Path(h) for h in args.head] if args.head else discover(cwd)
    if not heads:
        raise UsageError("no lockfiles found; pass --head PATH")
    if args.base and len(heads) != 1:
        raise UsageError("--base compares one lockfile; pass exactly one --head")

    changes: list[Change] = []
    unchecked: list[Unchecked] = []
    for head in heads:
        if not plain_file(head, cwd):
            if head.is_symlink() or head.exists():
                raise UsageError(f"refusing {head}: lockfiles must be regular files, not symlinks")
            raise UsageError(f"no such lockfile: {head}")
        base = Path(args.base).read_bytes() if args.base else git_show(args.git_base, head, cwd=cwd)
        name = os.path.relpath(head, cwd) if head.is_absolute() else head.as_posix()
        found, skipped = changes_for(name, head.read_bytes(), base)
        changes += found
        unchecked += skipped

    token = os.environ.get(args.github_token_env) or None
    results = evaluate(dedupe(changes), options=Options(github_token=token))
    results += [unchecked_result(u.change, u.rule_id, u.detail) for u in unchecked]
    rep = report(results)
    if args.format == "json":
        out = to_json(rep)
    elif args.format == "markdown":
        out = _markdown(rep)
    else:
        out = to_text(rep, color=args.output is None and sys.stdout.isatty())
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
    else:
        sys.stdout.write(out)
    return rep.exit_code(_FAIL_ON[args.fail_on])


def _markdown(rep: Report) -> str:
    """PR-comment markdown comes from the reporter the GitHub Action ships."""
    try:
        from . import markdown  # type: ignore[attr-defined, unused-ignore]
    except ImportError as err:
        raise _not_yet("--format markdown") from err
    out: str = markdown.to_markdown(rep)
    return out


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
    print("More: " + rule_url(doc.rule_id))
    if doc.rule_id in ("GRN-C002", "GRN-C003"):
        print(f"\nSensitive calls (set {SENSITIVE_SET_VERSION}):")
        for s in sensitive_set():
            print(f"  {s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
