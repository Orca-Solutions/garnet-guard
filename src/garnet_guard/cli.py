"""The ``garnet`` command."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, date, datetime
from pathlib import Path

from . import __version__
from .checks import DOCS
from .checks.docs import rule_url
from .engine import ECOSYSTEMS, Options, Report, compare, evaluate, report, unchecked_result
from .facts.pyindex import SENSITIVE_SET_VERSION, sensitive_set
from .lockfiles import LockfileError
from .models import Change, Policy, Severity
from .policy import (
    MAX_POLICY_BYTES,
    PolicyError,
    describe,
    expired_ignores,
    load_policy,
    policy_changes,
)
from .report import escape, to_json, to_text
from .sarif import to_sarif
from .workspace import (
    Unchecked,
    changes_for,
    dedupe,
    discover,
    git_show,
    plain_file,
    read_lockfile,
    registry_settings,
)

_FAIL_ON = {"warn": Severity.WARN, "block": Severity.BLOCK, "never": Severity.OFF}

_EXIT_CODES = """\
exit codes:
  0  nothing at or above --fail-on (by default, warnings exit 0)
  1  warn findings, with --fail-on warn
  2  block findings, with --fail-on warn or block
  3  Garnet couldn't finish: bad arguments, an invalid policy file, an unreadable
     lockfile or an internal error. This is never a pass.

Each finding links to its rule's page; `garnet explain RULE` prints a summary.
"""

_WRAPPER_EXIT_CODES = """\
exit codes:
  0  the check passed and the package manager succeeded
  1  warn findings, with fail_on = "warn"; nothing installed
  2  block findings; nothing installed
  3  Garnet couldn't check the command, or couldn't finish (nothing installed);
     or the package manager failed after the check (uv: the checked files were
     already written, and Garnet says so)
"""

_FAIL_ON_HELP = "exit non-zero at this verdict or worse (default: the policy's fail_on, else block)"
_POLICY_HELP = "policy file (default: garnet.toml here, else [tool.garnet] in pyproject.toml)"
_NO_POLICY_HELP = "don't read a policy file; use the default severities and no ignores"
_GITHUB_ENV_HELP = "environment variable that holds a GitHub token (default: GITHUB_TOKEN)"


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="garnet",
        description="Release-diff guard for dependency updates.",
        epilog=_EXIT_CODES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser(
        "check",
        help="check every dependency change between two lockfiles",
        description="Compare a trusted lockfile with an updated one and check every package\n"
        "version that changed. Reads uv.lock, poetry.lock, pylock.toml and pinned\n"
        "requirements files for PyPI, and package-lock.json, npm-shrinkwrap.json,\n"
        "pnpm-lock.yaml and yarn.lock (Yarn 1 and Yarn 2+) for npm.",
        epilog=_EXIT_CODES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    c.add_argument("--base", metavar="PATH", help="the lockfile you trust")
    c.add_argument(
        "--head",
        metavar="PATH",
        action="append",
        help="the updated lockfile; repeat for several (default: lockfiles found here)",
    )
    c.add_argument("--git-base", metavar="REF", help="read each base lockfile from this git ref")
    c.add_argument(
        "--policy-change",
        metavar="PATH",
        action="append",
        help="with --git-base: report what changed in this policy file since REF (repeatable)",
    )
    c.add_argument(
        "--format",
        choices=("text", "json", "sarif", "markdown"),
        default="text",
        help="report format (default: text)",
    )
    c.add_argument(
        "--output", metavar="PATH", help="write the report to this file instead of stdout"
    )
    _policy_args(c)
    c.add_argument(
        "--offline",
        action="store_true",
        help="use cached data only (not supported in this preview yet)",
    )
    c.add_argument(
        "--cache-dir",
        metavar="PATH",
        help="where to cache downloads (not supported in this preview yet)",
    )
    c.add_argument(
        "--github-token-env", default="GITHUB_TOKEN", metavar="NAME", help=_GITHUB_ENV_HELP
    )

    d = sub.add_parser(
        "diff",
        help="compare two releases of one package",
        description="Compare a release you trust with the one you are updating to.",
        epilog=_EXIT_CODES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    d.add_argument(
        "package",
        help="package name, prefixed with the ecosystem for npm (pypi:requests, npm:chalk, "
        "npm:@scope/name); PyPI when there is no prefix",
    )
    d.add_argument("old", help="the version you trust")
    d.add_argument("new", help="the version you are updating to")
    d.add_argument(
        "--format", choices=("text", "json"), default="text", help="report format (default: text)"
    )
    d.add_argument(
        "--output", metavar="PATH", help="write the report to this file instead of stdout"
    )
    _policy_args(d)
    d.add_argument(
        "--github-token-env", default="GITHUB_TOKEN", metavar="NAME", help=_GITHUB_ENV_HELP
    )

    e = sub.add_parser("explain", help="describe a rule")
    e.add_argument("rule_id", metavar="RULE", help="a rule ID, such as GRN-C003")

    pol = sub.add_parser("policy", help="validate a policy file")
    pol_sub = pol.add_subparsers(dest="policy_command", required=True)
    pc = pol_sub.add_parser(
        "check",
        help="check a policy file and list its ignores",
        description="Check a policy file and list its rule settings and ignores. With no\n"
        "PATH, checks the file garnet check would read here.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    pc.add_argument("path", nargs="?", metavar="PATH", help="the policy file")

    for tool, what, off in (
        ("pip", "pip install", "builds"),
        ("uv", "uv add, remove, lock or sync", "builds"),
        ("npm", "npm install, ci or update", "scripts and git"),
    ):
        w = sub.add_parser(
            tool,
            help=f"check a {what} command, then install only what was checked",
            description=f"garnet {tool} … resolves the command with {off} turned off, checks "
            "every\ndependency change, then installs exactly what was checked. Nothing is "
            "installed\nat or above fail_on, or when the command can't be resolved that way."
            "\n--garnet-force installs anyway. See docs/install-wrapper.md.",
            epilog=_WRAPPER_EXIT_CODES,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        w.add_argument("args", nargs=argparse.REMAINDER, help=f"the {tool} command's arguments")

    h = sub.add_parser(
        "hook",
        help="print an agent hook configuration, or run the hook",
        description="garnet hook claude-code|codex prints the hook configuration to add to\n"
        "the agent's settings. With run, it reads one PreToolUse event on stdin and\n"
        "answers it on stdout (the agent runs this; see docs/install-wrapper.md).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    h.add_argument("agent", choices=("claude-code", "codex"))
    h.add_argument("run", nargs="?", choices=("run",), help="answer one hook event")

    sub.add_parser("version", help="print the version")
    return p


def _policy_args(p: argparse.ArgumentParser) -> None:
    group = p.add_mutually_exclusive_group()
    group.add_argument("--policy", metavar="PATH", help=_POLICY_HELP)
    group.add_argument("--no-policy", action="store_true", help=_NO_POLICY_HELP)
    p.add_argument("--fail-on", choices=tuple(_FAIL_ON), help=_FAIL_ON_HELP)


def main(argv: Sequence[str] | None = None) -> int:
    """Run ``garnet`` and return its exit code. Any failure of Garnet itself is 3."""
    words = list(sys.argv[1:] if argv is None else argv)
    if words[:1] in (["pip"], ["uv"], ["npm"]) and words[1:2] not in (["-h"], ["--help"]):
        # The rest is the package manager's command line, not Garnet's options.
        return _guarded(lambda: _wrapper(words[0], words[1:]))
    try:
        args = _parser().parse_args(words)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 3
    return _guarded(lambda: _dispatch(args))


def _wrapper(tool: str, words: list[str]) -> int:
    from .install import wrapper

    return wrapper.main(tool, words)


def _hook(agent: str, run: bool) -> int:
    from .install import gate, hooks

    if run:
        return gate.run(agent)
    return hooks.print_config(agent)


def _guarded(task: Callable[[], int]) -> int:
    try:
        return task()
    except (UsageError, LockfileError, PolicyError) as err:
        print(f"garnet: {err}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        return 3
    except Exception as err:  # Garnet itself failed
        print(f"garnet: internal error: {type(err).__name__}: {err}", file=sys.stderr)
        return 3


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "hook":
        return _hook(args.agent, args.run == "run")
    if args.command in ("pip", "uv", "npm"):  # only reached for --help, handled by argparse
        return 0
    if args.command == "version":
        print(f"garnet {__version__}")
        return 0
    if args.command == "explain":
        return _explain(args.rule_id)
    if args.command == "check":
        return _check(args)
    if args.command == "policy":
        return _policy_check(args.path)
    return _diff(args)


class UsageError(Exception):
    """Bad arguments, or a feature this preview doesn't have yet."""


def _not_yet(flag: str) -> UsageError:
    return UsageError(f"{flag} isn't supported in this preview yet")


def _policy(args: argparse.Namespace) -> Policy:
    if args.no_policy:
        return Policy()
    return load_policy(Path(args.policy) if args.policy else None, today=_today())


def _fail_on(args: argparse.Namespace, policy: Policy) -> Severity:
    if args.fail_on:
        return _FAIL_ON[args.fail_on]
    return policy.fail_on if policy.fail_on is not None else Severity.BLOCK


def _today() -> date:
    return datetime.now(UTC).date()


def _check(args: argparse.Namespace) -> int:
    """``garnet check``: every dependency change between two lockfiles."""
    if args.offline or args.cache_dir:
        raise _not_yet("--offline/--cache-dir")
    if args.base and args.git_base:
        raise UsageError("use --base or --git-base, not both")
    if not args.base and not args.git_base:
        raise UsageError("give the trusted lockfile with --base PATH or --git-base REF")
    cwd = Path.cwd()
    policy = _policy(args)
    today = _today()
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
        base = (
            read_lockfile(Path(args.base)) if args.base else git_show(args.git_base, head, cwd=cwd)
        )
        name = os.path.relpath(head, cwd) if head.is_absolute() else head.as_posix()
        data = read_lockfile(head)
        registries = registry_settings(head, data, cwd)
        found, skipped = changes_for(name, data, base, registries=registries)
        changes += found
        unchecked += skipped

    token = os.environ.get(args.github_token_env) or None
    options = Options(github_token=token, today=today)
    results = evaluate(dedupe(changes), policy=policy, options=options)
    results += [
        unchecked_result(u.change, u.rule_id, u.detail, policy=policy, today=today)
        for u in unchecked
    ]
    edits = _policy_edits(args.git_base, args.policy_change or [], cwd)
    rep = report(results, policy=policy, today=today, policy_changes=edits)
    if args.format == "json":
        out = to_json(rep)
    elif args.format == "markdown":
        out = _markdown(rep)
    elif args.format == "sarif":
        out = to_sarif(rep)
    else:
        out = to_text(rep, color=args.output is None and sys.stdout.isatty())
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
    else:
        sys.stdout.write(out)
    return rep.exit_code(_fail_on(args, policy))


def _policy_edits(
    git_base: str | None, paths: list[str], cwd: Path
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """What the working tree changes in each policy file since ``git_base``.

    The check itself uses the policy it was given (the Action passes the base
    commit's), so these changes apply only after the pull request merges; the
    report lists them so the reviewer sees a policy edited beside a bump.
    """
    if not paths:
        return ()
    if not git_base:
        raise UsageError("--policy-change needs --git-base")
    out: list[tuple[str, tuple[str, ...]]] = []
    for name in sorted(set(paths)):
        path = Path(name)
        try:
            before = git_show(git_base, path, cwd=cwd)
        except ValueError as err:  # a path outside the repository
            raise UsageError(f"--policy-change {name}: not a file in this repository") from err
        lines: tuple[str, ...]
        if path.is_symlink() or (path.exists() and not plain_file(path, cwd)):
            lines = (f"{name} is not a regular file in this pull request, so it wasn't read",)
        elif path.exists() and path.stat().st_size > MAX_POLICY_BYTES:
            lines = (f"{name} is larger than {MAX_POLICY_BYTES} bytes, so it wasn't read",)
        else:
            after = path.read_bytes() if path.exists() else None
            lines = policy_changes(before, after, source=name)
        if lines:
            out.append((name, lines))
    return tuple(out)


def _markdown(rep: Report) -> str:
    """PR-comment markdown comes from the reporter the GitHub Action ships."""
    try:
        from . import markdown  # type: ignore[attr-defined, unused-ignore]
    except ImportError as err:
        raise _not_yet("--format markdown") from err
    out: str = markdown.to_markdown(rep)
    return out


def _diff(args: argparse.Namespace) -> int:
    """``garnet diff``: two releases of one package."""
    eco, _, name = (
        args.package.partition(":") if ":" in args.package else ("pypi", "", args.package)
    )
    if eco not in ECOSYSTEMS:
        print(f"garnet: unsupported ecosystem {eco!r}; supported: pypi, npm", file=sys.stderr)
        return 3
    policy = _policy(args)
    today = _today()
    token = os.environ.get(args.github_token_env) or None
    options = Options(github_token=token, today=today)
    try:
        result = compare(eco, name, args.old, args.new, policy=policy, options=options)
    except ValueError as err:
        raise UsageError(str(err)) from err
    rep = report([result], policy=policy, today=today)
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
    return rep.exit_code(_fail_on(args, policy))


def _policy_check(path: str | None) -> int:
    """``garnet policy check``: validate a policy file and say what it does."""
    policy = load_policy(Path(path) if path else None, today=_today())
    if policy.source is None:
        where = path or "here"
        print(f"No policy found {'in ' + where if path else where}; the defaults apply.")
        return 0
    expired = set(expired_ignores(policy, _today()))
    print(escape(f"{policy.source}: valid (sha256 {policy.sha256})"))
    if policy.default is not None:
        print(f"  default for warn rules: {policy.default.label}")
    if policy.fail_on is not None:
        print(f"  fail_on: {'never' if policy.fail_on == Severity.OFF else policy.fail_on.label}")
    for rule_id, severity in policy.rules.items():
        print(f"  {rule_id}: {severity.label}")
    for ignore in policy.ignores:
        state = "EXPIRED, no longer applies" if ignore in expired else "applies"
        print(escape(f"  ignore {describe(ignore)} ({state}): {ignore.reason}"))
    if not policy.ignores:
        print("  no ignores")
    return 0


def _explain(rule_id: str) -> int:
    """``garnet explain``: print a rule's docs."""
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
    # the rules that read the set
    if doc.rule_id in ("GRN-C002", "GRN-C003", "GRN-C007", "GRN-C012"):
        print(f"\nSensitive calls (set {SENSITIVE_SET_VERSION}):")
        for s in sensitive_set():
            print(f"  {s}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
