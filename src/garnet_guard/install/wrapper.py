"""``garnet pip install …`` and ``garnet uv add|remove|lock|sync …`` (SPEC §10.3).

Check first, then install exactly what was checked:

- pip runs the same command with ``--only-binary :all: -c <checked pins>``,
  so it can only install the wheels Garnet compared, by hash;
- uv writes the checked ``pyproject.toml`` and ``uv.lock`` back (only if
  neither changed meanwhile) and runs ``uv sync --frozen``, which installs
  from that lockfile without resolving again.

At or above ``fail_on`` nothing is installed. When Garnet can't resolve the
command without building, nothing is installed either, and the message
says what needs a build and what to do. ``--garnet-force`` overrides both.
"""

from __future__ import annotations

import os
import shlex
import shutil
import sys
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from ..report import escape
from . import check, pip, shellwords, uv
from .check import Deps, Handoff, Outcome

FORCE = "--garnet-force"
UV_SUBCOMMANDS = ("add", "remove", "lock", "sync")


class WrapperUsage(Exception):
    """The command isn't one the wrapper checks. Exit 3."""


def _split_flags(argv: Sequence[str]) -> tuple[bool, list[str]]:
    force = False
    args = []
    for a in argv:
        if a == FORCE:
            force = True
        elif a.startswith("--garnet-"):
            raise WrapperUsage(f"unknown option {a} (the wrapper's only option is {FORCE})")
        else:
            args.append(a)
    return force, args


def find_pip_python(env: dict[str, str]) -> str | None:
    """The Python that ``pip`` on PATH installs into. The script is read, never run."""
    exe = shutil.which("pip", path=env.get("PATH", ""))
    return shellwords.interpreter_for_pip(exe, env.get("PATH")) if exe else None


def main(
    tool: str,
    argv: Sequence[str],
    *,
    deps: Deps | None = None,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    stdout: TextIO | None = None,
) -> int:
    """Run ``garnet pip|uv …`` and return the exit code."""
    out = stdout or sys.stdout
    try:
        force, args = _split_flags(argv)
    except WrapperUsage as err:
        print(f"garnet: {err}", file=sys.stderr)
        return 3
    here = cwd or Path.cwd()
    environ = dict(os.environ) if env is None else env
    deps = deps or Deps(
        today=datetime.now(UTC).date(), github_token=environ.get("GITHUB_TOKEN") or None
    )
    with tempfile.TemporaryDirectory(prefix="garnet-") as wd:
        workdir = Path(wd)  # mkdtemp: only this user can read it
        try:
            outcome = _check(tool, args, here, environ, deps, workdir)
        except WrapperUsage as err:
            print(f"garnet: {err}", file=sys.stderr)
            return 3
        except (pip.PipError, uv.UvError) as err:
            print(f"garnet: {escape(check.redact(str(err)))}", file=sys.stderr)
            return 3
        return act(outcome, force=force, deps=deps, stdout=out)


def _check(
    tool: str, args: list[str], cwd: Path, env: dict[str, str], deps: Deps, workdir: Path
) -> Outcome:
    # As a shell would read it back, with any credentials in a URL replaced.
    shown = check.redact(shlex.join([tool, *args]))
    if tool == "pip":
        sub, _ = shellwords.subcommand(args, shellwords.PIP_GENERAL_VALUE_OPTIONS)
        if sub != "install":
            raise WrapperUsage("garnet pip checks pip install only: garnet pip install <args>")
        return check.check_pip(
            find_pip_python(env),
            args,
            cwd=cwd,
            env=env,
            command=shown,
            deps=deps,
            workdir=workdir,
        )
    sub, at = shellwords.subcommand(args, shellwords.UV_GLOBAL_VALUE_OPTIONS)
    if sub not in UV_SUBCOMMANDS:
        raise WrapperUsage(
            "garnet uv checks uv add, remove, lock and sync: garnet uv add <args>. "
            "uv pip, uv tool and uvx aren't checked yet."
        )
    return check.check_uv(
        shutil.which("uv", path=env.get("PATH", "")),
        sub,
        args[:at] + args[at + 1 :],
        cwd=cwd,
        env=env,
        command=shown,
        deps=deps,
        workdir=workdir,
    )


def act(outcome: Outcome, *, force: bool, deps: Deps, stdout: TextIO) -> int:
    """Print what the check found, then install, or don't."""

    def say(text: str = "") -> None:
        print(check.redact(text), file=stdout)

    if outcome.status == "uv_only":  # uv lock --check, --dry-run: nothing written
        say(escape(outcome.tool_output.rstrip()))
        return outcome.exit_code
    findings = check.report_text(outcome)
    if findings:
        say(findings.rstrip())
        say()
    if outcome.status == "cant_check":
        say(check.summary(outcome))
        for line in check.reason_lines(outcome):
            say(f"  - {line}")
        if not force:
            say()
            say("What you can do:")
            for pin in check.pins_to_try(outcome):
                say(f"  - Check a version that resolves without building: garnet {pin}")
            plain = escape(outcome.command)
            say(f"  - Run {plain} yourself. Garnet Guard doesn't check that, and it may run")
            say("    build code from the packages above.")
            say(f"  - Run it unchecked through Garnet Guard: garnet {plain} {FORCE}")
            return 3
        for b in outcome.blockers:
            say(escape(f"{FORCE}: not checked: {b.package}"))
        if not outcome.blockers:
            say(escape(f"{FORCE}: not checked: {outcome.command}"))
        return _run(outcome.original, stdout, deps)
    say(check.summary(outcome))
    if outcome.status == "stop":
        if not force:
            say(f"Nothing was installed. To install it anyway, add {FORCE}.")
            return outcome.exit_code
        say(f"{FORCE}: installing although the verdict is {_verdict(outcome)}.")
    handoff = outcome.handoff
    if handoff is None:
        return 0
    if handoff.write_back and handoff.copy is not None:
        try:
            written = uv.write_back(handoff.copy, handoff.write_back)
        except uv.Changed as changed:
            say(
                f"{changed} changed while Garnet Guard was checking. Nothing was written or "
                "installed; run the command again."
            )
            return 3
        if written:
            say(f"Wrote the checked {' and '.join(written)}.")
    if not handoff.argv:
        return 0
    return _run(handoff, stdout, deps)


def _verdict(outcome: Outcome) -> str:
    return outcome.report.verdict.value if outcome.report else "unknown"


def _run(handoff: Handoff | None, stdout: TextIO, deps: Deps) -> int:
    if handoff is None or not handoff.argv:
        return 3
    print(f"Running: {escape(check.redact(handoff.shown))}", file=stdout)
    stdout.flush()
    return deps.run(handoff.argv, cwd=handoff.cwd, env=handoff.env, capture=False).returncode
