"""The resolve-and-check step that ``garnet pip``, ``garnet uv`` and the agent
hooks share (SPEC §10.3).

1. Read the command and every file it names; refuse what would build or
   what Garnet can't compare (``pip.plan``, ``uv.plan``).
2. Resolve with builds off: pip's dry run with ``--only-binary :all:`` last,
   or uv in a private copy with ``--no-build``.
3. Compare what is installed or locked now (the base) with the resolution
   (the head), and check every change with ``engine.evaluate``.
4. See whether turning builds off made a requested package resolve lower
   than the package manager would pick, and if so, say so: that is "can't
   check", never a pass.

Nothing here installs. The result says what to run afterwards (the hand-off),
and only the wrapper runs it.
"""

from __future__ import annotations

import os
import re
import shlex
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Literal

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .. import engine
from ..engine import Options, Report, report, unchecked_result
from ..lockfiles import LockfileError
from ..models import (
    Change,
    ChangeResult,
    IndexFile,
    Policy,
    ProjectReleases,
    Severity,
    Verdict,
)
from ..policy import load_policy
from ..report import escape, to_text
from ..workspace import Unchecked, changes_for, dedupe, git_show
from . import npm, pip, uv
from .runner import Ran, Registry, Runner, TimedOut
from .runner import run as run_program

Evaluate = Callable[[list[Change], Policy, Options], list[ChangeResult]]


def _evaluate(changes: list[Change], policy: Policy, options: Options) -> list[ChangeResult]:
    return engine.evaluate(changes, policy=policy, options=options)


def _registry(options: Options) -> Registry:
    return lambda name: engine.pypi_releases(name, options)


def _head_lock(path: Path) -> bytes | None:
    """uv.lock as committed at git HEAD; None when it isn't tracked there."""
    try:
        return git_show("HEAD", path, cwd=path.parent)
    except (LockfileError, OSError, ValueError):
        return None


@dataclass(frozen=True)
class Deps:
    """What the check reaches outside for. Tests pass recorded stand-ins."""

    today: date
    run: Runner = run_program
    registry: Registry | None = None  # None: PyPI's JSON API
    evaluate: Evaluate = _evaluate
    committed_lock: Callable[[Path], bytes | None] = _head_lock
    github_token: str | None = None
    deadline: float | None = None  # a time.monotonic() value

    def options(self) -> Options:
        return Options(github_token=self.github_token, today=self.today)

    def releases(self, name: str) -> ProjectReleases:
        return (self.registry or _registry(self.options()))(name)

    def timeout(self) -> float | None:
        if self.deadline is None:
            return None
        left = self.deadline - time.monotonic()
        if left <= 1:
            raise TimedOut("Garnet Guard ran out of time")
        return left


@dataclass(frozen=True)
class Blocker:
    """A requested package Garnet couldn't resolve without building."""

    package: str  # what was asked for, e.g. "num2words 0.5.14"
    needs: str  # the requirement without a usable wheel, e.g. "docopt>=0.6.2"
    why: str  # "is published only as source"
    builds: bool = True  # False when the reason isn't a build (no such project)
    instead: str | None = None  # what resolved without building, e.g. "num2words 0.5.6"


@dataclass(frozen=True)
class Handoff:
    """A program to run after the check (wrapper only), the checked files to
    write first, a program to run after it succeeds, and lines to print last."""

    argv: tuple[str, ...]
    cwd: Path
    env: Mapping[str, str]
    shown: str  # how to show it to the user
    write_back: tuple[str, ...] = ()
    copy: uv.Copy | None = None
    then: Handoff | None = None  # npm rebuild of the unchanged packages' install scripts
    notes: tuple[str, ...] = ()  # escaped


Status = Literal["pass", "warn", "stop", "cant_check", "uv_only"]
Tool = Literal["pip", "uv", "npm"]


@dataclass
class Outcome:
    """What the check found for one command."""

    tool: Tool
    command: str  # the command as written, for messages (escape before printing)
    status: Status
    report: Report | None = None
    fail_on: Severity = Severity.BLOCK
    exit_code: int = 0
    reasons: list[str] = field(default_factory=list)  # why it couldn't check
    blockers: list[Blocker] = field(default_factory=list)
    handoff: Handoff | None = None  # what to run after a pass
    original: Handoff | None = None  # the command unchanged (--garnet-force)
    tool_output: str = ""  # uv's own output, for uv lock --check and friends

    @property
    def changes(self) -> int:
        return len(self.report.results) if self.report else 0


def _cant(tool: Tool, command: str, *reasons: str, **kw: object) -> Outcome:
    out = Outcome(tool, command, "cant_check", exit_code=3, reasons=list(reasons))
    for key, value in kw.items():
        setattr(out, key, value)
    return out


# The user part of a URL (``https://user:token@host``), up to its last "@".
_CREDENTIALS = re.compile(r"(://)[^/\s]+@")


def redact(text: str) -> str:
    """``text`` with the credentials in every URL replaced by ``****``.

    A command line can carry an index URL with a token in it; nothing Garnet
    prints or writes repeats one.
    """
    return _CREDENTIALS.sub(r"\1****@", text)


def tool_message(ran: Ran, lines: int = 12) -> str:
    """The end of a package manager's error output, with any URL credentials removed."""
    text = redact(ran.stderr.decode("utf-8", "replace"))
    kept = [line.rstrip() for line in text.splitlines() if line.strip()]
    return "\n".join(kept[-lines:])


def _python_ok(requires: str | None, python: Version | None) -> bool:
    if requires is None or python is None:
        return True
    try:
        return SpecifierSet(requires).contains(python, prereleases=True)
    except InvalidSpecifier:
        return True


def newest_release(
    releases: ProjectReleases, spec: SpecifierSet, *, pre: bool, python: Version | None
) -> Version | None:
    """The newest release that matches ``spec``, isn't yanked and supports ``python``.

    Pre-releases count as pip and uv count them: with ``pre``, when the
    specifier names one, or when no final release matches.
    """
    eligible: list[Version] = []
    for version, files in releases.releases:
        try:
            v = Version(version)
        except InvalidVersion:
            continue
        live = [f for f in files if not f.yanked]
        if live and any(_python_ok(f.requires_python, python) for f in live):
            eligible.append(v)
    matching = list(spec.filter(eligible, prereleases=True if pre else None))
    return max(matching) if matching else None


def why_no_wheel(name: str, spec: SpecifierSet, deps: Deps) -> tuple[str, bool]:
    """Why a requirement has no wheel to use, from PyPI's release list, and
    whether that reason is a build."""
    try:
        listed = deps.releases(name)
    except Exception:  # noqa: BLE001  (the reason is only for the message)
        return "needs a build or isn't on PyPI; Garnet Guard couldn't read its release list", True
    if not listed.on_registry:
        return "isn't on PyPI", False
    matching: list[IndexFile] = []
    for version, files in listed.releases:
        try:
            if spec.contains(Version(version), prereleases=True):
                matching.extend(f for f in files if not f.yanked)
        except InvalidVersion:
            continue
    if not matching:
        return "has no release on PyPI that matches", False
    if not any(f.packagetype == "bdist_wheel" for f in matching):
        return "is published only as source", True
    return "has no wheel for this platform or Python version", True


def _blocker(requirement: str, package: str | None, deps: Deps) -> Blocker:
    name = uv.requirement_name(requirement) or requirement
    try:
        spec = Requirement(requirement).specifier
    except InvalidRequirement:
        spec = SpecifierSet()
    why, builds = why_no_wheel(name, spec, deps)
    return Blocker(package or requirement, requirement, why, builds)


def _finish(
    tool: Tool,
    command: str,
    changes: list[Change],
    unchecked: list[Unchecked],
    *,
    cwd: Path,
    deps: Deps,
) -> tuple[Report, Severity]:
    policy = load_policy(cwd=cwd, today=deps.today)
    results = deps.evaluate(dedupe(changes), policy, deps.options()) if changes else []
    results += [
        unchecked_result(u.change, u.rule_id, u.detail, policy=policy, today=deps.today)
        for u in unchecked
    ]
    fail_on = policy.fail_on if policy.fail_on is not None else Severity.BLOCK
    return report(results, policy=policy, today=deps.today), fail_on


def _verdict(out: Outcome, rep: Report, fail_on: Severity) -> Outcome:
    out.report, out.fail_on = rep, fail_on
    if out.blockers:
        out.status, out.exit_code = "cant_check", 3
        return out
    code = rep.exit_code(fail_on)
    if code:
        out.status, out.exit_code = "stop", code
    else:
        # Below fail_on (or fail_on = "never"), a warn or block verdict is
        # still reported as one: only "pass" says nothing was found.
        out.status = "pass" if rep.verdict == Verdict.PASS else "warn"
    return out


# --- pip --------------------------------------------------------------------


def pip_python(given: str | None, cwd: Path) -> str | None:
    """pip's ``--python``: an interpreter, or an environment folder."""
    if given is None:
        return None
    path = Path(os.path.expanduser(given))
    path = path if path.is_absolute() else cwd / path
    if path.is_dir():
        for rel in ("bin/python", "bin/python3", "Scripts/python.exe"):
            if (path / rel).is_file():
                return str(path / rel)
        return None
    return str(path) if path.is_file() else None


def _pip_env(env: Mapping[str, str]) -> dict[str, str]:
    out = dict(env)
    out["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    out["PIP_NO_INPUT"] = "1"
    return out


def _pins_lines(pins: Mapping[str, str]) -> bytes:
    return "".join(f"{name}=={pins[name]}\n" for name in sorted(pins)).encode()


def check_pip(
    python: str | None,
    args: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    command: str,
    deps: Deps,
    workdir: Path,
) -> Outcome:
    """Check ``pip install …`` (``args`` from ``install`` on) without installing."""
    plan = pip.plan(args, cwd=cwd, env=env)
    target = pip_python(plan.python, cwd) if plan.python else python
    if plan.python and target is None:
        return _cant(
            "pip", command, f"pip's --python {plan.python} isn't a Python Garnet can find."
        )
    if target is None:
        return _cant("pip", command, "Garnet Guard can't find the Python this pip installs into.")
    pip_argv = (target, "-I", "-m", "pip")
    original = Handoff((*pip_argv, *args), cwd, env, command)
    if plan.refusals:
        return _refused("pip", command, plan.refusals, original)
    penv = _pip_env(env)
    config = deps.run([*pip_argv, "config", "list"], cwd=cwd, env=penv, timeout=deps.timeout())
    if config.returncode != 0:
        return _cant(
            "pip",
            command,
            "Garnet Guard couldn't read pip's configuration (pip config list failed).",
            original=original,
        )
    refusals = pip.config_refusals(config.stdout.decode("utf-8", "replace"))
    if refusals:
        return _refused("pip", command, refusals, original)
    inspected = deps.run([*pip_argv, "inspect"], cwd=cwd, env=penv, timeout=deps.timeout())
    if inspected.returncode != 0:
        return _cant(
            "pip",
            command,
            "Garnet Guard couldn't read what's installed (pip inspect failed; it needs pip 22.2 "
            "or later).",
            original=original,
        )
    installed = pip.parse_inspect(inspected.stdout)
    py_version = _version(installed.python_version)

    def resolve(pin: str | None, name: str) -> tuple[Ran, Path]:
        """pip's dry run, builds off; ``pin`` adds a one-line constraints file (a probe)."""
        path = workdir / f"{name}.json"
        extra: list[str] = []
        if pin:
            cpath = workdir / f"{name}.txt"
            cpath.write_text(pin + "\n", encoding="utf-8")
            extra = ["-c", str(cpath)]
        at = plan.insert_at
        argv = [
            *pip_argv,
            *plan.args[:at],
            "--dry-run",
            "--quiet",
            "--report",
            str(path),
            *extra,
            "--only-binary",
            ":all:",  # last, so nothing in the command turns builds back on
            *plan.args[at:],
        ]
        return deps.run(argv, cwd=cwd, env=penv, timeout=deps.timeout()), path

    ran, report_path = resolve(None, "pip-report")
    if ran.returncode != 0:
        unresolved = pip.unresolvable(ran.stderr.decode("utf-8", "replace"))
        if unresolved:
            blockers = [_blocker(u.requirement, u.wanted_by, deps) for u in unresolved]
            return _cant("pip", command, blockers=blockers, original=original)
        return _cant(
            "pip",
            command,
            "pip couldn't resolve this with builds turned off:\n" + tool_message(ran),
            original=original,
        )
    if not report_path.is_file():
        return _cant("pip", command, "pip wrote no installation report.", original=original)
    resolved = pip.parse_report(report_path.read_bytes())
    if any(not r.wheel for r in resolved):
        return _cant(
            "pip",
            command,
            "pip's resolution includes a file that isn't a wheel.",
            original=original,
        )

    out = Outcome("pip", command, "pass", original=original)
    out.blockers += _pip_newest(plan, resolved, py_version, resolve, deps)

    head = dict(installed.pins)
    unchecked: list[Unchecked] = []
    for r in resolved:
        if r.from_pypi:
            head[r.name] = r.version
        else:
            head.pop(r.name, None)
            change = Change("pypi", r.name, installed.pins.get(r.name), r.version)
            unchecked.append(
                Unchecked(change, "GRN-E005", "pip installs it from an index other than PyPI")
            )
    found, more = changes_for("requirements.txt", _pins_lines(head), _pins_lines(installed.pins))
    changes = [replace(c, lockfile=None, line=None) for c in found]
    rep, fail_on = _finish("pip", command, changes, unchecked + more, cwd=cwd, deps=deps)

    pins: dict[str, tuple[str, str | None]] = {
        name: (version, None) for name, version in installed.pins.items()
    }
    pins.update({r.name: (r.version, r.sha256) for r in resolved})
    pins_path = workdir / "garnet-checked-pins.txt"
    fd = os.open(pins_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(pip.pins_text(pins))
    at = plan.insert_at
    argv = (
        *pip_argv,
        *plan.args[:at],
        "--only-binary",
        ":all:",
        "-c",
        str(pins_path),
        *plan.args[at:],
    )
    before = shlex.join((*pip_argv, *plan.args[:at], "--only-binary", ":all:", "-c"))
    after = shlex.join(plan.args[at:])
    shown = f"{before} <checked pins>" + (f" {after}" if after else "")
    out.handoff = Handoff(argv, cwd, env, shown)
    return _verdict(out, rep, fail_on)


def _version(text: str | None) -> Version | None:
    try:
        return Version(text) if text else None
    except InvalidVersion:
        return None


def _pip_newest(
    plan: pip.Plan,
    resolved: list[pip.Resolved],
    python: Version | None,
    resolve: Callable[[str | None, str], tuple[Ran, Path]],
    deps: Deps,
) -> list[Blocker]:
    """Requested packages that resolved lower than their newest release
    because the newest needs a build."""
    if not plan.compare_newest:
        return []
    out = []
    for n, r in enumerate(sorted(resolved, key=lambda r: r.name)):
        if not (r.requested and r.from_pypi and r.name in plan.requested):
            continue
        spec = plan.requested[r.name] & plan.constraints.get(r.name, SpecifierSet())
        newest = newest_release(deps.releases(r.name), spec, pre=plan.pre, python=python)
        if newest is None or newest <= Version(r.version):
            continue
        ran, _ = resolve(f"{r.name}=={newest}", f"pip-probe-{n}")
        if ran.returncode == 0:
            continue  # pip picked the lower release for another reason
        unresolved = pip.unresolvable(ran.stderr.decode("utf-8", "replace"))
        if unresolved:
            u = unresolved[0]
            blocker = _blocker(u.requirement, f"{r.name} {newest}", deps)
            out.append(replace(blocker, instead=f"{r.name} {r.version}"))
    return out


def _refused(
    tool: Tool, command: str, refusals: Sequence[pip.Refusal], original: Handoff
) -> Outcome:
    lines = [f"{r.what}: {r.why}." for r in refusals]
    return _cant(tool, command, *lines, original=original)


# --- uv ---------------------------------------------------------------------


def check_uv(
    uv_exe: str | None,
    subcommand: str,
    args: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    command: str,
    deps: Deps,
    workdir: Path,
) -> Outcome:
    """Check ``uv add|remove|lock|sync …`` in a private copy of the project."""
    if uv_exe is None:
        return _cant("uv", command, "Garnet Guard can't find uv on PATH.")
    original = Handoff((uv_exe, subcommand, *args), cwd, env, command)
    plan = uv.plan(subcommand, args, cwd=cwd, env=env)
    if plan.refusals:
        return _refused("uv", command, plan.refusals, original)
    project = uv.find_project(plan.start)
    if project is None:
        return _cant(
            "uv", command, f"there's no pyproject.toml in {plan.start} or above.", original=original
        )
    try:
        refusals = uv.project_refusals(project)
        if refusals:
            return _refused("uv", command, refusals, original)
        copy = uv.copy_project(project, _private(workdir / "project"))
    except uv.UvError as err:
        return _cant("uv", command, f"{err}.", original=original)
    base = deps.committed_lock(project / "uv.lock")
    if base is None:
        base = copy.originals.get("uv.lock")
    renv = uv.resolve_env(env)

    def run_uv(argv: Sequence[str], where: Path) -> Ran:
        """uv in the copy: builds off and never a Python download (uv.resolve_env)."""
        full = [uv_exe, argv[0], uv.NO_PYTHON_DOWNLOADS, *argv[1:]]
        return deps.run(full, cwd=where, env=renv, timeout=deps.timeout())

    relocked = True
    if subcommand in ("add", "remove"):
        ran = run_uv([subcommand, "--no-sync", "--no-build", *plan.resolve], copy.root)
    elif subcommand == "lock":
        ran = run_uv(["lock", "--no-build", *plan.resolve], copy.root)
        if plan.check_only:
            out = Outcome("uv", command, "uv_only", exit_code=ran.returncode)
            out.tool_output = (ran.stderr + ran.stdout).decode("utf-8", "replace")
            return out
    else:  # sync
        ran = Ran(0)
        relocked = False
        if not plan.frozen:
            if not plan.upgrade:
                ran = run_uv(["lock", "--check", "--no-build", *plan.lock_args], copy.root)
            if plan.upgrade or ran.returncode != 0:
                if plan.locked:
                    out = Outcome("uv", command, "uv_only", exit_code=ran.returncode or 1)
                    out.tool_output = (ran.stderr + ran.stdout).decode("utf-8", "replace")
                    return out
                ran = run_uv(["lock", "--no-build", *plan.lock_args], copy.root)
                relocked = True
    if ran.returncode != 0:
        needs = uv.no_wheel_packages(ran.stderr.decode("utf-8", "replace"))
        if needs:
            asked = ", ".join(sorted(plan.requested)) or None
            blockers = [_blocker(name, asked, deps) for name in needs]
            return _cant("uv", command, blockers=blockers, original=original)
        return _cant(
            "uv",
            command,
            "uv couldn't resolve this with builds and Python downloads turned off:\n"
            + tool_message(ran),
            original=original,
        )
    head = copy.head("uv.lock")
    if head is None:
        return _cant("uv", command, "uv wrote no uv.lock.", original=original)
    local = uv.lock_sources(head)
    if local:
        # A git, path, directory, editable or URL package is built by the
        # sync, and has no release to compare with, whatever brought it in.
        lines = [
            f"uv.lock {name}: it comes from a {kind} source, which uv builds and Garnet Guard "
            "can't compare with a release."
            for name, kind in local
        ]
        return _cant("uv", command, *lines, original=original)

    out = Outcome("uv", command, "pass", original=original)
    if plan.compare_newest and plan.requested:
        floor = uv.requires_python_floor(copy.root)
        for n, name in enumerate(sorted(plan.requested)):
            found = _uv_newest(
                name, plan, head, floor, project, workdir / f"probe-{n}", run_uv, deps
            )
            if found:
                out.blockers.append(found)

    changes, unchecked = changes_for("uv.lock", head, base)
    rep, fail_on = _finish("uv", command, changes, unchecked, cwd=cwd, deps=deps)

    names = ("pyproject.toml", "uv.lock") if subcommand in ("add", "remove") else ("uv.lock",)
    writes = names if relocked else ()
    if subcommand == "lock" or plan.no_sync:
        argv: tuple[str, ...] = ()
        shown = ""
    else:
        argv = (uv_exe, "sync", "--frozen")
        if subcommand == "add":
            argv += ("--inexact",)
        argv += tuple(plan.handoff)
        for c in sorted({c.package for c in changes} | {u.change.package for u in unchecked}):
            argv += ("--no-build-package", c)
        shown = shlex.join(("uv", *argv[1:]))
    out.handoff = Handoff(argv, cwd, env, shown, writes, copy)
    return _verdict(out, rep, fail_on)


def _private(path: Path) -> Path:
    path.mkdir(mode=0o700)
    return path


def _uv_newest(
    name: str,
    plan: uv.Plan,
    head: bytes,
    floor: Version | None,
    project: Path,
    probe_dir: Path,
    run_uv: Callable[[Sequence[str], Path], Ran],
    deps: Deps,
) -> Blocker | None:
    """Whether ``name`` locked lower than its newest release because the newest needs a build."""
    locked = _version(uv.lock_version(head, name))
    if locked is None:
        return None
    newest = newest_release(deps.releases(name), plan.requested[name], pre=plan.pre, python=floor)
    if newest is None or newest <= locked:
        return None
    copy = uv.copy_project(project, _private(probe_dir))
    ran = run_uv(
        ["add", "--no-sync", "--no-build", *plan.index_args, f"{name}=={newest}"], copy.root
    )
    if ran.returncode == 0:
        return None  # uv picked the lower release for another reason
    needs = uv.no_wheel_packages(ran.stderr.decode("utf-8", "replace"))
    if not needs:
        return None
    return replace(_blocker(needs[0], f"{name} {newest}", deps), instead=f"{name} {locked}")


# --- npm --------------------------------------------------------------------


def check_npm(
    npm_exe: str | None,
    subcommand: str,
    args: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    command: str,
    deps: Deps,
    workdir: Path,
) -> Outcome:
    """Check ``npm install|ci|update …`` in a private copy of the project.

    ``subcommand`` is canonical (``npm.CHECKED``). install and update
    resolve with ``--package-lock-only`` and scripts and git off; ci checks
    the lockfile on disk. The base is the lockfile at git HEAD, else the
    one on disk before the command.
    """
    if npm_exe is None:
        return _cant("npm", command, "Garnet Guard can't find npm on PATH.")
    original = Handoff((npm_exe, subcommand, *args), cwd, env, command)
    plan = npm.plan(subcommand, args)
    if plan.refusals:
        return _refused("npm", command, plan.refusals, original)
    project = npm.find_project(cwd)
    lockfile = npm.lockfile_name(project)
    folder = _private(workdir / "project") / project.name
    folder.mkdir(mode=0o700)
    try:
        copy = uv.copy_project(project, folder, npm.COPIED, npm.MAX_FILE_BYTES)
        refusals = npm.project_refusals(project, copy.originals.get("package.json"))
    except (uv.UvError, npm.NpmError) as err:
        return _cant("npm", command, f"{err}.", original=original)
    if refusals:
        return _refused("npm", command, refusals, original)
    if copy.originals.get("package.json") is None and subcommand != "install":
        return _cant("npm", command, f"there's no package.json in {project}.", original=original)
    why = npm.program_refusal(npm_exe, project, cwd, env.get("PATH", ""))
    if why:
        return _cant(
            "npm",
            command,
            f"Garnet Guard doesn't start this npm before you approve the command: {why}.",
            original=original,
        )
    cenv = npm.check_env(env)  # no NODE_OPTIONS preloads in any npm the check runs
    version = deps.run([npm_exe, "--version"], cwd=copy.root, env=cenv, timeout=deps.timeout())
    major = npm.npm_major(version.stdout.decode("utf-8", "replace"))
    if version.returncode != 0 or major not in npm.TESTED_MAJORS:
        shown = escape(version.stdout.decode("utf-8", "replace").strip()[:40]) or "unknown"
        return _cant(
            "npm",
            command,
            f"npm here is version {shown}; Garnet Guard checks with npm 10 and 11, the versions "
            "its resolve step was tested with.",
            original=original,
        )
    # The user's settings, as npm in the project reads them (the copy holds
    # its .npmrc). npm config get runs no package code.
    config = deps.run(
        [npm_exe, "config", "get", *npm.CONFIG_KEYS],
        cwd=copy.root,
        env=cenv,
        timeout=deps.timeout(),
    )
    if config.returncode != 0:
        return _cant(
            "npm",
            command,
            "Garnet Guard couldn't read npm's settings (npm config get failed).",
            original=original,
        )
    bad, config_ignores = npm.config_refusals(config.stdout.decode("utf-8", "replace"))
    if bad:
        return _refused("npm", command, bad, original)

    renv = npm.resolve_env(env, workdir)
    if subcommand != "ci":
        ran = deps.run(
            [npm_exe, subcommand, *plan.resolve, *npm.RESOLVE_TAIL],
            cwd=copy.root,
            env=renv,
            timeout=deps.timeout(),
        )
        if ran.returncode != 0:
            return _cant(
                "npm",
                command,
                "npm couldn't resolve this with scripts and git turned off:\n" + tool_message(ran),
                original=original,
            )
    head = copy.head(lockfile)
    if head is None:
        why = f"npm wrote no {lockfile}." if subcommand != "ci" else f"there's no {lockfile}."
        return _cant("npm", command, why, original=original)
    try:
        lines = npm.lock_refusals(lockfile, head)
    except npm.NpmError as err:
        return _cant("npm", command, f"{err}.", original=original)
    if lines:
        return _cant("npm", command, *lines, original=original)

    base = deps.committed_lock(project / lockfile)
    if base is None:
        base = copy.originals.get(lockfile)
    changes, unchecked = changes_for(lockfile, head, base)
    out = Outcome("npm", command, "pass", original=original)
    rep, fail_on = _finish("npm", command, changes, unchecked, cwd=cwd, deps=deps)

    names = ("package.json", lockfile) if subcommand != "ci" else ()
    if plan.dry_run:
        out.handoff = None
        return _verdict(out, rep, fail_on)
    if plan.lock_only:
        out.handoff = Handoff((), cwd, env, "", names, copy)
        return _verdict(out, rep, fail_on)
    argv = (npm_exe, "ci", "--ignore-scripts", *plan.handoff)
    shown = shlex.join(("npm", *argv[1:]))
    then, notes = _npm_scripts(head, base, plan, config_ignores, copy, project, npm_exe, env)
    out.handoff = Handoff(argv, project, env, shown, names, copy, then, notes)
    return _verdict(out, rep, fail_on)


def _npm_scripts(
    head: bytes,
    base: bytes | None,
    plan: npm.Plan,
    config_ignores: bool,
    copy: uv.Copy,
    project: Path,
    npm_exe: str,
    env: Mapping[str, str],
) -> tuple[Handoff | None, tuple[str, ...]]:
    """npm rebuild for the unchanged packages' install scripts, and what to say
    about the ones that don't run.

    npm ci runs with --ignore-scripts, so no package that changed runs code
    as it installs, as uv's --no-build-package does for a changed package.
    A package is unchanged when the base lockfile has the same entry at the
    same path: name, version, resolved URL and integrity. npm rebuild is given
    that path (``./node_modules/a``), which npm 10 and 11 match exactly; a
    name and version would also match another package installed under that
    folder name deeper in the tree, or an alias of another package.
    """
    trusted = npm.entries(base)
    found = npm.scripted(head)
    unchanged = [s for s in found if trusted.get(s.path) == s]
    changed = [s for s in found if trusted.get(s.path) != s]
    notes = []
    if changed:
        listed = ", ".join(f"{s.package} {s.version}" for s in changed)
        specs = " ".join(s.rebuild_spec for s in changed)
        notes.append(
            escape(
                f"Install scripts that didn't run, because the package is new or changed: "
                f"{listed}. Garnet Guard checked these packages but doesn't run code from "
                f"one that changed. After reviewing them, run: npm rebuild {specs}"
            )
        )
    own = npm.root_scripts(copy.head("package.json"))
    if own:
        notes.append(
            escape(
                "The project's own install scripts didn't run ("
                + ", ".join(own)
                + "). To run one: npm run <name>"
            )
        )
    then = None
    if unchanged and not (plan.ignore_scripts or config_ignores):
        argv = (npm_exe, "rebuild", *(s.rebuild_spec for s in unchanged))
        then = Handoff(argv, project, env, shlex.join(("npm", *argv[1:])))
    return then, tuple(notes)


# --- What to say ------------------------------------------------------------


def blocker_lines(out: Outcome) -> list[str]:
    """One line per package Garnet couldn't resolve without building. Escaped."""
    lines = []
    for b in out.blockers:
        asked = uv.requirement_name(b.package.split(" ")[0])
        if asked and asked == uv.requirement_name(b.needs):
            line = f"{b.package} {b.why}." if b.instead else f"{b.needs} {b.why}."
        else:
            line = f"{b.package} needs {b.needs}, which {b.why}."
        if b.builds:
            needed = uv.requirement_name(b.needs) or b.needs
            line += f" Resolving {needed} would run its build code, so Garnet Guard didn't."
        if b.instead:
            name, _, version = b.instead.partition(" ")
            line += f" Without building, {name} resolves to {version}."
        lines.append(escape(line))
    return lines


def reason_lines(out: Outcome) -> list[str]:
    """Why Garnet didn't check: refusals and failures, then blockers. Escaped."""
    return [escape(r) for r in out.reasons] + blocker_lines(out)


def pins_to_try(out: Outcome) -> list[str]:
    """Commands with the versions Garnet resolved without building, to check instead."""
    pins = []
    for b in out.blockers:
        if b.instead:
            name, _, version = b.instead.partition(" ")
            word = "install" if out.tool == "pip" else "add"
            pins.append(escape(f"{out.tool} {word} {name}=={version}"))
    return pins


def report_text(out: Outcome) -> str:
    """The findings for the changes Garnet could check, as ``garnet check`` prints them."""
    if out.report is None or not out.report.results:
        return ""
    return to_text(out.report)


def summary(out: Outcome) -> str:
    """One line on what was checked and what it found. Escaped."""
    n = out.changes
    things = f"{n} dependency change" + ("" if n == 1 else "s")
    if out.status == "cant_check":
        if n:
            return (
                f"Garnet Guard checked {things} (above), but not the command as written. "
                "Nothing was installed."
            )
        return "Garnet Guard didn't check this command. Nothing was installed."
    if out.report is None or not n:
        return "Garnet Guard found no dependency changes to check."
    worst = out.report.verdict.value
    fail_on = "never" if out.fail_on == Severity.OFF else out.fail_on.label
    if out.status == "stop":
        return (
            f"Garnet Guard checked {things}: the verdict is {worst}, at or above "
            f"fail_on = {fail_on}."
        )
    if out.status == "warn":
        return f"Garnet Guard checked {things}: the verdict is {worst}, below fail_on = {fail_on}."
    return f"Garnet Guard checked {things}: nothing at warn or above."
