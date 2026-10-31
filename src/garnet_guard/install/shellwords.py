"""Find the package-manager commands in a shell command line, without running it.

The hooks see the command an agent is about to run. That text may come from
an agent that read hostile content, so it is only ever parsed, here, with the
standard library's ``shlex``. Nothing in it is run, expanded or sourced.

What is followed: ``&&``, ``||``, ``;``, ``|``, ``&`` and newlines; redirections
(dropped); the commands after shell reserved words (``if``, ``then``, ``do``,
``!``, ``{``) and in function bodies; leading ``NAME=value`` assignments and
literal ``export``; the wrappers ``sudo``, ``env``, ``command``, ``time``,
``nice``, ``nohup``, ``exec`` and ``timeout``; literal ``cd`` and ``pushd``;
``source <venv>/bin/activate``; one level of ``bash [options] -c '<literal
script>'``; and ``uv run``, read as the ``uv sync`` it starts with.

What makes a command "can't tell" when a package-manager word is in it:
command or process substitution, a shell variable in a package-manager
command, ``eval``, ``xargs``, here-documents, unbalanced quotes, text piped
into a shell, ``python -m uv``, a pip or uv option before the subcommand
that isn't in the tables below, a program not followed here with ``pip
install`` or ``uv add`` among its arguments, and anything else the shell
would expand before the package manager sees it. Scripts, aliases and
functions defined by an earlier command aren't visible here at all.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from .gate import PM_WORD, fold

# What the pre-scan writes in place of characters the shell would expand,
# so a word that held one is still known after shlex has removed the quotes.
_DOLLAR = "\ue000"
_TILDE = "\ue001"
_BACKTICK = "\ue002"
_EXPANDS = (_DOLLAR, _BACKTICK)

_SEPARATORS = frozenset({"&&", "||", ";", "|", "&", "|&", ";;", ";&", ";;&", "(", ")"})
_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)
_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ksh"})
_PIP = re.compile(r"^pip(?:3(?:\.\d+)?)?(?:\.exe)?$")
_PYTHON = re.compile(r"^(?:(?:python|pypy)(?:\d+(?:\.\d+)?)?[tdm]?|py)(?:\.exe)?$")
# Environment variables that change which package manager runs or where it
# installs. An unknown value for one of these makes later commands unclear.
_RELEVANT_ENV = re.compile(r"^(?:PIP_|UV_|PYTHON|VIRTUAL_ENV$|PATH$|CONDA_PREFIX$)")

# pip's general options, before the subcommand, and whether each takes a
# value (pip 26.2.2, main_parser's general group, aliases included). pip
# accepts any unique prefix of one of these.
PIP_GENERAL_OPTIONS: dict[str, bool] = {
    "--help": False, "--debug": False, "--isolated": False, "--require-virtualenv": False,
    "--require-venv": False, "--python": True, "--verbose": False, "--version": False,
    "--quiet": False, "--log": True, "--log-file": True, "--local-log": True,
    "--no-input": False, "--keyring-provider": True, "--proxy": True, "--no-proxy-env": False,
    "--retries": True, "--timeout": True, "--default-timeout": True, "--exists-action": True,
    "--trusted-host": True, "--cert": True, "--client-cert": True, "--cache-dir": True,
    "--no-cache-dir": False, "--disable-pip-version-check": False, "--no-color": False,
    "--no-python-version-warning": False, "--use-feature": True, "--use-deprecated": True,
    "--resume-retries": True,
}  # fmt: skip
PIP_GENERAL_VALUE_OPTIONS = frozenset(k for k, v in PIP_GENERAL_OPTIONS.items() if v)
_PIP_SHORT = frozenset("hvVq")
# uv's global options before the subcommand, and whether each takes a value
# (uv 0.11.32, hidden ones included). uv takes no abbreviations.
UV_GLOBAL_OPTIONS: dict[str, bool] = {
    "--cache-dir": True, "--color": True, "--config-file": True, "--directory": True,
    "--project": True, "--allow-insecure-host": True, "--trusted-host": True,
    "--python-preference": True, "--preview-features": True, "--python-fetch": True,
    "--quiet": False, "--verbose": False, "--no-cache": False, "--no-config": False,
    "--offline": False, "--native-tls": False, "--system-certs": False,
    "--managed-python": False, "--no-managed-python": False, "--no-python-downloads": False,
    "--allow-python-downloads": False, "--no-progress": False, "--preview": False,
    "--no-preview": False, "--help": False, "--version": False, "--no-color": False,
    "--show-settings": False, "--isolated": False, "--no-installer-metadata": False,
}  # fmt: skip
UV_GLOBAL_VALUE_OPTIONS = frozenset(k for k, v in UV_GLOBAL_OPTIONS.items() if v)
_UV_SHORT = frozenset("qvnhV")
# Shell words that start a compound command: the command after them runs.
_RESERVED = frozenset({"if", "then", "elif", "else", "do", "while", "until", "!", "{", "}"})
# Programs that only print, search or look up their arguments, so a
# package-manager word among them runs nothing.
_PRINTS = frozenset(
    {
        "echo", "printf", "man", "help", "which", "type", "whatis", "apropos", "info", "tldr",
        "grep", "egrep", "fgrep", "rg", "ag", "ack", "cat", "less", "more", "head", "tail",
    }
)  # fmt: skip
# Shell options that take a value (bash, sh, zsh, dash, ksh).
_SHELL_VALUE_OPTIONS = frozenset({"-o", "+o", "-O", "+O", "--rcfile", "--init-file"})

# Install-like subcommands of the tools Garnet doesn't wrap yet.
_NPM_INSTALLS = frozenset(
    {
        "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal",
        "isntall", "add", "ci", "clean-install", "ic", "install-clean", "isntall-clean",
        "update", "up", "upgrade", "udpate", "install-test", "it", "install-ci-test", "cit",
        "exec", "x",
    }
)  # fmt: skip
_PNPM_INSTALLS = frozenset({"add", "install", "i", "update", "up", "upgrade", "dlx"})
_YARN_INSTALLS = frozenset({"add", "install", "up", "upgrade", "upgrade-interactive", "dlx"})
_POETRY_INSTALLS = frozenset({"add", "install", "update", "lock", "sync"})
_NPM_WHY = (
    "Garnet Guard can't read npm, pnpm or yarn lockfiles yet, so it can't compare what "
    "this would install with what the project has now."
)


@dataclass(frozen=True)
class PipCommand:
    """``pip install …`` (any spelling), with the interpreter it installs into."""

    python: str | None  # absolute path of the target interpreter; None if not found
    program: str  # as written, for messages
    args: tuple[str, ...]  # everything after the program (or after ``-m pip``)
    cwd: str
    env: Mapping[str, str]  # assignments in effect for this command
    text: str


@dataclass(frozen=True)
class UvCommand:
    """``uv add|remove|lock|sync …``."""

    uv: str | None  # absolute path of uv; None if not found
    subcommand: str
    args: tuple[str, ...]  # every argument except ``uv`` and the subcommand
    cwd: str
    env: Mapping[str, str]
    text: str
    via_run: bool = False  # ``uv run``, checked as the ``uv sync`` it starts with


@dataclass(frozen=True)
class Unsupported:
    """An install with a tool Garnet doesn't check yet. Reported, never passed.

    ``ask``: the command installs packages Garnet can't see (uvx, uv tool,
    uv run --with, poetry), so it is "can't check", not a note.
    """

    tool: str
    why: str
    text: str
    ask: bool = False


@dataclass(frozen=True)
class Unclear:
    """A command Garnet can't read for sure, with a package-manager word in it."""

    why: str
    text: str


Found = PipCommand | UvCommand | Unsupported | Unclear


@dataclass(frozen=True)
class _Line:
    """A parsed command line: its simple commands and anything that clouds the whole line."""

    simple: tuple[tuple[str, ...], ...]
    unclear: str | None = None


def _prescan(text: str) -> tuple[str, str | None]:
    """Mark what the shell would expand, drop comments and fd numbers, and
    turn unquoted newlines into ``;``. Returns the text for shlex and, when
    the whole line is unclear, why."""
    out: list[str] = []
    why: str | None = None
    quote: str | None = None
    word_start = True
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if quote == "'":
            out.append(c)
            if c == "'":
                quote = None
            i += 1
            continue
        if c == "\\":
            if nxt == "\n":  # a line continuation
                i += 2
                continue
            out.append(text[i : i + 2])
            i += 2
            word_start = False
            continue
        if quote == '"':
            if c == '"':
                quote = None
            elif c == "$":
                c = _DOLLAR
            elif c == "`":
                c = _BACKTICK
            out.append(c)
            i += 1
            continue
        if c in "'\"":
            quote = c
            out.append(c)
            word_start = False
            i += 1
            continue
        if c == "#" and word_start:
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "\n":
            out.append(" ; ")
            word_start = True
            i += 1
            continue
        if c.isdigit() and word_start:
            j = i
            while j < n and text[j].isdigit():
                j += 1
            if j < n and text[j] in "<>":
                i = j  # "2>&1": drop the file descriptor, keep the operator
                continue
        if c == "<" and nxt == "<":
            why = why or "it uses a here-document"
        if c == "$":
            c = _DOLLAR
        elif c == "`":
            c = _BACKTICK
        elif c == "~" and word_start:
            c = _TILDE
        out.append(c)
        word_start = c in " \t;&|()<>"
        i += 1
    if quote:
        why = "its quotes don't balance"
    return "".join(out), why


def _split(text: str) -> _Line:
    """Simple commands of one command line, redirections dropped."""
    marked, why = _prescan(text)
    lexer = shlex.shlex(marked, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError:
        return _Line((), "its quotes don't balance")
    simple: list[tuple[str, ...]] = []
    current: list[str] = []
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        if tok in _SEPARATORS:
            if current:
                simple.append(tuple(current))
            current = []
            continue
        if tok and set(tok) <= set("<>&|") and ("<" in tok or ">" in tok):
            if tok.startswith("<<"):
                why = why or "it uses a here-document"
            skip_next = True  # the redirection's target
            continue
        if tok == "()":  # "name() { …; }": a function definition; its body follows
            current = []
            continue
        if not current and tok == "function":
            skip_next = True  # the function's name
            continue
        if not current and tok in _RESERVED:
            continue
        current.append(tok)
    if current:
        simple.append(tuple(current))
    return _Line(tuple(simple), why)


def _plain(word: str) -> str:
    """The word as the user wrote it, placeholders turned back into characters."""
    return word.replace(_DOLLAR, "$").replace(_TILDE, "~").replace(_BACKTICK, "`")


def _expands(word: str) -> bool:
    return any(m in word for m in _EXPANDS)


def _has_pm_word(words: Sequence[str]) -> bool:
    return PM_WORD.search(fold(" ".join(_plain(w) for w in words))) is not None


def _home(env: Mapping[str, str]) -> str:
    return env.get("HOME") or os.path.expanduser("~")


def _literal(word: str, env: Mapping[str, str]) -> str:
    """A word with no expansion in it, as the shell passes it on (a leading ``~`` expanded)."""
    if word.startswith(_TILDE):
        word = _home(env) + word[1:]
    return _plain(word)


def _path_word(word: str, cwd: str, env: Mapping[str, str]) -> str:
    """A literal path argument, made absolute against ``cwd``."""
    return os.path.normpath(os.path.join(cwd, _literal(word, env)))


@dataclass
class _State:
    cwd: str | None  # None once a ``cd`` Garnet can't follow has run
    env: dict[str, str]
    env_unknown: str | None = None  # why later commands' environment is unknown
    line: str = ""  # the whole command line, as given


def find_commands(
    command: str | Sequence[str],
    *,
    cwd: str,
    env: Mapping[str, str],
    depth: int = 0,
) -> list[Found]:
    """Every package-manager command in ``command``, in the order they run.

    ``command`` is a shell command line, or an argv list (Codex). ``env`` is
    the hook's environment, used for PATH and HOME; assignments in the
    command line are applied on top of it.
    """
    if not isinstance(command, str):
        argv = list(command)
        if argv and os.path.basename(argv[0]) in _SHELLS:
            script, _ = _shell_script(argv[1:])
            if script is not None:
                return find_commands(script, cwd=cwd, env=env, depth=depth)
        # An argv list reaches the program as is: no shell expands anything in it.
        state = _State(cwd, dict(env), line=shlex.join(argv))
        found = _simple(tuple(argv), shlex.join(argv), state, depth=1)
        if isinstance(found, list):
            return found
        return [found] if found else []
    line = _split(command)
    if line.unclear:
        return [Unclear(f"Garnet Guard can't tell what this runs: {line.unclear}.", command)]
    state = _State(cwd, dict(env), line=command)
    out: list[Found] = []
    for words in line.simple:
        text = " ".join(_plain(w) for w in words)
        found = _simple(words, text, state, depth)
        if isinstance(found, list):
            out.extend(found)
        elif found is not None:
            out.append(found)
    return out


def _simple(
    words: tuple[str, ...], text: str, state: _State, depth: int
) -> Found | list[Found] | None:
    """One simple command: what it runs, after assignments and wrappers."""
    env = dict(state.env)
    i = 0
    prefix: dict[str, str] = {}
    while i < len(words) and (m := _ASSIGNMENT.match(words[i])):
        name, value = m[1], m[2]
        if _expands(value):
            if _RELEVANT_ENV.match(name) and _has_pm_word(words[i + 1 :]):
                return Unclear(f"Garnet Guard can't tell the value of {name} here.", text)
        else:
            prefix[name] = _literal(value, env)
        i += 1
    rest = words[i:]
    if not rest:  # bare assignments update exported variables for later commands
        for name, value in prefix.items():
            if name in state.env or name == "PATH":
                state.env[name] = value
        return None
    env.update(prefix)
    rest, why = _unwrap(rest, env)
    if why:
        return Unclear(why, text) if _has_pm_word(rest) else None
    if not rest:
        return None
    prog = rest[0]
    base = os.path.basename(_plain(prog))
    if base in ("cd", "pushd", "popd"):
        _cd(rest, state)
        return None
    if base == "export":
        _export(rest[1:], state)
        return None
    if base == "unset":
        for name in rest[1:]:
            state.env.pop(name, None)
        return None
    if base in ("source", "."):
        _source(rest[1:], state)
        return None
    if base in ("eval", "xargs"):
        if _has_pm_word(rest[1:]):
            return Unclear(f"Garnet Guard can't tell what {base} runs here.", text)
        return None
    if base in _SHELLS:
        script, reads_stdin = _shell_script(rest[1:])
        if script is None:
            if reads_stdin and PM_WORD.search(fold(state.line)):
                return Unclear(
                    f"Garnet Guard can't tell what this {base} runs: it reads its commands from "
                    "a pipe or a redirection.",
                    text,
                )
            return None
        if not _has_pm_word([script]):
            return None
        if depth >= 1 or _expands(script):
            return Unclear(f"Garnet Guard can't tell what this {base} -c script runs.", text)
        if state.cwd is None or state.env_unknown:
            return Unclear(_unknown_why(state), text)
        return find_commands(_plain(script), cwd=state.cwd, env=env, depth=depth + 1)
    found = _recognize(rest, text)
    if found is None:
        return _later_word(rest, text)
    if isinstance(found, (Unclear, Unsupported)):
        return found
    if found != "uv-run" and any(_expands(w) for w in rest):  # uv run: its options only
        return Unclear(_EXPANDS_WHY, text)
    if state.cwd is None or state.env_unknown:
        return Unclear(_unknown_why(state), text)
    return _locate(found, rest, state.cwd, env)


_EXPANDS_WHY = (
    "Garnet Guard can't tell what this installs: it uses a shell variable or a "
    "command substitution, which the shell expands before the package manager runs."
)


def _shell_script(args: Sequence[str]) -> tuple[str | None, bool]:
    """For ``bash [options] -c SCRIPT``: the script. Otherwise None, and whether
    the shell reads its commands from stdin (no script file named)."""
    j = 0
    saw_c = saw_s = False
    while j < len(args):
        a = args[j]
        if a in ("--", "-"):
            j += 1
            break
        if a in _SHELL_VALUE_OPTIONS:
            j += 2
            continue
        if a.startswith("--"):
            j += 1
            continue
        if len(a) > 1 and a[0] in "-+":
            if a[0] == "-":
                saw_c = saw_c or "c" in a[1:]
                saw_s = saw_s or "s" in a[1:]
            j += 2 if a[-1] in "oO" else 1  # "-eo pipefail"
            continue
        break
    operands = args[j:]
    if saw_c:
        return (operands[0] if operands else None), False
    return None, saw_s or not operands


# Words after a program name that make a following pip or uv word an install.
_INSTALLISH = frozenset(
    {"install", "add", "remove", "lock", "sync", "run", "tool", "pip", "i", "ci", "update"}
)


def _later_word(words: tuple[str, ...], text: str) -> Unclear | None:
    """A program Garnet doesn't follow (``stdbuf``, ``ssh``, ``docker run``…) with
    ``pip install`` or ``uv add`` among its arguments: it may run them."""
    base = os.path.basename(_plain(words[0]))
    if base in _PRINTS or _PIP.match(base) or _PYTHON.match(base) or base in ("uv", "uv.exe"):
        return None
    plain = [os.path.basename(_plain(w)) for w in words[1:]]
    for k, w in enumerate(plain[:-1]):
        nxt = plain[k + 1]
        pm = _PIP.match(w) or w in ("uv", "uv.exe", "uvx", "poetry", "npm", "pnpm", "yarn")
        if (pm and nxt in _INSTALLISH) or (_PYTHON.match(w) and nxt.startswith("-m")):
            return Unclear(f"Garnet Guard can't tell what {_plain(words[0])} runs here.", text)
    return None


def _unknown_why(state: _State) -> str:
    if state.env_unknown:
        return f"Garnet Guard can't tell what this installs: {state.env_unknown}."
    return (
        "Garnet Guard can't tell which folder this runs in: an earlier cd or pushd "
        "used a path Garnet can't read."
    )


def _unwrap(words: tuple[str, ...], env: dict[str, str]) -> tuple[tuple[str, ...], str | None]:
    """Strip ``sudo``, ``env``, ``command``, ``time``, ``nice``, ``nohup``, ``exec``
    and ``timeout``. Returns the command they run, or why Garnet can't tell."""
    rest = list(words)
    for _ in range(8):
        if not rest:
            break
        base = os.path.basename(_plain(rest[0]))
        args = rest[1:]
        if base == "sudo":
            j = 0
            while j < len(args) and args[j].startswith("-"):
                if args[j] in ("-H", "-E"):
                    j += 1
                elif args[j] == "-u" and j + 1 < len(args):
                    j += 2
                elif args[j] == "--":
                    j += 1
                    break
                else:
                    return tuple(args), f"Garnet Guard can't tell what sudo {_plain(args[j])} does."
            while j < len(args) and (m := _ASSIGNMENT.match(args[j])) and not _expands(args[j]):
                env[m[1]] = _plain(m[2])
                j += 1
            rest = args[j:]
        elif base == "env":
            j = 0
            while j < len(args):
                if args[j] == "--":
                    j += 1
                    break
                if (m := _ASSIGNMENT.match(args[j])) and not _expands(args[j]):
                    env[m[1]] = _plain(m[2])
                    j += 1
                elif args[j].startswith("-"):
                    return tuple(args), f"Garnet Guard can't tell what env {_plain(args[j])} does."
                else:
                    break
            rest = args[j:]
        elif base == "command":
            if args and args[0] in ("-v", "-V"):
                return (), None  # looks a command up, runs nothing
            rest = args[1:] if args and args[0] == "-p" else args
        elif base == "time":
            rest = args[1:] if args and args[0] == "-p" else args
        elif base == "nice":
            if args and args[0] == "-n" and len(args) > 1:
                rest = args[2:]
            elif args and re.match(r"^-(\d+|-adjustment=\S+)$", args[0]):
                rest = args[1:]
            else:
                rest = args
        elif base in ("nohup", "exec"):
            if base == "exec" and args and args[0].startswith("-"):
                return tuple(args), "Garnet Guard can't tell what exec with options runs."
            rest = args
        elif base == "timeout":
            j = 0
            while j < len(args) and args[j].startswith("-"):
                j += 2 if args[j] in ("-s", "-k", "--signal", "--kill-after") else 1
            rest = args[j + 1 :]  # the duration, then the command
        else:
            break
    return tuple(rest), None


def _cd(words: tuple[str, ...], state: _State) -> None:
    base = os.path.basename(_plain(words[0]))
    args = [w for w in words[1:] if w not in ("-L", "-P", "--")]
    if base == "popd" or state.cwd is None:
        state.cwd = None
        return
    if not args:
        state.cwd = _home(state.env)
        return
    target = args[0]
    if _expands(target) or target == "-" or len(args) > 1:
        state.cwd = None
        return
    state.cwd = _path_word(target, state.cwd, state.env)


def _export(words: tuple[str, ...], state: _State) -> None:
    for w in words:
        if w.startswith("-"):
            continue
        m = _ASSIGNMENT.match(w)
        if not m:
            continue
        if _expands(m[2]):
            if _RELEVANT_ENV.match(m[1]):
                state.env_unknown = f"an earlier export set {m[1]} to a value Garnet can't read"
            continue
        state.env[m[1]] = _literal(m[2], state.env)


def _source(words: tuple[str, ...], state: _State) -> None:
    """``source <venv>/bin/activate`` selects that venv; any other sourced
    script could change anything, so later commands are unclear."""
    if len(words) == 1 and not _expands(words[0]) and state.cwd is not None:
        path = _path_word(words[0], state.cwd, state.env)
        if os.path.basename(path) == "activate" and os.path.basename(os.path.dirname(path)) in (
            "bin",
            "Scripts",
        ):
            bindir = os.path.dirname(path)
            state.env["VIRTUAL_ENV"] = os.path.dirname(bindir)
            state.env["PATH"] = bindir + os.pathsep + state.env.get("PATH", "")
            return
    state.env_unknown = "an earlier command sourced a script, which can change the environment"


def _recognize(
    words: tuple[str, ...], text: str
) -> Literal["pip", "uv", "uv-run"] | Unsupported | Unclear | None:
    """What a command (wrappers removed) is, if it names a package manager."""
    base = os.path.basename(_plain(words[0]))
    args = tuple(_plain(w) for w in words[1:])
    if _PIP.match(base):
        return _pip_kind(args, text)
    if _PYTHON.match(base):
        module, rest = _python_module(args)
        if module == "pip":
            return _pip_kind(rest, text)
        if module == "uv":
            found = _recognize(("uv", *rest), text)
            if found in ("uv", "uv-run"):
                return Unclear(
                    "Garnet Guard can't tell which uv python -m uv runs; it checks uv commands "
                    "that start with uv.",
                    text,
                )
            return found
        return None
    if base in ("uv", "uv.exe"):
        sub, at, unknown = _uv_subcommand(args)
        if unknown:
            return Unclear(f"Garnet Guard can't tell what uv {unknown} means here.", text)
        after = args[at + 1 :]
        if sub in ("add", "remove", "lock", "sync"):
            return "uv"
        if sub == "pip" and _subcommand(after, UV_GLOBAL_VALUE_OPTIONS)[0] in ("install", "sync"):
            return Unsupported(
                "uv pip", "Garnet Guard checks uv add, remove, lock and sync, not uv pip yet.", text
            )
        if sub == "tool" and _subcommand(after, UV_GLOBAL_VALUE_OPTIONS)[0] in (
            "install",
            "run",
            "upgrade",
        ):
            return Unsupported("uv tool", _TOOL_WHY, text, ask=True)
        if sub == "run":
            if any(a.split("=", 1)[0] in _UV_RUN_WITH for a in after):
                return Unsupported("uv run --with", _TOOL_WHY, text, ask=True)
            if _has_pm_word(after):
                return Unclear("Garnet Guard can't tell what uv run starts here.", text)
            return "uv-run"
        return None
    if base in ("uvx", "uvx.exe"):
        return Unsupported("uvx", _TOOL_WHY, text, ask=True)
    tool = base.split(".")[0]
    if tool == "npx":
        return Unsupported("npx", _NPM_WHY, text)
    if tool in _JS_INSTALLS:
        sub = _subcommand(args, frozenset())[0]
        if sub is None and tool in ("pnpm", "yarn"):  # bare pnpm and yarn install
            return Unsupported(tool, _NPM_WHY, text)
        if sub in _JS_INSTALLS[tool] or (tool == "yarn" and sub == "global"):
            return Unsupported(f"{tool} {sub}", _NPM_WHY, text)
        return None
    if base == "poetry":
        sub = _subcommand(args, frozenset())[0]
        if sub in _POETRY_INSTALLS:
            why = "Garnet Guard doesn't read Poetry projects yet."
            return Unsupported(f"poetry {sub}", why, text, ask=True)
    return None


_TOOL_WHY = (
    "It installs a tool into an environment of its own, which Garnet Guard doesn't check yet."
)
_UV_RUN_WITH = frozenset({"--with", "-w", "--with-requirements", "--with-editable"})
_JS_INSTALLS = {"npm": _NPM_INSTALLS, "pnpm": _PNPM_INSTALLS, "yarn": _YARN_INSTALLS}


def subcommand(args: Sequence[str], value_options: frozenset[str]) -> tuple[str | None, int]:
    """The first word that isn't an option (or an option's value), and its index."""
    return _subcommand(args, value_options)


def _pip_kind(args: Sequence[str], text: str) -> Literal["pip"] | Unclear | None:
    sub, _, unknown = pip_subcommand(args)
    if unknown:
        return Unclear(f"Garnet Guard can't tell what pip {unknown} means here.", text)
    return "pip" if sub == "install" else None


def pip_subcommand(args: Sequence[str]) -> tuple[str | None, int, str | None]:
    """pip's subcommand and its index, with general options read as pip reads
    them (a unique prefix counts). The third value is an option Garnet doesn't
    know, when one comes first: then the subcommand can't be told."""
    j = 0
    while j < len(args):
        a = args[j]
        if a == "--" or not a.startswith("-") or a == "-":
            break
        if a.startswith("--"):
            name, eq, _ = a.partition("=")
            hits = [k for k in PIP_GENERAL_OPTIONS if k == name] or [
                k for k in PIP_GENERAL_OPTIONS if k.startswith(name)
            ]
            if len(hits) != 1:
                return None, j, name
            j += 2 if PIP_GENERAL_OPTIONS[hits[0]] and not eq else 1
            continue
        if not set(a[1:]) <= _PIP_SHORT:
            return None, j, a
        j += 1
    return (args[j], j, None) if j < len(args) and args[j] != "--" else (None, j, None)


def _uv_subcommand(args: Sequence[str]) -> tuple[str | None, int, str | None]:
    """uv's subcommand and its index, like :func:`pip_subcommand`."""
    j = 0
    while j < len(args):
        a = args[j]
        if not a.startswith("-") or a in ("-", "--"):
            break
        if a.startswith("--"):
            name, eq, _ = a.partition("=")
            if name not in UV_GLOBAL_OPTIONS:
                return None, j, name
            j += 2 if UV_GLOBAL_OPTIONS[name] and not eq else 1
            continue
        if not set(a[1:]) <= _UV_SHORT:
            return None, j, a
        j += 1
    return (args[j], j, None) if j < len(args) and args[j] != "--" else (None, j, None)


def _subcommand(args: Sequence[str], value_options: frozenset[str]) -> tuple[str | None, int]:
    """The first argument that isn't an option or an option's value, and its index."""
    j = 0
    while j < len(args):
        a = args[j]
        if a == "--":
            return (args[j + 1], j + 1) if j + 1 < len(args) else (None, j)
        if a.startswith("-"):
            name = a.split("=", 1)[0]
            j += 2 if name in value_options and "=" not in a else 1
            continue
        return a, j
    return None, j


def _python_module(args: Sequence[str]) -> tuple[str | None, tuple[str, ...]]:
    """For ``python [options] -m MODULE args``: the module and its args."""
    j = 0
    while j < len(args):
        a = args[j]
        if re.match(r"^-\d", a) or a.startswith("-V:"):  # the py launcher's version selector
            j += 1
            continue
        if not a.startswith("-") or a == "-" or a.startswith("--"):
            return None, ()  # a script, stdin, or an option Garnet doesn't follow
        for k in range(1, len(a)):
            ch = a[k]
            if ch == "m":
                if a[k + 1 :]:
                    return a[k + 1 :], tuple(args[j + 1 :])
                return (args[j + 1], tuple(args[j + 2 :])) if j + 1 < len(args) else (None, ())
            if ch == "c":
                return None, ()
            if ch in "WX":
                if not a[k + 1 :]:
                    j += 1  # the option's value is the next word
                break
        j += 1
    return None, ()


def _locate(
    kind: Literal["pip", "uv", "uv-run"], words: tuple[str, ...], cwd: str, env: Mapping[str, str]
) -> Found | None:
    """Fill in where the package manager is: its path, and pip's interpreter."""
    text = " ".join(_plain(w) for w in words)
    prog = _literal(words[0], env)
    path = env.get("PATH", "")
    exe = _which(prog, cwd, path)
    args = tuple(_literal(w, env) for w in words[1:])
    if kind == "uv-run":
        _, at, _ = _uv_subcommand(args)
        raw = words[1:]
        if any(_expands(w) for w in raw[: at + 1]):
            return Unclear(_EXPANDS_WHY, text)
        return _uv_run(exe, args[:at], raw[at + 1 :], cwd, env, text)
    if kind == "uv":
        sub, at = _subcommand(args, UV_GLOBAL_VALUE_OPTIONS)
        return UvCommand(exe, sub or "", args[:at] + args[at + 1 :], cwd, dict(env), text)
    if _PYTHON.match(os.path.basename(prog)):
        _, pip_args = _python_module(args)
        return PipCommand(exe, prog, pip_args, cwd, dict(env), text)
    python = interpreter_for_pip(exe, path) if exe else None
    return PipCommand(python, prog, args, cwd, dict(env), text)


# uv run's options that take a value (uv 0.11.32), besides the global ones.
_UV_RUN_VALUE = frozenset(
    {
        "--extra", "--no-extra", "--group", "--no-group", "--only-group",
        "--no-editable-package", "--env-file", "--with", "--with-editable",
        "--with-requirements", "--package", "--python-platform", "--index", "--default-index",
        "--index-url", "--extra-index-url", "--find-links", "--index-strategy",
        "--keyring-provider", "--upgrade-package", "--upgrade-group", "--resolution",
        "--prerelease", "--fork-strategy", "--exclude-newer", "--exclude-newer-package",
        "--no-sources-package", "--reinstall-package", "--link-mode", "--config-setting",
        "--config-settings-package", "--no-build-isolation-package", "--no-build-package",
        "--no-binary-package", "--refresh-package", "--python",
    }
) | UV_GLOBAL_VALUE_OPTIONS  # fmt: skip
_UV_RUN_FLAGS = frozenset(
    {
        "--all-extras", "--dev", "--no-dev", "--no-default-groups", "--all-groups", "--module",
        "--only-dev", "--no-editable", "--exact", "--no-env-file", "--isolated", "--active",
        "--no-active", "--no-sync", "--locked", "--frozen", "--script", "--gui-script",
        "--all-packages", "--no-project", "--no-index", "--upgrade", "--no-sources",
        "--reinstall", "--compile-bytecode", "--no-build-isolation", "--no-build",
        "--no-binary", "--refresh",
    }
) | {k for k, v in UV_GLOBAL_OPTIONS.items() if not v}  # fmt: skip
_UV_RUN_SHORT = {
    "-m": "--module", "-s": "--script", "-w": "--with", "-i": "--index-url",
    "-f": "--find-links", "-U": "--upgrade", "-P": "--upgrade-package",
    "-C": "--config-setting", "-p": "--python", "-n": "--no-cache", "-q": "--quiet",
    "-v": "--verbose",
}  # fmt: skip
# uv run options that ``uv sync`` doesn't take, and that don't change what it installs.
_UV_RUN_ONLY = frozenset({"--module", "--env-file", "--no-env-file"})


def _uv_run(
    exe: str | None,
    before: tuple[str, ...],
    raw: tuple[str, ...],
    cwd: str,
    env: Mapping[str, str],
    text: str,
) -> Found | None:
    """``uv run [options] COMMAND``: unless told not to, uv locks and syncs the
    project first, with builds on. That is checked as ``uv sync`` with the
    same options; the command it then starts isn't Garnet's to read."""
    kept: list[str] = []
    args = tuple(_literal(w, env) for w in raw)
    j = 0
    while j < len(args):
        a = args[j]
        if a == "--" or not a.startswith("-") or a == "-":
            break
        name, eq, _ = a.partition("=")
        name = _UV_RUN_SHORT.get(name[:2], name) if not name.startswith("--") else name
        if a[:1] == "-" and a[1:2] != "-" and len(a) > 2 and name in _UV_RUN_VALUE:
            eq = "="  # "-p3.12"
        if name not in _UV_RUN_VALUE and name not in _UV_RUN_FLAGS:
            return Unclear(f"Garnet Guard can't tell what uv run {name} means here.", text)
        width = 2 if name in _UV_RUN_VALUE and not eq else 1
        if any(_expands(w) for w in raw[j : j + width]):
            return Unclear(_EXPANDS_WHY, text)
        given = list(args[j : j + width])
        j += width
        if name in ("--no-sync", "--no-project"):
            return None  # nothing is synced
        if name in ("--script", "--gui-script"):
            why = "It installs a script's own dependencies, which Garnet Guard doesn't check yet."
            return Unsupported("uv run --script", why, text, ask=True)
        if name not in _UV_RUN_ONLY:
            kept += given
    rest = args[j + 1 :] if j < len(args) and args[j] == "--" else args[j:]
    if rest and rest[0].endswith((".py", ".pyw")) and _inline_metadata(os.path.join(cwd, rest[0])):
        why = "It installs a script's own dependencies, which Garnet Guard doesn't check yet."
        return Unsupported("uv run <script>", why, text, ask=True)
    return UvCommand(exe, "sync", (*before, *kept), cwd, dict(env), text, via_run=True)


def _inline_metadata(path: str) -> bool:
    """Whether a script has a ``# /// script`` block (PEP 723). Read, never run."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(256 * 1024)
    except OSError:
        return False
    return re.search(rb"(?m)^# /// script\s*$", head) is not None


def _which(prog: str, cwd: str, path: str) -> str | None:
    if os.sep in prog or (os.altsep and os.altsep in prog):
        full = os.path.normpath(os.path.join(cwd, prog))
        return full if os.path.isfile(full) else None
    return shutil.which(prog, path=path)


def interpreter_for_pip(pip: str, path: str | None = None) -> str | None:
    """The Python a ``pip`` script runs under: its ``#!`` line, else a
    ``python`` beside it. The script is read, never run."""
    try:
        with open(pip, "rb") as fh:
            first = fh.readline(512)
    except OSError:
        first = b""
    if first.startswith(b"#!"):
        parts = first[2:].decode("utf-8", "replace").strip().split()
        if parts:
            if os.path.basename(parts[0]) == "env" and len(parts) > 1:
                found = shutil.which(parts[1], path=path)
                if found:
                    return found
            elif os.path.isabs(parts[0]) and os.path.isfile(parts[0]):
                return parts[0]
    folder = os.path.dirname(pip)
    for name in ("python", "python3", "python.exe"):
        for where in (folder, os.path.dirname(folder)):
            candidate = os.path.join(where, name)
            if os.path.isfile(candidate):
                return candidate
    return None
