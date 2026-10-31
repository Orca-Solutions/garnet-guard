"""Find the package-manager commands in a shell command line, without running it.

The hooks see the command an agent is about to run. That text may come from
an agent that read hostile content, so it is only ever parsed, here, with the
standard library's ``shlex``. Nothing in it is run, expanded or sourced.

What is followed: ``&&``, ``||``, ``;``, ``|``, ``&`` and newlines; redirections
(dropped); leading ``NAME=value`` assignments and literal ``export``; the
wrappers ``sudo``, ``env``, ``command``, ``time``, ``nice``, ``nohup``,
``exec`` and ``timeout``; literal ``cd`` and ``pushd``; ``source <venv>/bin/activate``;
and one level of ``bash -c '<literal script>'``.

What makes a command "can't tell" when a package-manager word is in it:
command or process substitution, a shell variable in a package-manager
command, ``eval``, ``xargs``, here-documents, unbalanced quotes, and
anything else the shell would expand before the package manager sees it.
Scripts, aliases and shell functions aren't visible here at all.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

# A package-manager word where a shell would read a program name: at the
# start, after an operator, a quote, a slash (a path) or "=".
PM_WORD = re.compile(
    r"(?:^|[\s;&|()`'\"/=<>{}])"
    r"(?:pip(?:3(?:\.\d+)?)?|uvx?|poetry|npm|npx|pnpm|yarn)(?:\.exe)?"
    r"(?=$|[\s;&|()`'\"<>{}])"
)

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
_PYTHON = re.compile(r"^(?:python(?:3(?:\.\d+)?)?|py)(?:\.exe)?$")
# Environment variables that change which package manager runs or where it
# installs. An unknown value for one of these makes later commands unclear.
_RELEVANT_ENV = re.compile(r"^(?:PIP_|UV_|PYTHON|VIRTUAL_ENV$|PATH$|CONDA_PREFIX$)")

# pip's general options that take a value, before the subcommand.
PIP_GENERAL_VALUE_OPTIONS = frozenset(
    {
        "--python",
        "--log",
        "--keyring-provider",
        "--proxy",
        "--retries",
        "--timeout",
        "--exists-action",
        "--trusted-host",
        "--cert",
        "--client-cert",
        "--cache-dir",
        "--use-feature",
        "--use-deprecated",
        "--resume-retries",
    }
)
# uv's global options that take a value, before the subcommand.
UV_GLOBAL_VALUE_OPTIONS = frozenset(
    {
        "--cache-dir",
        "--color",
        "--config-file",
        "--directory",
        "--project",
        "--allow-insecure-host",
        "--python-preference",
    }
)

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


@dataclass(frozen=True)
class Unsupported:
    """An install with a tool Garnet doesn't check yet. Reported, never passed."""

    tool: str
    why: str
    text: str


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
        if tok in ("{", "}", "!") and not current:
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
    return PM_WORD.search(" ".join(_plain(w) for w in words)) is not None


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
        if len(argv) == 3 and os.path.basename(argv[0]) in _SHELLS and _is_c_flag(argv[1]):
            return find_commands(argv[2], cwd=cwd, env=env, depth=depth)
        # An argv list reaches the program as is: no shell expands anything in it.
        state = _State(cwd, dict(env))
        found = _simple(tuple(argv), shlex.join(argv), state, depth=1)
        if isinstance(found, list):
            return found
        return [found] if found else []
    line = _split(command)
    if line.unclear:
        return [Unclear(f"Garnet Guard can't tell what this runs: {line.unclear}.", command)]
    state = _State(cwd, dict(env))
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
    if base in _SHELLS and len(rest) >= 3:
        if _is_c_flag(rest[1]):
            script = rest[2]
            if not _has_pm_word([script]):
                return None
            if depth >= 1 or _expands(script):
                return Unclear(f"Garnet Guard can't tell what this {base} -c script runs.", text)
            if state.cwd is None or state.env_unknown:
                return Unclear(_unknown_why(state), text)
            return find_commands(_plain(script), cwd=state.cwd, env=env, depth=depth + 1)
        return None
    found = _recognize(rest, text)
    if found is None or isinstance(found, (Unclear, Unsupported)):
        return found
    if any(_expands(w) for w in rest):
        return Unclear(
            "Garnet Guard can't tell what this installs: it uses a shell variable or a "
            "command substitution, which the shell expands before the package manager runs.",
            text,
        )
    if state.cwd is None or state.env_unknown:
        return Unclear(_unknown_why(state), text)
    return _locate(found, rest, state.cwd, env)


def _is_c_flag(word: str) -> bool:
    """``-c``, or a cluster such as ``-lc`` or ``-ec``."""
    return word.startswith("-") and not word.startswith("--") and "c" in word


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
) -> Literal["pip", "uv"] | Unsupported | Unclear | None:
    """What a command (wrappers removed) is, if it names a package manager."""
    base = os.path.basename(_plain(words[0]))
    args = tuple(_plain(w) for w in words[1:])
    if _PIP.match(base):
        return "pip" if _subcommand(args, PIP_GENERAL_VALUE_OPTIONS)[0] == "install" else None
    if _PYTHON.match(base):
        module, rest = _python_module(args)
        if module == "pip" and _subcommand(rest, PIP_GENERAL_VALUE_OPTIONS)[0] == "install":
            return "pip"
        return None
    if base in ("uv", "uv.exe"):
        sub, at = _subcommand(args, UV_GLOBAL_VALUE_OPTIONS)
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
            return Unsupported("uv tool", _TOOL_WHY, text)
        if sub == "run":
            if any(a.split("=", 1)[0] in _UV_RUN_WITH for a in after):
                return Unsupported("uv run --with", _TOOL_WHY, text)
            if _has_pm_word(after):
                return Unclear("Garnet Guard can't tell what uv run starts here.", text)
        return None
    if base in ("uvx", "uvx.exe"):
        return Unsupported("uvx", _TOOL_WHY, text)
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
            return Unsupported(f"poetry {sub}", "Garnet Guard doesn't wrap Poetry yet.", text)
    return None


_TOOL_WHY = (
    "it installs a tool into an environment of its own, which Garnet Guard doesn't check yet."
)
_UV_RUN_WITH = frozenset({"--with", "-w", "--with-requirements", "--with-editable"})
_JS_INSTALLS = {"npm": _NPM_INSTALLS, "pnpm": _PNPM_INSTALLS, "yarn": _YARN_INSTALLS}


def subcommand(args: Sequence[str], value_options: frozenset[str]) -> tuple[str | None, int]:
    """The first word that isn't an option (or an option's value), and its index."""
    return _subcommand(args, value_options)


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
    kind: Literal["pip", "uv"], words: tuple[str, ...], cwd: str, env: Mapping[str, str]
) -> Found:
    """Fill in where the package manager is: its path, and pip's interpreter."""
    text = " ".join(_plain(w) for w in words)
    prog = _literal(words[0], env)
    path = env.get("PATH", "")
    exe = _which(prog, cwd, path)
    args = tuple(_literal(w, env) for w in words[1:])
    if kind == "uv":
        sub, at = _subcommand(args, UV_GLOBAL_VALUE_OPTIONS)
        return UvCommand(exe, sub or "", args[:at] + args[at + 1 :], cwd, dict(env), text)
    if _PYTHON.match(os.path.basename(prog)):
        _, pip_args = _python_module(args)
        return PipCommand(exe, prog, pip_args, cwd, dict(env), text)
    python = interpreter_for_pip(exe, path) if exe else None
    return PipCommand(python, prog, args, cwd, dict(env), text)


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
