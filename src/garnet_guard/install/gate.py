"""The hooks' first step, which runs before every shell command an agent starts.

It reads the hook's JSON from stdin and returns at once, printing nothing,
unless the command names a package manager. It imports only the standard
library, so a command such as ``ls`` costs no more than starting Python.
Everything else is in :mod:`garnet_guard.install.hooks`, loaded only when
a package-manager word is present.

Printing nothing and exiting 0 means "no decision": the agent's own
permission rules apply as if the hook weren't there.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any, TextIO

MAX_INPUT_BYTES = 1024 * 1024

# A package-manager word where a shell would read a program name: at the
# start, after an operator, a quote, a slash (a path), "=" or python's "-m"
# (``python -mpip``). The command parser decides whether it really is one;
# ``echo "pip install x"`` gets this far and no further. It is matched
# against the text with backslashes and quotes taken out too (``fold``), as
# the shell takes them out of ``\pip`` and ``p'i'p``, and with the start of a
# ``${NAME:-default}`` taken out, so the default is read as a word.
PM_WORD = re.compile(
    r"(?:^|[\s;&|()`'\"/=<>{}\\]|-m)"
    r"(?:pip(?:3(?:\.\d+)?)?|uvx?|poetry|npm|npx|pnpm|yarn)(?:\.exe)?"
    r"(?=$|[\s;&|()`'\"<>{}\\])"
)
_CHUNK = 1024 * 1024


# The start of ``${NAME:-word}`` and its kin (``-``, ``=``, ``+``, ``?``, with or
# without ``:``), whose word the shell may put in place of the variable.
_DEFAULT = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=+?]")


def fold(text: str) -> str:
    """``text`` with backslashes and quote characters removed, as the shell
    removes them from a word, and each ``${NAME:-`` made a space, so the
    default value after it is a word of its own."""
    text = text.replace("\\", "").replace("'", "").replace('"', "")
    return _DEFAULT.sub(" ", text)


def has_pm_word(text: str) -> bool:
    return PM_WORD.search(text) is not None or PM_WORD.search(fold(text)) is not None


# The tools each agent runs shell commands with (SPEC §10.4).
SHELL_TOOLS = {"claude-code": frozenset({"Bash", "PowerShell"}), "codex": frozenset({"Bash"})}


def command_text(tool_input: object) -> str | None:
    """The shell command in ``tool_input``: a string, or an argv list (Codex)."""
    if not isinstance(tool_input, dict):
        return None
    command = tool_input.get("command")
    if isinstance(command, str):
        return command
    if isinstance(command, list) and all(isinstance(w, str) for w in command):
        return " ".join(command)
    return None


def needs_a_look(agent: str, payload: dict[str, Any]) -> bool:
    """True when the full hook has to read this command."""
    if payload.get("hook_event_name") != "PreToolUse":
        return False
    if payload.get("tool_name") not in SHELL_TOOLS.get(agent, frozenset()):
        return False
    text = command_text(payload.get("tool_input"))
    return text is not None and has_pm_word(text)


def decision(agent: str, reason: str, context: str | None = None) -> str:
    """The JSON for "Garnet couldn't check this": ask on Claude Code, deny on Codex.

    Codex has no ``ask`` and lets a call through when a hook fails, so the
    hook denies there and says how to rerun the command in a form it reads.
    """
    out: dict[str, Any] = {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask" if agent == "claude-code" else "deny",
        "permissionDecisionReason": reason,
    }
    # Claude Code shows an "ask" reason to the user only; the agent reads it
    # in additionalContext. Codex gives a "deny" reason to the agent.
    context = context or (reason if agent == "claude-code" else None)
    if context:
        out["additionalContext"] = context
    return json.dumps({"hookSpecificOutput": out}, ensure_ascii=True)


def _pm_word_in_rest(first: str, stdin: TextIO) -> bool:
    """Whether a package-manager word is anywhere in input too large to parse:
    the part read, then the rest of stdin a chunk at a time, never all held."""
    tail = ""
    chunk = first
    while chunk:
        text = tail + chunk
        if has_pm_word(text):
            return True
        tail = text[-256:]  # a word split across two chunks
        chunk = stdin.read(_CHUNK)
    return False


def run(
    agent: str,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """``garnet hook <agent> run``: read one hook event and answer it. Always 0."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    raw = stdin.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        print("garnet: hook input over 1 MB; not read", file=stderr)
        if _pm_word_in_rest(raw, stdin):
            print(
                decision(
                    agent, "Garnet Guard didn't check this command: its hook input is over 1 MB."
                ),
                file=stdout,
            )
        return 0
    try:
        payload = json.loads(raw)
    except ValueError as err:
        print(f"garnet: hook input isn't JSON ({err})", file=stderr)
        if has_pm_word(raw):
            reason = "Garnet Guard didn't check this command: it couldn't read the hook input."
            print(decision(agent, reason), file=stdout)
        return 0
    if not isinstance(payload, dict) or not needs_a_look(agent, payload):
        return 0
    try:
        from .hooks import handle

        handle(agent, payload, stdout=stdout, stderr=stderr)
    except Exception as err:  # Garnet failed on a package command: never a pass
        print(f"garnet: hook failed: {type(err).__name__}: {err}", file=stderr)
        reason = (
            "Garnet Guard didn't check this command: it failed while reading it "
            f"({type(err).__name__})."
        )
        print(decision(agent, reason), file=stdout)
    return 0
