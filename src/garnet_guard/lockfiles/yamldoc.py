"""A strict YAML reader for pnpm-lock.yaml and Yarn 2+ yarn.lock, and for
the registry keys of pnpm-workspace.yaml and .yarnrc.yml (ADR-0016).

The document is built here from PyYAML's parser events, not by a loader's
constructor. That way an alias, an anchor, a tag outside the core schema,
a merge key, a repeated key, a key that isn't a scalar and nesting deeper
than :data:`MAX_DEPTH` are refused at the event that carries them, before
anything is built, and each mapping records the line of every key. In a
settings file only the top-level keys Garnet reads are held to that; the
values of the others, which people write by hand (a pnpm catalog with
anchors), are passed over.

pnpm and Yarn read these files with js-yaml, a YAML 1.2 parser; PyYAML
reads YAML 1.1. Plain scalars are resolved the way the tool reads them:
``core`` follows js-yaml's default schema (pnpm), ``failsafe`` makes every
scalar text (Yarn). A plain scalar either specification would read as
something other than text (a number, a date, ``yes``) becomes a
:class:`Scalar`, which the parsers refuse wherever they need text. NEL,
LS and PS, line breaks in YAML 1.1 and ordinary characters in 1.2, are
refused outright.

Errors give a position, never the file's text: a report may be posted
publicly, and these files can hold tokens.
"""

from __future__ import annotations

import re
from typing import Any, Literal

import yaml

from .base import LockfileError

Schema = Literal["core", "failsafe"]

# pnpm and Yarn write five or six levels; this leaves room and stops a
# pathological file long before Python's recursion limit matters.
MAX_DEPTH = 32

_CORE = "tag:yaml.org,2002:"
_NODE_EVENTS = (yaml.ScalarEvent, yaml.AliasEvent, yaml.MappingStartEvent, yaml.SequenceStartEvent)
_LINE_BREAKS = re.compile("[\x85  ]")

# Plain scalars that js-yaml's default schema or YAML 1.1 reads as a null,
# a boolean, a number, a date, a merge key or a value key.
_NULLS = frozenset({"", "~", "null", "Null", "NULL"})
_TRUE = frozenset({"true", "True", "TRUE"})
_FALSE = frozenset({"false", "False", "FALSE"})
_YAML11_BOOLS = frozenset(
    {"yes", "Yes", "YES", "no", "No", "NO", "on", "On", "ON", "off", "Off", "OFF"}
)
_NOT_TEXT = re.compile(
    r"""
    [-+]?(?:0b[0-1_]+|0o[0-7_]+|0x[0-9a-fA-F_]+|[0-9][0-9_]*(?::[0-5]?[0-9])*)  # int
    | [-+]?(?:[0-9][0-9_]*)(?::[0-5]?[0-9])*(?:\.[0-9_]*)?(?:[eE][-+]?[0-9]+)?  # float
    | [-+]?\.[0-9_]+(?:[eE][-+]?[0-9]+)?
    | [-+]?\.(?:inf|Inf|INF) | \.(?:nan|NaN|NAN)
    | [0-9]{4}-[0-9]{1,2}-[0-9]{1,2}  # date and timestamp
      (?:(?:[Tt]|[\ \t]+)[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]*)?
         (?:[\ \t]*(?:Z|[-+][0-9]{1,2}(?::[0-9]{2})?))?)?
    | <<|=
    """,
    re.VERBOSE,
)
_MAYBE_NOT_TEXT = frozenset("-+.0123456789<=")
# js-yaml turns every key into text, so ``null:`` and ``'null':`` are one key.
_KEY_TEXT = {None: "null", True: "true", False: "false"}
_TEXT_KEY = {text: value for value, text in _KEY_TEXT.items()}


class Scalar:
    """A plain scalar YAML may read as something other than text: a number,
    a date, a YAML 1.1 boolean such as ``yes``. Only its text is kept."""

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Scalar) and other.text == self.text

    def __hash__(self) -> int:
        return hash(("Scalar", self.text))

    def __repr__(self) -> str:
        return f"Scalar({self.text!r})"


class Mapping(dict[Any, Any]):
    """A YAML mapping, with its own line and the 1-based line of each key."""

    __slots__ = ("line", "lines")

    def __init__(self, line: int) -> None:
        super().__init__()
        self.line = line
        self.lines: dict[Any, int] = {}


class Sequence(list[Any]):
    """A YAML sequence, with its line."""

    __slots__ = ("line",)

    def __init__(self, line: int) -> None:
        super().__init__()
        self.line = line


def _plain(value: str, schema: Schema) -> object:
    if schema == "failsafe":
        return None if value == "" else value
    if value in _NULLS:
        return None
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    if value in _YAML11_BOOLS:
        return Scalar(value)
    if value[0] in _MAYBE_NOT_TEXT and _NOT_TEXT.fullmatch(value):
        return Scalar(value)
    return value


def _scalar(event: yaml.ScalarEvent, schema: Schema, line: int) -> object:
    tag = event.tag
    if tag is None and not event.style:
        return _plain(event.value, schema)
    value = event.value
    if event.style == '"':  # only double quotes have escapes, and \ud800 is one
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as err:
            raise LockfileError(f"line {line}: a quoted string that isn't valid text") from err
    if tag is None or tag == "!" or tag == _CORE + "str":
        return value
    if schema == "core" and tag in (_CORE + "null", _CORE + "bool", _CORE + "int", _CORE + "float"):
        return Scalar(value)
    raise LockfileError(f"line {line}: a YAML tag Garnet doesn't read")


def _repeated(mapping: Mapping, key: object) -> bool:
    """True if ``key`` is already in ``mapping``, or would be once js-yaml
    turns keys into text: ``true`` and ``'true'``, ``1`` and ``'1'``."""
    if key in mapping:
        return True
    if isinstance(key, str):
        return Scalar(key) in mapping or (key in _TEXT_KEY and _TEXT_KEY[key] in mapping)
    if isinstance(key, Scalar):
        return key.text in mapping
    return isinstance(key, bool | None) and _KEY_TEXT[key] in mapping


def _refuse(event: yaml.Event, line: int, kind: str) -> None:
    if event.anchor is not None:  # type: ignore[attr-defined]
        raise LockfileError(f"line {line}: a YAML anchor, which Garnet refuses")
    tag = event.tag  # type: ignore[attr-defined]
    if tag is not None and tag != _CORE + kind:
        raise LockfileError(f"line {line}: a YAML tag Garnet doesn't read")


def _build(text: str, schema: Schema, read: frozenset[str] | None) -> object:
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    root: object = None
    documents = 0
    # The open collections, and for each mapping the key waiting for its value.
    stack: list[Mapping | Sequence] = []
    keys: list[object] = []
    waiting: list[bool] = []
    # Collections open inside a top-level value that isn't read (``read``).
    skipping = 0

    def unread() -> bool:
        """True if the next event starts the value of a top-level key that
        isn't read, which is passed over unchecked and left out."""
        return (
            read is not None
            and len(stack) == 1
            and isinstance(stack[0], Mapping)
            and waiting[0]
            and keys[0] not in read
        )

    def skip() -> None:
        top = stack[0]
        assert isinstance(top, Mapping)
        del top.lines[keys[0]]
        waiting[0] = False

    def add(value: object, line: int) -> None:
        nonlocal root
        if not stack:
            root = value
            return
        top = stack[-1]
        if isinstance(top, Sequence):
            top.append(value)
        elif not waiting[-1]:
            if isinstance(value, (Mapping, Sequence)):
                raise LockfileError(f"line {line}: a key that isn't a scalar")
            if isinstance(value, Scalar) and value.text == "<<":
                raise LockfileError(f"line {line}: a YAML merge key, which Garnet refuses")
            if _repeated(top, value):
                raise LockfileError(f"line {line}: a key repeated in one mapping")
            keys[-1] = value
            waiting[-1] = True
            top.lines[value] = line
        else:
            top[keys[-1]] = value
            waiting[-1] = False

    for event in yaml.parse(text, Loader=loader):
        kind = type(event)
        line = event.start_mark.line + 1
        if skipping:
            if kind is yaml.MappingStartEvent or kind is yaml.SequenceStartEvent:
                skipping += 1
                if len(stack) + skipping > MAX_DEPTH:
                    raise LockfileError(f"line {line}: nested deeper than Garnet reads")
            elif kind is yaml.MappingEndEvent or kind is yaml.SequenceEndEvent:
                skipping -= 1
                if not skipping:
                    skip()
            continue
        if unread() and kind in _NODE_EVENTS:
            if kind is yaml.MappingStartEvent or kind is yaml.SequenceStartEvent:
                skipping = 1
            else:
                skip()
            continue
        if kind is yaml.ScalarEvent:
            if event.anchor is not None:
                raise LockfileError(f"line {line}: a YAML anchor, which Garnet refuses")
            add(_scalar(event, schema, line), line)
        elif kind is yaml.MappingStartEvent or kind is yaml.SequenceStartEvent:
            mapping = kind is yaml.MappingStartEvent
            _refuse(event, line, "map" if mapping else "seq")
            if len(stack) >= MAX_DEPTH:
                raise LockfileError(f"line {line}: nested deeper than Garnet reads")
            stack.append(Mapping(line) if mapping else Sequence(line))
            keys.append(None)
            waiting.append(False)
        elif kind is yaml.MappingEndEvent or kind is yaml.SequenceEndEvent:
            node = stack.pop()
            keys.pop()
            waiting.pop()
            add(node, node.line)
        elif kind is yaml.AliasEvent:
            raise LockfileError(f"line {line}: a YAML alias, which Garnet refuses")
        elif kind is yaml.DocumentStartEvent:
            documents += 1
            if documents > 1:
                raise LockfileError(f"line {line}: a second YAML document")
    return root


def load(text: str, *, schema: Schema, read: frozenset[str] | None = None) -> object:
    """The document in ``text``: str, None, bool, :class:`Scalar`,
    :class:`Mapping` and :class:`Sequence` values only. Raises
    ``LockfileError`` with a position, never the file's text.

    ``read``, for a settings file, names the top-level keys the caller
    reads. The value of any other top-level key is passed over and left
    out of the document, anchors, aliases, tags and repeated keys in it
    included, as long as the file still parses as YAML. The top-level keys
    themselves, and everything under a key in ``read``, are held to the
    same rules as a lockfile."""
    m = _LINE_BREAKS.search(text)
    if m:
        line = text.count("\n", 0, m.start()) + 1
        raise LockfileError(
            f"line {line}: a NEL, LS or PS character, which YAML versions read differently"
        )
    try:
        return _build(text, schema, read)
    except yaml.MarkedYAMLError as err:
        mark = err.problem_mark or err.context_mark
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise LockfileError(f"invalid YAML{where}") from err
    except yaml.reader.ReaderError as err:
        line = text.count("\n", 0, err.position) + 1
        raise LockfileError(f"line {line}: a character YAML doesn't allow") from err
    except yaml.YAMLError as err:
        raise LockfileError("invalid YAML") from err
    except RecursionError as err:
        raise LockfileError("YAML nested too deeply to read") from err
