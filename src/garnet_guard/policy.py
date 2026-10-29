"""The policy file (SPEC §7): rule severities, expiring ignores and lower limits.

Parsing is strict. An unknown key, a bad value or an ignore without a reason
or an expiry date is a ``PolicyError`` (exit code 3), never a silent default.
Applying a policy is pure: the engine passes in today's date.
"""

from __future__ import annotations

import hashlib
import tomllib
from dataclasses import fields, replace
from datetime import date
from pathlib import Path
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .checks import DOCS
from .checks.docs import PLANNED
from .models import Change, Ignore, Limits, Policy, RuleDoc, Severity

POLICY_FILE = "garnet.toml"
PYPROJECT = "pyproject.toml"
MAX_POLICY_BYTES = 1024 * 1024

# Findings that mean something is wrong, not unusual. An ignore needs
# ``acknowledge_critical = true`` for these, and [garnet.rules] can't lower them.
CRITICAL = frozenset({"GRN-T007", "GRN-T008", "GRN-K001"})
# "Couldn't check" rules. [garnet.rules] and ``default`` can't lower them below
# their default, so a check that didn't run never quietly passes (AGENTS.md
# rule 4). A per-package ignore, with a reason and an expiry, still can.
COULDNT_CHECK = frozenset({"GRN-E001", "GRN-E002", "GRN-E003", "GRN-E004", "GRN-E005"})

_ECOSYSTEMS = ("pypi", "npm")
_SEVERITIES = {s.label: s for s in Severity}
_FAIL_ON = {"warn": Severity.WARN, "block": Severity.BLOCK, "never": Severity.OFF}
_TOP_KEYS = {"version", "default", "fail_on", "rules", "ignore", "limits"}
_IGNORE_KEYS = {
    "ecosystem",
    "package",
    "versions",
    "rules",
    "reason",
    "until",
    "acknowledge_critical",
}
_LIMIT_KEYS = {f.name for f in fields(Limits)}


class PolicyError(ValueError):
    """The policy file is invalid. The message names the file and the key."""


# --- Loading ---------------------------------------------------------------


def load_policy(path: Path | None = None, *, cwd: Path | None = None) -> Policy:
    """Read the policy SPEC §7.1 picks, or the defaults when there is none.

    With ``path``, that file must exist. Without it: ``garnet.toml`` in ``cwd``,
    then ``[tool.garnet]`` in ``cwd/pyproject.toml``.
    """
    if path is not None:
        if not path.is_file():
            raise PolicyError(f"no such policy file: {path}")
        return _load(path, str(path))
    here = cwd or Path.cwd()
    for name in (POLICY_FILE, PYPROJECT):
        candidate = here / name
        if candidate.is_file():
            return _load(candidate, name)
    return Policy()


def _load(path: Path, source: str) -> Policy:
    if path.stat().st_size > MAX_POLICY_BYTES:
        raise PolicyError(f"{source}: larger than {MAX_POLICY_BYTES} bytes")
    return parse_policy(path.read_bytes(), source=source, pyproject=path.name == PYPROJECT)


def parse_policy(data: bytes, *, source: str, pyproject: bool = False) -> Policy:
    """Parse a policy file's bytes. ``pyproject`` reads ``[tool.garnet]``.

    A ``pyproject.toml`` without a ``[tool.garnet]`` table means the defaults.
    """
    try:
        doc = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as err:
        raise PolicyError(f"{source}: not valid TOML: {err}") from err
    if pyproject:
        tool = doc.get("tool", {})
        table = tool.get("garnet") if isinstance(tool, dict) else None
        if table is None:
            return Policy()
        where = "[tool.garnet]"
    else:
        extra = sorted(set(doc) - {"garnet"})
        if extra:
            raise PolicyError(f"{source}: unknown top-level key {extra[0]!r}; use a [garnet] table")
        if "garnet" not in doc:
            raise PolicyError(f"{source}: no [garnet] table")
        table = doc["garnet"]
        where = "[garnet]"
    return _policy(_table(table, f"{source}: {where}"), source, where, data)


def _policy(t: dict[str, Any], source: str, where: str, data: bytes) -> Policy:
    ctx = f"{source}: {where}"
    _known(t, _TOP_KEYS, ctx)
    if "version" not in t:
        raise PolicyError(f"{ctx} needs version = 1")
    if t["version"] != 1 or isinstance(t["version"], bool):
        raise PolicyError(f"{ctx} version = {t['version']!r}: this Garnet Guard reads version 1")

    default = None
    if "default" in t:
        default = _choice(t["default"], ("info", "warn", "block"), f"{ctx} default")
    fail_on = None
    if "fail_on" in t:
        fail_on = _FAIL_ON[_label(t["fail_on"], tuple(_FAIL_ON), f"{ctx} fail_on")]

    rules = {
        rid: _rule_setting(rid, value, f"{source}: {where[:-1]}.rules]")
        for rid, value in sorted(_table(t.get("rules", {}), f"{ctx}.rules").items())
    }

    raw_ignores = t.get("ignore", [])
    if not isinstance(raw_ignores, list):
        raise PolicyError(f"{ctx} ignore must be an array of tables: [[{where[1:-1]}.ignore]]")
    ignores = tuple(
        _ignore(_table(entry, f"{ctx} ignore #{i}"), f"{source}: ignore #{i}")
        for i, entry in enumerate(raw_ignores, start=1)
    )

    return Policy(
        source=source,
        sha256=hashlib.sha256(data).hexdigest(),
        default=default,
        fail_on=fail_on,
        rules=rules,
        ignores=ignores,
        limits=_limits(_table(t.get("limits", {}), f"{ctx}.limits"), f"{ctx}.limits"),
    )


def _rule_setting(rule_id: str, value: object, ctx: str) -> Severity:
    doc = _rule_doc(rule_id, ctx)
    severity = _choice(value, tuple(_SEVERITIES), f'{ctx} "{rule_id}"')
    if doc is None:
        return severity  # a planned rule: nothing to protect yet
    if rule_id in CRITICAL and severity < doc.default:
        raise PolicyError(
            f'{ctx} "{rule_id}" = "{severity.label}": {rule_id} ({doc.name}) means a release '
            f"failed verification, so it can't be lowered for every package. To accept one "
            f"package after reviewing it, add a [[garnet.ignore]] for it with "
            f"acknowledge_critical = true, a reason and an until date."
        )
    if rule_id in COULDNT_CHECK and severity < doc.default:
        raise PolicyError(
            f'{ctx} "{rule_id}" = "{severity.label}": {rule_id} ({doc.name}) reports a check '
            f"that didn't run, so it can't go below {doc.default.label} for every package; a "
            f"check that didn't run would then pass. To accept one package, add a "
            f"[[garnet.ignore]] for it with a reason and an until date."
        )
    return severity


def _ignore(t: dict[str, Any], ctx: str) -> Ignore:
    _known(t, _IGNORE_KEYS, ctx)
    for key in ("package", "rules", "reason", "until"):
        if key not in t:
            raise PolicyError(
                f"{ctx} needs {key}; every ignore names a package, rules, a reason and an until date"
            )
    ecosystem = None
    if "ecosystem" in t:
        ecosystem = _label(t["ecosystem"], _ECOSYSTEMS, f"{ctx} ecosystem")
    package = _text(t["package"], f"{ctx} package")
    versions = None
    if "versions" in t:
        versions = _text(t["versions"], f"{ctx} versions")
        try:
            SpecifierSet(versions)
        except InvalidSpecifier as err:
            raise PolicyError(
                f'{ctx} versions = {versions!r} isn\'t a version specifier such as ">=2.0,<3"'
            ) from err
    rules = t["rules"]
    if not isinstance(rules, list) or not rules or not all(isinstance(r, str) for r in rules):
        raise PolicyError(f'{ctx} rules must be a non-empty list of rule IDs, such as ["GRN-C004"]')
    for rid in rules:
        _rule_doc(rid, f"{ctx} rules")
    ack = t.get("acknowledge_critical", False)
    if not isinstance(ack, bool):
        raise PolicyError(f"{ctx} acknowledge_critical must be true or false")
    critical = sorted(set(rules) & CRITICAL)
    if critical and not ack:
        raise PolicyError(
            f"{ctx} ignores {', '.join(critical)}, which means a release failed verification "
            f"or is known to be malicious. If you've reviewed it and still accept it, also set "
            f"acknowledge_critical = true."
        )
    return Ignore(
        package=package,
        rules=tuple(sorted(set(rules))),
        reason=_text(t["reason"], f"{ctx} reason"),
        until=_date(t["until"], f"{ctx} until"),
        ecosystem=ecosystem,
        versions=versions,
        acknowledge_critical=ack,
    )


def _limits(t: dict[str, Any], ctx: str) -> Limits:
    _known(t, _LIMIT_KEYS, ctx)
    defaults = Limits()
    lowered: dict[str, int] = {}
    for key, value in sorted(t.items()):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise PolicyError(f"{ctx} {key} must be a positive whole number")
        cap = getattr(defaults, key)
        if value > cap:
            raise PolicyError(f"{ctx} {key} = {value}: limits can only be lowered (default {cap})")
        lowered[key] = value
    return replace(defaults, **lowered)


def _table(value: object, ctx: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{ctx} must be a table")
    return value


def _known(t: dict[str, Any], allowed: set[str], ctx: str) -> None:
    unknown = sorted(set(t) - allowed)
    if unknown:
        raise PolicyError(
            f"{ctx}: unknown key {unknown[0]!r} (allowed: {', '.join(sorted(allowed))})"
        )


def _rule_doc(rule_id: str, ctx: str) -> RuleDoc | None:
    """The rule's docs, or None for a rule the SPEC lists that isn't built yet."""
    doc = DOCS.get(rule_id)
    if doc is None and rule_id not in PLANNED:
        raise PolicyError(f"{ctx}: unknown rule {rule_id!r}; `garnet explain` lists rule IDs")
    return doc


def _label(value: object, allowed: tuple[str, ...], ctx: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise PolicyError(f"{ctx} = {value!r}: use one of {', '.join(repr(a) for a in allowed)}")
    return value


def _choice(value: object, allowed: tuple[str, ...], ctx: str) -> Severity:
    return _SEVERITIES[_label(value, allowed, ctx)]


def _text(value: object, ctx: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{ctx} must be a non-empty string")
    return value.strip()


def _date(value: object, ctx: str) -> date:
    # TOML has a date type (until = 2027-06-30); a quoted ISO date works too.
    if isinstance(value, date) and not hasattr(value, "hour"):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError:
            pass
    raise PolicyError(f'{ctx} = {value!r}: use an ISO date such as "2027-06-30"')


# --- Applying ----------------------------------------------------------------


def severity_for(policy: Policy, doc: RuleDoc) -> Severity:
    """The severity a rule's findings get under ``policy``, before any check lowers it."""
    severity = doc.default
    if policy.default is not None and doc.default == Severity.WARN:
        severity = policy.default
    severity = policy.rules.get(doc.rule_id, severity)
    if doc.rule_id in COULDNT_CHECK or doc.rule_id in CRITICAL:
        severity = max(severity, doc.default)
    return severity


def matches(ignore: Ignore, rule_id: str, change: Change) -> bool:
    """True if ``ignore`` covers this rule for this change, expiry aside.

    ``versions`` is matched against the candidate version, pre-releases included.
    A version that isn't PEP 440 never matches a ``versions`` range.
    """
    if rule_id not in ignore.rules:
        return False
    if rule_id in CRITICAL and not ignore.acknowledge_critical:
        return False
    if ignore.ecosystem is not None and ignore.ecosystem != change.ecosystem:
        return False
    if _name(ignore.package, change.ecosystem) != _name(change.package, change.ecosystem):
        return False
    if ignore.versions is None:
        return True
    if change.ecosystem != "pypi":
        return False  # npm ranges arrive with npm support
    try:
        return SpecifierSet(ignore.versions).contains(Version(change.candidate), prereleases=True)
    except InvalidVersion:
        return False


def _name(package: str, ecosystem: str) -> str:
    return canonicalize_name(package) if ecosystem == "pypi" else package


def suppression(
    policy: Policy, rule_id: str, change: Change, today: date
) -> tuple[Ignore | None, tuple[Ignore, ...]]:
    """The first live ignore that covers the finding, and any expired ones that would have."""
    live: Ignore | None = None
    expired: list[Ignore] = []
    for ignore in policy.ignores:
        if not matches(ignore, rule_id, change):
            continue
        if ignore.expired(today):
            expired.append(ignore)
        elif live is None:
            live = ignore
    return live, tuple(expired)


def expired_ignores(policy: Policy, today: date) -> tuple[Ignore, ...]:
    """Every ignore past its ``until`` date, in file order."""
    return tuple(i for i in policy.ignores if i.expired(today))


def describe(ignore: Ignore) -> str:
    """One line naming an ignore, for reports: ``numpy >=2.0 GRN-C004 until 2027-06-30``."""
    what = " ".join(x for x in (ignore.ecosystem, ignore.package, ignore.versions) if x)
    return f"{what} {', '.join(ignore.rules)} until {ignore.until.isoformat()}"
