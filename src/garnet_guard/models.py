"""Shared data models. This module imports nothing from Garnet."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import IntEnum, StrEnum
from typing import Literal


class Severity(IntEnum):
    """How much a finding counts. Ordered, so ``max()`` gives the worst."""

    OFF = 0
    INFO = 1
    WARN = 2
    BLOCK = 3

    @property
    def label(self) -> str:
        """The lowercase name used in reports and policy: "warn", "block"."""
        return self.name.lower()


class Verdict(StrEnum):
    """The outcome for a change or a whole report. ``info`` findings still pass."""

    PASS = "pass"  # noqa: S105
    WARN = "warn"
    BLOCK = "block"

    @classmethod
    def from_severity(cls, severity: Severity) -> Verdict:
        if severity >= Severity.BLOCK:
            return cls.BLOCK
        if severity >= Severity.WARN:
            return cls.WARN
        return cls.PASS


@dataclass(frozen=True)
class Change:
    """One dependency update: ``package`` moves from ``baseline`` to ``candidate``.

    ``baseline`` is None for a newly added package, which gets only the
    absolute rules.
    """

    ecosystem: str
    package: str
    baseline: str | None
    candidate: str
    lockfile: str | None = None  # where the candidate is pinned (for SARIF and comments)
    line: int | None = None


EvidenceKind = Literal["file", "attestation", "tag", "advisory", "url", "note"]


@dataclass(frozen=True)
class Evidence:
    """One thing a reviewer can check for themselves: a file and line, a tag,
    an attestation, an advisory or a URL."""

    kind: EvidenceKind
    summary: str
    path: str | None = None
    line: int | None = None
    sha256: str | None = None
    url: str | None = None
    identity: str | None = None


@dataclass(frozen=True)
class RawFinding:
    """What a check returns: no suppression, and the rule's severity unless
    ``lowered_to`` says otherwise (a check may lower it, never raise it)."""

    rule_id: str
    title: str
    evidence: tuple[Evidence, ...]
    release: str | None = None
    lowered_to: Severity | None = None


@dataclass(frozen=True)
class RuleDoc:
    """A rule's name, default severity and the text ``garnet explain`` prints."""

    rule_id: str
    name: str
    kind: Literal["diff", "absolute"]
    default: Severity
    summary: str
    explanation: str
    remediation: str


@dataclass(frozen=True)
class Finding:
    """A ``RawFinding`` after the engine has added its rule's docs and severity."""

    rule_id: str
    name: str
    severity: Severity
    default_severity: Severity
    change: Change
    title: str
    evidence: tuple[Evidence, ...]
    explanation: str
    remediation: str
    release: str | None = None
    docs_url: str | None = None
    suppressed_by: Ignore | None = None  # still reported, but not in the verdict


@dataclass(frozen=True)
class ChangeResult:
    """Every finding for one change, worst first, and the verdict they add up to."""

    change: Change
    verdict: Verdict
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class Limits:
    """Caps on hostile input (SPEC §4.4). Hitting one is GRN-E003, never a pass."""

    max_artifact_bytes: int = 200 * 1024 * 1024
    max_total_uncompressed: int = 1024 * 1024 * 1024
    max_entries: int = 100_000
    max_ratio: int = 100
    max_py_file_bytes: int = 5 * 1024 * 1024
    budget_seconds: int = 120


# --- Policy (SPEC §7) ----------------------------------------------------


@dataclass(frozen=True)
class Ignore:
    """One ``[[garnet.ignore]]`` entry: findings someone reviewed and accepted.

    It applies to ``rules`` for ``package`` (and ``versions`` of the candidate,
    when set) through ``until``, then stops applying. ``package`` is normalized.
    """

    package: str
    rules: tuple[str, ...]
    reason: str
    until: date
    ecosystem: str | None = None
    versions: str | None = None
    acknowledge_critical: bool = False

    def expired(self, today: date) -> bool:
        """True after ``until``. The ignore still applies on that day."""
        return today > self.until


@dataclass(frozen=True)
class Policy:
    """A policy file, parsed and checked. ``Policy()`` is the defaults.

    ``source`` and ``sha256`` say which file it came from, for the report.
    """

    source: str | None = None
    sha256: str | None = None
    default: Severity | None = None  # replaces "warn" for rules whose default is warn
    fail_on: Severity | None = None  # None: the CLI's default
    rules: Mapping[str, Severity] = field(default_factory=dict)
    ignores: tuple[Ignore, ...] = ()
    limits: Limits = field(default_factory=Limits)


# --- Release facts -------------------------------------------------------


@dataclass(frozen=True)
class FileProvenance:
    """What the PEP 740 attestation for one file says, and whether it verified.

    ``present`` is False when PyPI has no attestation for the file.
    """

    filename: str
    present: bool
    verified: bool
    identity: str | None = None
    repository: str | None = None
    repository_id: str | None = None
    workflow: str | None = None
    environment: str | None = None
    trusted_publishing: bool | None = None
    error: str | None = None
    verification_ran: bool = True  # False: verifier unavailable, result unknown


FileKind = Literal["py", "pth", "native", "script", "data", "other"]


@dataclass(frozen=True)
class FileEntry:
    """One file inside an artifact, with ``path`` relative to the package root."""

    path: str
    size: int
    sha256: str
    kind: FileKind


@dataclass(frozen=True)
class CallSite:
    """A sensitive call (``subprocess.Popen``) and the function it sits in."""

    name: str
    line: int
    via: str | None = None  # function in this module the call was reached through
    from_module: str | None = None  # path of the module whose import started the chain
    handed_to: str | None = None  # the call the function went to, when it may not run it


@dataclass(frozen=True)
class ModuleIndex:
    """What one Python module does when it is imported, read with ``ast``."""

    module: str
    path: str
    top_level_calls: tuple[CallSite, ...]
    imports: tuple[str, ...]
    blob_sha1: str = ""  # the id git gives these bytes, to compare with the source tree


@dataclass(frozen=True)
class PthFile:
    """A ``.pth`` file and the lines in it that Python runs at every startup."""

    path: str
    exec_lines: tuple[str, ...]


@dataclass(frozen=True)
class UnsourcedFile:
    """A Python file in a release that is not byte-for-byte in the repository at
    the release's tag, and the sensitive calls it has that the source doesn't."""

    path: str
    in_source: bool  # True: the path exists at the tag with other content; False: absent
    calls: tuple[CallSite, ...]


@dataclass(frozen=True)
class SourceMatch:
    """How a release's Python files compare with its repository at the matched
    tag (GRN-C007). ``prefix`` is the directory they live under there."""

    repo: str
    tag: str
    commit: str
    prefix: str
    matched: int  # files byte-identical to the source
    unmatched: tuple[UnsourcedFile, ...]
    unchecked: tuple[str, ...] = ()  # files under a submodule Garnet couldn't read


@dataclass(frozen=True)
class ArtifactFacts:
    """One file of a release (a wheel or an sdist).

    Trust facts are filled in for every artifact. Content facts (``files``
    onward) only for the ones selected for inspection, the sdist and one wheel.
    """

    filename: str
    sha256: str
    packagetype: str  # "sdist" | "bdist_wheel" | other registry values
    uploaded_at: datetime | None
    provenance: FileProvenance | None  # None means "not looked up"
    inspected: bool = False  # True for the content selection
    downloaded_sha256: str | None = None  # what we actually got (GRN-T008)
    files: tuple[FileEntry, ...] = ()
    modules: tuple[ModuleIndex, ...] = ()
    pth_files: tuple[PthFile, ...] = ()
    build_backend: str | None = None
    setup_py_calls: tuple[CallSite, ...] = ()
    unparsed: tuple[str, ...] = ()  # .py files ast couldn't parse
    wheel_tag: str | None = None
    entry_points: tuple[str, ...] = ()  # modules named by entry points
    source_match: SourceMatch | None = None  # None: not compared (no tag, or a fetch error)
    # npm: the registry's Subresource Integrity string ("sha512-…") and the
    # one computed from the download (GRN-T008), and the package.json scripts
    # that run on the installing machine, as sorted (name, command) pairs.
    integrity: str | None = None
    downloaded_integrity: str | None = None
    install_scripts: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class TagInfo:
    """The git tag matched to a release version (GRN-T004)."""

    name: str
    sha: str | None
    repo: str | None = None  # owner/repo the tag was found in


@dataclass(frozen=True)
class FactError:
    """Something Garnet couldn't learn. Becomes a GRN-E finding."""

    code: Literal["GRN-E001", "GRN-E002", "GRN-E003"]
    summary: str
    rules: tuple[str, ...] = ()  # rules that couldn't be evaluated
    path: str | None = None


@dataclass(frozen=True)
class ReleaseFacts:
    """Everything Garnet learned about one release. Checks read only this.

    The ``*_checked`` flags tell "looked and found nothing" apart from "didn't
    look". Anything Garnet couldn't learn is in ``errors``.
    """

    ecosystem: str
    package: str
    version: str
    yanked: bool
    artifacts: tuple[ArtifactFacts, ...]
    source_repo: str | None = None
    tag: TagInfo | None = None
    tag_checked: bool = False
    tag_repos: tuple[str, ...] = ()  # every repo searched for the tag
    advisories: tuple[str, ...] = ()
    advisories_checked: bool = False
    errors: tuple[FactError, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def content(self) -> tuple[ArtifactFacts, ...]:
        """The artifacts whose contents were inspected."""
        return tuple(a for a in self.artifacts if a.inspected)
