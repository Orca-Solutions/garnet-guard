"""Shared data models. This module imports nothing from Garnet."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Literal


class Severity(IntEnum):
    OFF = 0
    INFO = 1
    WARN = 2
    BLOCK = 3

    @property
    def label(self) -> str:
        return self.name.lower()


class Verdict(StrEnum):
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
    ecosystem: str
    package: str
    baseline: str | None
    candidate: str
    lockfile: str | None = None  # where the candidate is pinned (for SARIF and comments)
    line: int | None = None


EvidenceKind = Literal["file", "attestation", "tag", "advisory", "url", "note"]


@dataclass(frozen=True)
class Evidence:
    kind: EvidenceKind
    summary: str
    path: str | None = None
    line: int | None = None
    sha256: str | None = None
    url: str | None = None
    identity: str | None = None


@dataclass(frozen=True)
class RawFinding:
    """What a check returns: no severity, no suppression."""

    rule_id: str
    title: str
    evidence: tuple[Evidence, ...]
    release: str | None = None


@dataclass(frozen=True)
class RuleDoc:
    rule_id: str
    name: str
    kind: Literal["diff", "absolute"]
    default: Severity
    summary: str
    explanation: str
    remediation: str


@dataclass(frozen=True)
class Finding:
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


@dataclass(frozen=True)
class ChangeResult:
    change: Change
    verdict: Verdict
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class Limits:
    max_artifact_bytes: int = 200 * 1024 * 1024
    max_total_uncompressed: int = 1024 * 1024 * 1024
    max_entries: int = 100_000
    max_ratio: int = 100
    max_py_file_bytes: int = 5 * 1024 * 1024
    budget_seconds: int = 120


# --- Release facts -------------------------------------------------------


@dataclass(frozen=True)
class FileProvenance:
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
    path: str
    size: int
    sha256: str
    kind: FileKind


@dataclass(frozen=True)
class CallSite:
    name: str
    line: int
    via: str | None = None  # local function the call was reached through


@dataclass(frozen=True)
class ModuleIndex:
    module: str
    path: str
    top_level_calls: tuple[CallSite, ...]
    imports: tuple[str, ...]


@dataclass(frozen=True)
class PthFile:
    path: str
    exec_lines: tuple[str, ...]


@dataclass(frozen=True)
class ArtifactFacts:
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


@dataclass(frozen=True)
class TagInfo:
    name: str
    sha: str | None


@dataclass(frozen=True)
class FactError:
    """Something Garnet couldn't learn. Becomes a GRN-E finding."""

    code: Literal["GRN-E001", "GRN-E002", "GRN-E003"]
    summary: str
    rules: tuple[str, ...] = ()  # rules that couldn't be evaluated
    path: str | None = None


@dataclass(frozen=True)
class ReleaseFacts:
    ecosystem: str
    package: str
    version: str
    yanked: bool
    artifacts: tuple[ArtifactFacts, ...]
    source_repo: str | None = None
    tag: TagInfo | None = None
    tag_checked: bool = False
    advisories: tuple[str, ...] = ()
    advisories_checked: bool = False
    errors: tuple[FactError, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def content(self) -> tuple[ArtifactFacts, ...]:
        return tuple(a for a in self.artifacts if a.inspected)
