"""Shared data models. This module imports nothing from Garnet."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
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
    notes: tuple[str, ...] = ()  # what the checks could and couldn't compare; never a verdict


@dataclass(frozen=True)
class Limits:
    """Caps on hostile input (SPEC §4.4). Hitting one is GRN-E003, never a pass."""

    max_artifact_bytes: int = 200 * 1024 * 1024
    max_total_uncompressed: int = 1024 * 1024 * 1024
    max_entries: int = 100_000
    max_ratio: int = 100
    max_py_file_bytes: int = 5 * 1024 * 1024
    max_js_file_bytes: int = 16 * 1024 * 1024  # bundles run larger than modules
    budget_seconds: int = 120


# --- Policy (SPEC §7) ----------------------------------------------------


@dataclass(frozen=True)
class Ignore:
    """One ``[[garnet.ignore]]`` entry: findings someone reviewed and accepted.

    It applies to ``rules`` for ``package`` (and ``versions`` of the candidate,
    when set) through ``until``, then stops applying. ``package`` is kept as
    written; it matches PEP 503 normalized on PyPI and exactly on npm.
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


FileKind = Literal["py", "pth", "native", "pyc", "script", "data", "other"]


@dataclass(frozen=True)
class JsUse:
    """A process, network or eval use in an npm package's JavaScript (GRN-C011).

    ``kind`` is "process", "network", "eval" or "obfuscated"; ``name`` is the
    module or global (``child_process``, ``fetch``). ``at_load`` is False when
    the use sits in a function body that isn't called where it is defined.
    """

    path: str
    line: int
    kind: str
    name: str
    at_load: bool


@dataclass(frozen=True)
class FileEntry:
    """One file inside an artifact, with ``path`` relative to the package root."""

    path: str
    size: int
    sha256: str
    kind: FileKind
    binary: str | None = None  # "ELF", "Mach-O" or "PE" when the bytes are native code
    hash_based: bool = False  # a PEP 552 .pyc: Python never compares its code with its source


ARGS_TEXT_LIMIT = 1000  # characters of a call's argument text kept in CallSite.args


@dataclass(frozen=True)
class CallSite:
    """A sensitive call (``subprocess.Popen``) and the function it sits in."""

    name: str
    line: int
    via: str | None = None  # function in this module the call was reached through
    from_module: str | None = None  # path of the module whose import started the chain
    handed_to: str | None = None  # the call the function went to, when it may not run it
    read: bool = False  # a read of a credential or CI setting, not a call (GRN-C003, info)
    # The call's arguments as ``ast`` reads them, for GRN-C002 (build scripts
    # only; None elsewhere): ``args`` is the text, keyword arguments sorted and
    # clipped; ``args_key`` a hash of the full, normalized tree, to compare.
    args: str | None = None
    args_key: str | None = None


@dataclass(frozen=True)
class ModuleIndex:
    """What one Python module does when it is imported, read with ``ast``."""

    module: str
    path: str
    top_level_calls: tuple[CallSite, ...]
    imports: tuple[str, ...]
    blob_sha1: str = ""  # the id git gives these bytes, to compare with the source tree
    # The sensitive calls anywhere in the file, by name (GRN-C012). Wheels only;
    # None in an sdist, and when Garnet couldn't walk the file.
    sensitive: tuple[str, ...] | None = None


@dataclass(frozen=True)
class PthFile:
    """A ``.pth`` file and the lines in it that Python runs at every startup."""

    path: str
    # As ``str.splitlines()`` splits the file, each time a line appears
    exec_lines: tuple[str, ...]
    # Lines Python 3.11 and 3.12 (a form feed inside a line) or 3.13 and later
    # (a line behind a BOM) run that ``exec_lines`` lacks, each once
    other_lines: tuple[str, ...] = ()

    @property
    def all_lines(self) -> tuple[str, ...]:
        """Every line some Python runs, each once."""
        return tuple(dict.fromkeys((*self.exec_lines, *self.other_lines)))


@dataclass(frozen=True)
class WheelDifference:
    """A Python file in another wheel of the release that differs from the one
    in the wheel Garnet read, with the sensitive calls the read copy lacks
    (GRN-C012). Recorded only when there is such a call."""

    wheel: str  # the other wheel's filename
    family: str  # the platform it is for: "Windows", "macOS", "Linux", "any", …
    path: str  # where it installs, relative to site-packages
    in_inspected: bool  # the wheel Garnet read has a file at this path
    calls: tuple[CallSite, ...]
    # False when the read wheel's copy couldn't be parsed, so every call counts
    read_copy_parsed: bool = True


@dataclass(frozen=True)
class WheelCalls:
    """The sensitive calls one Python file of a wheel makes anywhere in it, by
    name, in the wheel the content rules read or a wheel compared with it
    (GRN-C012). Recorded for a file with such a call, and for one Garnet
    couldn't parse or that is over the parse limit (``names`` is None), so the
    next version can ask what the same platform's wheel already did."""

    family: str  # the wheel's platform family, as in WheelDifference
    path: str  # where it installs, relative to site-packages
    names: tuple[str, ...] | None
    sha256: str = ""  # the file's bytes, so the next version can tell an unchanged copy


@dataclass(frozen=True)
class UnparsedWheelFile:
    """A Python file in a wheel GRN-C012 compared that differs from the read
    wheel's copy and that Garnet couldn't parse. GRN-E002 reports it unless a
    trusted wheel of the same platform family had the same bytes there."""

    wheel: str  # the compared wheel's filename
    family: str  # its platform family, as in WheelDifference
    path: str  # in the wheel
    sha256: str


@dataclass(frozen=True)
class UnsourcedFile:
    """A Python file in a release that is not byte-for-byte in the repository at
    the release's tag, and the sensitive calls it has that the source doesn't."""

    path: str
    in_source: bool  # True: the path exists at the tag with other content; False: absent
    calls: tuple[CallSite, ...]
    at: str = ""  # the repository path it was compared with; "" means prefix + path


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
class WheelOnlyCode:
    """Code in a file of the wheel the content rules read that the release's
    sdist doesn't have (GRN-C006): for a ``.py`` file, the sensitive calls its
    sdist copy doesn't make; for a ``.pth`` file, the executable lines its sdist
    copy lacks, or all of them when the sdist has no copy. Recorded only when
    there is such code, and for a ``.pth`` with no sdist copy at all."""

    path: str  # where the file installs, relative to site-packages
    at: str | None  # the sdist file it was compared with; None: the sdist has none
    calls: tuple[CallSite, ...] = ()
    lines: tuple[str, ...] = ()  # a .pth file's executable lines the sdist copy lacks
    sdist_parsed: bool = True  # False: the sdist copy couldn't be parsed, so every call counts


@dataclass(frozen=True)
class SdistMatch:
    """How the Python and ``.pth`` files of the wheel the content rules read
    compare with the release's sdist (GRN-C006). Counted over the wheel's
    parsed Python files that install in site-packages."""

    wheel: str  # the wheel's filename
    sdist: str  # the sdist's filename
    matched: int  # same bytes somewhere in the sdist (CRLF line endings read as LF)
    differ: int  # the sdist's copy at the same install path has other bytes
    absent: int  # the sdist has no copy
    code: tuple[WheelOnlyCode, ...] = ()
    # Install paths of files counted in ``differ`` or ``absent`` that parse but
    # are nested too deep for Garnet to list their calls (GRN-E002 names GRN-C006)
    unwalked: tuple[str, ...] = ()


@dataclass(frozen=True)
class Requirement:
    """A package an artifact declares it needs, installed without asking for an extra.

    ``spec`` is the requirement as written (``requests>=2.31``, or ``left-pad@^1.3.0``
    on npm); ``name`` is the ecosystem's normalized name. ``alias_of`` is the
    registry package an npm alias (``"x": "npm:y@^1"``) installs under the name.
    ``source`` is set when the dependency doesn't install from the registry at
    all: a URL, a git repository or a local path.
    """

    name: str
    spec: str
    alias_of: str | None = None
    source: str | None = None
    # Other declarations of this name in the same artifact that install
    # something else, as written (a second Requires-Dist line, or the name in
    # another package.json table, such as optionalDependencies, which npm lets
    # override dependencies). Only the first is compared and looked up.
    also: tuple[str, ...] = ()
    # What those declarations install instead of this one's registry
    # package: another registry package (an npm alias target), a URL, a git
    # repository or a path. GRN-C008 keeps its severity for them.
    also_installs: tuple[str, ...] = ()

    @property
    def package(self) -> str:
        """The registry package that installs."""
        return self.alias_of or self.name

    def with_others(self, others: Sequence[Requirement]) -> Requirement:
        """This requirement with the other declarations of its name that
        install something other than its registry package: their specs in
        ``also``, and what they install in ``also_installs``."""
        differ = [o for o in others if (o.source, o.package) != (self.source, self.package)]
        if not differ:
            return self
        return replace(
            self,
            also=tuple(o.spec for o in differ),
            also_installs=tuple(dict.fromkeys(o.source or o.package for o in differ)),
        )


@dataclass(frozen=True)
class DependencyProfile:
    """What the registry says about a package a release depends on (GRN-C008).

    Looked up only for dependencies the trusted version didn't declare.
    ``on_registry`` False means the registry has no such package.
    """

    name: str
    on_registry: bool
    first_release_at: datetime | None = None
    releases: int = 0
    source_repo: str | None = None
    latest_version: str | None = None
    owners: tuple[str, ...] = ()  # registry accounts: PyPI roles and organization, npm maintainers
    # npm: versions the registry's time table lists from before ``first_release_at``
    # that are no longer published (a name unpublished and created again), oldest first
    unpublished_versions: tuple[str, ...] = ()
    earliest_unpublished_at: datetime | None = None


@dataclass(frozen=True)
class EntryPoint:
    """One line of a wheel's ``entry_points.txt``: ``name = target`` under ``[group]``.

    ``path`` is the file in the wheel the line comes from.
    """

    group: str
    name: str
    target: str
    path: str = ""


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
    # Every entry point a wheel declares: each line of the entry_points.txt
    # of every .dist-info or .egg-info folder at its root or under
    # .data/purelib/ or platlib/, sorted by group and name, file order kept
    # within a name. ``entry_points_read``
    # is True only for a wheel read to the end, so an empty tuple there means
    # none. Read for wheels only: an sdist's may come from ``setup.py``.
    entry_point_specs: tuple[EntryPoint, ...] = ()
    entry_points_read: bool = False
    source_match: SourceMatch | None = None  # None: not compared (no tag, or a fetch error)
    # npm: the registry's Subresource Integrity string ("sha512-…") and the
    # one computed from the download (GRN-T008), and the package.json scripts
    # that run on the installing machine, as sorted (name, command) pairs.
    integrity: str | None = None
    downloaded_integrity: str | None = None
    install_scripts: tuple[tuple[str, str], ...] = ()
    # The dependencies the artifact's metadata declares (``Requires-Dist`` in a
    # wheel's METADATA or an sdist's PKG-INFO; ``dependencies``,
    # ``optionalDependencies`` and ``peerDependencies`` in package.json) that
    # install without asking for an extra. ``requirements_read`` tells an
    # artifact with no dependencies from one whose metadata wasn't found.
    requirements: tuple[Requirement, ...] = ()
    requirements_read: bool = False
    # npm: process, network and eval uses in the files the package's entry
    # points load (GRN-C011). ``js_scanned`` tells a tarball with none from
    # one that wasn't read (a replay records no files).
    js_uses: tuple[JsUse, ...] = ()
    js_scanned: bool = False


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
    # Registry profiles of the dependencies the trusted version didn't declare,
    # looked up by the engine for GRN-C008. A name with no profile and no
    # GRN-E001 naming GRN-C008 wasn't looked up at all (no baseline to diff).
    dependencies: tuple[DependencyProfile, ...] = ()
    # The registry accounts that own the package: PyPI's owner and maintainer
    # roles and organization (as they are today), npm's maintainers of this
    # version. Empty when the registry didn't say.
    owners: tuple[str, ...] = ()
    # GRN-C012: Python files in the release's other wheels (one per platform
    # family, and each late wheel) that differ from the wheel Garnet read and
    # have sensitive calls its copy lacks. ``wheels_compared`` lists the other
    # wheels read, as (filename, family); ``wheels_not_compared`` those left
    # out (more late wheels than the cap, GRN-E003). ``wheel_unparsed`` lists
    # the differing files of compared wheels that Garnet couldn't parse
    # (GRN-E002). ``wheel_calls`` holds the calls each file of the read wheel
    # and of the compared wheels makes, and ``read_wheel_family`` the read
    # wheel's family, when all its files were read; the next version's
    # GRN-C012 compares with them.
    wheel_differences: tuple[WheelDifference, ...] = ()
    wheels_compared: tuple[tuple[str, str], ...] = ()
    wheels_not_compared: tuple[str, ...] = ()
    wheel_families: tuple[str, ...] = ()  # the platform families of all its wheels
    wheel_calls: tuple[WheelCalls, ...] = ()
    read_wheel_family: str | None = None
    wheel_unparsed: tuple[UnparsedWheelFile, ...] = ()
    # GRN-C006: the wheel the content rules read compared with the release's
    # sdist. None when the release lacks one of the two, or Garnet couldn't
    # read one of them to the end (its GRN-E finding names GRN-C006).
    sdist_match: SdistMatch | None = None

    @property
    def content(self) -> tuple[ArtifactFacts, ...]:
        """The artifacts whose contents were inspected."""
        return tuple(a for a in self.artifacts if a.inspected)


@dataclass(frozen=True)
class IndexFile:
    """One file of a release as the registry lists it, for the install wrapper."""

    filename: str
    packagetype: str  # "bdist_wheel", "sdist", ...
    requires_python: str | None = None
    yanked: bool = False


@dataclass(frozen=True)
class ProjectReleases:
    """Every release a registry lists for one project, with its files.

    The install wrapper uses it to see whether resolving with builds off
    picked a lower release than the package manager would (SPEC §10.3), and
    to say why a requirement has no wheel it can use.
    """

    name: str
    on_registry: bool
    releases: tuple[tuple[str, tuple[IndexFile, ...]], ...] = ()  # (version, files)
