"""Content rules: what changed inside the release. Pure functions of facts."""

from __future__ import annotations

import functools
import posixpath
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import replace
from datetime import datetime

from packaging.tags import Tag

from ..models import (
    ArtifactFacts,
    CallSite,
    Change,
    DependencyProfile,
    EntryPoint,
    Evidence,
    FileEntry,
    JsUse,
    ModuleIndex,
    RawFinding,
    ReleaseFacts,
    Requirement,
    Severity,
    UnparsedWheelFile,
    WheelOnlyCode,
)
from . import wheel_tags

MAX_EVIDENCE = 25  # evidence lines per finding; the rest are counted, not listed
# A wheel's <name>-<version>.data/purelib/ and platlib/ install into site-packages itself.
_SITE_PREFIX = re.compile(r"^[^/]+\.data/(purelib|platlib)/")
# Dotted names in a .pth line: every one it could import, for GRN-C006's info split
_NAMES = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")

# Well-known build backends. A switch to one of these isn't GRN-C002; a switch
# to anything else, or to a backend shipped inside the sdist, is.
BACKEND_ALLOWLIST = frozenset(
    {
        "setuptools.build_meta",
        "setuptools.build_meta:__legacy__",
        "hatchling.build",
        "flit_core.buildapi",
        "poetry.core.masonry.api",
        "poetry_core.masonry.api",
        "pdm.backend",
        "pdm.pep517.api",
        "maturin",
        "scikit_build_core.build",
        "mesonpy",
        "uv_build",
        "pbr.build",
        "whey",
        "sipbuild.api",
        "enscons.api",
    }
)


CheckRule = Callable[[Change, ReleaseFacts | None, ReleaseFacts], Iterator[RawFinding]]


def _pick(rel: ReleaseFacts, kind: str) -> ArtifactFacts | None:
    """The inspected wheel or sdist of a release, if there is one."""
    for a in rel.content:
        if kind == "wheel" and a.filename.endswith(".whl"):
            return a
        if kind == "sdist" and a.packagetype == "sdist":
            return a
    return None


def _pair(
    base: ReleaseFacts, cand: ReleaseFacts
) -> tuple[ArtifactFacts | None, ArtifactFacts | None]:
    """The artifacts to compare: wheels when both have one, else sdists.

    When neither pairing is possible (the trusted version shipped only a
    wheel and the new one only an sdist, or the other way round) the two
    kinds are compared with each other, with a note, rather than not at all.
    A new version that adds a wheel beside its sdist is read both ways: see
    ``each_view``.
    """
    bw, cw = _pick(base, "wheel"), _pick(cand, "wheel")
    if bw is not None and cw is not None:
        return bw, cw
    bs, cs = _pick(base, "sdist"), _pick(cand, "sdist")
    if bs is not None and cs is not None:
        return bs, cs
    return bw or bs, cw or cs


def _views(base: ReleaseFacts | None, cand: ReleaseFacts) -> tuple[ReleaseFacts, ...]:
    """The candidate as the content rules read it.

    A new version that is the first to ship a wheel beside its sdist is read
    twice, each time against the trusted sdist: its sdist, which pip builds
    where no wheel fits, and its wheel, which pip installs everywhere else.
    Every other change is read once.
    """
    if (
        base is None
        or cand.ecosystem != "pypi"
        or _pick(base, "wheel") is not None
        or _pick(base, "sdist") is None
        or _pick(cand, "wheel") is None
        or _pick(cand, "sdist") is None
    ):
        return (cand,)
    sdist = tuple(a for a in cand.artifacts if not a.filename.endswith(".whl"))
    wheel = tuple(a for a in cand.artifacts if a.packagetype != "sdist")
    return replace(cand, artifacts=sdist), replace(cand, artifacts=wheel)


def each_view(rule: CheckRule) -> CheckRule:
    """Run a content rule on each way the candidate is read, and report each
    finding once: one that differs only in its notes is the same finding."""

    @functools.wraps(rule)
    def run(change: Change, base: ReleaseFacts | None, cand: ReleaseFacts) -> Iterator[RawFinding]:
        seen: set[tuple[str, str, tuple[Evidence, ...]]] = set()
        for view in _views(base, cand):
            for f in rule(change, base, view):
                key = (f.rule_id, f.title, tuple(e for e in f.evidence if e.kind != "note"))
                if key not in seen:
                    seen.add(key)
                    yield f

    return run


def _installed(a: ArtifactFacts, path: str) -> str:
    """A path as the wheel built from ``a`` would hold it: an sdist's
    ``src/`` folder is not part of the installed name."""
    return path[4:] if a.packagetype == "sdist" and path.startswith("src/") else path


def _clip(text: str, n: int = 160) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def _site_name(path: str) -> str:
    """A wheel path as it lands in site-packages (see ``facts.inventory.site_path``)."""
    return _SITE_PREFIX.sub("", path)


def _compare_note(b: ArtifactFacts, c: ArtifactFacts) -> tuple[Evidence, ...]:
    """A note when the two files compared aren't like for like."""
    if b.packagetype != c.packagetype:
        return (
            Evidence(
                "note",
                f"compared {c.filename} with {b.filename}: the releases ship different kinds of files",
            ),
        )
    if b.wheel_tag and c.wheel_tag and b.wheel_tag != c.wheel_tag:
        return (
            Evidence(
                "note", f"compared wheels with different tags: {b.wheel_tag} vs {c.wheel_tag}"
            ),
        )
    return ()


def new_pth_file(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-C001: a new .pth file, or new executable lines in an existing one.

    The lines ``str.splitlines()`` gives are compared first. A line that only
    some Pythons read as one (``PthFile.other_lines``) is then reported when
    the trusted file at the same path, or any trusted ``.pth`` for a new
    path, never ran it on any Python. That second pass only adds evidence.
    """
    if base is None:
        return
    b, c = _pair(base, cand)
    if b is None or c is None:
        return
    old = {_site_name(_installed(b, p.path)): p for p in b.pth_files}
    old_lines = {p.exec_lines for p in b.pth_files if p.exec_lines}
    every_old = {x for p in b.pth_files for x in p.all_lines}
    evidence: list[Evidence] = []
    hidden_evidence: list[Evidence] = []  # listed after, so the first pass reads as before
    for p in c.pth_files:
        size = next((f.size for f in c.files if f.path == p.path), 0)
        name = _site_name(_installed(c, p.path))
        ran = set(old[name].all_lines) if name in old else every_old
        hidden = [x for x in p.other_lines if x not in ran]
        if hidden:
            hidden_evidence.append(
                Evidence(
                    "file",
                    f"{p.path} has {len(hidden)} executable line(s) that only some Python "
                    f"versions read as a line: {_clip(hidden[0])}",
                    path=p.path,
                )
            )
        if name not in old:
            if p.exec_lines in old_lines:
                continue  # renamed (protobuf-<version>-nspkg.pth), same lines
            first = p.exec_lines[0] if p.exec_lines else "(no executable lines)"
            evidence.append(
                Evidence(
                    "file",
                    f"new {p.path} ({size:,} bytes, {len(p.exec_lines)} executable line(s)): {_clip(first)}",
                    path=p.path,
                    line=1,
                )
            )
        else:
            gained = [x for x in p.exec_lines if x not in old[name].exec_lines]
            if gained:
                evidence.append(
                    Evidence(
                        "file",
                        f"{p.path} gained {len(gained)} executable line(s): {_clip(gained[0])}",
                        path=p.path,
                    )
                )
    evidence += hidden_evidence
    if evidence:
        yield RawFinding(
            "GRN-C001",
            f"{cand.version} adds code that runs at every Python startup (.pth)",
            tuple(evidence[:MAX_EVIDENCE]) + _compare_note(b, c),
        )


def new_build_hook(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-C002: new sensitive calls in setup.py, or a new unusual build backend.

    Only sdists are compared: a wheel is already built. For npm the rule
    compares install-time scripts instead (``_new_install_script``). A
    trusted version that shipped no sdist had no build code at all, so
    every build-time call in the new sdist is new.
    """
    if base is None:
        return
    if change.ecosystem == "npm":
        yield from _new_install_script(base, cand)
        return
    c = _pick(cand, "sdist")
    if c is None:
        return
    b = _pick(base, "sdist")
    if b is None and any(a.packagetype == "sdist" for a in base.artifacts):
        return  # the trusted sdist couldn't be read; GRN-E001 says so
    evidence: list[Evidence] = []
    old_names = {s.name for s in b.setup_py_calls} if b is not None else set()
    old_backend = b.build_backend if b is not None else None
    for s in c.setup_py_calls:
        if s.name not in old_names:
            via = f" (in {s.via}())" if s.via else ""
            evidence.append(
                Evidence(
                    "file", f"setup.py:{s.line} calls {s.name}{via}", path="setup.py", line=s.line
                )
            )
    if c.build_backend != old_backend and c.build_backend is not None:
        if c.build_backend.startswith("in-tree:") or c.build_backend not in BACKEND_ALLOWLIST:
            evidence.append(
                Evidence(
                    "file",
                    f"build backend {old_backend or 'default'} → {c.build_backend}",
                    path="pyproject.toml",
                )
            )
    if evidence and b is None:
        evidence.append(
            Evidence("note", f"{base.version} shipped no sdist, so it had no build-time code")
        )
    if evidence:
        yield RawFinding(
            "GRN-C002",
            f"{cand.version} adds code that runs when the sdist is built",
            tuple(evidence[:MAX_EVIDENCE]),
        )


def _new_install_script(base: ReleaseFacts, cand: ReleaseFacts) -> Iterator[RawFinding]:
    """GRN-C002 for npm: a preinstall, install or postinstall script was added
    or changed. npm runs these on the machine that installs the package."""
    b = next(iter(base.content), None)
    c = next(iter(cand.content), None)
    if b is None or c is None:
        return
    old = dict(b.install_scripts)
    evidence: list[Evidence] = []
    for name, cmd in c.install_scripts:
        if name not in old:
            evidence.append(
                Evidence(
                    "file", f"package.json: new {name} script: {_clip(cmd)}", path="package.json"
                )
            )
        elif old[name] != cmd:
            evidence.append(
                Evidence(
                    "file",
                    f"package.json: {name} script changed to {_clip(cmd)} (was {_clip(old[name])})",
                    path="package.json",
                )
            )
    if evidence:
        yield RawFinding(
            "GRN-C002",
            f"{cand.version} adds or changes a script that runs when the package is installed",
            tuple(evidence[:MAX_EVIDENCE]),
        )


def _moved_from(path: str, baseline: tuple[ModuleIndex, ...]) -> set[str]:
    """Sensitive calls of the baseline module this new path was moved from."""
    best = _moved_module(path, baseline)
    return {s.name for s in best.top_level_calls if s.obscured is None} if best else set()


def _moved_module(path: str, baseline: tuple[ModuleIndex, ...]) -> ModuleIndex | None:
    """The baseline module this new path was moved from, if any.

    Vendored code often moves between folders (scipy 1.18.0 moved
    ``_lib/array_api_compat`` to ``_external/array_api_compat``). A baseline
    module sharing the longest path tail, at least ``<dir>/<file>``, counts as
    the same module, so only calls it didn't already make are new.
    """
    parts = path.split("/")
    best: ModuleIndex | None = None
    best_len = 1
    for m in baseline:
        other = m.path.split("/")
        n = 0
        while n < min(len(parts), len(other)) and parts[-1 - n] == other[-1 - n]:
            n += 1
        if (
            n == 0
            and other[:-1] == parts[:-1]
            and _public_name(other[-1]) == _public_name(parts[-1])
        ):
            n = len(parts)  # html5lib 1.0 renamed inputstream.py to _inputstream.py
        if n > best_len or (n == best_len and best is not None and m.path < best.path):
            best, best_len = m, n
    return best


def _public_name(filename: str) -> str:
    """``_inputstream.py`` and ``inputstream.py`` are the same module renamed."""
    return filename.lstrip("_")


def is_test_path(path: str) -> bool:
    """tests/ folders, a top-level test/ folder, test_*.py and conftest.py.

    A ``test/`` folder inside the package is installed code (``django.test``),
    so only one beside the package counts (docs/rules/GRN-C003.md).
    """
    parts = path.split("/")
    folders, name = parts[:-1], parts[-1]
    return (
        "tests" in folders
        or folders[:1] == ["test"]
        or name.startswith("test_")
        or name == "conftest.py"
    )


def _live_test_modules(art: ArtifactFacts) -> set[str]:
    """Test modules that run outside the package's own tests.

    A test module counts as live when a non-test module imports it, directly
    or through other test modules, or an entry point names it (a ``pytest11``
    plugin loads in every pytest run). Importing ``a.b.c`` also runs ``a``
    and ``a.b``.
    """
    return _live_modules(art, {m.module for m in art.modules if is_test_path(m.path)})


def _live_modules(art: ArtifactFacts, quiet: set[str], roots: Iterable[str] = ()) -> set[str]:
    """The modules in ``quiet`` that a module outside it imports, directly or
    through other modules in it, or that an entry point or ``roots`` names."""
    held = {m.module: m for m in art.modules if m.module in quiet}
    frontier = [i for m in art.modules if m.module not in held for i in m.imports]
    frontier += [*art.entry_points, *roots]
    reached: set[str] = set()
    while frontier:
        name = frontier.pop()
        parts = name.split(".")
        for n in range(1, len(parts) + 1):
            prefix = ".".join(parts[:n])
            if prefix in reached:
                continue
            reached.add(prefix)
            if prefix in held:
                frontier.extend(held[prefix].imports)
    return reached & set(held)


_RUNNERS = frozenset(
    {
        "threading.Thread",
        "threading.Timer",
        "multiprocessing.Process",
        "atexit.register",
        "signal.signal",
        "asyncio.run",
        "asyncio.create_task",
        "asyncio.ensure_future",
        "weakref.finalize",
        "_thread.start_new_thread",
        "os.register_at_fork",
    }
)
_RUNNER_METHODS = frozenset(
    {"submit", "apply_async", "map_async", "call_soon", "call_soon_threadsafe", "call_later"}
)


def _deferred(site: CallSite) -> bool:
    """A call reached only through a function handed to a call that may not run it."""
    return site.handed_to is not None and not _runs(site.handed_to)


def _runs(callee: str) -> bool:
    """Whether the call a function was handed to is known to run it.

    ``threading.Thread(target=f)`` and ``executor.submit(f)`` run f;
    ``functools.partial(f)``, ``map(f, xs)`` or a wrapper factory may never.
    """
    return callee in _RUNNERS or callee.rsplit(".", 1)[-1] in _RUNNER_METHODS


def _outside_package(art: ArtifactFacts, package: str) -> set[str]:
    """Paths of sdist modules that are not installed with the package.

    An sdist carries docs/conf.py, examples and benchmarks beside the package
    (ply 3.6's example/, mpmath 1.2.1's demo/); they run only when someone runs
    them. A wheel holds only what is installed, so nothing in it is outside.
    """
    if art.packagetype != "sdist":
        return set()
    return _outside_tops((f.path for f in art.files), (m.path for m in art.modules), package)


def _outside_tops(files: Iterable[str], modules: Iterable[str], package: str) -> set[str]:
    """The module paths in a folder at the top that holds no package: no
    ``__init__.py`` anywhere under it, and not named after the project."""
    tops = {f.split("/")[0] for f in files if f.endswith("/__init__.py")}
    name = package.lower().replace("-", "_").replace(".", "_")
    tops |= {"src", name, name.split("_")[0]}
    return {m for m in modules if "/" in m and m.split("/")[0] not in tops}


def _quiet_wheel_files(art: ArtifactFacts, package: str) -> set[str]:
    """Install paths of the wheel's Python files that run only when run on
    their own (GRN-C006 reports their code at info, as GRN-C003 does): test
    files, and files in a folder at the top of site-packages that holds no
    package (``scripts/readme-gen/``). One stays loud when a module outside
    this set imports it, an entry point names it, or a ``.pth`` line in the
    wheel names it."""
    site = {_site_name(m.path): m.module for m in art.modules}
    files = [_site_name(f.path) for f in art.files]
    paths = {p for p in site if is_test_path(p)} | _outside_tops(files, site, package)
    named = (w for p in art.pth_files for x in p.all_lines for w in _NAMES.findall(x))
    live = _live_modules(art, {site[p] for p in paths}, named)
    return {p for p in paths if site[p] not in live}


class _Reach:
    """How a call site in an artifact's module is reached at import (the
    kinds GRN-C003 reports, docs/rules/GRN-C003.md): from package code
    ("module"), only from test files nothing else imports ("test"), only from
    sdist files outside the package ("outside"), or only in a function handed
    to a call not known to run it ("handed")."""

    def __init__(self, art: ArtifactFacts, package: str) -> None:
        self.live_tests = _live_test_modules(art)
        self.module_of = {m.path: m.module for m in art.modules}
        self.outside = _outside_package(art, package)

    def test_only(self, m: ModuleIndex) -> bool:
        return is_test_path(m.path) and m.module not in self.live_tests

    def kind(self, m: ModuleIndex, s: CallSite) -> tuple[str, str]:
        """The site's kind, and the module counted for it in a title."""
        origin = s.from_module
        from_test = (
            origin is not None
            and is_test_path(origin)
            and self.module_of.get(origin) not in self.live_tests
        )
        from_outside = origin is not None and origin in self.outside
        counted = m.module
        if _deferred(s):
            kind = "handed"
        elif self.test_only(m) or from_test:
            kind = "test"
        elif m.path in self.outside or from_outside:
            kind = "outside"
        else:
            kind = "module"
        if origin is not None and kind != "handed" and (from_test or from_outside):
            counted = self.module_of.get(origin, origin)
        return kind, counted


def new_import_time_exec(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-C003: new import-time calls to the sensitive APIs in pyindex.

    A module byte-identical to a baseline file is skipped, and one moved from
    a baseline path is compared with that file. Three kinds of call are
    reported at info, each in its own finding (docs/rules/GRN-C003.md): calls
    in or reached only from test files that nothing else imports, calls in or
    reached only from sdist files outside the package, and calls in a function
    that import-time code only handed to another call which is not known to
    run it. A call that a package module reaches at import is reported once,
    at warn, whatever else reaches it.
    """
    if base is None:
        return
    b, c = _pair(base, cand)
    if b is None or c is None:
        return
    old = {m.module: {s.name for s in m.top_level_calls if s.obscured is None} for m in b.modules}
    old_hashes = {f.sha256 for f in b.files}
    old_unparsed = set(b.unparsed)
    new_hash = {f.path: f.sha256 for f in c.files}
    reach = _Reach(c, cand.package)
    kinds = ("module", "test", "outside", "handed", "read")
    # per kind: evidence, the files counted in the title, and the trusted
    # copies ast couldn't parse (a Python 2 wheel), module -> path
    found: dict[str, tuple[list[Evidence], set[str], dict[str, str]]] = {
        k: ([], set(), {}) for k in kinds
    }
    for m in c.modules:
        if m.module in old:
            before = old[m.module]
        elif new_hash.get(m.path) in old_hashes:
            continue  # byte-identical to a baseline file: moved, not added
        elif m.path in old_unparsed:
            before = set()
        else:
            before = _moved_from(m.path, b.modules)
        calls = [s for s in m.top_level_calls if s.obscured is None]
        # A function handed to two calls is scanned once per call; a site that
        # some call is known to run is not also "handed".
        ran = {(s.line, s.name) for s in calls if not _deferred(s)}
        sites: list[tuple[CallSite, str, str]] = []  # site, kind, file counted in the title
        for s in calls:
            if s.name in before:
                continue
            if _deferred(s) and (s.line, s.name) in ran:
                continue
            kind, counted = reach.kind(m, s)
            if s.read:
                if kind != "module":
                    continue  # a read only a test, an sdist extra or a handed function makes
                kind = "read"
            sites.append((s, kind, counted))
        # A site some package module reaches at import is a warn, whatever
        # else reaches it; a site several files reach is listed once.
        direct = {(s.line, s.name) for s, kind, _ in sites if kind == "module"}
        listed: set[tuple[str, int, str, str | None]] = set()
        for s, kind, counted in sites:
            if kind != "module" and (s.line, s.name) in direct:
                continue
            if (kind, s.line, s.name, s.via) in listed:
                continue
            listed.add((kind, s.line, s.name, s.via))
            evidence, files, unread = found[kind]
            start = f" from {s.from_module}" if s.from_module else ""
            how = f"handed to {s.handed_to}() at import" if _deferred(s) else "reached at import"
            via = f" (in {s.via}(), {how}{start})" if s.via else ""
            where = "new module " if m.module not in old and m.path not in old_unparsed else ""
            if m.path in old_unparsed:
                unread[m.module] = m.path
            verb = "reads" if s.read else "calls"
            evidence.append(
                Evidence(
                    "file",
                    f"{where}{m.path}:{s.line} {verb} {s.name}{via}",
                    path=m.path,
                    line=s.line,
                )
            )
            files.add(counted)
    for kind, (evidence, files, unread) in found.items():
        if not evidence:
            continue
        n = len(files)
        more = len(evidence) - MAX_EVIDENCE
        tail = (Evidence("note", f"and {more} more call site(s)"),) if more > 0 else ()
        note: tuple[Evidence, ...] = ()
        if kind == "test":
            title = (
                f"{cand.version} adds import-time calls to sensitive APIs reached only "
                f"from {n} test module(s) that no other module imports"
            )
            note = (
                Evidence(
                    "note",
                    "test files run only when the package's own tests run, "
                    "so this is reported at info",
                ),
            )
        elif kind == "outside":
            title = (
                f"{cand.version} adds import-time calls to sensitive APIs reached only "
                f"from {n} file(s) outside the package"
            )
            note = (
                Evidence(
                    "note",
                    "these files ship in the sdist but not in the installed package, "
                    "so they run only when run on their own; reported at info",
                ),
            )
        elif kind == "read":
            title = f"{cand.version} reads credentials or CI settings at import in {n} module(s)"
            note = (
                Evidence(
                    "note",
                    "a read is not a call, so this is reported at info; code that runs only "
                    "in CI or only when a token is set is how credential stealers stay quiet "
                    "on a developer's machine",
                ),
            )
        elif kind == "handed":
            title = (
                f"{cand.version} hands functions that call sensitive APIs to other "
                f"calls at import in {n} module(s)"
            )
            note = (
                Evidence(
                    "note",
                    "whether the receiving call runs them cannot be read from the source, "
                    "so this is reported at info",
                ),
            )
        elif unread and files <= unread.keys():
            title = (
                f"{cand.version} calls sensitive APIs at import in {n} module(s) whose "
                f"{base.version} copy couldn't be parsed"
            )
        else:
            title = f"{cand.version} adds import-time calls to sensitive APIs in {n} module(s)"
        if unread:
            note += (
                Evidence(
                    "note",
                    f"{base.version} has {', '.join(sorted(unread.values()))} too, but it "
                    "couldn't be parsed, so these calls may not be new",
                ),
            )
        yield RawFinding(
            "GRN-C003",
            title,
            tuple(evidence[:MAX_EVIDENCE]) + tail + note + _compare_note(b, c),
            lowered_to=None if kind == "module" else Severity.INFO,
        )


def obfuscated_blob(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-C005: new encoded literals and computed lookups in code that runs at import.

    The sites come from ``facts.obfuscation`` through the module index, with
    the reachability GRN-C003 uses. Only what a package module reaches at
    import is reported: sites reached only from test files nothing imports,
    from sdist files outside the package, or in a function only handed to a
    call not known to run it are left out. A literal or a built value (keys
    ``blob:`` and ``built:``) the trusted release had in any module isn't new;
    a computed lookup (``lookup:``) is compared with the same function in the
    same module, or the one it moved from. A site Garnet stopped reading at
    (``unread:``) is always reported. A module byte-identical to a trusted file is skipped.
    """
    if base is None:
        return
    b, c = _pair(base, cand)
    if b is None or c is None:
        return
    # A computed lookup is matched with the function it sits in too, so the
    # same ``getattr(os, n)`` written in a new function counts as new.
    trusted = [
        (m, {(s.obscured, s.via) for s in m.top_level_calls if s.obscured}) for m in b.modules
    ]
    anywhere = {k for _, keys in trusted for k, _ in keys if not k.startswith("lookup:")}
    by_module = {m.module: keys for m, keys in trusted}
    old_hashes = {f.sha256 for f in b.files}
    old_unparsed = set(b.unparsed)
    new_hash = {f.path: f.sha256 for f in c.files}
    reach = _Reach(c, cand.package)
    evidence: list[Evidence] = []
    files: set[str] = set()
    unread: dict[str, str] = {}
    for m in c.modules:
        sites = [s for s in m.top_level_calls if s.obscured is not None]
        if not sites:
            continue
        if m.module in by_module:
            before = by_module[m.module]
        elif new_hash.get(m.path) in old_hashes:
            continue  # byte-identical to a trusted file: moved, not added
        elif m.path in old_unparsed:
            before = set()
        else:
            moved = _moved_module(m.path, b.modules)
            before = by_module.get(moved.module, set()) if moved is not None else set()
        listed: set[tuple[int, str, str | None]] = set()
        for s in sites:
            stopped = s.obscured is not None and s.obscured.startswith(
                "unread:"
            )  # couldn't be read: never passed
            if not stopped and ((s.obscured, s.via) in before or s.obscured in anywhere):
                continue
            if reach.kind(m, s)[0] != "module" or (s.line, s.name, s.via) in listed:
                continue
            listed.add((s.line, s.name, s.via))
            start = f" from {s.from_module}" if s.from_module else ""
            via = f" (in {s.via}(), reached at import{start})" if s.via else ""
            new = m.module not in by_module and m.path not in old_unparsed
            if m.path in old_unparsed:
                unread[m.module] = m.path
            evidence.append(
                Evidence(
                    "file",
                    f"{'new module ' if new else ''}{m.path}:{s.line} {s.name}{via}",
                    path=m.path,
                    line=s.line,
                )
            )
            files.add(m.module)
    if not evidence:
        return
    more = len(evidence) - MAX_EVIDENCE
    tail = (Evidence("note", f"and {more} more"),) if more > 0 else ()
    note: tuple[Evidence, ...] = (
        Evidence(
            "note",
            "reported at info: packages also embed data and look names up for ordinary "
            "reasons; read what the literal holds and where the value goes",
        ),
    )
    if unread:
        note += (
            Evidence(
                "note",
                f"{base.version} has {', '.join(sorted(unread.values()))} too, but it "
                "couldn't be parsed, so these may not be new",
            ),
        )
    yield RawFinding(
        "GRN-C005",
        f"{cand.version} adds encoded literals or computed lookups at import in "
        f"{len(files)} module(s)",
        tuple(evidence[:MAX_EVIDENCE]) + tail + note + _compare_note(b, c),
    )


def _unparsed_new(
    base: ReleaseFacts | None, cand: ReleaseFacts
) -> tuple[ArtifactFacts | None, ArtifactFacts | None, list[str]]:
    """The trusted and the new artifact GRN-E002 compares, and the new one's
    new or changed .py files ast couldn't parse."""
    b, c = (
        _pair(base, cand)
        if base is not None
        else (None, _pick(cand, "wheel") or _pick(cand, "sdist"))
    )
    if c is None:
        return None, None, []
    old_hashes = {_installed(b, f.path): f.sha256 for f in b.files} if b is not None else {}
    new_hashes = {_installed(c, f.path): f.sha256 for f in c.files}
    bad = [
        p
        for p in c.unparsed
        if old_hashes.get(_installed(c, p)) != new_hashes.get(_installed(c, p))
    ]
    return b, c, bad


@each_view
def _unparsed_read(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-E002 for the artifact the content rules read, each way they read it."""
    b, c, bad = _unparsed_new(base, cand)
    if bad:
        yield RawFinding(
            "GRN-E002",
            f"{len(bad)} new or changed Python file(s) in {cand.version} couldn't be parsed",
            tuple(
                Evidence("file", f"{p}: not valid Python 3 syntax", path=p)
                for p in bad[:MAX_EVIDENCE]
            )
            + (_compare_note(b, c) if b is not None and c is not None else ()),
        )


def unparsed_changed(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-E002 for new or changed .py files ast couldn't parse, in the
    artifact the content rules read (a first wheel and its sdist each, see
    ``each_view``) and in each wheel GRN-C012 compared, and for the read
    wheel's files GRN-C006 couldn't list the calls of. GRN-C012's wheels are
    read once, against the whole candidate."""
    yield from _unparsed_read(change, base, cand)
    yield from _compared_unparsed(base, cand)
    yield from _sdist_unwalked(base, cand)


def _families_read(base: ReleaseFacts) -> set[str]:
    """The platform families of the trusted version's wheels Garnet read."""
    looked = {fam for _, fam in base.wheels_compared}
    if base.read_wheel_family is not None:
        looked.add(base.read_wheel_family)
    return looked


def _compared_unparsed(base: ReleaseFacts | None, cand: ReleaseFacts) -> Iterator[RawFinding]:
    """GRN-E002 naming GRN-C012, one per compared wheel, for its differing
    files Garnet couldn't parse. A file a trusted wheel of the same platform
    family had with the same bytes at the same path is left out: it makes the
    calls that wheel made, so none is new."""
    if not cand.wheel_unparsed:
        return
    read = _pick(cand, "wheel")
    against = read.filename if read is not None else "the wheel Garnet read"
    trusted = base.wheel_calls if base is not None else ()
    same = {(w.family, w.path, w.sha256) for w in trusted if w.sha256}
    looked = _families_read(base) if base is not None else set()
    by_wheel: dict[str, list[UnparsedWheelFile]] = {}
    for u in cand.wheel_unparsed:
        if (u.family, _site_name(u.path), u.sha256) not in same:
            by_wheel.setdefault(u.wheel, []).append(u)
    for wheel, files in sorted(by_wheel.items()):
        evidence = []
        for u in sorted(files, key=lambda u: u.path)[:MAX_EVIDENCE]:
            if base is None:
                why = "no trusted version to compare with"
            elif u.family in looked:
                why = f"new or changed since {base.version}'s {u.family} wheel"
            elif not base.artifacts:
                why = (
                    f"Garnet couldn't read {base.version}'s files, so it can't tell whether "
                    "this copy changed"
                )
            elif u.family not in base.wheel_families:
                why = f"{base.version} had no {u.family} wheel to compare with"
            else:
                why = (
                    f"Garnet didn't read {base.version}'s {u.family} wheel, so it can't tell "
                    "whether this copy changed"
                )
            evidence.append(Evidence("file", f"{u.path}: {why}", path=u.path))
        if len(files) > MAX_EVIDENCE:
            evidence.append(Evidence("note", f"and {len(files) - MAX_EVIDENCE} more"))
        evidence.append(Evidence("note", "not evaluated: GRN-C012"))
        yield RawFinding(
            "GRN-E002",
            f"{len(files)} Python file(s) in {wheel} couldn't be parsed to compare with {against}",
            tuple(evidence),
        )


def _no_trusted_pair(base: ReleaseFacts) -> str:
    """Why the trusted version gives GRN-C006 nothing to compare with."""
    v = base.version
    if not base.artifacts:
        return (
            f"Garnet couldn't read {v}'s files, so it can't tell whether {v}'s wheel had this code"
        )
    if not any(a.packagetype == "sdist" for a in base.artifacts):
        return f"{v} had no sdist, so nothing shows whether its wheel had this code"
    if not any(a.filename.endswith(".whl") for a in base.artifacts):
        return f"{v} had no wheel, so this code is new to the wheel"
    return (
        f"Garnet couldn't compare {v}'s wheel with its sdist, so it can't tell whether "
        f"{v} had this code"
    )


def _sdist_unwalked(base: ReleaseFacts | None, cand: ReleaseFacts) -> Iterator[RawFinding]:
    """GRN-E002 naming GRN-C006 for the read wheel's Python files that aren't
    in the sdist byte for byte and that parse but are nested too deep for
    Garnet to list their calls, so GRN-C006 can't tell whether they make one
    the sdist doesn't. A file the trusted version's wheel had with the same
    bytes at the same install path is left out: what it installs is unchanged,
    as GRN-E002 leaves out an unparsed file that didn't change."""
    sm = cand.sdist_match
    if base is None or sm is None or not sm.unwalked:
        return  # GRN-C006 compares nothing without a trusted version
    read = next((a for a in cand.artifacts if a.filename == sm.wheel), None)
    mine = {_site_name(f.path): f.sha256 for f in read.files} if read is not None else {}
    trusted = _pick(base, "wheel")
    theirs = {_site_name(f.path): f.sha256 for f in trusted.files} if trusted else {}
    if trusted is not None:
        why = f"new or changed since {base.version}'s wheel"
    elif not base.artifacts:
        why = f"Garnet couldn't read {base.version}'s files, so it can't tell whether it changed"
    else:
        why = f"{base.version} had no wheel to compare with"
    paths = [p for p in sm.unwalked if p not in theirs or theirs[p] != mine.get(p)]
    if not paths:
        return
    evidence = [
        Evidence(
            "file",
            f"{p}: not byte for byte in {sm.sdist}, and nested too deep for Garnet to list "
            f"its calls ({why})",
            path=p,
        )
        for p in paths[:MAX_EVIDENCE]
    ]
    if len(paths) > MAX_EVIDENCE:
        evidence.append(Evidence("note", f"and {len(paths) - MAX_EVIDENCE} more"))
    evidence.append(Evidence("note", "not evaluated: GRN-C006"))
    yield RawFinding(
        "GRN-E002",
        f"{len(paths)} Python file(s) in {sm.wheel} are nested too deep to compare with {sm.sdist}",
        tuple(evidence),
    )


def _wheel_only_line(w: WheelOnlyCode, sdist: str, c: CallSite) -> Evidence:
    via = f" (in {c.via}())" if c.via else ""
    if w.at is None:
        where = f"{sdist} has no such file"
    elif not w.sdist_parsed:
        where = f"{w.at} in {sdist} couldn't be parsed to compare"
    else:
        where = f"{w.at} in {sdist} doesn't"
    return Evidence(
        "file", f"{w.path}:{c.line} calls {c.name}{via}; {where}", path=w.path, line=c.line
    )


def _wheel_only_pth(w: WheelOnlyCode, sdist: str, lines: list[str]) -> Evidence:
    if w.at is not None:
        text = f"{w.path} has {len(lines)} executable line(s) that {w.at} in {sdist} doesn't"
    elif lines:
        text = f"{w.path} ({len(lines)} executable line(s)) has no copy in {sdist}"
    else:
        text = f"{w.path} (no executable lines) has no copy in {sdist}"
    if lines:
        text += f": {_clip(lines[0])}"
    return Evidence("file", text, path=w.path, line=1)


def sdist_wheel_mismatch(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-C006: the wheel the content rules read has code its own sdist
    doesn't. A Python file that isn't byte for byte in the sdist makes a
    sensitive call the sdist's copy doesn't make (any call, when there is no
    copy), or a ``.pth`` file has no sdist copy or executable lines its copy
    lacks.

    A reviewer who reads the sdist, or the repository it was made from, never
    sees such code. Files a build writes (a ``_version.py``) differ too, and
    have no such calls, so they stay quiet. A call or line the trusted
    version's wheel already carried outside its sdist, at the same install
    path, isn't new; for a ``.pth`` file a line counts as carried at any path,
    as GRN-C001 lets a ``.pth`` be renamed.

    Code only in test files or in files outside the release's packages is a
    separate finding at info, as GRN-C003 reports such files (the
    maintainer's 2026-10-31 decision): see ``_quiet_wheel_files``. A ``.pth``
    file is never at info.
    """
    if base is None or cand.sdist_match is None:
        return
    sm = cand.sdist_match
    calls_before: dict[str, set[str]] = {}
    lines_before: set[str] = set()
    bare_before: set[str] = set()  # .pth paths the trusted sdist had no copy of
    if base.sdist_match is not None:
        for w in base.sdist_match.code:
            calls_before.setdefault(w.path, set()).update(c.name for c in w.calls)
            lines_before.update(w.lines)
            if w.at is None and w.path.endswith(".pth"):
                bare_before.add(w.path)
    read = next((a for a in cand.artifacts if a.filename == sm.wheel), None)
    quiet = _quiet_wheel_files(read, cand.package) if read is not None else set()
    # loud: warn; quiet: test files and files outside the packages, at info
    found: dict[bool, tuple[list[Evidence], list[str]]] = {False: ([], []), True: ([], [])}
    for w in sm.code:
        if w.path.endswith(".pth"):
            lines = [x for x in w.lines if x not in lines_before]
            if not lines and (w.lines or w.at is not None or w.path in bare_before):
                continue
            evidence, files = found[False]  # a .pth runs at every startup: never quiet
            files.append(w.path)
            evidence.append(_wheel_only_pth(w, sm.sdist, lines))
            continue
        new = [c for c in w.calls if c.name not in calls_before.get(w.path, set())]
        if new:
            evidence, files = found[w.path in quiet]
            files.append(w.path)
            evidence.extend(_wheel_only_line(w, sm.sdist, c) for c in new)
    head = Evidence(
        "note",
        f"compared {sm.wheel} with {sm.sdist}: {sm.matched} Python file(s) match the sdist, "
        f"{sm.differ} differ from their copy there, {sm.absent} have none",
    )
    note = (Evidence("note", _no_trusted_pair(base)),) if base.sdist_match is None else ()
    for is_quiet, (evidence, files) in found.items():
        if not evidence:
            continue
        more = len(evidence) - MAX_EVIDENCE
        tail = (Evidence("note", f"and {more} more"),) if more > 0 else ()
        if not is_quiet:
            title = (
                f"{cand.version}'s wheel has code that is not in its sdist ({len(files)} file(s))"
            )
            why: tuple[Evidence, ...] = ()
        else:
            title = (
                f"{cand.version}'s wheel has code that is not in its sdist only in test "
                f"files or files outside its packages ({len(files)} file(s))"
            )
            why = (
                Evidence(
                    "note",
                    "test files and files outside the release's packages run only when run "
                    "on their own, and no other module, entry point or .pth file in the wheel "
                    "names these, so this is reported at info",
                ),
            )
        yield RawFinding(
            "GRN-C006",
            title,
            (head, *evidence[:MAX_EVIDENCE], *tail, *why, *note),
            lowered_to=Severity.INFO if is_quiet else None,
        )


def _source_matched(rel: ReleaseFacts) -> ArtifactFacts | None:
    """The artifact whose Python files were compared with the source tree."""
    return next((a for a in rel.content if a.source_match is not None), None)


def code_not_in_source(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-C007: a Python file in the release isn't the one at the release's
    tag, and it has sensitive calls the source file doesn't.

    Files that differ from the source are common (a generated version
    module, Cython output) and have no such calls, so they stay quiet. A
    call the trusted version already carried outside its source, at the same
    path, isn't new either.
    """
    if base is None:
        return
    c = _source_matched(cand)
    if c is None or c.source_match is None:
        return
    sm = c.source_match
    before: dict[str, set[str]] = {}
    b = _source_matched(base)
    if b is not None and b.source_match is not None:
        before = {u.path: {s.name for s in u.calls} for u in b.source_match.unmatched}
    evidence: list[Evidence] = []
    files = 0
    for u in sm.unmatched:
        new = [s for s in u.calls if s.name not in before.get(u.path, set())]
        if not new:
            continue
        files += 1
        at = u.at or sm.prefix + u.path
        for s in new:
            via = f" (in {s.via}())" if s.via else ""
            where = f"differs from {at} at {sm.tag}" if u.in_source else f"has no {at} at {sm.tag}"
            evidence.append(
                Evidence(
                    "file",
                    f"{u.path}:{s.line} calls {s.name}{via}; the source {where}",
                    path=u.path,
                    line=s.line,
                    url=f"https://github.com/{sm.repo}/blob/{sm.commit}/{at}"
                    if u.in_source
                    else None,
                )
            )
    if not evidence:
        return
    head = Evidence(
        "tag",
        f"{cand.version} → tag {sm.tag} at {sm.commit[:12]} in github.com/{sm.repo}; "
        f"{sm.matched} Python file(s) match the source, {len(sm.unmatched)} don't",
        url=f"https://github.com/{sm.repo}/tree/{sm.tag}",
    )
    more = len(evidence) - MAX_EVIDENCE
    tail = (Evidence("note", f"and {more} more call site(s)"),) if more > 0 else ()
    yield RawFinding(
        "GRN-C007",
        f"{cand.version} contains code that is not in github.com/{sm.repo} at tag {sm.tag} "
        f"({files} file(s))",
        (head, *evidence[:MAX_EVIDENCE], *tail),
    )


# GRN-C008: a dependency first published this close to the release that adds
# it is reported at warn, whoever owns it; an established one at info.
YOUNG_DEPENDENCY_DAYS = 90
_REGISTRY = {"pypi": "PyPI", "npm": "npm"}


def _released(first: datetime, p: DependencyProfile, registry: str, *, short: bool = False) -> str:
    """When a dependency was first released, in the words its record allows.

    A name that was unpublished and created again has an earlier history the
    date doesn't cover, so it is the earliest version still published.
    """
    day = f"{first:%Y-%m-%d}"
    if not p.unpublished_versions:
        return f"first released {day}"
    if short:
        return f"earliest version still published {day}"
    return f"earliest version still published {day} ({_unpublished(p, registry)})"


def _unpublished(p: DependencyProfile, registry: str) -> str:
    gone = p.unpublished_versions
    shown = ", ".join(gone[:3]) + (f" and {len(gone) - 3} more" if len(gone) > 3 else "")
    since = f" from {p.earliest_unpublished_at:%Y-%m-%d}" if p.earliest_unpublished_at else ""
    return f"{registry} also lists {shown}{since}, since unpublished"


_REGISTRY_PAGE = {
    "pypi": "https://pypi.org/project/{}/",
    "npm": "https://www.npmjs.com/package/{}",
}


def _metadata_pair(
    base: ReleaseFacts, cand: ReleaseFacts
) -> tuple[ArtifactFacts | None, ArtifactFacts | None]:
    """The artifacts whose declared dependencies are compared: the content
    pair on PyPI, the tarball on npm, and only when both were read."""
    if cand.ecosystem == "npm":
        b, c = next(iter(base.content), None), next(iter(cand.content), None)
    else:
        b, c = _pair(base, cand)
    if b is None or c is None or not (b.requirements_read and c.requirements_read):
        return None, None
    return b, c


def _dependency_changes(
    base: ReleaseFacts, cand: ReleaseFacts
) -> tuple[
    list[Requirement],
    list[tuple[Requirement, Requirement]],
    ArtifactFacts | None,
    ArtifactFacts | None,
]:
    """The candidate's new dependencies, and the ones it kept whose source or
    alias changed (``(old, new)``), with the two artifacts compared."""
    b, c = _metadata_pair(base, cand)
    if b is None or c is None:
        return [], [], None, None
    old = {r.name: r for r in b.requirements}
    new = [r for r in c.requirements if r.name not in old]
    moved = [
        (old[r.name], r)
        for r in c.requirements
        if r.name in old
        and (
            (r.source, r.alias_of) != (old[r.name].source, old[r.name].alias_of)
            or _declared_again(r, old[r.name])
        )
    ]
    return new, moved, b, c


def _declared_again(r: Requirement, before: Requirement | None = None) -> tuple[str, ...]:
    """What another declaration of ``r``'s name installs instead of its
    registry package (another registry package, a URL, a repository, a path)
    that the trusted version's ``before`` didn't declare. Garnet compares and
    looks up only the first declaration, so these weren't looked up."""
    had = set(before.also_installs) if before is not None else set()
    return tuple(t for t in r.also_installs if t not in had)


def _again_said(r: Requirement, targets: tuple[str, ...]) -> str:
    """The evidence for a name declared again to install something else."""
    others = "; ".join(_clip(a, 80) for a in r.also[:3])
    said = ", ".join(_clip(t, 80) for t in targets[:3])
    return f"{_clip(r.spec, 120)}: also declared as {others}, which installs {said}; Garnet didn't look that up"


def new_requirement_names(base: ReleaseFacts | None, cand: ReleaseFacts) -> tuple[str, ...]:
    """The registry packages the engine looks up for GRN-C008: what the
    candidate's new dependencies, and its kept ones that now install another
    package, install from the registry. In declaration order."""
    if base is None:
        return ()
    new, moved, _, _ = _dependency_changes(base, cand)
    wanted = [r for r in new if r.source is None]
    wanted += [r for _, r in moved if r.source is None and r.alias_of is not None]
    return tuple(dict.fromkeys(r.package for r in wanted))


def _uploaded(rel: ReleaseFacts) -> datetime | None:
    """When the release's first file was uploaded, if the registry said."""
    stamps = [a.uploaded_at for a in rel.artifacts if a.uploaded_at is not None]
    return min(stamps) if stamps else None


def _installs(r: Requirement) -> str:
    """What a requirement installs, for the evidence."""
    if r.source is not None:
        return _clip(r.source, 120)
    return r.package


def new_dependency(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-C008: the candidate declares a dependency the baseline didn't, or a
    dependency it kept now installs from somewhere else.

    Every new dependency is reported, with what the registry says about it.
    The rule keeps its severity for one that installs from outside the
    registry, one the registry doesn't have, one whose name is declared again
    to install another package or a source outside the registry
    (``Requirement.also_installs``, which Garnet doesn't look up; for a kept
    dependency, when that is new), and one whose first release came
    within ``YOUNG_DEPENDENCY_DAYS`` of this release (or after it), even when
    an account that owns the trusted package owns it too: whoever holds that
    account could have made both. An established dependency is reported at
    info. A new dependency the engine couldn't look up is listed at info, and
    GRN-E001 says the lookup failed.
    """
    if base is None:
        return
    new, moved, b, c = _dependency_changes(base, cand)
    if b is None or c is None or not (new or moved):
        return
    registry = _REGISTRY.get(change.ecosystem, "the registry")
    page = _REGISTRY_PAGE.get(change.ecosystem, "{}")
    profiles = {p.name: p for p in cand.dependencies}
    trusted_owners = set(base.owners)
    uploaded = _uploaded(cand)
    evidence: list[Evidence] = []
    flagged: list[str] = []

    for old, r in moved:
        was = f"{old.spec} in {base.version}"
        again = _declared_again(r, old)
        if again:
            flagged.append(f"{r.name} is declared again to install {_clip(again[0], 80)}")
            evidence.append(Evidence("note", _again_said(r, again)))
            if (r.source, r.alias_of) == (old.source, old.alias_of):
                continue
        if r.source is not None:
            flagged.append(f"{r.name} now installs from outside {registry}")
            evidence.append(Evidence("note", f"{r.spec}: installs from {_installs(r)}; was {was}"))
            continue
        url = page.format(r.package)
        if r.alias_of is None:
            # Back to the registry package of that name: the usual case.
            evidence.append(
                Evidence("url", f"{r.spec}: installs from {registry}; was {was}", url=url)
            )
            continue
        # The same name now installs a different package.
        flagged.append(f"{r.name} now installs {r.package}")
        p = profiles.get(r.package)
        about = ""
        if p is not None and not p.on_registry:
            about = f"; {registry} has no package named {r.package}"
        elif p is not None and p.first_release_at is not None:
            about = f"; {r.package} {_released(p.first_release_at, p, registry)}"
        evidence.append(
            Evidence(
                "url",
                f"{r.spec}: installs {r.package} under the name {r.name}{about}; was {was}",
                url=url,
            )
        )

    for r in new:
        again = _declared_again(r)
        if again:
            flagged.append(f"{r.name} is declared again to install {_clip(again[0], 80)}")
            evidence.append(Evidence("note", _again_said(r, again)))
        if r.source is not None:
            flagged.append(f"{r.name} installs from outside {registry}")
            evidence.append(
                Evidence("note", f"{r.spec}: new dependency, installed from {_installs(r)}")
            )
            continue
        p = profiles.get(r.package)
        url = page.format(r.package)
        alias = f" (installs {r.package})" if r.alias_of else ""
        if p is None:
            evidence.append(
                Evidence("note", f"{r.spec}: new dependency{alias}; {registry} was not consulted")
            )
            continue
        if not p.on_registry:
            flagged.append(f"{r.package} is not on {registry}")
            evidence.append(
                Evidence("url", f"{r.spec}: {registry} has no package named {r.package}", url=url)
            )
            continue
        parts = [alias.strip(" ()")] if alias else []
        shared = sorted(trusted_owners & set(p.owners))
        if p.first_release_at is not None:
            when = _released(p.first_release_at, p, registry, short=True)
            if uploaded is not None:
                days = (uploaded - p.first_release_at).days
                if days < 0:
                    when += f", after {cand.version} itself"
                else:
                    when += f", {days} day(s) before {cand.version}"
                if days < YOUNG_DEPENDENCY_DAYS:
                    since = (
                        "'s earliest version still published was released"
                        if p.unpublished_versions
                        else " was first released"
                    )
                    flagged.append(f"{r.package}{since} {max(days, 0)} day(s) before it")
            parts.append(when)
            if p.unpublished_versions:
                parts.append(_unpublished(p, registry))
        else:
            parts.append("no upload dates on record")
        parts.append(f"{p.releases} release(s)")
        parts.append(f"github.com/{p.source_repo}" if p.source_repo else "no repository link")
        if shared:
            parts.append(f"owned by {', '.join(shared[:3])}, who also own(s) {base.package}")
        evidence.append(Evidence("url", f"{r.spec}: {'; '.join(parts)}", url=url))

    heads = []
    if new:
        heads.append(f"{cand.version} depends on {len(new)} package(s) that {base.version} didn't")
    if moved:
        heads.append(
            f"{len(moved)} dependency(ies) install from somewhere else than in {base.version}"
        )
    title = "; ".join(heads + flagged[:3])
    yield RawFinding(
        "GRN-C008",
        title,
        tuple(evidence[:MAX_EVIDENCE]) + _compare_note(b, c),
        lowered_to=None if flagged else Severity.INFO,
    )


# GRN-C009: entry point groups another tool loads on its own, so the target
# runs inside that tool, in the environment the package is installed in
# (pytest, setuptools builds that don't isolate themselves, flake8, keyring...).
AUTO_LOADED_GROUPS = frozenset(
    {
        "pytest11",
        "egg_info.writers",
        "flake8.extension",
        "flake8.report",
        "keyring.backends",
        "pydantic",
        "tox",
        "hatch",
        "pdm",
        "poetry.plugin",
        "poetry.application.plugin",
    }
)
AUTO_LOADED_PREFIXES = ("setuptools.", "distutils.", "virtualenv.", "pygments.", "opentelemetry_")
_SCRIPT_GROUPS = ("console_scripts", "gui_scripts")
# Groups whose tool loads every line, a repeated name too, so a line that runs
# now ran before unless its target is new. setuptools (its hooks and file
# finders, distutils.setup_keywords for a keyword in use, egg_info.writers),
# flake8, keyring, pydantic, pdm, poetry and virtualenv load each entry of the
# group; opentelemetry runs each instrumentor. pygments picks a lexer by the
# class a line loads, not the line's name, and loads every lexer to match a
# file name or content. pytest, tox and hatch (pluggy) skip a name they have
# registered, and a lookup (distutils.commands, pygments.styles,
# pygments.filters, pygments.formatters, the other opentelemetry_ groups)
# returns the first line that matches: those keep the first-line test.
_EVERY_LINE_GROUPS = frozenset(
    {
        "distutils.setup_keywords",
        "egg_info.writers",
        "flake8.extension",
        "flake8.report",
        "keyring.backends",
        "opentelemetry_instrumentor",
        "opentelemetry_pre_instrument",
        "opentelemetry_post_instrument",
        "pydantic",
        "pdm",
        "poetry.plugin",
        "poetry.application.plugin",
        "pygments.lexers",
    }
)
_EVERY_LINE_PREFIXES = ("setuptools.", "virtualenv.")
# Of those, the groups whose tool loads every line's target whatever the
# line's name, and never uses the name to pick a line or skip one: a target
# any line of the group listed in the trusted version already ran, so a line
# that only gives it a new name runs nothing new (mako 1.4.1 renamed its
# lexers css+mako to css_mako, with the same classes). The other groups keep
# comparing name by name, because the name decides what runs:
# distutils.setup_keywords loads a line when a setup() call uses the keyword
# it names, egg_info.writers passes the name as the file to write, pydantic
# and opentelemetry_instrumentor skip the names a user turns off
# (PYDANTIC_DISABLE_PLUGINS, OTEL_PYTHON_DISABLED_INSTRUMENTATIONS),
# flake8 enables an off-by-default plugin and picks a formatter by name,
# virtualenv picks a creator, seeder or discovery by name, and the other
# setuptools.* groups aren't known to ignore it. pdm and poetry load each line
# and call what it loads (pdm 2.29 ``Core.load_plugins``, poetry 2.2
# ``PluginManager.load_plugins``).
_NAME_BLIND_GROUPS = frozenset(
    {
        "keyring.backends",
        "opentelemetry_post_instrument",
        "opentelemetry_pre_instrument",
        "pdm",
        "poetry.application.plugin",
        "poetry.plugin",
        "pygments.lexers",
        "setuptools.file_finders",
        "setuptools.finalize_distribution_options",
    }
)
# Names a tool skips in a group above, so their targets never ran: setuptools
# drops a finalize_distribution_options hook named 2to3_doctests.
_SKIPPED_NAMES = {"setuptools.finalize_distribution_options": frozenset({"2to3_doctests"})}


def _auto_loaded(group: str) -> bool:
    return group in AUTO_LOADED_GROUPS or group.startswith(AUTO_LOADED_PREFIXES)


def _loads_every_line(group: str) -> bool:
    return group in _EVERY_LINE_GROUPS or group.startswith(_EVERY_LINE_PREFIXES)


def _spaceless(target: str) -> str:
    # ``mod:func [extra]`` and ``mod:func[extra]`` are the same target.
    return "".join(target.split())


def _shadows(script: str, package: str) -> bool:
    """Whether a new script would run in place of a common command. A
    project's own command doesn't count: pytest installs ``pytest``."""
    name = script.lower()
    return name in _COMMANDS and name != re.sub(r"[-_.]+", "-", package).lower()


def _own_metadata(path: str) -> bool:
    """Whether an entry_points.txt is the one installers make commands from:
    in the ``.dist-info`` folder at the root of the wheel, with both names
    spelled exactly, as pip matches them."""
    folder, _, name = path.partition("/")
    return name == "entry_points.txt" and folder.endswith(".dist-info")


def _read_from(path: str) -> str:
    """Why an entry_points.txt other than the wheel's own counts."""
    folder = path.rpartition("/")[0]
    if "/" not in folder and folder.endswith(".dist-info"):
        return f"read from {path}, which macOS and Windows open as entry_points.txt"
    return (
        f"read from {path}, a second metadata folder, which importlib.metadata reads as "
        "another installed package"
    )


# Which of a name's lines in one entry_points.txt runs: pip keeps the last
# target of a script name; pytest, tox and hatch (pluggy) skip a plugin name
# they have already registered; setuptools and keyring load every line of
# their groups.
_WHICH_LOADS = {
    "console_scripts": "pip installs the last",
    "gui_scripts": "pip installs the last",
    "pytest11": "pytest loads the first",
    "tox": "tox loads the first",
    "hatch": "hatch loads the first",
}
_EACH_LOADS = "a tool that loads the whole group loads each one; a lookup by name takes the first"
# What changed when no target is new but the line that runs is another one.
_NOW = {
    "console_scripts": "pip now installs",
    "gui_scripts": "pip now installs",
    "pytest11": "pytest now loads",
    "tox": "tox now loads",
    "hatch": "hatch now loads",
}
_NOW_LOOKUP = "a lookup by name now returns"


def _by_name(specs: tuple[EntryPoint, ...]) -> dict[tuple[str, str], list[EntryPoint]]:
    out: dict[tuple[str, str], list[EntryPoint]] = {}
    for e in specs:
        out.setdefault((e.group, e.name), []).append(e)
    return out


def _running(eps: list[EntryPoint]) -> EntryPoint | None:
    """The line of a script name that pip installs: the last in the wheel's
    own file (None: no command)."""
    own = [e for e in eps if _own_metadata(e.path)]
    return own[-1] if own else None


# importlib.metadata's ``EntryPoint.pattern``: a target that doesn't match it
# fails to load, so it never ran.
_LOADABLE = re.compile(r"[\w.]+\s*(:\s*[\w.]+\s*)?(\[.*\]\s*)?$")


def _loaded_targets(specs: tuple[EntryPoint, ...]) -> dict[str, set[str]]:
    """For each group in ``_NAME_BLIND_GROUPS``, every target its tool
    loads, under any name it doesn't skip. A target that can't load isn't
    one: ``demo.p q:L`` never ran, so ``demo.pq:L`` under another name is new."""
    out: dict[str, set[str]] = {}
    for e in specs:
        if (
            e.group in _NAME_BLIND_GROUPS
            and e.name not in _SKIPPED_NAMES.get(e.group, ())
            and _LOADABLE.match(e.target.strip())
        ):
            out.setdefault(e.group, set()).add(_spaceless(e.target))
    return out


def _firsts(eps: list[EntryPoint]) -> list[EntryPoint]:
    """A name's first line in each file. pluggy registers a name from the
    first line it reads and a lookup by name returns the first; which file
    is read first is the order the folders are listed in."""
    out: dict[str, EntryPoint] = {}
    for e in eps:
        out.setdefault(e.path, e)
    return list(out.values())


def _targets(eps: list[EntryPoint], n: int) -> str:
    """A name's targets in file order: the first two and the last, and a
    count of the others, when there are more than three."""
    if len(eps) <= 3:
        return ", then ".join(_clip(e.target, n) for e in eps)
    first, second, last = (_clip(e.target, n) for e in (eps[0], eps[1], eps[-1]))
    return f"{first}, then {second}, then {len(eps) - 3:,} more line(s), then {last}"


_MAX_SUMMARY = 1000  # characters of one entry point's evidence line


def new_entry_point(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-C009: the candidate's wheel declares an entry point the baseline's
    didn't, or points an existing one somewhere else.

    An entry point is a group and a name. It is reported when the candidate
    lists a target for it that the baseline's wheel didn't, so a second line
    for a name counts, or when a line runs that didn't: for a script, the
    line pip installs (``_running``); for a group read by its first line, a
    target first in a file that was first in none (``_firsts``); for a group
    whose tool loads every line (``_loads_every_line``), never, since each
    line already ran. In a group whose tool also ignores the name
    (``_NAME_BLIND_GROUPS``), a target any line of the baseline's group
    listed is not new, so a renamed line is quiet. Lines removed, repeated
    or reordered with nothing new running are not.
    It keeps the rule's severity for a group another tool loads without being
    asked (``AUTO_LOADED_GROUPS``) and for a script named like a common
    command other than the project's own that the candidate's own file
    declares and the baseline's didn't, so a script moved into that file
    from another counts; any other new or changed entry point is reported at
    info. The evidence lists those that keep the severity first, each line
    clipped. Wheels only, each read to the end: an sdist's entry
    points may be computed by ``setup.py``, and a wheel Garnet stopped
    reading may hold more (GRN-E002 or GRN-E003 names this rule).
    """
    if base is None:
        return
    b, c = _pair(base, cand)
    if b is None or c is None or not (b.entry_points_read and c.entry_points_read):
        return
    old = _by_name(b.entry_point_specs)
    loaded = _loaded_targets(b.entry_point_specs)
    found: list[tuple[bool, Evidence]] = []
    loud: list[str] = []
    retargeted = False
    for (group, name), eps in _by_name(c.entry_point_specs).items():
        was = old.get((group, name), [])
        # A target the group's tool already loaded under another name is
        # not new (``_NAME_BLIND_GROUPS``).
        before = {_spaceless(e.target) for e in was} | loaded.get(group, set())
        added = [i for i, e in enumerate(eps) if _spaceless(e.target) not in before]
        script = group in _SCRIPT_GROUPS
        runs: EntryPoint | None = None  # for a script, the line pip installs now
        ran: EntryPoint | None = None  # and the one it installed before
        now: EntryPoint | None = None  # a line that runs now and didn't before
        if script:
            runs, ran = _running(eps), _running(was)
            if runs and (ran is None or _spaceless(runs.target) != _spaceless(ran.target)):
                now = runs
        elif not _loads_every_line(group):
            first = {_spaceless(e.target) for e in _firsts(was)}
            now = next((e for e in _firsts(eps) if _spaceless(e.target) not in first), None)
        if not (added or now):
            continue  # lines removed, repeated or reordered: nothing new runs
        retargeted = retargeted or bool(was)
        shown, where = _clip(name, 80) or '""', _clip(group, 80)
        files = sorted({e.path for e in eps})
        # The first new target leads the notes, so the clip can't drop it.
        why: list[str] = []
        if added and len(eps) > 3 and 2 <= added[0] < len(eps) - 1:
            why.append(f"first new target: {_clip(eps[added[0]].target, 120)}")
        warns = True
        if _auto_loaded(group):
            why.append(f"[{where}] is loaded automatically by the tool that reads it")
            loud.append(f"[{where}] {shown}")
        elif script and runs and not ran and _shadows(name, change.package):
            why.append(f"a script named {name} can shadow the {name} command")
            loud.append(f"script {name}")
        else:
            warns = False
        if script and runs and was and not ran:
            why.append(
                f"{base.version} listed it only outside its own entry_points.txt, "
                "which makes no command"
            )
        if not added and now and (ran or not script):
            note = f"{_NOW.get(group, _NOW_LOOKUP)} {_clip(now.target, 120)}"
            if not script and len(files) > 1:
                note += f" if {_clip(now.path, 120)} is read first"
            why.append(note)
        if len(eps) > 1 and len(files) == 1:
            why.append(f"{len(eps)} lines for one name: {_WHICH_LOADS.get(group, _EACH_LOADS)}")
        why += [_read_from(p) for p in files if not _own_metadata(p)]
        what = f"[{where}] {shown} = {_targets(eps, 120)}"
        what += f" (was {_targets(was, 80)})" if was else " (new)"
        at = eps[added[0]] if added else now or eps[0]
        summary = _clip("; ".join([what, *why]), _MAX_SUMMARY)
        found.append((warns, Evidence("file", summary, path=f"{c.filename}:{at.path}")))
    if not found:
        return
    found.sort(key=lambda t: not t[0])  # stable: the entries that warn first
    evidence = [ev for _, ev in found]
    more = len(evidence) - MAX_EVIDENCE
    tail = (Evidence("note", f"and {more} more entry point(s)"),) if more > 0 else ()
    if retargeted:
        title = f"{cand.version} adds or changes {len(found)} entry point(s)"
    else:
        title = f"{cand.version} declares {len(found)} entry point(s) that {base.version} didn't"
    if loud:
        title += ", including " + ", ".join(loud[:3])
        if len(loud) > 3:
            title += f" and {len(loud) - 3} more"
    yield RawFinding(
        "GRN-C009",
        title,
        tuple(evidence[:MAX_EVIDENCE]) + tail + _compare_note(b, c),
        lowered_to=None if loud else Severity.INFO,
    )


# GRN-C010: files that run without the package being imported. Python imports
# ``sitecustomize`` and ``usercustomize`` from site-packages at every start; a
# wheel's ``.data/scripts/`` files become commands on PATH, and ``.data/data/``
# files land under the environment's prefix, where other tools read their
# configuration (``etc/jupyter/``).
#
# The startup modules are matched by top-level module name, not file name:
# Python imports a ``sitecustomize/`` package, a ``.pyc`` with no source and an
# extension module (``sitecustomize.cpython-312-x86_64-linux-gnu.so``,
# ``.abi3.so``, ``.pyd``) just as it imports ``sitecustomize.py``, and a
# case-insensitive filesystem treats ``SiteCustomize.py`` as the same file. A
# ``__pycache__/sitecustomize.*.pyc`` with no source beside it isn't imported.
_STARTUP_MODULES = frozenset({"sitecustomize", "usercustomize"})
_SITE_DIRS = frozenset({"site-packages", "dist-packages"})
_DATA_DIR = re.compile(r"^[^/]+\.data/(scripts|data)/(.+)$")
# Windows runs a command named git from git.exe, git.cmd, git.bat or git.com.
_WINDOWS_RUNNABLE = frozenset({"bat", "cmd", "com", "exe"})
_COMMANDS = frozenset(
    {
        "bash",
        "cat",
        "cp",
        "curl",
        "docker",
        "env",
        "gcc",
        "git",
        "gpg",
        "grep",
        "kubectl",
        "ls",
        "make",
        "mv",
        "node",
        "npm",
        "npx",
        "openssl",
        "pip",
        "pip3",
        "pipx",
        "poetry",
        "pytest",
        "python",
        "python3",
        "rm",
        "scp",
        "sh",
        "ssh",
        "sudo",
        "tar",
        "tox",
        "uv",
        "uvx",
        "wget",
        "which",
        "zsh",
    }
)


def _is_startup_module(site: str) -> bool:
    """Whether a path relative to site-packages imports as sitecustomize or
    usercustomize: its first part up to the first dot, in any case."""
    return site.split("/", 1)[0].split(".", 1)[0].lower() in _STARTUP_MODULES


def _startup_kind(path: str) -> tuple[str, str] | None:
    """(where, name) for a wheel file that runs or installs outside the package.

    ``where`` is "site-packages" for a startup module in site-packages,
    "site-data" for one under ``.data/data/`` that installs into a
    site-packages folder below the prefix, else "scripts" or "data".
    """
    site = _site_name(path)
    if _is_startup_module(site):
        return "site-packages", site
    m = _DATA_DIR.match(path)
    if not m:
        return None
    where, name = m.group(1), m.group(2)
    if where == "data":
        parts = name.split("/")
        for i, part in enumerate(parts[:-1]):
            if part.lower() in _SITE_DIRS and _is_startup_module("/".join(parts[i + 1 :])):
                return "site-data", name
    return where, name


def new_startup_file(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-C010: the candidate's wheel adds a file that runs, or installs,
    outside the package: a ``sitecustomize`` or ``usercustomize`` module,
    package or extension in site-packages (also under ``.data/purelib/``,
    ``platlib/``, or a site-packages folder under ``.data/data/``), a script
    under ``.data/scripts/``, or a file under ``.data/data/``.

    The startup modules, scripts named like a common command, and data files
    under ``etc/`` keep the rule's severity; other scripts and data files are
    reported at info. Wheels only: an sdist installs what its build decides.
    """
    if base is None:
        return
    b, c = _pair(base, cand)
    if b is None or c is None or not (b.inspected and c.inspected):
        return
    if not (b.filename.endswith(".whl") and c.filename.endswith(".whl")):
        return
    old = {k for f in b.files if (k := _startup_kind(f.path)) is not None}
    evidence: list[Evidence] = []
    loud = 0
    for f in c.files:
        k = _startup_kind(f.path)
        if k is None or k in old:
            continue
        where, name = k
        if where == "site-packages":
            why = "Python imports it from site-packages at every start"
            loud += 1
        elif where == "site-data":
            why = f"installs as <prefix>/{name}, where Python imports it at every start"
            loud += 1
        elif where == "scripts":
            command = posixpath.basename(name)
            why = f"installs as the command {command}"
            stem, dot, ext = command.lower().rpartition(".")
            usual = stem if dot and ext in _WINDOWS_RUNNABLE else command.lower()
            if usual in _COMMANDS:
                why += f", which can run instead of the usual {usual}"
                loud += 1
        else:
            why = f"installs as <prefix>/{name}"
            if name.startswith("etc/"):
                why += ", where other tools read their configuration"
                loud += 1
        evidence.append(
            Evidence("file", f"{f.path}: {why} ({f.size:,} bytes)", path=f.path, sha256=f.sha256)
        )
    if not evidence:
        return
    yield RawFinding(
        "GRN-C010",
        f"{cand.version} adds {len(evidence)} file(s) that run or install outside the package",
        tuple(evidence[:MAX_EVIDENCE]) + _compare_note(b, c),
        lowered_to=None if loud else Severity.INFO,
    )


# GRN-C011: what each kind of JavaScript use is, for the evidence line.
_JS_GLOBALS = {
    "eval": "calls eval, which runs a string as code",
    "Function": "calls Function, which runs a string as code",
    "fetch": "calls fetch",
    "XMLHttpRequest": "uses XMLHttpRequest",
    "WebSocket": "uses WebSocket",
}


def _js_what(u: JsUse) -> str:
    if u.kind == "obfuscated":
        return f"has {u.name} in the shape javascript-obfuscator writes"
    return _JS_GLOBALS.get(u.name, f"loads {u.name}")


def new_js_use(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-C011: the JavaScript an npm package loads uses a process, network or
    eval API, or carries obfuscated code, that the trusted version's didn't.

    Compared by name across the package: a use moved from one file to another
    is not new. Each name is shown once, at a place where it runs when the file
    loads when there is one. npm only, and only when both tarballs were read.
    """
    if base is None:
        return
    b = next(iter(base.content), None)
    c = next(iter(cand.content), None)
    if b is None or c is None or not (b.js_scanned and c.js_scanned):
        return
    old = {(u.kind, u.name) for u in b.js_uses}
    added: dict[tuple[str, str], list[JsUse]] = {}
    for u in c.js_uses:
        if (u.kind, u.name) not in old:
            added.setdefault((u.kind, u.name), []).append(u)
    if not added:
        return
    evidence: list[Evidence] = []
    for key in sorted(added):
        uses = added[key]
        first = min(uses, key=lambda u: (not u.at_load, u.path, u.line))
        when = "when the file loads" if first.at_load else "inside a function"
        more = f"; {len(uses) - 1} more place(s)" if len(uses) > 1 else ""
        evidence.append(
            Evidence(
                "file",
                f"{first.path}:{first.line} {_js_what(first)} ({when}){more}",
                path=first.path,
                line=first.line,
            )
        )
    names = sorted({name for _, name in added})
    shown = ", ".join(names[:4]) + (f" and {len(names) - 4} more" if len(names) > 4 else "")
    yield RawFinding(
        "GRN-C011",
        f"{cand.version}'s JavaScript uses {shown}, which {base.version}'s didn't",
        tuple(evidence[:MAX_EVIDENCE]),
    )


def wheels_differ(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-C012: another wheel of the candidate has a Python file that differs
    from the wheel the content rules read and makes a sensitive call the read
    copy doesn't.

    A platform's wheel may differ for good reasons (delvewheel adds DLL loading
    to Windows wheels), so a call any of the trusted version's wheels for the
    same platform family made at the same path, the one it read included, is
    not new.

    When the read copy didn't parse, the trusted version's wheel for that
    family is what the call is compared with. Only when that comparison isn't
    possible either, and GRN-E002 already warns for the read copy as new or
    changed, is the line listed at info.
    """
    if base is None or not cand.wheel_differences:
        return
    read = _pick(cand, "wheel")
    if read is None:
        return
    before: dict[tuple[str, str], set[str]] = {}
    unread: set[tuple[str, str]] = set()  # the trusted copy couldn't be parsed
    for w in base.wheel_calls:
        if w.names is None:
            unread.add((w.family, w.path))
        else:
            before.setdefault((w.family, w.path), set()).update(w.names)
    looked = _families_read(base)
    # A first wheel beside an sdist is read against the trusted sdist in a view
    # of its own (each_view), and that view is where GRN-E002 reports it.
    _, reported, bad = _unparsed_new(base, _views(base, cand)[-1])
    warned = (
        {_site_name(p) for p in bad} if reported and reported.filename == read.filename else set()
    )
    base_families = set(base.wheel_families)
    evidence: list[Evidence] = []
    wheels: list[str] = []  # the wheel each evidence line is from
    compared = False  # a line where the read copy was there and parsed, or absent
    warn = False  # a line that GRN-E002 doesn't already warn for
    for d in cand.wheel_differences:
        known = before.get((d.family, d.path), set())
        trusted = d.family in looked and (d.family, d.path) not in unread
        for c in d.calls:
            if c.name in known:
                continue
            via = f" (in {c.via}())" if c.via else ""
            if not d.in_inspected:
                where = f"{read.filename} has no such file"
            elif d.read_copy_parsed:
                where = f"the same file in {read.filename} doesn't"
            else:
                where = f"the same file in {read.filename} couldn't be parsed to compare"
                if trusted:
                    where += f", and {base.version}'s {d.family} wheel didn't make this call there"
            text = f"{d.wheel}: {d.path}:{c.line} calls {c.name}{via}; {where}"
            if not base.artifacts:  # Garnet saw none of its files; GRN-E001 says why
                text += f" (Garnet couldn't read {base.version}'s files to compare with)"
            elif d.family not in base_families:
                text += f" ({base.version} had no {d.family} wheel to compare with)"
            elif (d.family, d.path) in unread:
                text += (
                    f" ({base.version}'s {d.family} copy couldn't be parsed, so this call may "
                    "not be new)"
                )
            evidence.append(Evidence("file", text, path=d.path, line=c.line))
            wheels.append(d.wheel)
            parsed = not d.in_inspected or d.read_copy_parsed
            compared = compared or parsed
            warn = warn or parsed or trusted or d.path not in warned
    if not evidence:
        return
    n = len(set(wheels))
    if compared:
        title = f"{n} other wheel(s) of {cand.version} have code the wheel Garnet read doesn't"
    else:
        title = (
            f"{n} other wheel(s) of {cand.version} have code Garnet couldn't compare "
            "with the wheel it read"
        )
    more = len(evidence) - MAX_EVIDENCE
    tail: tuple[Evidence, ...] = ()
    if more > 0:
        rest = ", ".join(sorted(set(wheels[MAX_EVIDENCE:])))
        tail = (Evidence("note", f"and {more} more call site(s), in {rest}"),)
    note: tuple[Evidence, ...] = ()
    if not warn:
        # Old releases read through a Python 2 wheel: the read copies don't
        # parse, and GRN-E002 warns for the ones that are new or changed.
        note = (
            Evidence(
                "note",
                f"the copies in {read.filename} are new or changed and couldn't be parsed, "
                "which GRN-E002 reports, so this is reported at info",
            ),
        )
    yield RawFinding(
        "GRN-C012",
        title,
        tuple(evidence[:MAX_EVIDENCE]) + tail + note,
        lowered_to=None if warn else Severity.INFO,
    )


def late_wheels_not_compared(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-E003 naming GRN-C012 for the late wheels past its cap: their files
    weren't compared, and a check Garnet couldn't run is never a pass."""
    if not cand.wheels_not_compared:
        return
    left = sorted(cand.wheels_not_compared)
    evidence = [Evidence("file", w) for w in left[:MAX_EVIDENCE]]
    if len(left) > MAX_EVIDENCE:
        evidence.append(Evidence("note", f"and {len(left) - MAX_EVIDENCE} more"))
    evidence.append(Evidence("note", "not evaluated: GRN-C012"))
    yield RawFinding(
        "GRN-E003",
        f"Couldn't fully check {cand.version}: {len(left)} late wheel(s) weren't compared with "
        "the wheel Garnet read; GRN-C012 compares up to 30",
        tuple(evidence),
    )


# GRN-C004: a compiled extension module is named for the module it provides,
# tagged for the interpreter it was built for: ``name.cpython-312-x86_64-linux-gnu.so``,
# ``name.abi3.so``, ``name.cp312-win_amd64.pyd`` (a ``.pyd`` is one even untagged).
# A shared library is ``libname.so`` or ``libname.so.1``; an untagged ``name.so``
# counts as one too. mypyc's shared module starts with a hash
# (``81d243bd2c585b0f4821__mypyc.cpython-313-...so``).
_EXTENSION_MODULE = re.compile(r"^[A-Za-z0-9_]+(\.[A-Za-z0-9_-]+\.so|(\.[A-Za-z0-9_-]+)?\.pyd)$")
# Extensions that say a file is native code. Besides libraries and executables:
# ELF GPU code objects, NVIDIA's ``.cubin`` and AMD's ``.hsaco`` and ``.co``
# (rocBLAS kernels, which torch's ROCm wheels bundle); Node.js addons
# (``.node``), JNI and MATLAB libraries; and LLVM's linker, ``ld.lld``, which
# pytorch-triton-rocm bundles. A CUDA ``.fatbin`` isn't ELF, so it needs no
# entry. Python's own file types say a file is something else.
_NATIVE_PARTS = frozenset(
    {
        *("so", "pyd", "dylib", "dll", "exe", "o", "obj", "bundle", "bin", "elf", "out"),
        *("sys", "ko", "cubin", "hsaco", "co", "node", "jnilib", "lld"),
        *("mexa64", "mexmaci64", "mexmaca64", "mexw64"),
    }
)
# A separate debug file is named for its library: ``libfoo.so.debug``.
_DEBUG_PARTS = frozenset({"debug", "dbg"})
_PYTHON_PARTS = frozenset({"py", "pyw", "pyi", "pth", "pyc"})
# A cached .pyc is named for its source and the interpreter that compiled it
# (``a.cpython-313.pyc``, ``a.cpython-313.opt-1.pyc``).
_CACHED_PYC = re.compile(r"^[^.]+\.[A-Za-z0-9_-]+(\.opt-[0-9]+)?\.pyc$")
# A version with a pre-release, post-release, dev or free-threading suffix, as
# one part: ``13t`` (``python3.13t``), ``0rc1``, ``0b2``, ``1post1``, ``1dev0``.
_SUFFIXED_VERSION = re.compile(r"[0-9]+(a|b|rc|t|post|dev)[0-9]*")
# A CPython build's ABI tag: ``cp313``, ``cp313t`` (free-threaded), ``cp37m``
# (before 3.8), ``d`` for a debug build.
_CPYTHON_ABI = re.compile(r"cp3([0-9]+)([tdm]*)")
_MANYLINUX = re.compile(r"manylinux_[0-9]+_[0-9]+_(\w+)")
# CPython's platform triplet for a manylinux wheel's architecture, where it
# isn't ``<arch>-linux-gnu``: ``.cpython-313-i386-linux-gnu.so`` in an ``i686`` wheel.
_LINUX_TRIPLET = {
    "i686": "i386-linux-gnu",
    "armv6l": "arm-linux-gnueabihf",
    "armv7l": "arm-linux-gnueabihf",
    "ppc64": "powerpc64-linux-gnu",
    "ppc64le": "powerpc64le-linux-gnu",
}
_ANY_PYTHON = frozenset({Tag("py3", "none", "any")})
_WHEEL_DATA = re.compile(r"^[^/]+\.data/([^/]+)/")
_LIBS_FOLDER = re.compile(r"^([^/]+)\.libs/")


def _install_key(path: str) -> str:
    """A path keyed by where it installs, so it is the same in every release.

    The wheel's ``<name>-<version>.data`` folder carries the version, and
    auditwheel's ``<name>.libs`` folder the project's name as that release
    spelled it (``Pillow.libs``, then ``pillow.libs``).
    """
    if m := _WHEEL_DATA.match(path):
        scheme, rest = m.group(1), path[m.end() :]
        path = rest if scheme in ("purelib", "platlib") else f".data/{scheme}/{rest}"
    if m := _LIBS_FOLDER.match(path):
        path = re.sub(r"[-_.]+", "_", m.group(1)).lower() + ".libs/" + path[m.end() :]
    return path


def _strip_versions(parts: list[str]) -> None:
    """Drop a version at the end. A part that starts with a digit is one when
    it is all digits (``so.3``), follows a part that is (``1.0.2k``,
    ``1.2.3rc1``), reads as a version with a suffix (``13t``, ``0rc1``) or
    isn't a word (``25.1-linux-x86_64``). ``7z``, ``3gp`` and ``3ds`` after a
    name are extensions."""
    while parts and parts[-1][:1].isdigit():
        last = parts[-1]
        version = last.isdigit() or not last.isalnum() or bool(_SUFFIXED_VERSION.fullmatch(last))
        if not (version or (len(parts) > 1 and parts[-2].isdigit())):
            return
        parts.pop()


def _named_as(path: str) -> str:
    """What a file's last extension says it is: "native", "python", "other",
    or "" when the name has none (as an executable usually doesn't).

    A version at the end doesn't count: ``libssl.so.3`` and ``libssl.so.1.0.2k``
    are named native, ``tool-1.2.3rc1`` and ``python3.13t`` have no extension,
    and ``data.7z`` is named as something else. A debug file named for its
    library is named native, but a native part earlier in the name isn't
    enough: ``logo.so.png`` says PNG.
    """
    parts = posixpath.basename(path).lower().split(".")[1:]
    _strip_versions(parts)
    if len(parts) > 1 and parts[-1] in _DEBUG_PARTS:
        parts.pop()
        _strip_versions(parts)
        return "native" if parts and parts[-1] in _NATIVE_PARTS else "other"
    if not parts:
        return ""
    if parts[-1] in _PYTHON_PARTS:
        return "python"
    return "native" if parts[-1] in _NATIVE_PARTS else "other"


def _native(f: FileEntry) -> bool:
    return f.binary is not None or f.kind == "native"


def _what(f: FileEntry) -> str:
    if f.binary is None:
        return f"a file named as native code ({f.size:,} bytes)"
    return f"{f.binary} native code ({f.size:,} bytes)"


def _platform_tag(filename: str) -> str:
    """A wheel's platform tag (``any`` for pure Python), or "" for an sdist."""
    return filename[:-4].rsplit("-", 1)[-1] if filename.endswith(".whl") else ""


def _os_family(tag: str) -> str:
    if tag.startswith("win"):
        return "windows"
    if tag.startswith("macosx"):
        return "macos"
    return "linux" if "linux" in tag else tag


def _ships_compiled(rel: ReleaseFacts) -> bool:
    """Whether a release has a wheel for some platform, read or not."""
    return any(_platform_tag(a.filename) not in ("", "any") for a in rel.artifacts)


def _natives_comparable(base: ReleaseFacts, b: ArtifactFacts, c: ArtifactFacts) -> bool:
    """Whether the trusted artifact shows what native code its release shipped
    where the new one's would install.

    It doesn't when the kinds differ (an sdist compiles its own), when the two
    wheels are for different operating systems, or when the trusted one is a
    pure-Python wheel read in place of compiled ones that don't fit this
    machine, and the new one is compiled. Both happen when the trusted release
    had no wheel for the Python Garnet runs on: Garnet read pillow 10.3.0's
    macOS wheel and frozenlist 1.4.1's pure-Python one. Two pure-Python wheels
    are what pip installs here on both sides, so they are compared.
    """
    if b.packagetype != c.packagetype:
        return False
    old, new = _platform_tag(b.filename), _platform_tag(c.filename)
    if old != "any":
        return _os_family(old) == _os_family(new)
    return new == "any" or not _ships_compiled(base)


def _extension_suffixes(tag: Tag) -> frozenset[str]:
    """The extension suffixes, such as ``.abi3.so``, that every Python
    installing a wheel tag tries after a module's name: the
    EXTENSION_SUFFIXES they all share.

    On Linux and macOS: ``.so``; ``.abi3.so`` when only CPython with the GIL
    installs the tag (an ``abi3`` or ``cp313`` ABI; a free-threaded build
    doesn't try it); and the version-tagged suffix when the ABI names one
    CPython build, on a manylinux or macOS platform
    (``.cpython-313-x86_64-linux-gnu.so``, ``.cpython-313t-darwin.so``). On
    Windows: ``.pyd``, and ``.cp313-win_amd64.pyd`` likewise. No suffix on
    another platform, such as ``any``. A musllinux tag gets no tagged suffix:
    CPython names that triplet ``linux-gnu`` or ``linux-musl``, depending on
    its version and build.
    """
    abi = _CPYTHON_ABI.fullmatch(tag.abi)
    family = _os_family(tag.platform)
    if family == "windows":
        if abi is None:
            return frozenset({".pyd"})
        free_threaded = "t" if "t" in abi[2] else ""
        return frozenset({".pyd", f".cp3{abi[1]}{free_threaded}-{tag.platform}.pyd"})
    if family not in ("linux", "macos"):
        return frozenset()
    found = {".so"}
    if tag.abi == "abi3" or (abi is not None and "t" not in abi[2]):
        found.add(".abi3.so")
    if abi is not None and family == "macos":
        found.add(f".cpython-3{abi[1]}{abi[2]}-darwin.so")
    elif abi is not None and (linux := _MANYLINUX.fullmatch(tag.platform)):
        triplet = _LINUX_TRIPLET.get(linux[1], f"{linux[1]}-linux-gnu")
        found.add(f".cpython-3{abi[1]}{abi[2]}-{triplet}.so")
    return frozenset(found)


def _ahead_of_pyc(a: ArtifactFacts) -> set[str]:
    """The modules (``demo/a``) that every Python installing this artifact
    finds ahead of a ``.pyc`` of their name, under the names its path finder
    tries in order: a package (``demo/a/__init__`` plus ``.py``, ``.pyc`` or an
    extension suffix), then an extension module (``demo/a`` plus an extension
    suffix), then ``demo/a.py`` (and ``.pyw`` in a Windows wheel).

    An extension suffix counts only when every tag of the wheel has it (see
    ``_extension_suffixes``): ``.cpython-313-x86_64-linux-gnu.so`` only in a
    wheel for that one CPython build and platform, none in a pure-Python wheel
    or an sdist. No other name comes first: ``a.x.so`` and
    ``a/__init__.cpython-313.pyc`` aren't tried."""
    wheel = wheel_tags.parse(a.filename)
    tags = wheel.tags if wheel is not None else _ANY_PYTHON
    extensions = frozenset.intersection(*(_extension_suffixes(t) for t in tags))
    windows = all(_os_family(t.platform) == "windows" for t in tags)
    sources = (".py", ".pyw") if windows else (".py",)
    found: set[str] = set()
    for f in a.files:
        folder, name = posixpath.split(_install_key(_installed(a, f.path)))
        stem, dot, rest = name.partition(".")
        if not stem or not dot:
            continue
        suffix = dot + rest
        module = suffix in sources or suffix in extensions
        if module:
            found.add(posixpath.join(folder, stem))
        if stem == "__init__" and (module or suffix == ".pyc"):
            found.add(folder)
    return found


def _pyc_reason(
    f: FileEntry,
    key: str,
    prior: FileEntry | None,
    sources: set[str],
    ahead: set[str],
    lost: str | None,
) -> str | None:
    """Why a ``.pyc`` is reported, or None when Python won't run it in place of
    readable source, or ran it already in the trusted release. ``lost`` names
    the ``.py`` of that name the trusted release shipped, when the new one
    removes it."""
    folder, name = posixpath.split(key)
    if posixpath.basename(folder) == "__pycache__" and _CACHED_PYC.match(name):
        # Python reads a cached .pyc only for the source it was compiled from.
        # A hash-based one is never compared with that source's code: Python
        # checks at most the hash in its header, which the release supplies.
        source = posixpath.join(posixpath.dirname(folder), name.split(".")[0] + ".py")
        if not f.hash_based or source not in sources:
            return None
        return (
            f"hash-based bytecode ({f.size:,} bytes) that Python can load in place of "
            f"{source} without comparing its code with that file"
        )
    # Any other .pyc, in __pycache__ or not, imports as a module of its own
    # name when Python finds nothing ahead of it. A name with another dot
    # never imports: pytest's own cache, test_x.cpython-313-pytest-8.4.1.pyc,
    # carries an extra part after the interpreter's tag.
    if "." in name[:-4] or key[:-4] in ahead:
        return None
    what = f"compiled bytecode ({f.size:,} bytes) with no source beside it"
    if lost is not None:
        return f"{what}; {lost}"
    return None if prior is not None else what


def new_binary(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-C004: the candidate adds native code or bytecode that hides from the rules.

    Warned: native bytes under a name whose last extension says otherwise (a
    DLL named ``.py``), new or changed; any native file when the trusted
    release shipped none, new or where a file that wasn't native was; a
    sourceless ``.pyc``, which Python imports unless a package, extension
    module or ``.py`` of that name comes first on every Python the wheel
    installs on, new or whose ``.py`` the trusted release had; and a new or
    changed hash-based ``.pyc`` in ``__pycache__``, which Python loads in
    place of its source without comparing its code. A new shared library or
    executable in a folder that held no native code, in a release that
    already shipped some, is reported at info. New extension modules in a
    release that already had some, rebuilt binaries and new ones in a folder
    that already held native code are not reported.
    """
    if base is None:
        return
    b, c = _pair(base, cand)
    if b is None or c is None or not (b.inspected and c.inspected):
        return
    old = {_install_key(_installed(b, f.path)): f for f in b.files}
    native_dirs = {posixpath.dirname(k) for k, f in old.items() if _native(f)}
    comparable = _natives_comparable(base, b, c)
    sources = {_install_key(_installed(c, f.path)) for f in c.files if f.kind == "py"}
    ahead = _ahead_of_pyc(c)
    old_sources = {k for k, f in old.items() if f.kind == "py"}
    found: list[tuple[bool, str, Evidence]] = []
    changed = False
    unsourced = 0
    for f in c.files:
        key = _install_key(_installed(c, f.path))
        prior = old.get(key)
        lost = None
        if f.kind == "pyc" and key[:-1] in old_sources and key[:-1] not in sources:
            lost = f"{base.version} shipped {key[:-1]}"
        # An unchanged .pyc whose .py was removed may now run in its place.
        unchanged = prior is not None and prior.sha256 == f.sha256
        if unchanged and (lost is None or f.binary is not None):
            continue
        name = posixpath.basename(f.path)
        strong = True
        if f.binary is not None and _named_as(name) in ("python", "other"):
            why = f"{_what(f)} under the name {name}"
        elif _native(f):
            if (prior is not None and _native(prior)) or not comparable:
                continue
            if not native_dirs:
                # A release with compiled wheels shipped native code even when
                # the wheel read has none.
                if b.packagetype == "sdist" or _ships_compiled(base):
                    had = f"{b.filename} had"
                else:
                    had = f"{base.version} shipped"
                why = f"{_what(f)}; {had} no native code"
            elif _EXTENSION_MODULE.match(name) or posixpath.dirname(key) in native_dirs:
                continue
            else:
                strong = False
                why = f"{_what(f)} in a folder that held no native code in {base.version}"
        elif f.kind == "pyc" and (reason := _pyc_reason(f, key, prior, sources, ahead, lost)):
            why = reason
        else:
            continue
        if unchanged:
            unsourced += 1
        else:
            changed = changed or prior is not None
        evidence = Evidence("file", f"{f.path}: {why}", path=f.path, sha256=f.sha256)
        found.append((strong, f.path, evidence))
    if not found:
        return
    # The files that hide code first, then the rest, each by path.
    found.sort(key=lambda t: (not t[0], t[1]))
    n = len(found)
    if unsourced == n:
        title = f"{cand.version} removes the source of {n} .pyc file(s), so Python imports the bytecode instead"
    elif unsourced:
        title = f"{cand.version} adds, changes or removes the source of {n} file(s) of native code or bytecode"
    elif changed:
        title = f"{cand.version} adds or changes {n} file(s) of native code or bytecode"
    else:
        title = f"{cand.version} adds {n} file(s) of native code or bytecode that {base.version} didn't have"
    yield RawFinding(
        "GRN-C004",
        title,
        tuple(e for _, _, e in found[:MAX_EVIDENCE]) + _compare_note(b, c),
        lowered_to=None if any(strong for strong, _, _ in found) else Severity.INFO,
    )
