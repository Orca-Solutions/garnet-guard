"""Content rules: what changed inside the release. Pure functions of facts."""

from __future__ import annotations

from collections.abc import Iterator

from ..models import (
    ArtifactFacts,
    Change,
    Evidence,
    ModuleIndex,
    RawFinding,
    ReleaseFacts,
    Severity,
)

MAX_EVIDENCE = 25  # evidence lines per finding; the rest are counted, not listed

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
    """The artifacts to compare: wheels when both have one, else sdists."""
    bw, cw = _pick(base, "wheel"), _pick(cand, "wheel")
    if bw is not None and cw is not None:
        return bw, cw
    return _pick(base, "sdist"), _pick(cand, "sdist")


def _clip(text: str, n: int = 160) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def _tag_note(b: ArtifactFacts, c: ArtifactFacts) -> tuple[Evidence, ...]:
    """A note when the two wheels compared were built for different platforms."""
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
    """GRN-C001: a new .pth file, or new executable lines in an existing one."""
    if base is None:
        return
    b, c = _pair(base, cand)
    if b is None or c is None:
        return
    old = {p.path: p for p in b.pth_files}
    evidence: list[Evidence] = []
    for p in c.pth_files:
        size = next((f.size for f in c.files if f.path == p.path), 0)
        if p.path not in old:
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
            gained = [x for x in p.exec_lines if x not in old[p.path].exec_lines]
            if gained:
                evidence.append(
                    Evidence(
                        "file",
                        f"{p.path} gained {len(gained)} executable line(s): {_clip(gained[0])}",
                        path=p.path,
                    )
                )
    if evidence:
        yield RawFinding(
            "GRN-C001",
            f"{cand.version} adds code that runs at every Python startup (.pth)",
            tuple(evidence[:MAX_EVIDENCE]) + _tag_note(b, c),
        )


def new_build_hook(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-C002: new sensitive calls in setup.py, or a new unusual build backend.

    Only sdists are compared: a wheel is already built.
    """
    if base is None:
        return
    b, c = _pick(base, "sdist"), _pick(cand, "sdist")
    if b is None or c is None:
        return
    evidence: list[Evidence] = []
    old_names = {s.name for s in b.setup_py_calls}
    for s in c.setup_py_calls:
        if s.name not in old_names:
            evidence.append(
                Evidence("file", f"setup.py:{s.line} calls {s.name}", path="setup.py", line=s.line)
            )
    if c.build_backend != b.build_backend and c.build_backend is not None:
        if c.build_backend.startswith("in-tree:") or c.build_backend not in BACKEND_ALLOWLIST:
            evidence.append(
                Evidence(
                    "file",
                    f"build backend {b.build_backend or 'default'} → {c.build_backend}",
                    path="pyproject.toml",
                )
            )
    if evidence:
        yield RawFinding(
            "GRN-C002",
            f"{cand.version} adds code that runs when the sdist is built",
            tuple(evidence[:MAX_EVIDENCE]),
        )


def _moved_from(path: str, baseline: tuple[ModuleIndex, ...]) -> set[str]:
    """Sensitive calls of the baseline module this new path was moved from.

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
        if n > best_len or (n == best_len and best is not None and m.path < best.path):
            best, best_len = m, n
    return {s.name for s in best.top_level_calls} if best is not None else set()


def is_test_path(path: str) -> bool:
    """tests/ folders, test_*.py and conftest.py (docs/rules/GRN-C003.md)."""
    parts = path.split("/")
    name = parts[-1]
    return "tests" in parts[:-1] or name.startswith("test_") or name == "conftest.py"


def _live_test_modules(art: ArtifactFacts) -> set[str]:
    """Test modules that run outside the package's own tests.

    A test module counts as live when a non-test module imports it, directly
    or through other test modules, or an entry point names it (a ``pytest11``
    plugin loads in every pytest run). Importing ``a.b.c`` also runs ``a``
    and ``a.b``.
    """
    tests = {m.module: m for m in art.modules if is_test_path(m.path)}
    frontier = [i for m in art.modules if m.module not in tests for i in m.imports]
    frontier += list(art.entry_points)
    reached: set[str] = set()
    while frontier:
        name = frontier.pop()
        parts = name.split(".")
        for n in range(1, len(parts) + 1):
            prefix = ".".join(parts[:n])
            if prefix in reached:
                continue
            reached.add(prefix)
            if prefix in tests:
                frontier.extend(tests[prefix].imports)
    return reached & set(tests)


def new_import_time_exec(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-C003: new import-time calls to the sensitive APIs in pyindex.

    A module byte-identical to a baseline file is skipped, and one moved from
    a baseline path is compared with that file. Calls in test files that
    nothing else imports are reported at info (docs/rules/GRN-C003.md).
    """
    if base is None:
        return
    b, c = _pair(base, cand)
    if b is None or c is None:
        return
    old = {m.module: {s.name for s in m.top_level_calls} for m in b.modules}
    old_hashes = {f.sha256 for f in b.files}
    new_hash = {f.path: f.sha256 for f in c.files}
    live_tests = _live_test_modules(c)
    found: dict[bool, tuple[list[Evidence], set[str]]] = {False: ([], set()), True: ([], set())}
    for m in c.modules:
        if m.module in old:
            before = old[m.module]
        elif new_hash.get(m.path) in old_hashes:
            continue  # byte-identical to a baseline file: moved, not added
        else:
            before = _moved_from(m.path, b.modules)
        test_only = is_test_path(m.path) and m.module not in live_tests
        evidence, modules = found[test_only]
        for s in m.top_level_calls:
            if s.name in before:
                continue
            via = f" (in {s.via}(), reached at import)" if s.via else ""
            where = "new module " if m.module not in old else ""
            evidence.append(
                Evidence(
                    "file",
                    f"{where}{m.path}:{s.line} calls {s.name}{via}",
                    path=m.path,
                    line=s.line,
                )
            )
            modules.add(m.module)
    for test_only, (evidence, modules) in found.items():
        if not evidence:
            continue
        note: tuple[Evidence, ...]
        more = len(evidence) - MAX_EVIDENCE
        tail = (Evidence("note", f"and {more} more call site(s)"),) if more > 0 else ()
        if test_only:
            title = (
                f"{cand.version} adds import-time calls to sensitive APIs in "
                f"{len(modules)} test module(s) that no other module imports"
            )
            note = (
                Evidence(
                    "note",
                    "test files run only when the package's own tests run, "
                    "so this is reported at info",
                ),
            )
        else:
            title = f"{cand.version} adds import-time calls to sensitive APIs in {len(modules)} module(s)"
            note = ()
        yield RawFinding(
            "GRN-C003",
            title,
            tuple(evidence[:MAX_EVIDENCE]) + tail + note + _tag_note(b, c),
            lowered_to=Severity.INFO if test_only else None,
        )


def unparsed_changed(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    """GRN-E002 for new or changed .py files ast couldn't parse."""
    b, c = (
        _pair(base, cand)
        if base is not None
        else (None, _pick(cand, "wheel") or _pick(cand, "sdist"))
    )
    if c is None:
        return
    old_hashes = {f.path: f.sha256 for f in b.files} if b is not None else {}
    new_hashes = {f.path: f.sha256 for f in c.files}
    bad = [p for p in c.unparsed if old_hashes.get(p) != new_hashes.get(p)]
    if bad:
        yield RawFinding(
            "GRN-E002",
            f"{len(bad)} new or changed Python file(s) in {cand.version} couldn't be parsed",
            tuple(
                Evidence("file", f"{p}: not valid Python 3 syntax", path=p)
                for p in bad[:MAX_EVIDENCE]
            ),
        )
