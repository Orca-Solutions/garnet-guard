"""Content rules: what changed inside the release. Pure functions of facts."""

from __future__ import annotations

from collections.abc import Iterator

from ..models import ArtifactFacts, Change, Evidence, RawFinding, ReleaseFacts

MAX_EVIDENCE = 25

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


def new_import_time_exec(
    change: Change, base: ReleaseFacts | None, cand: ReleaseFacts
) -> Iterator[RawFinding]:
    if base is None:
        return
    b, c = _pair(base, cand)
    if b is None or c is None:
        return
    old = {m.module: {s.name for s in m.top_level_calls} for m in b.modules}
    evidence: list[Evidence] = []
    modules: set[str] = set()
    for m in c.modules:
        before = old.get(m.module, set())
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
    if evidence:
        more = len(evidence) - MAX_EVIDENCE
        tail = (Evidence("note", f"and {more} more call site(s)"),) if more > 0 else ()
        yield RawFinding(
            "GRN-C003",
            f"{cand.version} adds import-time calls to sensitive APIs in {len(modules)} module(s)",
            tuple(evidence[:MAX_EVIDENCE]) + tail + _tag_note(b, c),
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
