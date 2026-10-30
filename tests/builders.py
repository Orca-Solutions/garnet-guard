"""Build tiny synthetic artifacts and facts in memory. No real malware here."""

from __future__ import annotations

import io
import tarfile
import zipfile
from dataclasses import replace

from garnet_guard.facts.inventory import inspect_artifact
from garnet_guard.models import (
    ArtifactFacts,
    FactError,
    FileProvenance,
    Limits,
    ReleaseFacts,
    TagInfo,
)


def wheel(files: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in sorted(files.items()):
            zf.writestr(name, body)
    return buf.getvalue()


def sdist(prefix: str, files: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, body in sorted(files.items()):
            data = body.encode() if isinstance(body, str) else body
            info = tarfile.TarInfo(f"{prefix}/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def prov(
    filename: str,
    *,
    present: bool = True,
    verified: bool = True,
    repo: str = "github.com/o/r",
    repo_id: str | None = "1",
    workflow: str = ".github/workflows/release.yml",
    environment: str | None = None,
) -> FileProvenance:
    if not present:
        return FileProvenance(filename, present=False, verified=False)
    return FileProvenance(
        filename,
        present=True,
        verified=verified,
        repository=repo,
        repository_id=repo_id,
        workflow=workflow,
        environment=environment,
        trusted_publishing=True,
        error=None if verified else "bad signature",
    )


def _provenance(filename: str, spec: FileProvenance | None | str) -> FileProvenance | None:
    if spec == "ok":
        return prov(filename)
    if spec == "none":
        return prov(filename, present=False)
    return spec  # type: ignore[return-value]


def artifact(
    version: str,
    files: dict[str, str | bytes] | None,
    *,
    kind: str = "wheel",
    package: str = "demo",
    provenance: FileProvenance | None | str = "ok",
    limits: Limits | None = None,
) -> tuple[ArtifactFacts, tuple[FactError, ...]]:
    """One wheel or sdist of ``package``, inspected when ``files`` is given.

    Returns the facts and the errors the inspection raised (GRN-E003 when a
    limit was hit), the same two things the fetcher gets back.
    """
    if kind == "wheel":
        filename, packagetype = f"{package}-{version}-py3-none-any.whl", "bdist_wheel"
    else:
        filename, packagetype = f"{package}-{version}.tar.gz", "sdist"
    art = ArtifactFacts(
        filename=filename,
        sha256="0" * 64,
        packagetype=packagetype,
        uploaded_at=None,
        provenance=_provenance(filename, provenance),
    )
    if files is None:
        return art, ()
    data = wheel(files) if kind == "wheel" else sdist(f"{package}-{version}", files)
    ins = inspect_artifact(filename, data, limits or Limits(), sdist=kind == "sdist")
    art = replace(
        art,
        inspected=True,
        files=tuple(ins.files),
        modules=tuple(ins.modules),
        pth_files=tuple(ins.pth_files),
        build_backend=ins.build_backend,
        setup_py_calls=ins.setup_py_calls,
        unparsed=tuple(ins.unparsed),
        entry_points=tuple(sorted(ins.entry_points)),
        requirements=ins.requirements,
        requirements_read=ins.requirements_read,
        wheel_tag="py3-none-any" if kind == "wheel" else None,
    )
    return art, tuple(ins.errors)


def release(
    version: str,
    files: dict[str, str | bytes] | None = None,
    *,
    provenance: FileProvenance | None | str = "ok",
    tag: bool | None = True,
    package: str = "demo",
    sdist_files: dict[str, str | bytes] | None = None,
    sdist_only: bool = False,
    limits: Limits | None = None,
) -> ReleaseFacts:
    """A release with a wheel (``files``), and an sdist when ``sdist_files`` is given.

    ``sdist_only`` drops the wheel. ``provenance`` applies to every artifact.
    """
    artifacts: list[ArtifactFacts] = []
    errors: list[FactError] = []
    kinds = [("wheel", files)] if not sdist_only else []
    if sdist_files is not None:
        kinds.append(("sdist", sdist_files))
    for kind, content in kinds:
        art, errs = artifact(
            version, content, kind=kind, package=package, provenance=provenance, limits=limits
        )
        artifacts.append(art)
        errors.extend(errs)
    return ReleaseFacts(
        ecosystem="pypi",
        package=package,
        version=version,
        yanked=False,
        artifacts=tuple(artifacts),
        source_repo="o/r",
        tag=TagInfo(version, "abc") if tag else None,
        tag_checked=tag is not None,
        errors=tuple(errors),
    )
