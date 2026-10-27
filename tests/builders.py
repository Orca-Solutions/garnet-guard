"""Build tiny synthetic artifacts and facts in memory. No real malware here."""

from __future__ import annotations

import io
import tarfile
import zipfile

from garnet_guard.facts.inventory import inspect_artifact
from garnet_guard.models import ArtifactFacts, FileProvenance, Limits, ReleaseFacts, TagInfo


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


def release(
    version: str,
    files: dict[str, str | bytes] | None = None,
    *,
    provenance: FileProvenance | None | str = "ok",
    tag: bool | None = True,
    package: str = "demo",
) -> ReleaseFacts:
    filename = f"{package}-{version}-py3-none-any.whl"
    p: FileProvenance | None
    if provenance == "ok":
        p = prov(filename)
    elif provenance == "none":
        p = prov(filename, present=False)
    else:
        p = provenance  # type: ignore[assignment]
    art = ArtifactFacts(
        filename=filename,
        sha256="0" * 64,
        packagetype="bdist_wheel",
        uploaded_at=None,
        provenance=p,
    )
    if files is not None:
        ins = inspect_artifact(filename, wheel(files), Limits(), sdist=False)
        art = ArtifactFacts(
            filename=filename,
            sha256="0" * 64,
            packagetype="bdist_wheel",
            uploaded_at=None,
            provenance=p,
            inspected=True,
            files=tuple(ins.files),
            modules=tuple(ins.modules),
            pth_files=tuple(ins.pth_files),
            unparsed=tuple(ins.unparsed),
            entry_points=tuple(sorted(ins.entry_points)),
            wheel_tag="py3-none-any",
        )
    return ReleaseFacts(
        ecosystem="pypi",
        package=package,
        version=version,
        yanked=False,
        artifacts=(art,),
        source_repo="o/r",
        tag=TagInfo(version, "abc") if tag else None,
        tag_checked=tag is not None,
    )
