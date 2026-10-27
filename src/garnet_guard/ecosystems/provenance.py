"""Verify PEP 740 provenance with Sigstore via ``pypi-attestations``.

Each attestation is verified against the Trusted Publisher named in its own
bundle, and the result records who that publisher was. Comparing publishers
between releases is the checks' job.
"""

from __future__ import annotations

import base64
import logging
import threading

from cryptography import x509
from pydantic import ValidationError
from pypi_attestations import (
    Attestation,
    AttestationError,
    Distribution,
    GitHubPublisher,
    GitLabPublisher,
    Provenance,
    Publisher,
)

from ..models import FileProvenance

# Fulcio certificate extension: Source Repository Identifier (a stable repo id,
# unchanged by renames).
_OID_SOURCE_REPO_ID = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.15")

# sigstore logs a warning for every offline TUF load; that is not news to users.
logging.getLogger("sigstore").setLevel(logging.ERROR)

_lock = threading.Lock()
_online_ok: bool | None = None


def _cert_facts(cert_data: bytes | str) -> tuple[str | None, str | None]:
    """Return (signer identity URI, source repository id) from a Fulcio cert."""
    try:
        der = base64.b64decode(cert_data) if isinstance(cert_data, str) else cert_data
        cert = x509.load_der_x509_certificate(der)
    except (ValueError, TypeError):
        return None, None
    identity = None
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        identity = uris[0] if uris else None
    except x509.ExtensionNotFound:
        pass
    repo_id = None
    try:
        ext = cert.extensions.get_extension_for_oid(_OID_SOURCE_REPO_ID).value
        raw = ext.value if isinstance(ext, x509.UnrecognizedExtension) else b""
        # DER UTF8String: tag 0x0c, short length, value
        if len(raw) >= 2 and raw[0] == 0x0C and raw[1] < 0x80:
            repo_id = raw[2 : 2 + raw[1]].decode("utf-8", "replace")
    except x509.ExtensionNotFound:
        pass
    return identity, repo_id


def _verify(att: Attestation, publisher: Publisher, dist: Distribution) -> None:
    """Verify online once per process; fall back to the bundled trust root."""
    global _online_ok
    verify = att.verify
    with _lock:
        mode = _online_ok
    if mode is not False:
        try:
            verify(publisher, dist, offline=False)
            with _lock:
                _online_ok = True
            return
        except AttestationError:
            raise
        except Exception:  # TUF refresh unreachable; use the bundled trust root
            with _lock:
                _online_ok = False
    verify(publisher, dist, offline=True)


def verify_provenance(filename: str, sha256: str, body: bytes) -> FileProvenance:
    try:
        prov = Provenance.model_validate_json(body)
    except ValidationError as err:
        return FileProvenance(
            filename, present=True, verified=False, error=f"malformed provenance: {err.title}"
        )
    if not prov.attestation_bundles:
        return FileProvenance(filename, present=False, verified=False)

    dist = Distribution(name=filename, digest=sha256)
    bundle = prov.attestation_bundles[0]
    pub = bundle.publisher
    repository = workflow = environment = None
    if isinstance(pub, GitHubPublisher):
        repository = f"github.com/{pub.repository}"
        workflow = f".github/workflows/{pub.workflow}"
        environment = pub.environment or None
    elif isinstance(pub, GitLabPublisher):
        repository = f"gitlab.com/{pub.repository}"
        workflow = pub.workflow_filepath
        environment = pub.environment or None
    else:
        repository = f"{pub.kind}:unknown"

    identity = repo_id = None
    try:
        for b in prov.attestation_bundles:
            for att in b.attestations:
                _verify(att, b.publisher, dist)
                if identity is None:
                    identity, repo_id = _cert_facts(att.verification_material.certificate)
    except AttestationError as err:
        return FileProvenance(
            filename,
            present=True,
            verified=False,
            repository=repository,
            workflow=workflow,
            environment=environment,
            trusted_publishing=True,
            error=str(err)[:300],
        )
    except Exception as err:  # verifier unavailable: couldn't check is not pass
        return FileProvenance(
            filename,
            present=True,
            verified=False,
            repository=repository,
            workflow=workflow,
            environment=environment,
            trusted_publishing=True,
            error=f"could not run verification: {type(err).__name__}",
            verification_ran=False,
        )
    return FileProvenance(
        filename,
        present=True,
        verified=True,
        identity=identity,
        repository=repository,
        repository_id=repo_id,
        workflow=workflow,
        environment=environment,
        trusted_publishing=True,
    )
