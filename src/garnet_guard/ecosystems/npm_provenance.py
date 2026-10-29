"""Verify npm provenance: a SLSA statement signed with Sigstore.

The registry serves, per release, a Sigstore bundle whose DSSE envelope holds
an in-toto statement naming the tarball and its SHA-512. The signing
certificate, issued by Fulcio to a CI job, names the repository and workflow
that published it. Comparing publishers between releases is the checks' job.

Bundles logged since 2026 carry a ``dsse`` Rekor entry and go through
``sigstore``'s verifier unchanged. Older ones carry an ``intoto`` entry, which
sigstore-python no longer accepts, so ``_verify_intoto_entry`` repeats the
verifier's steps on them with the same trust root: certificate chain, Rekor's
signed entry timestamp, the DSSE signature and the log entry's payload hash.
It does not check the Merkle inclusion proof or the certificate's SCT.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import threading
from datetime import UTC, datetime
from typing import Any

import rfc8785
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from OpenSSL.crypto import X509, X509Store, X509StoreContext, X509StoreContextError, X509StoreFlags
from sigstore._internal.trust import KeyringPurpose
from sigstore._utils import KeyID
from sigstore.errors import VerificationError
from sigstore.models import Bundle, ClientTrustConfig, InvalidBundle, TrustedRoot
from sigstore.verify import Verifier, policy

from ..models import FileProvenance

SLSA_PREDICATES = frozenset({"https://slsa.dev/provenance/v1", "https://slsa.dev/provenance/v0.2"})
_IN_TOTO = "application/vnd.in-toto+json"
# npm's 2023 bundles carry Statement v0.1 with SLSA v0.2; later ones v1 with SLSA v1.
_STATEMENT_TYPES = frozenset(
    {"https://in-toto.io/Statement/v1", "https://in-toto.io/Statement/v0.1"}
)
_ISSUERS = {
    "https://token.actions.githubusercontent.com": "github.com",
    "https://gitlab.com": "gitlab.com",
}
# Fulcio certificate extensions (Sigstore OID 1.3.6.1.4.1.57264.1.*).
_OID_SOURCE_REPO_URI = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.12")
_OID_SOURCE_REPO_ID = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.15")
_OID_BUILD_CONFIG_URI = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.18")

logging.getLogger("sigstore").setLevel(logging.ERROR)

_lock = threading.Lock()
_root: TrustedRoot | None = None


class ProvenanceError(Exception):
    """The attestation is present but doesn't verify (GRN-T007)."""


def _trusted_root() -> TrustedRoot:
    """Sigstore's trust root, refreshed once per process; the bundled copy offline."""
    global _root
    with _lock:
        if _root is None:
            try:
                _root = ClientTrustConfig.production(offline=False).trusted_root
            except Exception:  # TUF refresh unreachable; use the bundled trust root
                _root = ClientTrustConfig.production(offline=True).trusted_root
        return _root


def _der_utf8(raw: bytes) -> str | None:
    """Decode a DER UTF8String (tag 0x0c, short or long length)."""
    if len(raw) < 2 or raw[0] != 0x0C:
        return None
    length, start = raw[1], 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or len(raw) < 2 + n:
            return None
        length, start = int.from_bytes(raw[2 : 2 + n], "big"), 2 + n
    return raw[start : start + length].decode("utf-8", "replace")


def _extension(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> str | None:
    try:
        ext = cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None
    return _der_utf8(ext.value) if isinstance(ext, x509.UnrecognizedExtension) else None


def _san_uri(cert: x509.Certificate) -> str | None:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    return uris[0] if uris else None


def _leaf_certificate(raw: dict[str, Any]) -> x509.Certificate:
    """The signing certificate of a bundle, read from its JSON form.

    Bundles before v0.3 carry it as the first entry of ``x509CertificateChain``,
    later ones as ``certificate``.
    """
    material = raw.get("verificationMaterial") or {}
    chain = (material.get("x509CertificateChain") or {}).get("certificates") or []
    first = chain[0] if chain and isinstance(chain[0], dict) else material.get("certificate")
    der_b64 = first.get("rawBytes") if isinstance(first, dict) else None
    if not isinstance(der_b64, str):
        raise ProvenanceError("bundle has no signing certificate")
    try:
        return x509.load_der_x509_certificate(base64.b64decode(der_b64))
    except (ValueError, TypeError) as err:
        raise ProvenanceError("malformed signing certificate") from err


def _verify_intoto_entry(cert: x509.Certificate, raw: dict[str, Any], root: TrustedRoot) -> None:
    """Verify a bundle whose Rekor entry is ``intoto/0.0.2`` (see module docstring).

    Works from the bundle's JSON, because ``sigstore`` refuses to load the
    2023 bundles that have an inclusion promise but no inclusion proof.
    """
    entries = raw.get("verificationMaterial", {}).get("tlogEntries") or []
    if len(entries) != 1:
        raise ProvenanceError(f"expected one log entry, found {len(entries)}")
    entry = entries[0]
    envelope = raw.get("dsseEnvelope") or {}
    sigs = envelope.get("signatures") or []
    if len(sigs) != 1:
        raise ProvenanceError(f"expected one signature, found {len(sigs)}")
    try:
        integrated = datetime.fromtimestamp(int(entry["integratedTime"]), tz=UTC)
        set_sig = base64.b64decode(entry["inclusionPromise"]["signedEntryTimestamp"])
        key_id = base64.b64decode(entry["logId"]["keyId"])
        body_b64 = entry["canonicalizedBody"]
        body = json.loads(base64.b64decode(body_b64))
        payload = base64.b64decode(envelope["payload"])
        payload_type = envelope["payloadType"]
        signature = base64.b64decode(sigs[0]["sig"])
    except (KeyError, TypeError, ValueError) as err:
        raise ProvenanceError(f"malformed log entry: {type(err).__name__}") from err

    # Rekor's signed entry timestamp binds the entry body and the time it was logged.
    canonical = rfc8785.dumps(
        {
            "body": body_b64,
            "integratedTime": int(entry["integratedTime"]),
            "logID": key_id.hex(),
            "logIndex": int(entry["logIndex"]),
        }
    )
    try:
        root.rekor_keyring(KeyringPurpose.VERIFY).verify(
            key_id=KeyID(key_id), signature=set_sig, data=canonical
        )
    except VerificationError as err:
        raise ProvenanceError(f"log entry timestamp: {err}") from err

    # The certificate chains to a Fulcio root and was valid when the entry was
    # logged. OpenSSL does the path validation, as in sigstore's own verifier;
    # cryptography's verifier only accepts TLS certificates.
    store = X509Store()
    store.set_flags(X509StoreFlags.X509_STRICT)
    for ca in root.get_fulcio_certs():
        store.add_cert(X509.from_cryptography(ca))
    store.set_time(integrated)
    try:
        X509StoreContext(store, X509.from_cryptography(cert)).verify_certificate()
    except X509StoreContextError as err:
        raise ProvenanceError(f"certificate chain: {err}"[:300]) from err
    if not (cert.not_valid_before_utc <= integrated <= cert.not_valid_after_utc):
        raise ProvenanceError("certificate was not valid when the entry was logged")

    # The log entry is about this envelope: same payload hash, signature and certificate.
    content = body.get("spec", {}).get("content", {}) if isinstance(body, dict) else {}
    logged_hash = content.get("payloadHash", {})
    if logged_hash.get("algorithm") != "sha256" or logged_hash.get("value") != (
        hashlib.sha256(payload).hexdigest()
    ):
        raise ProvenanceError("log entry payload hash does not match the envelope")
    logged = (content.get("envelope", {}).get("signatures") or [{}])[0]
    try:
        logged_sig = base64.b64decode(base64.b64decode(logged.get("sig", "")))
        logged_cert = base64.b64decode(logged.get("publicKey", ""))
    except ValueError as err:
        raise ProvenanceError("malformed log entry signature") from err
    if (
        logged_sig != signature
        or logged_cert.strip() != cert.public_bytes(serialization.Encoding.PEM).strip()
    ):
        raise ProvenanceError("log entry signature or certificate does not match the envelope")

    # The envelope is signed by the certificate's key.
    pae = f"DSSEv1 {len(payload_type)} {payload_type} {len(payload)} ".encode() + payload
    key = cert.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ProvenanceError("unsupported signing key type")
    try:
        key.verify(signature, pae, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as err:
        raise ProvenanceError("DSSE signature is invalid") from err


def _verify_bundle(raw: dict[str, Any]) -> tuple[x509.Certificate, bytes]:
    """Verify one Sigstore bundle; return its certificate and the signed statement."""
    issuers = policy.AnyOf([policy.OIDCIssuer(i) for i in _ISSUERS])
    root = _trusted_root()
    try:
        kind = raw["verificationMaterial"]["tlogEntries"][0]["kindVersion"]["kind"]
    except (KeyError, IndexError, TypeError) as err:
        raise ProvenanceError("bundle has no log entry") from err
    try:
        if kind == "intoto":
            cert = _leaf_certificate(raw)
            _verify_intoto_entry(cert, raw, root)
            issuers.verify(cert)
            envelope = raw.get("dsseEnvelope") or {}
            if envelope.get("payloadType") != _IN_TOTO:
                raise ProvenanceError("envelope payload is not an in-toto statement")
            payload = base64.b64decode(envelope["payload"])
        else:
            try:
                bundle = Bundle.from_json(json.dumps(raw))
            except InvalidBundle as err:
                raise ProvenanceError(f"malformed bundle: {err}"[:300]) from err
            payload_type, payload = Verifier(trusted_root=root).verify_dsse(bundle, issuers)
            if payload_type != _IN_TOTO:
                raise ProvenanceError("envelope payload is not an in-toto statement")
            cert = bundle.signing_certificate
    except VerificationError as err:
        raise ProvenanceError(str(err)[:300]) from err
    return cert, payload


def _statement_matches(payload: bytes, package: str, version: str, sha512: str) -> str:
    """Check the statement's subject is this tarball; return its predicate type."""
    try:
        stmt = json.loads(payload)
    except ValueError as err:
        raise ProvenanceError("statement is not JSON") from err
    if not isinstance(stmt, dict) or stmt.get("_type") not in _STATEMENT_TYPES:
        raise ProvenanceError("statement is not an in-toto statement")
    predicate = stmt.get("predicateType")
    if predicate not in SLSA_PREDICATES:
        raise ProvenanceError(f"statement predicate is not SLSA provenance: {predicate}"[:300])
    subjects = stmt.get("subject") or []
    # purl encodes the scope as %40scope (nx: pkg:npm/nx@1, tinycolor: pkg:npm/%40ctrl/tinycolor@1)
    wanted = {f"pkg:npm/{package}@{version}", f"pkg:npm/{package.replace('@', '%40', 1)}@{version}"}
    for s in subjects:
        if isinstance(s, dict) and s.get("name") in wanted:
            digest = s.get("digest", {}).get("sha512", "")
            if isinstance(digest, str) and digest.lower() == sha512.lower():
                return str(predicate)
            raise ProvenanceError("statement names this release with a different SHA-512")
    raise ProvenanceError(f"statement does not name pkg:npm/{package}@{version}"[:300])


def sri_sha512(integrity: str) -> str | None:
    """The hex SHA-512 of a ``sha512-<base64>`` Subresource Integrity string."""
    algo, _, b64 = integrity.partition("-")
    if algo != "sha512":
        return None
    try:
        digest = base64.b64decode(b64, validate=True)
    except ValueError:
        return None
    return digest.hex() if len(digest) == 64 else None


def _publisher(cert: x509.Certificate) -> tuple[str | None, str | None, str | None, str | None]:
    """(identity, repository, repository id, workflow path) from a Fulcio certificate."""
    identity = _san_uri(cert)
    repo_uri = _extension(cert, _OID_SOURCE_REPO_URI)
    repo_id = _extension(cert, _OID_SOURCE_REPO_ID)
    build = _extension(cert, _OID_BUILD_CONFIG_URI)
    repository = None
    if repo_uri:
        for prefix in ("https://", "http://"):
            if repo_uri.startswith(prefix):
                repository = repo_uri[len(prefix) :].rstrip("/")
    workflow = None
    if build and repo_uri and build.startswith(repo_uri.rstrip("/") + "/"):
        workflow = build[len(repo_uri.rstrip("/")) + 1 :].split("@", 1)[0]
    return identity, repository, repo_id, workflow


def verify_provenance(
    package: str,
    version: str,
    filename: str,
    integrity: str,
    body: bytes,
    *,
    trusted_publishing: bool | None,
) -> FileProvenance:
    """Verify the registry's attestations document for one release.

    ``integrity`` is the registry's SRI string for the tarball; the statement
    must name the same SHA-512. A failed verification returns
    ``verified=False`` with the error (GRN-T007). A verifier that couldn't run
    sets ``verification_ran=False``, which the checks report as couldn't-check.
    """
    try:
        doc = json.loads(body)
        attestations = doc.get("attestations", []) if isinstance(doc, dict) else []
    except ValueError:
        return FileProvenance(
            filename, present=True, verified=False, error="malformed attestations"
        )
    slsa = [
        a.get("bundle")
        for a in attestations
        if isinstance(a, dict) and a.get("predicateType") in SLSA_PREDICATES
    ]
    if not slsa or not isinstance(slsa[0], dict):
        return FileProvenance(filename, present=False, verified=False)
    sha512 = sri_sha512(integrity)
    if sha512 is None:
        return FileProvenance(
            filename,
            present=True,
            verified=False,
            error="registry integrity is not SHA-512, so the statement can't be matched",
        )
    try:
        cert, payload = _verify_bundle(slsa[0])
        _statement_matches(payload, package, version, sha512)
    except ProvenanceError as err:
        return FileProvenance(
            filename,
            present=True,
            verified=False,
            trusted_publishing=trusted_publishing,
            error=str(err)[:300],
        )
    except Exception as err:  # verifier unavailable: couldn't check is not pass
        return FileProvenance(
            filename,
            present=True,
            verified=False,
            trusted_publishing=trusted_publishing,
            error=f"could not run verification: {type(err).__name__}",
            verification_ran=False,
        )
    identity, repository, repo_id, workflow = _publisher(cert)
    return FileProvenance(
        filename,
        present=True,
        verified=True,
        identity=identity,
        repository=repository,
        repository_id=repo_id,
        workflow=workflow,
        environment=None,
        trusted_publishing=trusted_publishing,
    )
