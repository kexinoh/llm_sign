"""TLS-style certificate validation for response-embedded provider certs.

This module reuses the standard TLS / X.509 server-certificate
validation path (via ``cryptography.x509.verification``) to authenticate
the provider certificate that a signed OpenAI-compatible response
embeds at ``llm_sign.certificate_chain``.

This is deliberately *not* a new PKI. It is the exact same procedure
that an HTTPS client performs against a server certificate during a TLS
handshake: validate the chain against a set of TLS trust anchors,
enforce name matching against the expected host, and reject expired or
otherwise non-conforming certificates. The only difference is that the
certificate being validated arrives inside the response body rather
than during the TLS handshake of the (possibly relayed) transport
connection.

Callers can supply their own ``trust_anchors``; by default the system
OpenSSL trust store is used, with a ``certifi`` fallback when the
system store is empty (this matches how typical HTTPS clients in
Python behave).
"""

from __future__ import annotations

import datetime as _dt
import ssl
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import verification

from llm_sign.keys.tls import load_pem_certificates


class CertificateTrustError(Exception):
    """The provider certificate chain failed TLS / X.509 validation."""


def load_system_trust_anchors() -> List[x509.Certificate]:
    """Load PEM certificates from the default TLS trust paths.

    Checks the paths advertised by ``ssl.get_default_verify_paths``, and
    falls back to ``certifi.where()`` when neither cafile nor capath
    yielded a usable anchor. This mirrors the resolution order most
    Python HTTPS clients end up with in practice.
    """
    certificates: List[x509.Certificate] = []
    seen: set[bytes] = set()
    paths = ssl.get_default_verify_paths()
    if paths.cafile:
        _extend_unique(certificates, seen, Path(paths.cafile))
    if paths.capath:
        capath = Path(paths.capath)
        if capath.is_dir():
            for entry in capath.glob("*"):
                _extend_unique(certificates, seen, entry)
    if not certificates:
        try:
            import certifi  # type: ignore
        except ImportError:  # pragma: no cover - certifi is a soft dep
            certifi = None  # type: ignore
        if certifi is not None:
            _extend_unique(certificates, seen, Path(certifi.where()))
    if not certificates:
        raise CertificateTrustError(
            "no system TLS trust anchors were found; install certifi or "
            "configure ssl default verify paths"
        )
    return certificates


def verify_certificate_chain(
    certificate_chain: Sequence[x509.Certificate],
    *,
    expected_host: str,
    trust_anchors: Optional[Sequence[x509.Certificate]] = None,
    validation_time: Optional[_dt.datetime] = None,
) -> x509.Certificate:
    """Validate ``certificate_chain`` as a TLS server certificate chain.

    - ``expected_host`` is matched against the leaf certificate's
      subjectAltName DNS entries (with wildcard handling) exactly as an
      HTTPS client would.
    - ``trust_anchors`` defaults to the system TLS store.
    - ``validation_time`` defaults to the current UTC time. It is
      intentionally the wall clock, not a time asserted by the signer.

    Returns the validated leaf certificate.

    Raises :class:`CertificateTrustError` on any trust, path, time,
    name-matching or conformance failure.
    """

    if not certificate_chain:
        raise CertificateTrustError("empty certificate chain")

    leaf = certificate_chain[0]
    intermediates = list(certificate_chain[1:])
    anchors = list(trust_anchors) if trust_anchors is not None else load_system_trust_anchors()
    store = verification.Store(anchors)

    builder = verification.PolicyBuilder().store(store)
    if validation_time is not None:
        builder = builder.time(validation_time)
    try:
        verifier = builder.build_server_verifier(x509.DNSName(expected_host))
    except Exception as exc:  # pragma: no cover - DNSName validation
        raise CertificateTrustError(f"invalid expected host: {exc}") from exc

    try:
        verifier.verify(leaf, intermediates)
    except verification.VerificationError as exc:
        raise CertificateTrustError(str(exc) or "certificate chain is not trusted") from exc
    return leaf


def public_key_from_verified_chain(
    certificate_chain: Sequence[x509.Certificate],
    *,
    expected_host: str,
    trust_anchors: Optional[Sequence[x509.Certificate]] = None,
    validation_time: Optional[_dt.datetime] = None,
):
    """Return the leaf public key after full TLS chain validation."""

    leaf = verify_certificate_chain(
        certificate_chain,
        expected_host=expected_host,
        trust_anchors=trust_anchors,
        validation_time=validation_time,
    )
    return leaf.public_key()


def load_pem_trust_anchors(paths: Iterable[str | Path]) -> List[x509.Certificate]:
    """Load trust anchors from one or more PEM files or directories."""
    certificates: List[x509.Certificate] = []
    seen: set[bytes] = set()
    for path in paths:
        _extend_unique(certificates, seen, Path(path))
    return certificates


def _extend_unique(
    certificates: List[x509.Certificate],
    seen: set[bytes],
    path: Path,
) -> None:
    if not path.exists():
        return
    if path.is_dir():
        for entry in path.glob("*"):
            _extend_unique(certificates, seen, entry)
        return
    try:
        loaded = load_pem_certificates(path.read_bytes())
    except (OSError, ValueError):
        return
    for certificate in loaded:
        fingerprint = certificate.fingerprint(hashes.SHA256())
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        certificates.append(certificate)


__all__ = [
    "CertificateTrustError",
    "load_pem_trust_anchors",
    "load_system_trust_anchors",
    "public_key_from_verified_chain",
    "verify_certificate_chain",
]
