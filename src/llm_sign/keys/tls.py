"""Minimal TLS/SSL certificate helpers used for transcript signing.

This module deliberately does **not** implement any PKI trust model: no
trust anchors, no certification path validation, no revocation checks,
no EKU or issuer-extension enforcement. It only exposes the small pieces
of certificate handling that are needed to reuse the private key and
public key material that a provider already has on disk for TLS (for
example the files passed to ``vllm serve --ssl-certfile / --ssl-keyfile``):

* parse PEM-encoded certificate blobs into ``cryptography`` objects, and
* derive a stable ``key_id`` from a certificate's SubjectPublicKeyInfo.

Trust between a signer and a verifier is established out of band, by
pinning the signer's public key (see
:class:`llm_sign.keys.ed25519.StaticKeyPolicy`). A certificate here is
treated purely as a container for a public key, not as a CA-issued
credential.
"""

from __future__ import annotations

import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from llm_sign.core.base64 import b64url_encode


def load_pem_certificates(data: bytes | str) -> list[x509.Certificate]:
    """Parse one or more PEM-encoded X.509 certificates.

    Accepts either ``bytes`` or ``str``. ``str`` inputs are encoded as
    ASCII before parsing, which matches how PEM is defined. The returned
    certificates are only used as public-key containers; no path
    validation is performed here or anywhere else in the library.
    """
    if isinstance(data, str):
        data = data.encode("ascii")
    marker = b"-----END CERTIFICATE-----"
    certificates: list[x509.Certificate] = []
    for part in data.split(marker):
        if b"-----BEGIN CERTIFICATE-----" not in part:
            continue
        pem = part + marker + b"\n"
        certificates.append(x509.load_pem_x509_certificate(pem))
    return certificates


def certificate_key_id(cert: x509.Certificate) -> str:
    """Return the ``spki-sha256:...`` key id for a certificate.

    The value is derived purely from the certificate's SubjectPublicKeyInfo
    DER encoding; it does not depend on the issuer, signature, validity
    window, or any extension. The same helper is used to derive the
    ``key_id`` of a standalone public key (see
    :func:`llm_sign.keys.ed25519.spki_sha256_key_id`).
    """
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "spki-sha256:" + b64url_encode(hashlib.sha256(spki).digest())


__all__ = [
    "certificate_key_id",
    "load_pem_certificates",
]
