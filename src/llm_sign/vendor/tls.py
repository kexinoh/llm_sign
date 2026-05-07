"""Provider-side TLS certificate credential loading.

This is the path vLLM-style integrations need: the provider already receives
``--ssl-certfile`` and ``--ssl-keyfile``. The certificate key type determines
the signing suite; it is not assumed to be Ed25519.

The certificate is used purely as a container for the provider's public key
and host identity. ``llm_sign`` does not run any PKI / CA trust chain
validation; clients establish trust by pinning the provider's public key
out of band (see :class:`llm_sign.keys.ed25519.StaticKeyPolicy`).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Sequence, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, NameOID

from llm_sign.core.crypto import infer_suite_for_private_key
from llm_sign.core.errors import VerificationError
from llm_sign.core.blocks import TranscriptSigner
from llm_sign.keys.tls import certificate_key_id, load_pem_certificates


@dataclass(frozen=True)
class TLSCertificateCredential:
    issuer: str
    key_id: str
    suite_id: str
    private_key: Any
    certificate_chain: Sequence[x509.Certificate]

    @classmethod
    def from_files(
        cls,
        *,
        ssl_certfile: Union[str, Path],
        ssl_keyfile: Union[str, Path],
        issuer: Optional[str] = None,
        password: Optional[bytes] = None,
    ) -> "TLSCertificateCredential":
        certificates = load_pem_certificates(Path(ssl_certfile).read_bytes())
        if not certificates:
            raise ValueError("ssl_certfile does not contain certificates")
        private_key = serialization.load_pem_private_key(
            Path(ssl_keyfile).read_bytes(),
            password=password,
        )
        leaf = certificates[0]
        _assert_key_matches_certificate(private_key, leaf)
        return cls(
            issuer=issuer or _tls_server_name(leaf),
            key_id=certificate_key_id(leaf),
            suite_id=infer_suite_for_private_key(private_key),
            private_key=private_key,
            certificate_chain=certificates,
        )

    def signer(self) -> TranscriptSigner:
        return TranscriptSigner(
            issuer=self.issuer,
            key_id=self.key_id,
            private_key=self.private_key,
            suite_id=self.suite_id,
        )

    def certificate_chain_pem(self) -> list[str]:
        return [
            cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
            for cert in self.certificate_chain
        ]


def _assert_key_matches_certificate(private_key: Any, cert: x509.Certificate) -> None:
    private_spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert_spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if private_spki != cert_spki:
        raise VerificationError("ssl_keyfile private key does not match ssl_certfile")


def _tls_server_name(cert: x509.Certificate) -> str:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        names = san.get_values_for_type(x509.DNSName)
        if names:
            return names[0]
    except x509.ExtensionNotFound:
        pass
    attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attributes:
        return attributes[0].value
    raise VerificationError("TLS certificate has no DNS subject identity")
