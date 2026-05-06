"""X.509 CA-mode key policy for transcript signing."""

from __future__ import annotations

import datetime as _dt
import hashlib
from typing import Any, Iterable, List, Optional, Sequence, Set

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

from llm_sign.core.base64 import b64url_encode
from llm_sign.core.blocks import Block, KeyPolicy
from llm_sign.core.crypto import public_key_compatible_with_suite
from llm_sign.core.errors import VerificationError


LLM_SIGN_ISSUER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.55555.1.1")
LLM_SIGN_TRANSCRIPT_EKU_OID = x509.ObjectIdentifier("1.3.6.1.4.1.55555.1.2")


def certificate_key_id(cert: x509.Certificate) -> str:
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "spki-sha256:" + b64url_encode(hashlib.sha256(spki).digest())


def load_pem_certificates(data: bytes | str) -> list[x509.Certificate]:
    """Parse one or more PEM-encoded X.509 certificates.

    Accepts either ``bytes`` or ``str``. ``str`` inputs are encoded as ASCII
    before parsing, which matches how PEM is defined.
    """
    if isinstance(data, str):
        data = data.encode("ascii")
    marker = b"-----END CERTIFICATE-----"
    certificates = []
    for part in data.split(marker):
        if b"-----BEGIN CERTIFICATE-----" not in part:
            continue
        pem = part + marker + b"\n"
        certificates.append(x509.load_pem_x509_certificate(pem))
    return certificates


def der_utf8_string(value: str) -> bytes:
    data = value.encode("utf-8")
    if len(data) < 128:
        length = bytes([len(data)])
    else:
        raw_len = len(data).to_bytes((len(data).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw_len)]) + raw_len
    return b"\x0c" + length + data


def parse_der_utf8_string(data: bytes) -> str:
    if not data or data[0] != 0x0C:
        raise VerificationError("issuer extension is not a DER UTF8String")
    if len(data) < 2:
        raise VerificationError("issuer extension has truncated length")
    first_len = data[1]
    offset = 2
    if first_len & 0x80:
        count = first_len & 0x7F
        if count == 0 or len(data) < 2 + count:
            raise VerificationError("issuer extension has invalid length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    else:
        length = first_len
    value = data[offset : offset + length]
    if offset + length != len(data):
        raise VerificationError("issuer extension has trailing bytes")
    return value.decode("utf-8")


class X509KeyPolicy(KeyPolicy):
    """Resolve issuer keys through X.509 certificate paths."""

    def __init__(
        self,
        *,
        trust_anchors: Sequence[x509.Certificate],
        certificate_chains: Sequence[Sequence[x509.Certificate]],
        validation_time: Optional[_dt.datetime] = None,
        revocation_mode: str = "soft_fail",
        revoked_serials: Optional[Iterable[int]] = None,
        issuer_binding: str = "llm-sign-extension",
        allow_tls_server_auth: bool = False,
        expected_issuer: Optional[str] = None,
    ) -> None:
        if revocation_mode not in {"soft_fail", "hard_fail"}:
            raise ValueError("revocation_mode must be soft_fail or hard_fail")
        self.trust_anchors = list(trust_anchors)
        self.certificate_chains = [list(chain) for chain in certificate_chains]
        self.validation_time = validation_time or _dt.datetime.now(_dt.timezone.utc)
        if self.validation_time.tzinfo is None:
            self.validation_time = self.validation_time.replace(tzinfo=_dt.timezone.utc)
        self.revocation_mode = revocation_mode
        self.revoked_serials: Set[int] = set(revoked_serials or [])
        self.issuer_binding = issuer_binding
        self.allow_tls_server_auth = allow_tls_server_auth
        self.expected_issuer = expected_issuer

    def resolve(self, block: Block) -> Any:
        matches: List[Any] = []
        for chain in self.certificate_chains:
            try:
                key = self._resolve_from_chain(block, chain)
                matches.append(key)
            except (
                VerificationError,
                x509.ExtensionNotFound,
                TypeError,
                ValueError,
                UnicodeDecodeError,
            ):
                continue

        if len(matches) != 1:
            raise VerificationError("unresolved, ambiguous, expired, or untrusted key")
        return matches[0]

    def _resolve_from_chain(
        self,
        block: Block,
        chain: Sequence[x509.Certificate],
    ) -> Any:
        if not chain:
            raise VerificationError("missing certificate path")
        if self.expected_issuer is not None and block.issuer != self.expected_issuer:
            raise VerificationError("issuer mismatch")
        leaf = chain[0]
        if certificate_key_id(leaf) != block.key_id:
            raise VerificationError("key_id mismatch")
        if _issuer_name(leaf, self.issuer_binding) != block.issuer:
            raise VerificationError("issuer extension mismatch")

        self._validate_leaf(leaf, block)
        self._validate_path(chain)
        public_key = leaf.public_key()
        if not public_key_compatible_with_suite(public_key, block.suite_id):
            raise VerificationError("SPKI algorithm incompatible with suite_id")
        return public_key

    def _validate_leaf(self, cert: x509.Certificate, block: Block) -> None:
        _check_time(cert, self.validation_time)
        _check_revocation(cert, self.revocation_mode, self.revoked_serials)

        basic = _leaf_basic_constraints(cert, self.allow_tls_server_auth)
        if basic is not None and basic.ca:
            raise VerificationError("issuer certificate has CA == true")

        usage = _leaf_key_usage(cert, self.allow_tls_server_auth)
        if usage is not None and not usage.digital_signature:
            raise VerificationError("missing digitalSignature key usage")

        eku = _leaf_extended_key_usage(cert, self.allow_tls_server_auth)
        if eku is None:
            return
        has_transcript_eku = LLM_SIGN_TRANSCRIPT_EKU_OID in eku
        has_server_auth = ExtendedKeyUsageOID.SERVER_AUTH in eku
        if not has_transcript_eku and not (self.allow_tls_server_auth and has_server_auth):
            raise VerificationError("missing transcript-signing EKU")

    def _validate_path(self, chain: Sequence[x509.Certificate]) -> None:
        if not self._is_trusted_anchor(chain[-1]):
            raise VerificationError("certificate path does not reach a trust anchor")

        ca_basics: dict[int, x509.BasicConstraints] = {}
        for index, cert in enumerate(chain):
            _check_time(cert, self.validation_time)
            _check_revocation(cert, self.revocation_mode, self.revoked_serials)

            if index == 0:
                continue

            ca_basics[index] = _validate_ca_certificate(cert)

        _check_path_length_constraints(ca_basics)

        for cert, issuer in zip(chain, chain[1:]):
            if cert.issuer != issuer.subject:
                raise VerificationError("certificate issuer mismatch")
            _verify_certificate_signature(cert, issuer)

    def _is_trusted_anchor(self, cert: x509.Certificate) -> bool:
        cert_fp = cert.fingerprint(hashes.SHA256())
        return any(anchor.fingerprint(hashes.SHA256()) == cert_fp for anchor in self.trust_anchors)


def _issuer_name(cert: x509.Certificate, issuer_binding: str) -> str:
    try:
        extension = cert.extensions.get_extension_for_oid(LLM_SIGN_ISSUER_OID)
        if not extension.critical:
            raise VerificationError("issuer extension is not critical")
        value = extension.value
        if not isinstance(value, x509.UnrecognizedExtension):
            raise VerificationError("issuer extension has unsupported representation")
        return parse_der_utf8_string(value.value)
    except x509.ExtensionNotFound:
        if issuer_binding != "tls-server-name":
            raise VerificationError("missing issuer extension")
        return _tls_server_name(cert)


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
    raise VerificationError("certificate has no DNS subject identity")


def _leaf_basic_constraints(
    cert: x509.Certificate,
    allow_tls_server_auth: bool,
) -> Optional[x509.BasicConstraints]:
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    except x509.ExtensionNotFound:
        if allow_tls_server_auth:
            return None
        raise VerificationError("missing basic constraints")


def _leaf_key_usage(
    cert: x509.Certificate,
    allow_tls_server_auth: bool,
) -> Optional[x509.KeyUsage]:
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    except x509.ExtensionNotFound:
        if allow_tls_server_auth:
            return None
        raise VerificationError("missing key usage")


def _leaf_extended_key_usage(
    cert: x509.Certificate,
    allow_tls_server_auth: bool,
) -> Optional[x509.ExtendedKeyUsage]:
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
    except x509.ExtensionNotFound:
        if allow_tls_server_auth:
            return None
        raise VerificationError("missing transcript-signing EKU")


def _validate_ca_certificate(cert: x509.Certificate) -> x509.BasicConstraints:
    basic = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    if not basic.ca:
        raise VerificationError("CA certificate has CA != true")

    usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
    if not usage.key_cert_sign:
        raise VerificationError("missing keyCertSign key usage")

    try:
        cert.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
    except x509.ExtensionNotFound:
        return basic
    raise VerificationError("name constraints are not supported by this implementation")


def _check_path_length_constraints(
    ca_basics: dict[int, x509.BasicConstraints],
) -> None:
    for index, basic in ca_basics.items():
        if basic.path_length is None:
            continue
        ca_certificates_below = index - 1
        if ca_certificates_below > basic.path_length:
            raise VerificationError("path length constraint exceeded")


def _check_time(cert: x509.Certificate, validation_time: _dt.datetime) -> None:
    not_before = _to_aware(cert.not_valid_before_utc)
    not_after = _to_aware(cert.not_valid_after_utc)
    if validation_time < not_before or validation_time > not_after:
        raise VerificationError("certificate expired or not yet valid")


def _to_aware(value: _dt.datetime) -> _dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=_dt.timezone.utc)
    return value


def _check_revocation(
    cert: x509.Certificate,
    mode: str,
    revoked_serials: Set[int],
) -> None:
    if cert.serial_number in revoked_serials:
        raise VerificationError("revoked certificate")
    if mode == "hard_fail" and cert.serial_number not in revoked_serials:
        raise VerificationError("unknown revocation status under hard_fail policy")


def _verify_certificate_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    public_key = issuer.public_key()
    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes)
            return
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
            return
    except InvalidSignature as exc:
        raise VerificationError("certificate signature verification failure") from exc
    raise VerificationError("unsupported certificate signature public key")
