"""Signing suite operations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import OrderedDict
import hashlib
from typing import Any, Iterable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

from .errors import EncodingError, VerificationError


class SignatureSuite(ABC):
    """A transcript signing suite backed by library crypto primitives."""

    suite_id: str
    digest_size: int

    @abstractmethod
    def supports_private_key(self, private_key: Any) -> bool:
        raise NotImplementedError

    @abstractmethod
    def supports_public_key(self, public_key: Any) -> bool:
        raise NotImplementedError

    @abstractmethod
    def sign_digest(self, private_key: Any, digest: bytes) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def verify_signature(self, public_key: Any, signature: bytes, digest: bytes) -> None:
        raise NotImplementedError

    @abstractmethod
    def digest(self, data: bytes) -> bytes:
        raise NotImplementedError


class Ed25519Sha256Suite(SignatureSuite):
    suite_id = "sha256-ed25519-v1"
    digest_size = 32

    def supports_private_key(self, private_key: Any) -> bool:
        return isinstance(private_key, ed25519.Ed25519PrivateKey)

    def supports_public_key(self, public_key: Any) -> bool:
        return isinstance(public_key, ed25519.Ed25519PublicKey)

    def sign_digest(self, private_key: Any, digest: bytes) -> bytes:
        return private_key.sign(digest)

    def verify_signature(self, public_key: Any, signature: bytes, digest: bytes) -> None:
        public_key.verify(signature, digest)

    def digest(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()


class RsaPssSha256Suite(SignatureSuite):
    suite_id = "sha256-rsa-pss-v1"
    digest_size = 32

    def supports_private_key(self, private_key: Any) -> bool:
        return isinstance(private_key, rsa.RSAPrivateKey)

    def supports_public_key(self, public_key: Any) -> bool:
        return isinstance(public_key, rsa.RSAPublicKey)

    def sign_digest(self, private_key: Any, digest: bytes) -> bytes:
        return private_key.sign(
            digest,
            self._padding(),
            utils.Prehashed(hashes.SHA256()),
        )

    def verify_signature(self, public_key: Any, signature: bytes, digest: bytes) -> None:
        public_key.verify(
            signature,
            digest,
            self._padding(),
            utils.Prehashed(hashes.SHA256()),
        )

    def digest(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def _padding(self) -> padding.PSS:
        return padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.DIGEST_LENGTH,
        )


class EcdsaP256Sha256Suite(SignatureSuite):
    suite_id = "sha256-ecdsa-p256-v1"
    digest_size = 32

    def supports_private_key(self, private_key: Any) -> bool:
        return isinstance(private_key, ec.EllipticCurvePrivateKey) and isinstance(
            private_key.curve,
            ec.SECP256R1,
        )

    def supports_public_key(self, public_key: Any) -> bool:
        return isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(
            public_key.curve,
            ec.SECP256R1,
        )

    def sign_digest(self, private_key: Any, digest: bytes) -> bytes:
        return private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

    def verify_signature(self, public_key: Any, signature: bytes, digest: bytes) -> None:
        public_key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

    def digest(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()


_SUITES: "OrderedDict[str, SignatureSuite]" = OrderedDict()


def register_signature_suite(suite: SignatureSuite) -> None:
    if suite.suite_id in _SUITES:
        raise ValueError(f"duplicate signing suite: {suite.suite_id}")
    if suite.digest_size <= 0:
        raise ValueError("suite digest_size must be positive")
    _SUITES[suite.suite_id] = suite


def supported_suite_ids() -> tuple[str, ...]:
    return tuple(_SUITES)


def require_supported_suite(suite_id: str) -> None:
    _suite_for_id(suite_id, error_cls=EncodingError)


def suite_hash_size(suite_id: str) -> int:
    return _suite_for_id(suite_id, error_cls=EncodingError).digest_size


def digest_bytes(suite_id: str, data: bytes) -> bytes:
    return _suite_for_id(suite_id, error_cls=EncodingError).digest(data)


def infer_suite_for_private_key(private_key: Any) -> str:
    suite = _single_matching_suite(
        (candidate for candidate in _SUITES.values() if candidate.supports_private_key(private_key)),
        "private key",
        error_cls=EncodingError,
    )
    return suite.suite_id


def infer_suite_for_public_key(public_key: Any) -> str:
    suite = _single_matching_suite(
        (candidate for candidate in _SUITES.values() if candidate.supports_public_key(public_key)),
        "public key",
        error_cls=VerificationError,
    )
    return suite.suite_id


def public_key_compatible_with_suite(public_key: Any, suite_id: str) -> bool:
    try:
        return _suite_for_id(suite_id).supports_public_key(public_key)
    except (EncodingError, VerificationError):
        return False


def sign_digest(private_key: Any, suite_id: str, digest: bytes) -> bytes:
    suite = _suite_for_id(suite_id, error_cls=EncodingError)
    if not suite.supports_private_key(private_key):
        raise EncodingError("private key is incompatible with signing suite")
    _check_digest_size(suite, digest)
    return suite.sign_digest(private_key, digest)


def verify_signature(public_key: Any, suite_id: str, signature: bytes, digest: bytes) -> None:
    suite = _suite_for_id(suite_id)
    if not suite.supports_public_key(public_key):
        raise VerificationError("public key is incompatible with signing suite")
    _check_digest_size(suite, digest)
    suite.verify_signature(public_key, signature, digest)


def _suite_for_id(suite_id: str, error_cls=VerificationError) -> SignatureSuite:
    suite = _SUITES.get(suite_id)
    if suite is None:
        raise error_cls(f"unsupported signing suite: {suite_id}")
    return suite


def _single_matching_suite(
    suites: Iterable[SignatureSuite],
    label: str,
    error_cls,
) -> SignatureSuite:
    matches = list(suites)
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise error_cls(f"unsupported {label} type for transcript signing")
    raise error_cls(f"ambiguous {label} type; specify suite_id")


def _check_digest_size(suite: SignatureSuite, digest: bytes) -> None:
    if len(digest) != suite.digest_size:
        raise EncodingError(f"digest must be {suite.digest_size} octets")


register_signature_suite(Ed25519Sha256Suite())
register_signature_suite(RsaPssSha256Suite())
register_signature_suite(EcdsaP256Sha256Suite())

ED25519_SHA256 = Ed25519Sha256Suite.suite_id
RSA_PSS_SHA256 = RsaPssSha256Suite.suite_id
ECDSA_P256_SHA256 = EcdsaP256Sha256Suite.suite_id
