"""Key helpers and simple key policies."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from llm_sign.core.base64 import b64url_encode
from llm_sign.core.blocks import Block, KeyPolicy
from llm_sign.core.crypto import public_key_compatible_with_suite
from llm_sign.core.errors import VerificationError


@dataclass(frozen=True)
class Ed25519KeyPair:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    key_id: str

    @classmethod
    def generate(cls) -> "Ed25519KeyPair":
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return cls(
            private_key=private_key,
            public_key=public_key,
            key_id=spki_sha256_key_id(public_key),
        )


def spki_sha256_key_id(public_key: Any) -> str:
    spki = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "spki-sha256:" + b64url_encode(hashlib.sha256(spki).digest())


class StaticKeyPolicy(KeyPolicy):
    """In-memory key policy for tests and local deployments."""

    def __init__(self, keys: Mapping[Tuple[str, str, str], Any]) -> None:
        self._keys: Dict[Tuple[str, str, str], Any] = dict(keys)

    def resolve(self, block: Block) -> Any:
        key = self._keys.get((block.issuer, block.key_id, block.suite_id))
        if key is None:
            raise VerificationError("unresolved, ambiguous, expired, or untrusted key")
        if not public_key_compatible_with_suite(key, block.suite_id):
            raise VerificationError("unsupported suite_id")
        return key
