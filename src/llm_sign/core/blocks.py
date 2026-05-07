"""Signed block construction and chain verification."""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional

from cryptography.exceptions import InvalidSignature

from .base64 import b64url_decode, b64url_encode
from .crypto import infer_suite_for_private_key, sign_digest, verify_signature
from .encoding import (
    SUITE_ID,
    VERSION,
    block_digest as compute_block_digest,
    encode_bytes,
    encode_field,
    encode_optional_bytes,
    encode_text,
    encode_uint64,
    payload_digest as compute_payload_digest,
    validate_digest,
    validate_identifier,
)
from .errors import CanonicalizationError, EncodingError, VerificationError
from .profiles import Profile


PROVIDER_RECEIVED_INPUT = "provider_received_input"
PROVIDER_OUTPUT = "provider_output"
TOOL_RESULT = "tool_result"


@dataclass(frozen=True)
class Block:
    version: str
    suite_id: str
    chain_id: bytes
    seq: int
    issuer: str
    key_id: str
    type: str
    profile_id: str
    prev_block_digest: Optional[bytes]
    payload_digest: bytes

    def encode(self) -> bytes:
        self.validate_shape()
        return b"".join(
            [
                encode_field("version", encode_text(self.version)),
                encode_field("suite_id", encode_text(self.suite_id)),
                encode_field("chain_id", encode_bytes(self.chain_id)),
                encode_field("seq", encode_uint64(self.seq)),
                encode_field("issuer", encode_text(self.issuer)),
                encode_field("key_id", encode_text(self.key_id)),
                encode_field("type", encode_text(self.type)),
                encode_field("profile_id", encode_text(self.profile_id)),
                encode_field(
                    "prev_block_digest",
                    encode_optional_bytes(self.prev_block_digest),
                ),
                encode_field("payload_digest", encode_bytes(self.payload_digest)),
            ]
        )

    def digest(self) -> bytes:
        return compute_block_digest(self.suite_id, self.encode())

    def validate_shape(self) -> None:
        if self.version != VERSION:
            raise EncodingError("unsupported block version")
        if len(self.chain_id) < 16:
            raise EncodingError("chain_id must be at least 16 octets")
        if self.seq < 0 or self.seq > 2**64 - 1:
            raise EncodingError("seq out of uint64 range")
        validate_identifier(self.suite_id, "suite_id")
        validate_identifier(self.issuer, "issuer")
        validate_identifier(self.key_id, "key_id")
        validate_identifier(self.type, "type")
        validate_identifier(self.profile_id, "profile_id")
        validate_digest(self.payload_digest, "payload_digest", self.suite_id)
        if self.prev_block_digest is not None:
            validate_digest(self.prev_block_digest, "prev_block_digest", self.suite_id)
        if self.seq == 0 and self.prev_block_digest is not None:
            raise EncodingError("genesis block must not have prev_block_digest")
        if self.seq > 0 and self.prev_block_digest is None:
            raise EncodingError("non-genesis block must have prev_block_digest")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "suite_id": self.suite_id,
            "chain_id": b64url_encode(self.chain_id),
            "seq": self.seq,
            "issuer": self.issuer,
            "key_id": self.key_id,
            "type": self.type,
            "profile_id": self.profile_id,
            "prev_block_digest": (
                None if self.prev_block_digest is None else b64url_encode(self.prev_block_digest)
            ),
            "payload_digest": b64url_encode(self.payload_digest),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Block":
        return cls(
            version=str(data["version"]),
            suite_id=str(data["suite_id"]),
            chain_id=b64url_decode(data["chain_id"]),
            seq=int(data["seq"]),
            issuer=str(data["issuer"]),
            key_id=str(data["key_id"]),
            type=str(data["type"]),
            profile_id=str(data["profile_id"]),
            prev_block_digest=(
                None
                if data["prev_block_digest"] is None
                else b64url_decode(data["prev_block_digest"])
            ),
            payload_digest=b64url_decode(data["payload_digest"]),
        )


@dataclass(frozen=True)
class SignedBlock:
    block: Block
    signature: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "block": self.block.to_dict(),
            "signature": b64url_encode(self.signature),
            "block_digest": b64url_encode(self.block.digest()),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SignedBlock":
        return cls(
            block=Block.from_dict(data["block"]),
            signature=b64url_decode(data["signature"]),
        )


@dataclass(frozen=True)
class VerifiedBlock:
    signed_block: SignedBlock
    block_digest: bytes
    payload_state: str


class PayloadState:
    PAYLOAD_VERIFIED = "payload_verified"
    DIGEST_ONLY = "digest_only"
    PAYLOAD_INVALID = "payload_invalid"


@dataclass(frozen=True)
class ChainVerification:
    valid: bool
    blocks: List[VerifiedBlock]
    errors: List[str]


class KeyPolicy:
    def resolve(self, block: Block) -> Any:
        raise NotImplementedError


class TranscriptSigner:
    def __init__(
        self,
        *,
        issuer: str,
        key_id: str,
        private_key: Any,
        suite_id: Optional[str] = None,
    ) -> None:
        self.issuer = issuer
        self.key_id = key_id
        self.private_key = private_key
        self.suite_id = suite_id or infer_suite_for_private_key(private_key)

    def sign_payload(
        self,
        *,
        block_type: str,
        profile: Profile,
        payload: Any,
        previous: Optional[SignedBlock] = None,
        chain_id: Optional[bytes] = None,
    ) -> SignedBlock:
        return sign_payload(
            issuer=self.issuer,
            key_id=self.key_id,
            private_key=self.private_key,
            block_type=block_type,
            profile=profile,
            payload=payload,
            previous=previous,
            chain_id=chain_id,
            suite_id=self.suite_id,
        )


def sign_payload(
    *,
    issuer: str,
    key_id: str,
    private_key: Any,
    block_type: str,
    profile: Profile,
    payload: Any,
    previous: Optional[SignedBlock] = None,
    chain_id: Optional[bytes] = None,
    suite_id: Optional[str] = None,
) -> SignedBlock:
    actual_suite_id = suite_id or infer_suite_for_private_key(private_key)
    if previous is None:
        seq = 0
        prev_digest = None
        actual_chain_id = chain_id or os.urandom(16)
    else:
        seq = previous.block.seq + 1
        prev_digest = previous.block.digest()
        actual_chain_id = previous.block.chain_id
        if chain_id is not None and chain_id != actual_chain_id:
            raise ValueError("chain_id does not match previous block")

    canonical_payload = profile.canonicalize(payload)
    digest = compute_payload_digest(actual_suite_id, profile.profile_id, canonical_payload)
    block = Block(
        version=VERSION,
        suite_id=actual_suite_id,
        chain_id=actual_chain_id,
        seq=seq,
        issuer=issuer,
        key_id=key_id,
        type=block_type,
        profile_id=profile.profile_id,
        prev_block_digest=prev_digest,
        payload_digest=digest,
    )
    signature = sign_digest(private_key, actual_suite_id, block.digest())
    return SignedBlock(block=block, signature=signature)


def verify_chain(
    signed_blocks: Iterable[SignedBlock],
    *,
    key_policy: KeyPolicy,
    profiles: Mapping[str, Profile],
    payloads: Optional[Mapping[int, Any]] = None,
    enforce_baseline_turns: bool = True,
) -> ChainVerification:
    blocks = list(signed_blocks)
    payloads = payloads or {}
    verified: List[VerifiedBlock] = []
    errors: List[str] = []

    if not blocks:
        return ChainVerification(False, [], ["empty chain"])

    previous: Optional[SignedBlock] = None
    seen_seq: Dict[int, SignedBlock] = {}

    for signed in blocks:
        block = signed.block
        try:
            block.validate_shape()
            _check_signature_length(signed.signature)
            _check_duplicate_seq(seen_seq, signed)
            _check_chain_link(previous, signed)
            if enforce_baseline_turns:
                _check_supported_block_type_sequence(previous, block)
            public_key = key_policy.resolve(block)
            verify_signature(public_key, block.suite_id, signed.signature, block.digest())
            payload_state = _verify_payload(block, profiles, payloads)
            if payload_state == PayloadState.PAYLOAD_INVALID:
                raise VerificationError("payload digest mismatch")
            verified.append(
                VerifiedBlock(
                    signed_block=signed,
                    block_digest=block.digest(),
                    payload_state=payload_state,
                )
            )
            seen_seq[block.seq] = signed
            previous = signed
        except (
            CanonicalizationError,
            EncodingError,
            VerificationError,
            InvalidSignature,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            errors.append(f"seq {getattr(block, 'seq', '?')}: {exc}")
            return ChainVerification(False, verified, errors)

    if enforce_baseline_turns:
        try:
            _check_chain_terminates_with_provider_output(blocks)
        except VerificationError as exc:
            last_seq = blocks[-1].block.seq if blocks else "?"
            errors.append(f"seq {last_seq}: {exc}")
            return ChainVerification(False, verified, errors)

    return ChainVerification(True, verified, [])


def _check_signature_length(signature: bytes) -> None:
    if not isinstance(signature, bytes) or len(signature) == 0:
        raise VerificationError("signature length mismatch")


def _check_duplicate_seq(seen_seq: Mapping[int, SignedBlock], signed: SignedBlock) -> None:
    existing = seen_seq.get(signed.block.seq)
    if existing is None:
        return
    same_block = existing.block.encode() == signed.block.encode()
    same_signature = hmac.compare_digest(existing.signature, signed.signature)
    if not same_block or not same_signature:
        raise VerificationError("duplicate sequence number with different block")


def _check_chain_link(previous: Optional[SignedBlock], signed: SignedBlock) -> None:
    block = signed.block
    if previous is None:
        if block.seq != 0:
            raise VerificationError("first block must have seq 0")
        if block.prev_block_digest is not None:
            raise VerificationError("genesis block has prev_block_digest")
        return

    if block.version != previous.block.version:
        raise VerificationError("version mismatch")
    if block.suite_id != previous.block.suite_id:
        raise VerificationError("suite_id mismatch")
    if block.chain_id != previous.block.chain_id:
        raise VerificationError("chain_id mismatch")
    if block.issuer != previous.block.issuer:
        raise VerificationError("issuer mismatch")
    if block.seq != previous.block.seq + 1:
        raise VerificationError("sequence gap")
    expected = previous.block.digest()
    if block.prev_block_digest is None or not hmac.compare_digest(
        block.prev_block_digest,
        expected,
    ):
        raise VerificationError("prev_block_digest mismatch")


def _check_supported_block_type_sequence(
    previous: Optional[SignedBlock],
    block: Block,
) -> None:
    supported = {PROVIDER_RECEIVED_INPUT, PROVIDER_OUTPUT, TOOL_RESULT}
    if block.type not in supported:
        raise VerificationError(f"unsupported block type: {block.type}")
    if previous is None:
        if block.type != PROVIDER_RECEIVED_INPUT:
            raise VerificationError(f"unexpected block type at seq {block.seq}: {block.type}")
        return

    previous_type = previous.block.type
    if block.type == PROVIDER_RECEIVED_INPUT:
        if previous_type not in {PROVIDER_OUTPUT, TOOL_RESULT}:
            raise VerificationError(f"unexpected block type at seq {block.seq}: {block.type}")
    elif block.type == PROVIDER_OUTPUT:
        if previous_type != PROVIDER_RECEIVED_INPUT:
            raise VerificationError(f"unexpected block type at seq {block.seq}: {block.type}")
    elif block.type == TOOL_RESULT:
        if previous_type not in {PROVIDER_OUTPUT, TOOL_RESULT}:
            raise VerificationError(f"unexpected block type at seq {block.seq}: {block.type}")


def _check_chain_terminates_with_provider_output(
    blocks: List[SignedBlock],
) -> None:
    """Reject chains where any turn lacks its corresponding ``PROVIDER_OUTPUT``.

    A signed turn is meaningful only when both halves are present: the
    request the provider received *and* the response it produced. Without
    this rule a relay could strip the output block (or never sign it)
    and still ship a chain that links and signature-verifies cleanly,
    which would let the relay synthesize an unsigned response while
    pointing the user at a signed-looking artifact. We therefore require
    every ``PROVIDER_RECEIVED_INPUT`` to be closed by a later
    ``PROVIDER_OUTPUT`` in the same chain — equivalently, the last block
    in the chain must be ``PROVIDER_OUTPUT`` (a ``TOOL_RESULT`` tail
    means the provider's reply to the most recent input is missing).
    """

    last = blocks[-1].block
    if last.type != PROVIDER_OUTPUT:
        raise VerificationError(
            "chain must terminate with a provider_output block; "
            f"got terminating type {last.type!r}"
        )

    pending_input = False
    for signed in blocks:
        block_type = signed.block.type
        if block_type == PROVIDER_RECEIVED_INPUT:
            if pending_input:
                # Two inputs in a row would have been caught by the
                # per-block sequence rule, but be defensive.
                raise VerificationError(
                    "provider_received_input not closed by provider_output"
                )
            pending_input = True
        elif block_type == PROVIDER_OUTPUT:
            if not pending_input:
                raise VerificationError(
                    "provider_output without preceding provider_received_input"
                )
            pending_input = False
        # TOOL_RESULT does not open or close a turn.

    if pending_input:
        raise VerificationError(
            "provider_received_input not closed by provider_output"
        )


def _verify_payload(
    block: Block,
    profiles: Mapping[str, Profile],
    payloads: Mapping[int, Any],
) -> str:
    if block.seq not in payloads:
        return PayloadState.DIGEST_ONLY
    profile = profiles[block.profile_id]
    actual = compute_payload_digest(
        block.suite_id,
        block.profile_id,
        profile.canonicalize(payloads[block.seq]),
    )
    if hmac.compare_digest(actual, block.payload_digest):
        return PayloadState.PAYLOAD_VERIFIED
    return PayloadState.PAYLOAD_INVALID
