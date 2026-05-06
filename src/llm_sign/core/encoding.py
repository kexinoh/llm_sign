"""Primitive encodings and digest construction."""

from __future__ import annotations

from typing import Optional

from .crypto import ED25519_SHA256, digest_bytes, require_supported_suite, suite_hash_size
from .errors import EncodingError


SUITE_ID = ED25519_SHA256
VERSION = "1"


def _len64(data: bytes) -> bytes:
    length = len(data)
    if length > 2**64 - 1:
        raise EncodingError("value is too large for len64")
    return length.to_bytes(8, "big")


def encode_text(value: str) -> bytes:
    if not isinstance(value, str):
        raise EncodingError("text value must be str")
    data = value.encode("utf-8")
    return b"\x01" + _len64(data) + data


def encode_uint64(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool):
        raise EncodingError("uint64 value must be int")
    if value < 0 or value > 2**64 - 1:
        raise EncodingError("uint64 value out of range")
    return b"\x02" + value.to_bytes(8, "big")


def encode_bytes(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise EncodingError("bytes value must be bytes")
    return b"\x03" + _len64(value) + value


def encode_null() -> bytes:
    return b"\x04"


def encode_optional_bytes(value: Optional[bytes]) -> bytes:
    return encode_null() if value is None else encode_bytes(value)


def encode_field(name: str, value: bytes) -> bytes:
    return encode_text(name) + value


def sha256(data: bytes) -> bytes:
    return digest_bytes(ED25519_SHA256, data)


def payload_digest(suite_id: str, profile_id: str, canonical_payload: bytes) -> bytes:
    require_supported_suite(suite_id)
    return digest_bytes(
        suite_id,
        encode_text("llm-sign.payload.v1")
        + encode_text(suite_id)
        + encode_text(profile_id)
        + encode_bytes(canonical_payload)
    )


def block_digest(suite_id: str, encoded_block: bytes) -> bytes:
    require_supported_suite(suite_id)
    return digest_bytes(
        suite_id,
        encode_text("llm-sign.block.v1")
        + encode_text(suite_id)
        + encode_bytes(encoded_block)
    )


def validate_identifier(value: str, field_name: str) -> None:
    if not isinstance(value, str):
        raise EncodingError(f"{field_name} must be a string")
    data = value.encode("utf-8")
    if not data or len(data) > 128:
        raise EncodingError(f"{field_name} must be 1 to 128 octets")
    if any(byte < 0x21 or byte > 0x7E for byte in data):
        raise EncodingError(f"{field_name} must contain printable ASCII only")


def validate_digest(value: bytes, field_name: str, suite_id: str) -> None:
    if not isinstance(value, bytes):
        raise EncodingError(f"{field_name} must be bytes")
    expected = suite_hash_size(suite_id)
    if len(value) != expected:
        raise EncodingError(f"{field_name} must be {expected} octets")
