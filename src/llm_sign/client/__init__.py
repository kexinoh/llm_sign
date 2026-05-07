"""Client-side verifier APIs for CLI and platform integrations.

``llm_sign`` does not ship a CA / PKI trust model. Clients establish
trust in a provider by pinning the provider's public key out of band
(for example from the same TLS certificate the provider serves). The
helpers in this module all expect such a pinned public key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

from llm_sign.core.blocks import ChainVerification
from llm_sign.core.crypto import infer_suite_for_public_key
from llm_sign.keys.ed25519 import StaticKeyPolicy, spki_sha256_key_id
from llm_sign.keys.tls import certificate_key_id, load_pem_certificates
from llm_sign.verifier import load_signed_blocks, verify_artifact


@dataclass(frozen=True)
class OpenAIResponseSignatureReport:
    """Optional verification status for an OpenAI-compatible response."""

    has_signature: bool
    host_name: Optional[str]
    valid: Optional[bool]


def trust_public_key(
    *,
    issuer: str,
    key_id: str,
    public_key: Any,
    suite_id: Optional[str] = None,
) -> StaticKeyPolicy:
    """Build a static verifier policy for one trusted transcript signing key."""

    resolved_suite_id = suite_id or infer_suite_for_public_key(public_key)
    return StaticKeyPolicy({(issuer, key_id, resolved_suite_id): public_key})


def verify_with_public_key(
    artifact: Mapping[str, Any],
    *,
    public_key: Any,
    issuer: Optional[str] = None,
    key_id: Optional[str] = None,
    suite_id: Optional[str] = None,
    platform: Optional[str] = None,
    payloads: Optional[Mapping[int, Any]] = None,
) -> ChainVerification:
    """Verify an artifact against one trusted public key.

    ``issuer``, ``key_id``, ``suite_id`` and ``platform`` are optional: when
    omitted they are read from the artifact's first signed block (or the
    artifact envelope for ``platform``). Pinning them explicitly is still
    recommended in production, since reading them from the artifact means
    the verifier accepts whatever issuer the signer claimed; as long as the
    public key matches the signature this is sound, but it skips the
    "did this artifact come from the issuer I expected" check.
    """

    block_metadata = _first_block_metadata(artifact)
    resolved_issuer = issuer if issuer is not None else block_metadata.get("issuer")
    resolved_key_id = key_id if key_id is not None else block_metadata.get("key_id")
    resolved_suite_id = (
        suite_id if suite_id is not None else block_metadata.get("suite_id")
    )
    resolved_platform = (
        platform if platform is not None else artifact.get("platform")
    )
    if resolved_issuer is None:
        raise ValueError(
            "issuer is required and could not be inferred from the artifact"
        )
    if resolved_key_id is None:
        raise ValueError(
            "key_id is required and could not be inferred from the artifact"
        )

    return verify_artifact(
        artifact,
        key_policy=trust_public_key(
            issuer=resolved_issuer,
            key_id=resolved_key_id,
            public_key=public_key,
            suite_id=resolved_suite_id,
        ),
        platform=resolved_platform,
        payloads=payloads,
    )


def verify_openai_response_with_public_key(
    response: Mapping[str, Any],
    *,
    public_key: Any,
    issuer: Optional[str] = None,
    key_id: Optional[str] = None,
    suite_id: Optional[str] = None,
    platform: Optional[str] = None,
    payloads: Optional[Mapping[int, Any]] = None,
) -> ChainVerification:
    """Verify an OpenAI-compatible response using a pinned public key.

    Convenience wrapper that extracts the artifact from the response and
    delegates to :func:`verify_with_public_key`. All metadata parameters
    behave the same: optional, inferred from the artifact when omitted.
    """
    artifact = artifact_from_openai_response(response)
    return verify_with_public_key(
        artifact,
        public_key=public_key,
        issuer=issuer,
        key_id=key_id,
        suite_id=suite_id,
        platform=platform,
        payloads=payloads,
    )


def _first_block_metadata(artifact: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return ``{issuer, key_id, suite_id}`` from the artifact's first block."""
    chain = artifact.get("chain", artifact.get("signed_blocks"))
    if not isinstance(chain, list) or not chain:
        return {}
    first = chain[0]
    if not isinstance(first, Mapping):
        return {}
    block = first.get("block")
    if not isinstance(block, Mapping):
        return {}
    out: Dict[str, Any] = {}
    for k in ("issuer", "key_id", "suite_id"):
        v = block.get(k)
        if isinstance(v, str):
            out[k] = v
    return out


def artifact_from_openai_response(response: Mapping[str, Any]) -> Mapping[str, Any]:
    """Extract llm_sign.artifact from an OpenAI-compatible response."""

    artifact = _optional_artifact_from_openai_response(response)
    if artifact is None:
        raise ValueError("OpenAI response must include llm_sign.artifact")
    return artifact


def host_name_from_artifact(artifact: Mapping[str, Any]) -> Optional[str]:
    """Return the host name claimed by the first signed block."""

    chain = artifact.get("chain", artifact.get("signed_blocks"))
    if not isinstance(chain, list) or not chain:
        return None
    signed = chain[0]
    if not isinstance(signed, Mapping):
        return None
    block = signed.get("block")
    if not isinstance(block, Mapping):
        return None
    issuer = block.get("issuer")
    if not isinstance(issuer, str):
        return None
    return issuer


def verify_openai_response_signature(
    response: Any,
    *,
    public_key: Optional[Any] = None,
    issuer: Optional[str] = None,
    key_id: Optional[str] = None,
    suite_id: Optional[str] = None,
    payloads: Optional[Mapping[int, Any]] = None,
    platform: Optional[str] = None,
) -> OpenAIResponseSignatureReport:
    """Report on a response's signature status.

    Unsigned responses yield ``has_signature=False, valid=None``. Signed
    responses are verified against ``public_key`` when provided; without a
    pinned public key the signature cannot be independently verified and
    ``valid`` is reported as ``None``.
    """

    response_data = openai_response_to_dict(response)
    artifact = _optional_artifact_from_openai_response(response_data)
    if artifact is None:
        return OpenAIResponseSignatureReport(
            has_signature=False,
            host_name=None,
            valid=None,
        )

    host_name = host_name_from_artifact(artifact)
    if public_key is None:
        # Signature is present but we have nothing to verify it against.
        return OpenAIResponseSignatureReport(
            has_signature=True,
            host_name=host_name,
            valid=None,
        )

    try:
        verification = verify_with_public_key(
            artifact,
            public_key=public_key,
            issuer=issuer,
            key_id=key_id,
            suite_id=suite_id,
            platform=platform,
            payloads=payloads,
        )
    except Exception:
        return OpenAIResponseSignatureReport(
            has_signature=True,
            host_name=host_name,
            valid=False,
        )

    return OpenAIResponseSignatureReport(
        has_signature=True,
        host_name=host_name,
        valid=verification.valid,
    )


def verification_summary(result: ChainVerification) -> Dict[str, Any]:
    """Return a compact JSON-serializable verification summary."""

    return {
        "valid": result.valid,
        "errors": result.errors,
        "blocks": [
            {
                "seq": block.signed_block.block.seq,
                "type": block.signed_block.block.type,
                "payload_state": block.payload_state,
            }
            for block in result.blocks
        ],
    }


def openai_response_signature_summary(
    report: OpenAIResponseSignatureReport,
) -> Dict[str, Any]:
    """Return a compact JSON-serializable OpenAI response signature summary."""

    return {
        "has_signature": report.has_signature,
        "host_name": report.host_name,
        "valid": report.valid,
    }


def openai_response_to_dict(value: Any) -> dict[str, Any]:
    """Convert an OpenAI SDK response object into a plain JSON-compatible dict."""

    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "model_dump"):
        data = value.model_dump(mode="json", exclude_none=True)
        extra = getattr(value, "model_extra", None)
        if isinstance(extra, Mapping):
            data.update(
                {key: _to_json_value(extra_value) for key, extra_value in extra.items()}
            )
        return data
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise TypeError(f"Unsupported OpenAI response type: {type(value)!r}")


def _optional_artifact_from_openai_response(
    response: Mapping[str, Any],
) -> Optional[Mapping[str, Any]]:
    llm_sign = response.get("llm_sign")
    if not isinstance(llm_sign, Mapping):
        return None
    artifact = llm_sign.get("artifact")
    if not isinstance(artifact, Mapping):
        return None
    return artifact


def _to_json_value(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, Mapping):
        return {key: _to_json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_to_json_value(item) for item in value]
    return value


__all__ = [
    "OpenAIResponseSignatureReport",
    "StaticKeyPolicy",
    "artifact_from_openai_response",
    "certificate_key_id",
    "host_name_from_artifact",
    "load_pem_certificates",
    "load_signed_blocks",
    "openai_response_signature_summary",
    "openai_response_to_dict",
    "spki_sha256_key_id",
    "trust_public_key",
    "verify_artifact",
    "verify_openai_response_signature",
    "verify_openai_response_with_public_key",
    "verification_summary",
    "verify_with_public_key",
]
