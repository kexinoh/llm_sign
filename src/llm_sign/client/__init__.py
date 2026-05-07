"""Client-side verifier APIs for CLI and platform integrations.

Trust model
-----------

The threat ``llm_sign`` targets is middleman / relay tampering: a client
talks to a relay over HTTPS, and the relay forwards to the real
provider. The client's TLS session only authenticates the relay, so
the client cannot learn the provider's signing public key from its own
TLS handshake.

By convention the provider ships its TLS certificate alongside the
signed transcript, in ``response["llm_sign"]["certificate_chain"]``.
The client authenticates that certificate the same way an HTTPS client
authenticates a server certificate: standard X.509 chain validation
against the system TLS trust store, with the expected host name
matched against the leaf's subjectAltName. This is not a new PKI, it
is the same Web PKI the client would have used if it were talking
directly to the provider over HTTPS. ``llm_sign.tls_verify`` wraps
``cryptography.x509.verification`` for this step.

After the chain is trusted, the signed ``key_id`` field (an SPKI-SHA256
of the signer's public key) is cross-checked against the validated
leaf's SPKI, and the transcript signature is verified with that key.
A relay cannot forge a signature because it does not hold the
provider's private key, and cannot swap the embedded chain for one
rooted in the same system trust store unless it also controls the
DNS name claimed by the artifact (which it does not).

Callers that do not want to rely on the Web PKI — for example when the
provider uses a private TLS hierarchy or a self-signed certificate —
can pass explicit ``trust_anchors``, disable chain validation with
``verify_tls=False`` (trust-on-first-use against the embedded
certificate), or pin a public key directly via
:func:`verify_openai_response_with_public_key`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

from cryptography import x509

from llm_sign.core.blocks import ChainVerification
from llm_sign.core.crypto import infer_suite_for_public_key
from llm_sign.keys.ed25519 import StaticKeyPolicy, spki_sha256_key_id
from llm_sign.keys.tls import certificate_key_id, load_pem_certificates
from llm_sign.tls_verify import (
    CertificateTrustError,
    load_system_trust_anchors,
    verify_certificate_chain,
)
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


def certificate_chain_from_openai_response(
    response: Mapping[str, Any],
    *,
    required: bool = True,
) -> Optional[List[x509.Certificate]]:
    """Extract the provider's PEM certificate chain from an OpenAI response.

    The provider is expected to attach its TLS certificate chain at
    ``response["llm_sign"]["certificate_chain"]`` (leaf first). This is
    the channel the client uses to learn the provider's public key when
    the underlying TLS session only authenticates an intermediary relay.

    The chain is only **parsed** here; the caller decides how to
    authenticate it (TLS chain validation, trust-on-first-use, etc).
    If ``required`` is ``False`` and the field is absent, ``None`` is
    returned.
    """

    llm_sign = response.get("llm_sign")
    if not isinstance(llm_sign, Mapping):
        if required:
            raise ValueError("OpenAI response must include llm_sign.certificate_chain")
        return None

    raw_chain = llm_sign.get("certificate_chain")
    if raw_chain is None:
        artifact = llm_sign.get("artifact")
        if isinstance(artifact, Mapping):
            raw_chain = artifact.get("certificate_chain")
    if raw_chain is None:
        if required:
            raise ValueError("OpenAI response must include llm_sign.certificate_chain")
        return None
    if not isinstance(raw_chain, list):
        raise ValueError("llm_sign.certificate_chain must be a list of PEM strings")

    certificates: List[x509.Certificate] = []
    for pem in raw_chain:
        if not isinstance(pem, str):
            raise ValueError("certificate_chain entries must be PEM strings")
        certificates.extend(load_pem_certificates(pem.encode("ascii")))
    if not certificates:
        raise ValueError("certificate_chain must contain at least one certificate")
    return certificates


def public_key_from_openai_response(
    response: Mapping[str, Any],
    *,
    expected_host: Optional[str] = None,
    trust_anchors: Optional[Sequence[x509.Certificate]] = None,
    verify_tls: bool = True,
) -> Any:
    """Return the provider's signing public key from an OpenAI response.

    Reads ``llm_sign.certificate_chain`` (leaf first). When
    ``verify_tls`` is true (the default), the chain is validated as a
    standard TLS server certificate chain — same procedure as an HTTPS
    client handshake — against ``trust_anchors`` (or the system TLS
    trust store) with ``expected_host`` matched against the leaf's
    subjectAltName.

    ``expected_host`` defaults to the ``issuer`` value on the signed
    artifact's first block (which the provider binds to its TLS server
    name); callers can override it to pin a different identity.

    When ``verify_tls`` is ``False`` the chain is parsed but not
    authenticated. This is useful for self-signed providers and local
    development; it reduces the client to trust-on-first-use of the
    embedded certificate.

    Raises :class:`CertificateTrustError` on chain validation failure.
    """

    chain = certificate_chain_from_openai_response(response)
    assert chain is not None  # required=True above

    if not verify_tls:
        return chain[0].public_key()

    host = expected_host
    if host is None:
        artifact = _optional_artifact_from_openai_response(response)
        if artifact is not None:
            host = host_name_from_artifact(artifact)
    if host is None:
        raise CertificateTrustError(
            "expected_host could not be inferred; pass expected_host explicitly"
        )
    return verify_certificate_chain(
        chain,
        expected_host=host,
        trust_anchors=trust_anchors,
    ).public_key()


def verify_openai_response(
    response: Mapping[str, Any],
    *,
    expected_host: Optional[str] = None,
    trust_anchors: Optional[Sequence[x509.Certificate]] = None,
    verify_tls: bool = True,
    issuer: Optional[str] = None,
    key_id: Optional[str] = None,
    suite_id: Optional[str] = None,
    platform: Optional[str] = None,
    payloads: Optional[Mapping[int, Any]] = None,
) -> ChainVerification:
    """Verify an OpenAI response using the provider certificate it carries.

    The provider's TLS certificate chain is read from
    ``response["llm_sign"]["certificate_chain"]`` and, by default,
    validated against the system TLS trust store exactly as an HTTPS
    client would validate a server certificate. The transcript is then
    verified with the public key embedded in the trusted leaf.

    Parameters
    ----------
    expected_host:
        Host name the leaf certificate must match. Defaults to the
        ``issuer`` value on the first signed block.
    trust_anchors:
        Optional list of PEM ``x509.Certificate`` objects. When
        ``None``, the system TLS trust store is used.
    verify_tls:
        When ``False``, the chain is parsed but not validated (trust
        the embedded certificate on its own). Use this only for
        self-signed providers or local development.

    Callers that want to skip certificate handling entirely and pin a
    known public key should use :func:`verify_openai_response_with_public_key`.
    """

    public_key = public_key_from_openai_response(
        response,
        expected_host=expected_host,
        trust_anchors=trust_anchors,
        verify_tls=verify_tls,
    )
    return verify_openai_response_with_public_key(
        response,
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
    expected_host: Optional[str] = None,
    trust_anchors: Optional[Sequence[x509.Certificate]] = None,
    verify_tls: bool = True,
    issuer: Optional[str] = None,
    key_id: Optional[str] = None,
    suite_id: Optional[str] = None,
    payloads: Optional[Mapping[int, Any]] = None,
    platform: Optional[str] = None,
) -> OpenAIResponseSignatureReport:
    """Non-raising report on a response's signature status.

    - Unsigned responses yield ``has_signature=False, valid=None``.
    - Signed responses are verified against ``public_key`` when pinned,
      otherwise against the provider certificate embedded in
      ``llm_sign.certificate_chain``. By default the embedded chain is
      validated against the system TLS trust store (see
      :func:`verify_openai_response`); pass ``trust_anchors`` or
      ``verify_tls=False`` to override.
    - Any failure — untrusted chain, bad signature, missing certificate
      — yields ``valid=False``.
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

    resolved_public_key = public_key
    if resolved_public_key is None:
        try:
            resolved_public_key = public_key_from_openai_response(
                response_data,
                expected_host=expected_host,
                trust_anchors=trust_anchors,
                verify_tls=verify_tls,
            )
        except Exception:
            return OpenAIResponseSignatureReport(
                has_signature=True,
                host_name=host_name,
                valid=False,
            )

    try:
        verification = verify_with_public_key(
            artifact,
            public_key=resolved_public_key,
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
    "CertificateTrustError",
    "OpenAIResponseSignatureReport",
    "StaticKeyPolicy",
    "artifact_from_openai_response",
    "certificate_chain_from_openai_response",
    "certificate_key_id",
    "host_name_from_artifact",
    "load_pem_certificates",
    "load_signed_blocks",
    "load_system_trust_anchors",
    "openai_response_signature_summary",
    "openai_response_to_dict",
    "public_key_from_openai_response",
    "spki_sha256_key_id",
    "trust_public_key",
    "verify_artifact",
    "verify_openai_response",
    "verify_openai_response_signature",
    "verify_openai_response_with_public_key",
    "verification_summary",
    "verify_with_public_key",
]
