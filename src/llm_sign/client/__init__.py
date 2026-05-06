"""Client-side verifier APIs for CLI and platform integrations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import ssl
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from llm_sign.core.blocks import ChainVerification
from llm_sign.core.crypto import infer_suite_for_public_key
from llm_sign.keys.ed25519 import StaticKeyPolicy, spki_sha256_key_id
from llm_sign.keys.x509 import X509KeyPolicy, certificate_key_id, load_pem_certificates
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
    issuer: str,
    key_id: str,
    public_key: Any,
    suite_id: Optional[str] = None,
    platform: Optional[str] = None,
    payloads: Optional[Mapping[int, Any]] = None,
) -> ChainVerification:
    """Verify an artifact against one trusted public key."""

    return verify_artifact(
        artifact,
        key_policy=trust_public_key(
            issuer=issuer,
            key_id=key_id,
            public_key=public_key,
            suite_id=suite_id,
        ),
        platform=platform,
        payloads=payloads,
    )


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


def certificate_chain_from_openai_response(
    response: Mapping[str, Any],
    *,
    required: bool = True,
) -> Optional[list[x509.Certificate]]:
    """Extract supplier PEM certificate chain from an OpenAI-compatible response."""

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
    if raw_chain is None and not required:
        return None
    if not isinstance(raw_chain, list):
        raise ValueError("OpenAI response must include llm_sign.certificate_chain")

    certificates: list[x509.Certificate] = []
    for pem in raw_chain:
        if not isinstance(pem, str):
            raise ValueError("certificate_chain entries must be PEM strings")
        certificates.extend(load_pem_certificates(pem.encode("ascii")))
    if not certificates:
        raise ValueError("certificate_chain must contain at least one certificate")
    return certificates


def x509_key_policy_from_certificate_chain(
    certificate_chain: Sequence[x509.Certificate],
    *,
    trust_anchors: Sequence[x509.Certificate],
    issuer_binding: str = "tls-server-name",
    allow_tls_server_auth: bool = True,
    validation_time: Any = None,
    revocation_mode: str = "soft_fail",
    revoked_serials: Optional[Iterable[int]] = None,
    expected_issuer: Optional[str] = None,
) -> X509KeyPolicy:
    """Build an X.509 verifier policy from a supplier certificate chain."""

    return X509KeyPolicy(
        trust_anchors=trust_anchors,
        certificate_chains=_candidate_certificate_chains(certificate_chain, trust_anchors),
        validation_time=validation_time,
        revocation_mode=revocation_mode,
        revoked_serials=revoked_serials,
        issuer_binding=issuer_binding,
        allow_tls_server_auth=allow_tls_server_auth,
        expected_issuer=expected_issuer,
    )


def verify_openai_response_with_certificate_chain(
    response: Mapping[str, Any],
    *,
    trust_anchors: Sequence[x509.Certificate],
    payloads: Optional[Mapping[int, Any]] = None,
    platform: Optional[str] = None,
    issuer_binding: str = "tls-server-name",
    allow_tls_server_auth: bool = True,
    validation_time: Any = None,
    revocation_mode: str = "soft_fail",
    revoked_serials: Optional[Iterable[int]] = None,
    expected_issuer: Optional[str] = None,
) -> ChainVerification:
    """Verify llm_sign.artifact using the supplier chain in an OpenAI response."""

    certificate_chain = certificate_chain_from_openai_response(response)
    key_policy = x509_key_policy_from_certificate_chain(
        certificate_chain,
        trust_anchors=trust_anchors,
        issuer_binding=issuer_binding,
        allow_tls_server_auth=allow_tls_server_auth,
        validation_time=validation_time,
        revocation_mode=revocation_mode,
        revoked_serials=revoked_serials,
        expected_issuer=expected_issuer,
    )
    return verify_artifact(
        artifact_from_openai_response(response),
        key_policy=key_policy,
        platform=platform,
        payloads=payloads,
    )


def verify_openai_response_signature(
    response: Any,
    *,
    trust_anchors: Optional[Sequence[x509.Certificate]] = None,
    payloads: Optional[Mapping[int, Any]] = None,
    platform: Optional[str] = None,
    issuer_binding: str = "tls-server-name",
    allow_tls_server_auth: bool = True,
    validation_time: Any = None,
    revocation_mode: str = "soft_fail",
    revoked_serials: Optional[Iterable[int]] = None,
    expected_issuer: Optional[str] = None,
) -> OpenAIResponseSignatureReport:
    """Verify a response if it carries llm_sign data; unsigned responses are allowed."""

    response_data = openai_response_to_dict(response)
    artifact = _optional_artifact_from_openai_response(response_data)
    if artifact is None:
        return OpenAIResponseSignatureReport(
            has_signature=False,
            host_name=None,
            valid=None,
        )

    host_name = host_name_from_artifact(artifact)
    try:
        if trust_anchors is None:
            trust_anchors = load_system_trust_anchors()
        certificate_chain = certificate_chain_from_openai_response(response_data)
        key_policy = x509_key_policy_from_certificate_chain(
            certificate_chain,
            trust_anchors=trust_anchors,
            issuer_binding=issuer_binding,
            allow_tls_server_auth=allow_tls_server_auth,
            validation_time=validation_time,
            revocation_mode=revocation_mode,
            revoked_serials=revoked_serials,
            expected_issuer=expected_issuer,
        )
        verification = verify_artifact(
            artifact,
            key_policy=key_policy,
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


def load_system_trust_anchors() -> list[x509.Certificate]:
    """Load PEM certificates from the Python/OpenSSL default TLS trust paths."""

    paths = ssl.get_default_verify_paths()
    certificates: list[x509.Certificate] = []
    seen: set[bytes] = set()
    if paths.cafile:
        _extend_unique_certificates(certificates, seen, Path(paths.cafile))
    if paths.capath:
        for path in Path(paths.capath).glob("*"):
            _extend_unique_certificates(certificates, seen, path)
    if not certificates:
        raise ValueError("no system TLS trust anchors were found")
    return certificates


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

    summary: Dict[str, Any] = {
        "has_signature": report.has_signature,
        "host_name": report.host_name,
        "valid": report.valid,
    }
    return summary


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


def _candidate_certificate_chains(
    certificate_chain: Sequence[x509.Certificate],
    trust_anchors: Sequence[x509.Certificate],
) -> list[list[x509.Certificate]]:
    chain = list(certificate_chain)
    if not chain:
        raise ValueError("certificate_chain must contain at least one certificate")
    if any(_same_certificate(chain[-1], anchor) for anchor in trust_anchors):
        return [chain]
    chains = [
        chain + [anchor]
        for anchor in trust_anchors
        if chain[-1].issuer == anchor.subject
    ]
    return chains or [chain]


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


def _extend_unique_certificates(
    certificates: list[x509.Certificate],
    seen: set[bytes],
    path: Path,
) -> None:
    if not path.is_file():
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


def _same_certificate(left: x509.Certificate, right: x509.Certificate) -> bool:
    return left.fingerprint(hashes.SHA256()) == right.fingerprint(hashes.SHA256())


__all__ = [
    "OpenAIResponseSignatureReport",
    "StaticKeyPolicy",
    "X509KeyPolicy",
    "artifact_from_openai_response",
    "certificate_key_id",
    "certificate_chain_from_openai_response",
    "load_signed_blocks",
    "load_system_trust_anchors",
    "host_name_from_artifact",
    "openai_response_signature_summary",
    "openai_response_to_dict",
    "spki_sha256_key_id",
    "trust_public_key",
    "verify_openai_response_signature",
    "verify_openai_response_with_certificate_chain",
    "verification_summary",
    "verify_artifact",
    "verify_with_public_key",
    "x509_key_policy_from_certificate_chain",
]
