"""Server-side signing APIs for producing transcript artifacts."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from llm_sign import __version__ as _LIB_VERSION
from llm_sign.core.blocks import (
    PROVIDER_OUTPUT,
    PROVIDER_RECEIVED_INPUT,
    SignedBlock,
    TranscriptSigner,
)
from llm_sign.keys.ed25519 import Ed25519KeyPair
from llm_sign.profiles.openai_chat import OpenAIChatInputProfile, OpenAIChatOutputProfile
from llm_sign.vendor import TLSCertificateCredential, load_pem_certificates


DEFAULT_ISSUER = "provider.example"
OPENAI_COMPATIBLE_PLATFORM = "openai-compatible"
ARTIFACT_SCHEMA = "llm-sign.artifact.v1"

# Minimum verifier version that can fully process artifacts produced by this
# library version. Bump this only when the wire format introduces a change
# that older verifiers cannot interpret correctly. It is *not* automatically
# tied to ``__version__`` so that minor library updates with backwards
# compatible artifacts do not force every verifier in the wild to upgrade.
DEFAULT_MIN_VERIFIER_VERSION = "0.1.0"


def generate_ed25519_key_pair() -> Ed25519KeyPair:
    """Generate an Ed25519 transcript signing key pair."""

    return Ed25519KeyPair.generate()


def signer_from_key_pair(
    key_pair: Ed25519KeyPair,
    *,
    issuer: str = DEFAULT_ISSUER,
) -> TranscriptSigner:
    """Create a transcript signer from an Ed25519 key pair."""

    return create_signer(
        issuer=issuer,
        key_id=key_pair.key_id,
        private_key=key_pair.private_key,
    )


def create_signer(
    *,
    issuer: str,
    key_id: str,
    private_key: Any,
    suite_id: Optional[str] = None,
) -> TranscriptSigner:
    """Create a transcript signer for a provider-controlled private key."""

    return TranscriptSigner(
        issuer=issuer,
        key_id=key_id,
        private_key=private_key,
        suite_id=suite_id,
    )


def sign_openai_chat_turn(
    *,
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    signer: TranscriptSigner,
) -> Dict[str, Any]:
    """Sign one OpenAI-compatible Chat Completions request/response turn."""

    return sign_openai_chat_turns(
        turns=[(request, response)],
        signer=signer,
    )


def sign_openai_chat_turns(
    *,
    turns: Iterable[Tuple[Mapping[str, Any], Mapping[str, Any]]],
    signer: TranscriptSigner,
) -> Dict[str, Any]:
    """Sign OpenAI-compatible Chat Completions turns into one artifact."""

    input_profile = OpenAIChatInputProfile()
    output_profile = OpenAIChatOutputProfile()
    chain: List[SignedBlock] = []
    artifact_turns: List[Dict[str, Any]] = []
    last_block: Optional[SignedBlock] = None

    for request, response in turns:
        input_block = signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=input_profile,
            payload=request,
            previous=last_block,
        )
        output_block = signer.sign_payload(
            block_type=PROVIDER_OUTPUT,
            profile=output_profile,
            payload=response,
            previous=input_block,
        )
        chain.extend([input_block, output_block])
        artifact_turns.append({"request": dict(request), "response": dict(response)})
        last_block = output_block

    return create_artifact(chain=chain, turns=artifact_turns)


def create_artifact(
    *,
    chain: Sequence[SignedBlock],
    turns: Optional[Sequence[Mapping[str, Any]]] = None,
    payloads: Optional[Mapping[int, Any]] = None,
    platform: str = OPENAI_COMPATIBLE_PLATFORM,
    min_verifier_version: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the standard JSON artifact envelope from signed blocks.

    The ``library`` field is informational metadata: it records the signing
    library version and the minimum verifier version needed to interpret the
    artifact. Both values are excluded from the canonical signing digest, so
    upgrading the library never invalidates already-signed artifacts.

    A verifier observing ``library.min_verifier_version`` higher than its own
    ``llm_sign.__version__`` should refuse the artifact and tell the operator
    to upgrade rather than silently produce a misleading "valid" result.
    """

    artifact: Dict[str, Any] = {
        "schema": ARTIFACT_SCHEMA,
        "library": {
            "name": "llm_sign",
            "version": _LIB_VERSION,
            "min_verifier_version": min_verifier_version or DEFAULT_MIN_VERIFIER_VERSION,
        },
        "platform": platform,
        "chain": [block.to_dict() for block in chain],
    }
    if turns is not None:
        artifact["turns"] = list(turns)
    if payloads is not None:
        artifact["payloads"] = {str(seq): payload for seq, payload in payloads.items()}
    return artifact


__all__ = [
    "ARTIFACT_SCHEMA",
    "DEFAULT_ISSUER",
    "DEFAULT_MIN_VERIFIER_VERSION",
    "OPENAI_COMPATIBLE_PLATFORM",
    "TLSCertificateCredential",
    "create_artifact",
    "create_signer",
    "generate_ed25519_key_pair",
    "load_pem_certificates",
    "sign_openai_chat_turn",
    "sign_openai_chat_turns",
    "signer_from_key_pair",
]
