"""LLM transcript signing primitives."""

from . import client, server
from .core.blocks import (
    Block,
    ChainVerification,
    PayloadState,
    SignedBlock,
    TOOL_RESULT,
    TranscriptSigner,
    VerifiedBlock,
    sign_payload,
    verify_chain,
)
from .core.crypto import (
    SignatureSuite,
    infer_suite_for_private_key,
    infer_suite_for_public_key,
    register_signature_suite,
    supported_suite_ids,
)
from .keys.ed25519 import Ed25519KeyPair, StaticKeyPolicy
from .keys.x509 import LLM_SIGN_ISSUER_OID, LLM_SIGN_TRANSCRIPT_EKU_OID, X509KeyPolicy
from .profiles.openai_chat import OpenAIChatInputProfile, OpenAIChatOutputProfile, OpenAIToolResultProfile
from .vendor import TLSCertificateCredential
from .verifier import load_signed_blocks, verify_artifact

__all__ = [
    "Block",
    "ChainVerification",
    "Ed25519KeyPair",
    "OpenAIChatInputProfile",
    "OpenAIChatOutputProfile",
    "OpenAIToolResultProfile",
    "PayloadState",
    "SignedBlock",
    "SignatureSuite",
    "StaticKeyPolicy",
    "TOOL_RESULT",
    "TranscriptSigner",
    "TLSCertificateCredential",
    "LLM_SIGN_ISSUER_OID",
    "LLM_SIGN_TRANSCRIPT_EKU_OID",
    "VerifiedBlock",
    "X509KeyPolicy",
    "client",
    "infer_suite_for_private_key",
    "infer_suite_for_public_key",
    "load_signed_blocks",
    "sign_payload",
    "register_signature_suite",
    "supported_suite_ids",
    "server",
    "verify_artifact",
    "verify_chain",
]
