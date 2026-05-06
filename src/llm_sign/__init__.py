"""LLM transcript signing primitives."""

from importlib.metadata import PackageNotFoundError as _PkgNotFound
from importlib.metadata import version as _pkg_version

try:
    __version__ = _pkg_version("llm-sign")
except _PkgNotFound:  # pragma: no cover - source checkout without install
    __version__ = "0.0.0+unknown"

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
from .profiles.openai_chat import (
    OpenAIChatInputProfile,
    OpenAIChatOutputProfile,
    OpenAIToolResultProfile,
    project_openai_chat_request,
    project_openai_chat_response,
)
from .vendor import TLSCertificateCredential
from .verifier import load_signed_blocks, verify_artifact

__all__ = [
    "__version__",
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
    "project_openai_chat_request",
    "project_openai_chat_response",
    "sign_payload",
    "register_signature_suite",
    "supported_suite_ids",
    "server",
    "verify_artifact",
    "verify_chain",
]
