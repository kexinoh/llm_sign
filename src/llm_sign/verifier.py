"""High-level artifact verification APIs for CLI and platform integrations."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from .core.blocks import ChainVerification, KeyPolicy, SignedBlock, verify_chain
from .platforms import get_platform_adapter


DEFAULT_PLATFORM = "openai-compatible"


def load_signed_blocks(artifact: Mapping[str, Any]) -> list[SignedBlock]:
    chain = artifact.get("chain", artifact.get("signed_blocks"))
    if chain is None:
        raise ValueError("artifact must contain chain or signed_blocks")
    if not isinstance(chain, list):
        raise ValueError("artifact chain must be a list")
    return [SignedBlock.from_dict(item) for item in chain]


def verify_artifact(
    artifact: Mapping[str, Any],
    *,
    key_policy: KeyPolicy,
    platform: Optional[str] = None,
    payloads: Optional[Mapping[int, Any]] = None,
) -> ChainVerification:
    adapter_name = platform or artifact.get("platform") or DEFAULT_PLATFORM
    adapter = get_platform_adapter(str(adapter_name))
    signed_blocks = load_signed_blocks(artifact)
    verification_payloads: Dict[int, Any] = dict(adapter.payloads_from_artifact(artifact))
    if payloads:
        verification_payloads.update(payloads)
    return verify_chain(
        signed_blocks,
        key_policy=key_policy,
        profiles=adapter.profiles(),
        payloads=verification_payloads,
    )
