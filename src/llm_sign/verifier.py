"""High-level artifact verification APIs for CLI and platform integrations."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from .core.blocks import ChainVerification, KeyPolicy, SignedBlock, verify_chain
from .platforms import get_platform_adapter


DEFAULT_PLATFORM = "openai-compatible"

# Protocol version this build understands. Unlike the package version, this
# is a single monotonically-increasing integer tied to the wire format. It
# bumps only when an artifact produced by a newer signer cannot be safely
# interpreted by a reader at the previous version; unrelated library changes
# (bug fixes, refactors, added convenience helpers, new platforms) MUST NOT
# bump it.
SUPPORTED_PROTOCOL_VERSION = 1


class IncompatibleArtifactVersionError(RuntimeError):
    """Raised when the artifact's protocol version is newer than we can read.

    The ``protocol.min_reader_version`` field is higher than this build's
    :data:`SUPPORTED_PROTOCOL_VERSION`. An older reader may not understand
    the newer wire semantics and could otherwise produce a misleading
    "valid" result; refusing is the only safe behavior.
    """


def load_signed_blocks(artifact: Mapping[str, Any]) -> list[SignedBlock]:
    chain = artifact.get("chain", artifact.get("signed_blocks"))
    if chain is None:
        raise ValueError("artifact must contain chain or signed_blocks")
    if not isinstance(chain, list):
        raise ValueError("artifact chain must be a list")
    return [SignedBlock.from_dict(item) for item in chain]


def check_artifact_protocol_compatibility(
    artifact: Mapping[str, Any],
    *,
    supported_protocol_version: int = SUPPORTED_PROTOCOL_VERSION,
) -> None:
    """Raise :class:`IncompatibleArtifactVersionError` if we cannot read it.

    Artifacts without a ``protocol`` field are treated as protocol version 1
    (the value in use when this field was introduced) and accepted.
    """
    protocol = artifact.get("protocol")
    if not isinstance(protocol, Mapping):
        return
    required = protocol.get("min_reader_version")
    if not isinstance(required, int):
        return
    if required > supported_protocol_version:
        raise IncompatibleArtifactVersionError(
            f"This artifact uses llm_sign protocol version {required} but "
            f"this build only understands up to version "
            f"{supported_protocol_version}. Upgrade llm_sign to verify it."
        )


def verify_artifact(
    artifact: Mapping[str, Any],
    *,
    key_policy: KeyPolicy,
    platform: Optional[str] = None,
    payloads: Optional[Mapping[int, Any]] = None,
) -> ChainVerification:
    check_artifact_protocol_compatibility(artifact)
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
