"""High-level artifact verification APIs for CLI and platform integrations."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from . import __version__ as _LIB_VERSION
from .core.blocks import ChainVerification, KeyPolicy, SignedBlock, verify_chain
from .platforms import get_platform_adapter


DEFAULT_PLATFORM = "openai-compatible"


class IncompatibleArtifactVersionError(RuntimeError):
    """Raised when the installed llm_sign is too old to verify the artifact.

    The artifact's ``library.min_verifier_version`` field is greater than the
    locally installed ``llm_sign.__version__``. Upgrading the local
    ``llm_sign`` is the only safe action: an older verifier may not
    understand newer profile or chain semantics and could otherwise produce
    a misleading "valid" result.
    """


def load_signed_blocks(artifact: Mapping[str, Any]) -> list[SignedBlock]:
    chain = artifact.get("chain", artifact.get("signed_blocks"))
    if chain is None:
        raise ValueError("artifact must contain chain or signed_blocks")
    if not isinstance(chain, list):
        raise ValueError("artifact chain must be a list")
    return [SignedBlock.from_dict(item) for item in chain]


def check_artifact_version_compatibility(
    artifact: Mapping[str, Any],
    *,
    installed_version: Optional[str] = None,
) -> None:
    """Raise :class:`IncompatibleArtifactVersionError` if local lib is too old.

    Older artifacts (produced before this metadata was introduced) lack the
    ``library`` field and are accepted unconditionally for backwards
    compatibility.
    """
    library = artifact.get("library")
    if not isinstance(library, Mapping):
        return  # pre-versioning artifact, accept
    required = library.get("min_verifier_version")
    if not isinstance(required, str):
        return
    local = installed_version or _LIB_VERSION
    if _version_tuple(local) < _version_tuple(required):
        signer_version = library.get("version")
        raise IncompatibleArtifactVersionError(
            f"This artifact was signed with llm_sign {signer_version!r} and "
            f"requires verifier >= {required}, but the locally installed "
            f"llm_sign is {local}. Upgrade with: "
            f"pip install --upgrade 'llm_sign>={required}'"
        )


def _version_tuple(version: str) -> tuple[int, ...]:
    """Parse ``MAJOR.MINOR.PATCH[...]`` into a comparable tuple.

    Local-version segments after ``+`` (e.g. ``0.1.0+local``) are stripped.
    Pre-release tags after ``-`` are dropped too; SemVer-strict ordering of
    pre-releases is intentionally not handled here because the comparison is
    only used for "do I need to upgrade?" gating.
    """
    base = version.split("+", 1)[0].split("-", 1)[0]
    parts: list[int] = []
    for part in base.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def verify_artifact(
    artifact: Mapping[str, Any],
    *,
    key_policy: KeyPolicy,
    platform: Optional[str] = None,
    payloads: Optional[Mapping[int, Any]] = None,
) -> ChainVerification:
    check_artifact_version_compatibility(artifact)
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
