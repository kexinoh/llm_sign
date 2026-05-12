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
from llm_sign.profiles.openai_responses import (
    OpenAIResponsesInputProfile,
    OpenAIResponsesOutputProfile,
)
from llm_sign.keys.tls import load_pem_certificates
from llm_sign.vendor import TLSCertificateCredential


DEFAULT_ISSUER = "provider.example"
OPENAI_COMPATIBLE_PLATFORM = "openai-compatible"
OPENAI_RESPONSES_PLATFORM = "openai-responses"
ARTIFACT_SCHEMA = "llm-sign.artifact.v1"

# Minimum verifier version that can fully process artifacts produced by this
# library version. Bump this only when the wire format introduces a change
# that older verifiers cannot interpret correctly. It is *not* automatically
# tied to ``__version__`` so that minor library updates with backwards
# compatible artifacts do not force every verifier in the wild to upgrade.
DEFAULT_MIN_VERIFIER_VERSION = "0.1.0"
# Artifact protocol version this build produces. A single integer tied to
# the wire format (see llm_sign.verifier.SUPPORTED_PROTOCOL_VERSION).
PROTOCOL_VERSION = 1


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
        last_block = output_block

    # Note: we deliberately do NOT echo a copy of (request, response) back
    # in the artifact (no ``turns`` field). The artifact only carries the
    # signed chain — block digests and signatures, plus the certificate
    # chain on the envelope. The user-visible HTTP body is the canonical
    # source of the request/response bytes; that's what the client
    # already consumes and pins to the chain's terminating blocks.
    # Echoing the same bytes a second time inside the envelope would be
    # ~28% wire overhead with no security benefit; an audit consumer
    # who wants the original bytes is responsible for keeping the HTTP
    # envelope (or its top-level fields) alongside the artifact.
    return create_artifact(chain=chain)


def sign_openai_responses_turn(
    *,
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    signer: TranscriptSigner,
    parent_hash: Optional[str] = None,
    start_seq: int = 0,
) -> Dict[str, Any]:
    """Sign one OpenAI Responses API request/response turn.

    Unlike :func:`sign_openai_chat_turn`, the Responses API is stateful:
    a request carries ``previous_response_id`` as a pointer to a prior
    turn whose content lives in the server's store, not in the current
    request body. This function signs the pointer (via the input
    profile's whitelist) but *not* the content of that prior turn —
    that was already signed by the prior turn's own artifact. The
    client is responsible for linking consecutive artifacts locally
    (see ``llm_sign.client.verify_openai_responses_chain``).

    Each call produces its own self-contained 2-block chain. ``seq``
    on the input block defaults to 0; ``start_seq`` lets callers pick
    up numbering from a prior turn so multi-turn Responses sessions
    have monotonically-increasing seq across turns (turn 1 = 0,1;
    turn 2 = 2,3; turn 3 = 4,5; etc). The chain itself is still
    independent — ``prev_block_digest`` on the first block is
    ``null`` regardless of ``start_seq``, because forked turns (the
    same ``previous_response_id`` referenced twice) each get their
    own artifact and we don't pretend they form a single chain
    extension. The cross-turn link is by ``previous_response_hash``
    in the signed input payload (see ``parent_hash``).

    ``parent_hash``: when supplied, the server's trusted hash of the
    ``previous_response_id`` turn's artifact. It is injected into the
    signed input payload under ``previous_response_hash`` so the
    current turn's signature is bound to a specific parent artifact,
    not merely to whatever content is currently sitting under that id
    string. Clients that verify multi-turn sessions cross-check this
    signed field against the hash they observed on the prior turn's
    envelope; any mismatch signals that the parent was substituted
    between signing and verification (e.g. via session-store
    poisoning, or a relay that showed the client a different parent
    from the one the provider actually continued). Server integrations
    should derive the hash from their own session store (not from
    client-supplied input) — this is what makes the cross-check
    meaningful.
    """

    input_profile = OpenAIResponsesInputProfile()
    output_profile = OpenAIResponsesOutputProfile()

    signed_request: Mapping[str, Any]
    if parent_hash is not None:
        # Inject the server-trusted parent hash into the signed input.
        # We avoid mutating the caller's dict.
        signed_request = {**dict(request), "previous_response_hash": parent_hash}
    else:
        signed_request = request

    input_block = signer.sign_payload(
        block_type=PROVIDER_RECEIVED_INPUT,
        profile=input_profile,
        payload=signed_request,
        start_seq=start_seq,
    )
    output_block = signer.sign_payload(
        block_type=PROVIDER_OUTPUT,
        profile=output_profile,
        payload=response,
        previous=input_block,
    )

    return create_artifact(
        chain=[input_block, output_block],
        platform=OPENAI_RESPONSES_PLATFORM,
    )


def artifact_terminal_digest(artifact: Mapping[str, Any]) -> Optional[str]:
    """Return the base64url-encoded block_digest of the chain's last block.

    This is the canonical "fingerprint" of an artifact — every byte
    that affects the signed transcript (payload digests, block
    metadata, previous-block links) flows into this digest, and the
    digest itself is part of what the provider's key signs at the
    terminating block. Downstream integrations can use this as the
    ``parent_hash`` to bind a later turn to this specific artifact.

    The digest is recomputed from the block's canonical encoding
    rather than read from the wire — there is no ``block_digest``
    field on the wire because it would just be a deterministic copy
    of what every honest verifier computes for itself anyway.

    Returns ``None`` if the artifact has no chain (malformed input)
    or the terminal block is malformed.
    """

    from llm_sign.core.base64 import b64url_encode
    from llm_sign.core.blocks import Block

    chain = artifact.get("chain", artifact.get("signed_blocks"))
    if not isinstance(chain, list) or not chain:
        return None
    last = chain[-1]
    if not isinstance(last, Mapping):
        return None
    block_data = last.get("block")
    if not isinstance(block_data, Mapping):
        return None
    # ``artifact.common`` hoists fields that are constant across the
    # chain; merge them back so ``Block.from_dict`` sees the full
    # block dict.
    common = artifact.get("common")
    if isinstance(common, Mapping):
        merged = dict(common)
        merged.update(block_data)
        block_data = merged
    try:
        block = Block.from_dict(block_data)
        return b64url_encode(block.digest())
    except (KeyError, TypeError, ValueError):
        return None


def create_artifact(
    *,
    chain: Sequence[SignedBlock],
    turns: Optional[Sequence[Mapping[str, Any]]] = None,
    payloads: Optional[Mapping[int, Any]] = None,
    platform: str = OPENAI_COMPATIBLE_PLATFORM,
    min_reader_version: Optional[int] = None,
) -> Dict[str, Any]:
    """Build the standard JSON artifact envelope from signed blocks.

    The ``protocol`` field records the artifact's wire protocol version
    and the minimum reader version needed to interpret it. Both values
    live at the envelope level, outside the per-block payload digest, so
    this metadata never affects signature validity.

    A reader whose ``SUPPORTED_PROTOCOL_VERSION`` is lower than the
    artifact's ``protocol.min_reader_version`` should refuse it (see
    :func:`llm_sign.verifier.check_artifact_protocol_compatibility`)
    rather than silently produce a misleading "valid" result.
    """

    artifact: Dict[str, Any] = {
        "schema": ARTIFACT_SCHEMA,
        "protocol": {
            "version": PROTOCOL_VERSION,
            "min_reader_version": (
                min_reader_version if min_reader_version is not None
                else PROTOCOL_VERSION
            ),
        },
        "platform": platform,
    }

    # Hoist block fields that are constant across the entire chain
    # into a shared ``common`` envelope. Verifiers merge ``common``
    # back into each block dict before reconstructing the canonical
    # block bytes, so the signer's view is unchanged. The four
    # hoisted fields are equality-enforced across blocks by
    # ``verify_chain``'s prev-link checks (suite_id/issuer/version
    # mismatch raises) — this is just the wire serialization
    # following suit. ``key_id`` is hoisted opportunistically; an
    # extension that mixed signers within a chain would keep it
    # per-block.
    signed_dicts = [block.to_dict() for block in chain]
    block_dicts = [signed["block"] for signed in signed_dicts]
    common: Dict[str, Any] = {}
    if block_dicts:
        for key in ("version", "suite_id", "issuer", "key_id"):
            values = {b.get(key) for b in block_dicts}
            if len(values) == 1 and None not in values:
                common[key] = block_dicts[0][key]
                for b in block_dicts:
                    b.pop(key, None)
    if common:
        artifact["common"] = common
    artifact["chain"] = signed_dicts

    if turns is not None:
        artifact["turns"] = list(turns)
    if payloads is not None:
        artifact["payloads"] = {str(seq): payload for seq, payload in payloads.items()}
    return artifact


def attach_signed_artifact_to_openai_response(
    response: Dict[str, Any],
    *,
    artifact: Mapping[str, Any],
    credential: Optional[TLSCertificateCredential] = None,
    certificate_chain_pem: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Attach a signed artifact to an OpenAI-compatible response in-place.

    Writes ``response["llm_sign"] = {"artifact": artifact, ...}`` and, if
    the provider has a TLS credential or PEM chain handy, also attaches
    ``response["llm_sign"]["certificate_chain"]``. Clients read the
    provider's signing public key out of that chain — the relay between
    client and provider cannot forge it because it does not hold the
    provider's private key, and swapping the chain would cause the
    signed ``key_id`` to no longer match the leaf public key.

    Additionally writes ``response["llm_sign"]["artifact_hash"]`` — the
    base64url-encoded ``block_digest`` of the artifact's terminating
    block (see :func:`artifact_terminal_digest`). This is a
    convenience copy of a value already implicit in the signed chain;
    Responses API server integrations persist the response envelope
    (including this field) in their session store so they can later
    inject the parent's hash into the signed input of a follow-up turn.

    Returns ``response`` for convenience.
    """

    llm_sign: Dict[str, Any] = {"artifact": dict(artifact)}
    if certificate_chain_pem is None and credential is not None:
        certificate_chain_pem = credential.certificate_chain_pem()
    if certificate_chain_pem is not None:
        llm_sign["certificate_chain"] = list(certificate_chain_pem)
    terminal_digest = artifact_terminal_digest(artifact)
    if terminal_digest is not None:
        llm_sign["artifact_hash"] = terminal_digest
    response["llm_sign"] = llm_sign
    return response


__all__ = [
    "ARTIFACT_SCHEMA",
    "DEFAULT_ISSUER",
    "DEFAULT_MIN_VERIFIER_VERSION",
    "OPENAI_COMPATIBLE_PLATFORM",
    "OPENAI_RESPONSES_PLATFORM",
    "PROTOCOL_VERSION",
    "TLSCertificateCredential",
    "artifact_terminal_digest",
    "attach_signed_artifact_to_openai_response",
    "create_artifact",
    "create_signer",
    "generate_ed25519_key_pair",
    "load_pem_certificates",
    "sign_openai_chat_turn",
    "sign_openai_chat_turns",
    "sign_openai_responses_turn",
    "signer_from_key_pair",
]
