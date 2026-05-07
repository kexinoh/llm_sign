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

from llm_sign.core.blocks import (
    PROVIDER_OUTPUT,
    PROVIDER_RECEIVED_INPUT,
    ChainVerification,
)
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
    request: Optional[Mapping[str, Any]] = None,
) -> ChainVerification:
    """Verify an OpenAI-compatible response using a pinned public key.

    Convenience wrapper that extracts the artifact from the response and
    delegates to :func:`verify_with_public_key`. All metadata parameters
    behave the same: optional, inferred from the artifact when omitted.

    The user-visible response body — the top-level OpenAI Chat Completions
    fields the caller actually consumed (``choices``, ``model``, ...) —
    is automatically pinned to the chain's terminating ``provider_output``
    block as its expected payload. This closes a substitution attack
    where a relay leaves the signed artifact intact but rewrites the
    visible ``response["choices"][...]`` content. Any divergence between
    the signed transcript and the bytes the user reads results in
    ``valid=False`` with a ``payload digest mismatch`` error.

    If ``request`` is supplied, it is similarly pinned to the chain's
    terminating ``provider_received_input`` block. Callers that need to
    pin earlier turns can still pass an explicit ``payloads`` mapping;
    those entries take precedence over the automatic pinning.
    """

    artifact = artifact_from_openai_response(response)
    auto_payloads = _user_visible_payloads_from_response(
        artifact, response=response, request=request,
    )
    if payloads:
        auto_payloads.update(payloads)
    return verify_with_public_key(
        artifact,
        public_key=public_key,
        issuer=issuer,
        key_id=key_id,
        suite_id=suite_id,
        platform=platform,
        payloads=auto_payloads,
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
    request: Optional[Mapping[str, Any]] = None,
) -> ChainVerification:
    """Verify an OpenAI response using the provider certificate it carries.

    The provider's TLS certificate chain is read from
    ``response["llm_sign"]["certificate_chain"]`` and, by default,
    validated against the system TLS trust store exactly as an HTTPS
    client would validate a server certificate. The transcript is then
    verified with the public key embedded in the trusted leaf.

    Beyond chain authentication and signature verification, this also
    pins the **user-visible** response body — the top-level OpenAI
    fields (``choices``, ``model``, ``response_format``) excluding the
    ``llm_sign`` envelope — to the signed transcript. A relay that
    leaves the artifact intact but rewrites those fields will trigger
    ``payload digest mismatch``. See
    :func:`verify_openai_response_with_public_key` for the same
    automatic pinning behaviour.

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
    request:
        The original request the caller sent to the provider. When
        supplied, it is pinned to the chain's terminating
        ``provider_received_input`` block so a relay rewriting the
        request mid-flight is also caught. Optional because the request
        is not part of the response envelope; if omitted only the
        response body is pinned.

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
        request=request,
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
    request: Optional[Mapping[str, Any]] = None,
) -> OpenAIResponseSignatureReport:
    """Non-raising report on a response's signature status.

    - Unsigned responses yield ``has_signature=False, valid=None``.
    - Signed responses are verified against ``public_key`` when pinned,
      otherwise against the provider certificate embedded in
      ``llm_sign.certificate_chain``. By default the embedded chain is
      validated against the system TLS trust store (see
      :func:`verify_openai_response`); pass ``trust_anchors`` or
      ``verify_tls=False`` to override.
    - The user-visible response body is automatically pinned to the
      chain's terminating ``provider_output`` block (see
      :func:`verify_openai_response_with_public_key`); a relay that
      rewrites visible content yields ``valid=False``.
    - Any failure — untrusted chain, bad signature, missing certificate,
      visible content not matching the signed transcript — yields
      ``valid=False``.
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
        verification = verify_openai_response_with_public_key(
            response_data,
            public_key=resolved_public_key,
            issuer=issuer,
            key_id=key_id,
            suite_id=suite_id,
            platform=platform,
            payloads=payloads,
            request=request,
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


# ---------------------------------------------------------------------------
# OpenAI Responses API wrappers
# ---------------------------------------------------------------------------
#
# The Responses API (``/v1/responses``) is a stateful conversation endpoint:
# a request may carry ``previous_response_id`` as a pointer to a prior
# response retained in the provider's store. The envelope layout is
# identical to Chat Completions — ``response["llm_sign"] = {"artifact":
# ..., "certificate_chain": ...}`` — so the existing
# :func:`verify_openai_response*` helpers already work for it. These
# wrappers exist to make call sites self-documenting and to bundle a
# Responses-specific multi-turn checker (:func:`verify_openai_responses_chain`)
# that stitches together the artifacts of consecutive turns in one
# conversation via their ``previous_response_id`` pointers.


def verify_openai_responses_response_with_public_key(
    response: Mapping[str, Any],
    *,
    public_key: Any,
    issuer: Optional[str] = None,
    key_id: Optional[str] = None,
    suite_id: Optional[str] = None,
    payloads: Optional[Mapping[int, Any]] = None,
    request: Optional[Mapping[str, Any]] = None,
) -> ChainVerification:
    """Verify a Responses API envelope with a pinned signing public key.

    Alias of :func:`verify_openai_response_with_public_key` with the
    ``platform`` pinned to ``"openai-responses"`` so that the
    ``previous_response_id`` pointer is interpreted under the Responses
    API input/output profiles rather than the Chat Completions ones.
    """

    return verify_openai_response_with_public_key(
        response,
        public_key=public_key,
        issuer=issuer,
        key_id=key_id,
        suite_id=suite_id,
        platform="openai-responses",
        payloads=payloads,
        request=request,
    )


def verify_openai_responses_response(
    response: Mapping[str, Any],
    *,
    expected_host: Optional[str] = None,
    trust_anchors: Optional[Sequence[x509.Certificate]] = None,
    verify_tls: bool = True,
    issuer: Optional[str] = None,
    key_id: Optional[str] = None,
    suite_id: Optional[str] = None,
    payloads: Optional[Mapping[int, Any]] = None,
    request: Optional[Mapping[str, Any]] = None,
) -> ChainVerification:
    """Verify a Responses API envelope using its embedded certificate chain.

    Pins the user-visible top-level response body (with the
    ``llm_sign`` envelope stripped) to the artifact's terminating
    ``provider_output`` block — same substitution-attack defence as
    :func:`verify_openai_response` — and verifies the transcript
    signature against the TLS-authenticated leaf public key.

    The user-visible response is projected through
    :class:`llm_sign.profiles.openai_responses.OpenAIResponsesOutputProfile`
    before the digest comparison, so vLLM-only fields (``kv_transfer_params``,
    ``input_messages``, ``output_messages``, ...) that do not appear in
    the signed whitelist do not cause canonicalization to fail.
    """

    return verify_openai_response(
        response,
        expected_host=expected_host,
        trust_anchors=trust_anchors,
        verify_tls=verify_tls,
        issuer=issuer,
        key_id=key_id,
        suite_id=suite_id,
        platform="openai-responses",
        payloads=payloads,
        request=request,
    )


def verify_openai_responses_response_signature(
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
    request: Optional[Mapping[str, Any]] = None,
) -> OpenAIResponseSignatureReport:
    """Non-raising signature report for a Responses API envelope.

    Same behaviour as :func:`verify_openai_response_signature` but
    pinned to the Responses platform (see
    :func:`verify_openai_responses_response` for the projection
    rationale).
    """

    return verify_openai_response_signature(
        response,
        public_key=public_key,
        expected_host=expected_host,
        trust_anchors=trust_anchors,
        verify_tls=verify_tls,
        issuer=issuer,
        key_id=key_id,
        suite_id=suite_id,
        platform="openai-responses",
        payloads=payloads,
        request=request,
    )


@dataclass(frozen=True)
class ResponsesChainVerification:
    """Verification status for a linked sequence of Responses API turns."""

    valid: bool
    errors: List[str]
    # Per-turn per-envelope verification (same order as the input list)
    turns: List[ChainVerification]


def verify_openai_responses_chain(
    turns: Sequence[Mapping[str, Any]],
    *,
    expected_host: Optional[str] = None,
    trust_anchors: Optional[Sequence[x509.Certificate]] = None,
    verify_tls: bool = True,
    public_key: Optional[Any] = None,
    issuer: Optional[str] = None,
    key_id: Optional[str] = None,
    suite_id: Optional[str] = None,
) -> ResponsesChainVerification:
    """Verify a linked sequence of ``/v1/responses`` turns.

    Each element of ``turns`` is a dict ``{"request": ..., "response": ...}``
    captured from one HTTP round-trip, **in chronological order**. This
    helper checks three things:

    1. Each envelope verifies on its own (signature valid, certificate
       chain authenticates, user-visible body pinned to the artifact —
       same guarantees as :func:`verify_openai_responses_response`).
    2. The first request's ``previous_response_id`` is ``None`` (this
       is the conversation root), or matches an externally supplied
       anchor passed as ``turns[0]["request"]["previous_response_id"]``
       if the caller is continuing a pre-existing conversation.
    3. For ``N > 0``, ``turns[N]["request"]["previous_response_id"] ==
       turns[N-1]["response"]["id"]`` — the chain of parent pointers
       is self-consistent. Because the pointer is itself inside the
       signed input payload (see
       :class:`llm_sign.profiles.openai_responses.OpenAIResponsesInputProfile`'s
       ``include_fields``), any relay that rewrote it to fork the
       conversation onto a different parent is caught here.

    Forking is legitimate under the Responses API protocol: the same
    ``previous_response_id`` may be re-used by multiple create calls.
    This function does **not** detect forks; it only certifies that
    *the particular linear sequence the caller presents* is internally
    consistent. Fork detection is explicitly out of scope per
    ``spec/normalization.md`` §12.
    """

    if not turns:
        return ResponsesChainVerification(
            valid=False, errors=["empty turn sequence"], turns=[]
        )

    per_turn_results: List[ChainVerification] = []
    errors: List[str] = []

    for index, turn in enumerate(turns):
        request = turn.get("request")
        response = turn.get("response")
        if not isinstance(request, Mapping) or not isinstance(response, Mapping):
            errors.append(
                f"turn {index}: each turn must be a mapping with "
                "'request' and 'response' fields"
            )
            break

        response_dict = openai_response_to_dict(response)

        # For multi-turn Responses API verification we also reconstruct
        # the server's view of the request. The provider injects
        # ``previous_response_hash`` into the signed input payload,
        # looked up from its own session store. That field is *not*
        # part of what the client sent on the wire, so the client
        # request we hold locally has to be augmented with the hash
        # *we observed* on the parent turn's envelope for the digest
        # comparison to succeed.
        #
        # If the hash we observed agrees with what the server signed,
        # the envelope's input block digest checks out. If it
        # disagrees (store poisoning, cross-session grafting), the
        # digest mismatch is what will flag the attack — precisely the
        # property we wanted this mechanism to give us.
        request_for_pinning: Mapping[str, Any] = request
        if index > 0:
            prior_response_dict = openai_response_to_dict(
                turns[index - 1]["response"]
            )
            observed_parent_hash = _envelope_artifact_hash(prior_response_dict)
            if observed_parent_hash is not None:
                request_for_pinning = {
                    **dict(request),
                    "previous_response_hash": observed_parent_hash,
                }

        # Envelope-level verification (signature, chain, pin user-visible).
        try:
            if public_key is not None:
                verification = verify_openai_responses_response_with_public_key(
                    response_dict,
                    public_key=public_key,
                    issuer=issuer,
                    key_id=key_id,
                    suite_id=suite_id,
                    request=request_for_pinning,
                )
            else:
                verification = verify_openai_responses_response(
                    response_dict,
                    expected_host=expected_host,
                    trust_anchors=trust_anchors,
                    verify_tls=verify_tls,
                    issuer=issuer,
                    key_id=key_id,
                    suite_id=suite_id,
                    request=request_for_pinning,
                )
        except Exception as exc:
            errors.append(f"turn {index}: envelope verification raised: {exc}")
            break

        per_turn_results.append(verification)
        if not verification.valid:
            errors.append(
                f"turn {index}: envelope invalid: {verification.errors}"
            )
            break

        # Parent-pointer consistency: the request claims a parent via
        # previous_response_id, which is itself inside the signed
        # input payload. For turn 0 we only record the response id;
        # callers continuing a prior session are responsible for
        # verifying that session separately.
        if index == 0:
            continue

        claimed_parent = request.get("previous_response_id")
        prior_response_id = _previous_turn_response_id(turns[index - 1])
        if claimed_parent != prior_response_id:
            errors.append(
                f"turn {index}: previous_response_id={claimed_parent!r} does "
                f"not match prior turn response id {prior_response_id!r}"
            )
            break

        # Parent-artifact hash consistency (defence in depth). The
        # provider injects a server-trusted parent hash into the
        # current turn's signed input payload as
        # ``previous_response_hash``. The envelope-level digest check
        # above already catches a hash mismatch (we injected the
        # observed parent hash into ``request_for_pinning`` before
        # calling the verifier — if it disagrees with what the server
        # signed, the input block's digest won't match). This explicit
        # comparison exists to produce a more specific error message
        # than "seq 0: payload digest mismatch", and to detect
        # legitimate downgrade attempts (signed side None while
        # observed side has a hash, or vice versa).
        signed_parent_hash = _signed_previous_response_hash(response_dict)
        observed_parent_hash = _envelope_artifact_hash(
            openai_response_to_dict(turns[index - 1]["response"])
        )
        if signed_parent_hash != observed_parent_hash:
            errors.append(
                f"turn {index}: previous_response_hash mismatch "
                f"(signed={signed_parent_hash!r}, "
                f"observed={observed_parent_hash!r}) — parent artifact "
                "was substituted between signing and verification, or "
                "one side skipped the hash binding"
            )
            break

    return ResponsesChainVerification(
        valid=not errors,
        errors=errors,
        turns=per_turn_results,
    )


def _signed_previous_response_hash(
    response: Mapping[str, Any],
) -> Optional[str]:
    """Return the ``previous_response_hash`` that the provider signed.

    The field lives inside the terminating ``provider_received_input``
    block's canonical payload. It is present only when the provider
    injected a server-trusted parent hash at sign time (Responses API
    only — Chat Completions does not use this field).
    """

    artifact = _optional_artifact_from_openai_response(response)
    if artifact is None:
        return None
    turns_ = artifact.get("turns")
    if not isinstance(turns_, list) or not turns_:
        return None
    last_turn = turns_[-1]
    if not isinstance(last_turn, Mapping):
        return None
    request = last_turn.get("request") or last_turn.get("input")
    if not isinstance(request, Mapping):
        return None
    value = request.get("previous_response_hash")
    return value if isinstance(value, str) else None


def _envelope_artifact_hash(
    response: Mapping[str, Any],
) -> Optional[str]:
    """Return ``response["llm_sign"]["artifact_hash"]`` if present."""

    llm_sign = response.get("llm_sign")
    if not isinstance(llm_sign, Mapping):
        return None
    value = llm_sign.get("artifact_hash")
    return value if isinstance(value, str) else None


def _previous_turn_response_id(turn: Mapping[str, Any]) -> Optional[str]:
    response = turn.get("response")
    if response is None:
        return None
    data = openai_response_to_dict(response)
    value = data.get("id")
    return value if isinstance(value, str) else None


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


def _strip_llm_sign_envelope(response: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``response`` without the ``llm_sign`` envelope.

    The envelope is added by the provider for transport and is not
    part of the OpenAI Chat Completions output schema, so it must be
    excluded before the body is canonicalized for digest comparison.
    """

    return {key: value for key, value in response.items() if key != "llm_sign"}


def _terminal_block_seqs_by_type(
    artifact: Mapping[str, Any],
) -> Dict[str, int]:
    """Return ``{block_type: last seq}`` for terminating-relevant blocks.

    Used to pin the user-visible request/response bytes to the right
    block in the signed chain. We only care about the *last* input and
    the *last* output: those represent the turn the caller actually
    consumed. Earlier turns can still be pinned via explicit
    ``payloads``.
    """

    chain = artifact.get("chain", artifact.get("signed_blocks"))
    seqs: Dict[str, int] = {}
    if not isinstance(chain, list):
        return seqs
    for signed in chain:
        if not isinstance(signed, Mapping):
            continue
        block = signed.get("block")
        if not isinstance(block, Mapping):
            continue
        block_type = block.get("type")
        seq = block.get("seq")
        if not isinstance(block_type, str) or not isinstance(seq, int):
            continue
        seqs[block_type] = seq
    return seqs


def _project_request_for_platform(
    platform: Optional[str],
    request: Mapping[str, Any],
) -> Dict[str, Any]:
    """Apply the platform's request-profile projection to a request body.

    Server-side integrations (``vllm/entrypoints/openai/llm_sign.py``)
    call the matching ``project_*_request`` helper before signing, so
    that their schema-extending fields (``min_tokens``,
    ``prompt_logprobs``, ``kv_transfer_params`` ...) are dropped and
    the canonicalized payload matches what the signer saw. The client
    must apply the same projection to the user-visible request before
    pinning it to the terminating ``provider_received_input`` block —
    otherwise canonicalization trips on "unknown fields" and rejects
    legitimate traffic.
    """

    from llm_sign.profiles.openai_chat import project_openai_chat_request
    from llm_sign.profiles.openai_responses import project_openai_responses_request

    normalized = (platform or "").lower().replace("_", "-")
    if normalized in {"openai-responses", "responses", "openai-responses-api"}:
        return project_openai_responses_request(request)
    # Default: Chat Completions projection. This also covers legacy
    # artifacts where the ``platform`` field is absent.
    return project_openai_chat_request(request)


def _project_response_for_platform(
    platform: Optional[str],
    response: Mapping[str, Any],
) -> Dict[str, Any]:
    """Apply the platform's response-profile projection to a response body."""

    from llm_sign.profiles.openai_chat import project_openai_chat_response
    from llm_sign.profiles.openai_responses import project_openai_responses_response

    normalized = (platform or "").lower().replace("_", "-")
    if normalized in {"openai-responses", "responses", "openai-responses-api"}:
        return project_openai_responses_response(response)
    return project_openai_chat_response(response)


def _user_visible_payloads_from_response(
    artifact: Mapping[str, Any],
    *,
    response: Mapping[str, Any],
    request: Optional[Mapping[str, Any]] = None,
) -> Dict[int, Any]:
    """Map the user-visible request/response onto chain seqs for digest pinning.

    The platform adapter ordinarily pulls payloads out of the artifact's
    own ``turns`` field — but those bytes are written by the signer and
    a relay can keep them aligned with the signature while rewriting
    the **top-level** response body that the caller actually reads.
    This helper takes the top-level response (sans ``llm_sign``
    envelope), and optionally the original request, and pins them to
    the chain's terminating ``provider_output`` / ``provider_received_input``
    blocks. Combined with :func:`llm_sign.core.blocks.verify_chain`'s
    digest check, this guarantees that any divergence between what the
    user sees and what was signed produces ``payload digest mismatch``.

    The response is projected through the platform's response profile
    *before* pinning, so integration-specific extensions the provider
    stripped at sign time (vLLM's ``prompt_logprobs``, ``kv_transfer_params``,
    etc.) do not cause canonicalization to fail on "unknown fields".
    Same treatment for ``request``.
    """

    platform = artifact.get("platform") if isinstance(artifact, Mapping) else None

    seqs = _terminal_block_seqs_by_type(artifact)
    payloads: Dict[int, Any] = {}
    output_seq = seqs.get(PROVIDER_OUTPUT)
    if output_seq is not None:
        stripped_response = _strip_llm_sign_envelope(response)
        payloads[output_seq] = _project_response_for_platform(
            platform, stripped_response,
        )
    if request is not None:
        input_seq = seqs.get(PROVIDER_RECEIVED_INPUT)
        if input_seq is not None:
            payloads[input_seq] = _project_request_for_platform(
                platform, dict(request),
            )
    return payloads


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
    "ResponsesChainVerification",
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
    "verify_openai_responses_chain",
    "verify_openai_responses_response",
    "verify_openai_responses_response_signature",
    "verify_openai_responses_response_with_public_key",
    "verification_summary",
    "verify_with_public_key",
]
