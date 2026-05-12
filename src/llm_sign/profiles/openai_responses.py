"""OpenAI Responses API canonicalization profiles.

The Responses API (``/v1/responses``) is OpenAI's stateful conversation
endpoint: a request may carry ``previous_response_id`` as a pointer to
a prior response whose content the server retains server-side. Because
the server does *not* re-send the prior response inside the new request
body, what this profile signs is necessarily narrower than what the
client might imply:

* The **input profile** covers the user-visible request fields, including
  the ``previous_response_id`` pointer. Signing the pointer means a
  relay cannot rewrite the parent reference without invalidating the
  block; signing the *content* of that prior response is not this
  profile's job — it was already covered by *that turn's* artifact, and
  the client is responsible for linking them locally (see
  :func:`llm_sign.client.verify_openai_responses_chain`).
* The **output profile** covers the fields the client actually consumes
  (``output``, ``status``, ``model`` ...). Per-turn metadata that varies
  on replay (``id``, ``created_at``, ``usage``) is deliberately excluded
  so that canonicalization is stable across transport encoders.

Forking is a legitimate part of the Responses API: a client may issue
multiple requests with the same ``previous_response_id``. Per the
protocol spec, llm_sign guarantees the integrity of each presented
chain but not uniqueness of successors — fork detection is explicitly
out of scope (see ``spec/normalization.md`` §12).
"""

from __future__ import annotations

from typing import Any, Mapping, Set

from .canonical_json import canonical_json_bytes, project_mapping


class OpenAIResponsesInputProfile:
    """Canonicalizes OpenAI Responses API request-shaped payloads."""

    profile_id = "openai.responses.input.v1"

    # Fields that can affect model-visible input, output semantics, or
    # the structural relationship to a prior turn. The
    # ``previous_response_id`` pointer is signed so a relay cannot swap
    # the parent reference without producing a ``payload digest
    # mismatch``; the *content* of the referenced prior turn is signed
    # by its own artifact.
    #
    # ``previous_response_hash`` is the *server-injected* companion to
    # ``previous_response_id``: clients never send it on the wire.
    # When the provider resolves ``previous_response_id`` against its
    # session store, it looks up the hash of the parent turn's artifact
    # and injects it into the signed input payload. This binds the
    # current turn's signature to a *specific* prior artifact rather
    # than to whatever content happens to be sitting under that id
    # string at verification time, so neither server-side store
    # substitution nor a relay grafting the current turn onto a
    # different (but also valid) prior conversation can go undetected.
    include_fields: Set[str] = {
        "frequency_penalty",
        "input",
        "instructions",
        "logit_bias",
        "max_output_tokens",
        "max_tool_calls",
        "model",
        "parallel_tool_calls",
        "presence_penalty",
        "previous_response_hash",
        "previous_response_id",
        "prompt",
        "reasoning",
        "response_format",
        "seed",
        "service_tier",
        "temperature",
        "text",
        "tool_choice",
        "tools",
        "top_k",
        "top_logprobs",
        "top_p",
        "truncation",
    }

    # Transport, storage, accounting, and session-control metadata:
    # these either do not affect generation (``metadata``, ``user``) or
    # control how the server persists the response rather than what
    # it contains (``store``, ``stream``, ``background``,
    # ``previous_input_messages``). ``request_id`` is excluded because
    # the server assigns the canonical id; ``safety_identifier`` and
    # ``prompt_cache_key`` are opaque to the transcript.
    #
    # This set is the *OpenAI-defined* fields we acknowledge but
    # deliberately do not sign. Integration-specific extensions that
    # are not in the OpenAI schema (vLLM's ``vllm_xargs``,
    # ``kv_transfer_params``, ``cache_salt``, ``priority``, ...) do
    # *not* go here — they are stripped earlier by
    # :func:`project_openai_responses_request`, which keeps only
    # fields in ``include ∪ exclude``. Keeping this set tight to the
    # OpenAI schema means llm_sign does not need to track every
    # downstream integration's extension fields.
    exclude_fields: Set[str] = {
        "background",
        "include",
        "metadata",
        "previous_input_messages",
        "prompt_cache_key",
        "safety_identifier",
        "store",
        "stream",
        "user",
    }

    required_fields: Set[str] = {"input", "model"}

    def canonicalize(self, payload: Mapping[str, Any]) -> bytes:
        projected = project_mapping(
            payload,
            include=self.include_fields,
            exclude=self.exclude_fields,
            required=self.required_fields,
            profile_name=self.profile_id,
        )
        return canonical_json_bytes(projected)


def project_openai_responses_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Drop fields the Responses API input profile does not sign.

    Mirror of :func:`llm_sign.profiles.openai_chat.project_openai_chat_request`
    for the Responses API: platform-specific fields that aren't in the
    whitelist are removed before signing so that any downstream
    re-canonicalization produces the same payload digest.
    """

    allowed = (
        OpenAIResponsesInputProfile.include_fields
        | OpenAIResponsesInputProfile.exclude_fields
    )
    return {k: v for k, v in payload.items() if k in allowed}


class OpenAIResponsesOutputProfile:
    """Canonicalizes OpenAI Responses API response-shaped payloads."""

    profile_id = "openai.responses.output.v1"

    # The response body the client reads: what was produced, by which
    # model, how it links back to a prior turn, and its completion
    # status. ``previous_response_id`` is echoed back on the response
    # by vLLM so signing it here lets a verifier cross-check the link
    # without needing the original request.
    include_fields: Set[str] = {
        "incomplete_details",
        "instructions",
        "model",
        "output",
        "output_messages",
        "previous_response_id",
        "status",
    }

    # Fields that change on every call for reasons outside the
    # transcript itself (``id``, ``created_at``, ``usage`` are
    # per-invocation server bookkeeping; ``object`` is a constant tag;
    # ``service_tier`` / ``system_fingerprint`` reflect routing rather
    # than content). Excluding them keeps canonicalization stable
    # across FastAPI encoders.
    #
    # Integration-specific response fields (vLLM's ``kv_transfer_params``,
    # ``input_messages``, ``output_messages``, ...) are *not* listed
    # here for the same reason as on the input side: they are stripped
    # by :func:`project_openai_responses_response` before reaching
    # canonicalization.
    exclude_fields: Set[str] = {
        "background",
        "created_at",
        "frequency_penalty",
        "id",
        "max_output_tokens",
        "max_tool_calls",
        "metadata",
        "object",
        "parallel_tool_calls",
        "presence_penalty",
        "prompt",
        "reasoning",
        "service_tier",
        "system_fingerprint",
        "temperature",
        "text",
        "tool_choice",
        "tools",
        "top_logprobs",
        "top_p",
        "truncation",
        "usage",
        "user",
    }

    required_fields: Set[str] = {"output", "model", "status"}

    def canonicalize(self, payload: Mapping[str, Any]) -> bytes:
        projected = project_mapping(
            payload,
            include=self.include_fields,
            exclude=self.exclude_fields,
            required=self.required_fields,
            profile_name=self.profile_id,
        )
        return canonical_json_bytes(projected)


def project_openai_responses_response(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Drop fields the Responses API output profile does not sign.

    Mirror of :func:`llm_sign.profiles.openai_chat.project_openai_chat_response`.
    """

    allowed = (
        OpenAIResponsesOutputProfile.include_fields
        | OpenAIResponsesOutputProfile.exclude_fields
    )
    return {k: v for k, v in payload.items() if k in allowed}
