"""OpenAI-compatible Chat Completions canonicalization profiles."""

from __future__ import annotations

from typing import Any, Mapping, Set

from .canonical_json import canonical_json_bytes, project_mapping


class OpenAIChatInputProfile:
    """Canonicalizes OpenAI Chat Completions request-shaped payloads."""

    profile_id = "openai.chat-completions.input.v1"

    # Fields that can affect model-visible input, output semantics, or response
    # shape. Transport, storage, and accounting metadata are intentionally absent.
    include_fields: Set[str] = {
        "audio",
        "frequency_penalty",
        "function_call",
        "functions",
        "logit_bias",
        "max_completion_tokens",
        "max_tokens",
        "messages",
        "modalities",
        "model",
        "n",
        "parallel_tool_calls",
        "prediction",
        "presence_penalty",
        "reasoning_effort",
        "response_format",
        "seed",
        "stop",
        "temperature",
        "tool_choice",
        "tools",
        "top_p",
        "web_search_options",
    }

    exclude_fields: Set[str] = {
        "metadata",
        "service_tier",
        "store",
        "stream",
        "stream_options",
        "user",
    }

    required_fields: Set[str] = {"messages", "model"}

    def canonicalize(self, payload: Mapping[str, Any]) -> bytes:
        projected = project_mapping(
            payload,
            include=self.include_fields,
            exclude=self.exclude_fields,
            required=self.required_fields,
            profile_name=self.profile_id,
        )
        return canonical_json_bytes(projected)


class OpenAIChatOutputProfile:
    """Canonicalizes OpenAI Chat Completions response-shaped payloads."""

    profile_id = "openai.chat-completions.output.v1"

    include_fields: Set[str] = {
        "choices",
        "model",
        "response_format",
    }

    exclude_fields: Set[str] = {
        "created",
        "id",
        "input_user",
        "metadata",
        "object",
        "request_id",
        "seed",
        "service_tier",
        "system_fingerprint",
        "tool_choice",
        "usage",
    }

    required_fields: Set[str] = {"choices", "model"}

    def canonicalize(self, payload: Mapping[str, Any]) -> bytes:
        projected = project_mapping(
            payload,
            include=self.include_fields,
            exclude=self.exclude_fields,
            required=self.required_fields,
            profile_name=self.profile_id,
        )
        return canonical_json_bytes(projected)


class OpenAIToolResultProfile:
    """Canonicalizes OpenAI Chat Completions tool result messages."""

    profile_id = "openai.tool-result.v1"

    include_fields: Set[str] = {
        "content",
        "name",
        "role",
        "tool_call_id",
    }

    exclude_fields: Set[str] = {
        "metadata",
    }

    required_fields: Set[str] = {"content", "role", "tool_call_id"}

    def canonicalize(self, payload: Mapping[str, Any]) -> bytes:
        projected = project_mapping(
            payload,
            include=self.include_fields,
            exclude=self.exclude_fields,
            required=self.required_fields,
            profile_name=self.profile_id,
        )
        return canonical_json_bytes(projected)
