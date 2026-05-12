"""Adapter for OpenAI Responses API artifacts."""

from __future__ import annotations

from typing import Any, Dict, Mapping

from llm_sign.core.blocks import PROVIDER_OUTPUT, PROVIDER_RECEIVED_INPUT
from llm_sign.core.profiles import Profile
from llm_sign.profiles.openai_responses import (
    OpenAIResponsesInputProfile,
    OpenAIResponsesOutputProfile,
)


class OpenAIResponsesAdapter:
    name = "openai-responses"
    aliases = ("responses", "openai-responses-api")

    def __init__(self) -> None:
        self.input_profile = OpenAIResponsesInputProfile()
        self.output_profile = OpenAIResponsesOutputProfile()

    def profiles(self) -> Mapping[str, Profile]:
        return {
            self.input_profile.profile_id: self.input_profile,
            self.output_profile.profile_id: self.output_profile,
        }

    def payloads_from_artifact(self, artifact: Mapping[str, Any]) -> Mapping[int, Any]:
        """Pull seq-indexed payloads from an artifact's ``turns`` and ``payloads``.

        Same layout as the Chat Completions adapter — each turn is an
        ``{"request": ..., "response": ...}`` pair, mapped onto the
        ``provider_received_input`` / ``provider_output`` blocks in
        order. Responses API artifacts are always single-turn in the
        current integration (one HTTP request = one artifact = one
        turn) but we handle the multi-turn case too for completeness
        and audit-log reconstruction.
        """

        payloads: Dict[int, Any] = {}
        for key, value in artifact.get("payloads", {}).items():
            payloads[int(key)] = value

        turns = artifact.get("turns", [])
        if not artifact.get("chain"):
            # Legacy shape (no chain): fall back to positional mapping.
            for index, turn in enumerate(turns):
                if not isinstance(turn, Mapping):
                    raise ValueError("artifact turns must be objects")
                request = turn.get("request", turn.get("input"))
                response = turn.get("response", turn.get("output"))
                if request is not None:
                    payloads.setdefault(index * 2, request)
                if response is not None:
                    payloads.setdefault(index * 2 + 1, response)
            return payloads

        turn_index = 0
        for signed in artifact.get("chain", []):
            block = signed.get("block", {})
            seq = int(block["seq"])
            if seq in payloads:
                if block.get("type") == PROVIDER_OUTPUT:
                    turn_index += 1
                continue
            if turn_index >= len(turns):
                continue
            turn = turns[turn_index]
            if not isinstance(turn, Mapping):
                raise ValueError("artifact turns must be objects")
            block_type = block.get("type")
            if block_type == PROVIDER_RECEIVED_INPUT:
                request = turn.get("request", turn.get("input"))
                if request is not None:
                    payloads[seq] = request
            elif block_type == PROVIDER_OUTPUT:
                response = turn.get("response", turn.get("output"))
                if response is not None:
                    payloads[seq] = response
                turn_index += 1

        return payloads
