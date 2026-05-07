import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional
from urllib import request as urllib_request

from llm_sign import ChainVerification
from llm_sign.blocks import PROVIDER_OUTPUT, PROVIDER_RECEIVED_INPUT, TOOL_RESULT
from llm_sign.client import (
    StaticKeyPolicy,
    artifact_from_openai_response,
    public_key_from_openai_response,
    verify_artifact,
    verify_openai_response_with_public_key,
)

from tests.e2e_support.constants import ISSUER, SUITE_ID


@dataclass(frozen=True)
class VerifiedChatCompletion:
    artifact: Mapping[str, Any]
    response: Mapping[str, Any]
    verification: ChainVerification


class SignedChatClient:
    def __init__(
        self,
        *,
        endpoint: str,
        key_id: str,
        public_key: Any,
        issuer: str = ISSUER,
    ) -> None:
        self.endpoint = endpoint
        self.key_policy = StaticKeyPolicy({(issuer, key_id, SUITE_ID): public_key})
        self._payloads = {}

    def create_chat_completion(self, request: Mapping[str, Any]) -> VerifiedChatCompletion:
        envelope = self._post_json(request)
        artifact = envelope["artifact"]
        response = artifact["turns"][-1]["response"]
        payloads = self._payloads_for_artifact(artifact, request, response)
        verification = self.verify_artifact(
            artifact,
            payloads=payloads,
        )
        if verification.valid:
            self._payloads = payloads
        return VerifiedChatCompletion(
            artifact=artifact,
            response=response,
            verification=verification,
        )

    def verify_artifact(
        self,
        artifact: Mapping[str, Any],
        *,
        request: Optional[Mapping[str, Any]] = None,
        response: Optional[Mapping[str, Any]] = None,
        turns: Optional[list[tuple[Mapping[str, Any], Mapping[str, Any]]]] = None,
        payloads: Optional[Mapping[int, Any]] = None,
    ) -> ChainVerification:
        verification_payloads = {}
        if payloads is not None:
            verification_payloads.update(payloads)
        elif turns is not None:
            for index, (turn_request, turn_response) in enumerate(turns):
                verification_payloads[index * 2] = turn_request
                verification_payloads[index * 2 + 1] = turn_response
        else:
            if request is not None:
                verification_payloads[0] = request
            if response is not None:
                verification_payloads[1] = response
        return verify_artifact(
            artifact,
            key_policy=self.key_policy,
            payloads=verification_payloads or None,
        )

    def _post_json(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib_request.Request(
            self.endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib_request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def _payloads_for_artifact(
        self,
        artifact: Mapping[str, Any],
        request: Mapping[str, Any],
        response: Mapping[str, Any],
    ) -> dict[int, Any]:
        return _payloads_for_artifact(self._payloads, artifact, request, response)


class EmbeddedCertificateSignedChatClient:
    """Client that reads the provider public key from the response itself.

    The response is expected to carry the provider's TLS certificate at
    ``llm_sign.certificate_chain`` (leaf first). The client extracts the
    public key from the leaf certificate and uses it to verify the
    signed artifact. No CA / PKI validation is performed: trust in the
    certificate comes from the fact that a relay cannot forge a
    signature with the provider's private key.
    """

    def __init__(self, *, endpoint: str) -> None:
        self.endpoint = endpoint
        self._payloads = {}

    def create_chat_completion(self, request: Mapping[str, Any]) -> VerifiedChatCompletion:
        response = self._post_json(request)
        artifact = artifact_from_openai_response(response)
        signed_response = artifact["turns"][-1]["response"]
        payloads = self._payloads_for_artifact(artifact, request, signed_response)
        public_key = public_key_from_openai_response(response)
        verification = verify_openai_response_with_public_key(
            response,
            public_key=public_key,
            payloads=payloads,
        )
        if verification.valid:
            self._payloads = payloads
        return VerifiedChatCompletion(
            artifact=artifact,
            response=signed_response,
            verification=verification,
        )

    def _post_json(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib_request.Request(
            self.endpoint,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib_request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def _payloads_for_artifact(
        self,
        artifact: Mapping[str, Any],
        request: Mapping[str, Any],
        response: Mapping[str, Any],
    ) -> dict[int, Any]:
        return _payloads_for_artifact(self._payloads, artifact, request, response)


def _payloads_for_artifact(
    existing_payloads: Mapping[int, Any],
    artifact: Mapping[str, Any],
    request: Mapping[str, Any],
    response: Mapping[str, Any],
) -> dict[int, Any]:
    payloads = dict(existing_payloads)
    tool_results = {
        message["tool_call_id"]: message
        for message in request.get("messages", [])
        if message.get("role") == "tool"
    }
    for signed in artifact["chain"]:
        block = signed["block"]
        seq = block["seq"]
        if seq in payloads:
            continue
        block_type = block["type"]
        if block_type == TOOL_RESULT:
            tool_result = tool_results.get(_tool_call_id_for_block(artifact, seq))
            if tool_result is not None:
                payloads[seq] = _json_clone(tool_result)
        elif block_type == PROVIDER_RECEIVED_INPUT:
            payloads[seq] = _json_clone(request)
        elif block_type == PROVIDER_OUTPUT:
            payloads[seq] = _json_clone(response)
    return payloads


def _json_clone(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value, sort_keys=True))


def _tool_call_id_for_block(artifact: Mapping[str, Any], seq: int) -> Optional[str]:
    payload = artifact.get("payloads", {}).get(str(seq))
    if isinstance(payload, Mapping):
        tool_call_id = payload.get("tool_call_id")
        if isinstance(tool_call_id, str):
            return tool_call_id
    return None
