from copy import deepcopy
import unittest

from llm_sign import Ed25519KeyPair, PayloadState
from llm_sign.blocks import PROVIDER_OUTPUT, PROVIDER_RECEIVED_INPUT, TOOL_RESULT
from llm_sign.client import (
    openai_response_signature_summary,
    openai_response_to_dict,
    verify_openai_response_signature,
)

from tests.e2e_support.client import SignedChatClient
from tests.e2e_support.constants import ISSUER, NUMBER_COUNT, RESPONSE_ID
from tests.e2e_support.payloads import (
    build_chat_request,
    build_multi_tool_call_request,
    build_tool_call_request,
    build_tool_result,
    build_tool_result_request,
    build_tool_results,
    build_tool_results_for_response,
    numbers_content,
    request_numbers,
    response_numbers,
    tool_result_numbers,
)
from tests.e2e_support.proxy import JsonProxyHttpServer
from tests.e2e_support.server import SignedChatHttpServer

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


class E2ESignedClientFlowTests(unittest.TestCase):
    def setUp(self):
        self.keys = Ed25519KeyPair.generate()

    def test_signed_openai_compatible_artifact_verifies_end_to_end(self):
        request = build_chat_request()

        with SignedChatHttpServer(self.keys) as server:
            client = self._client(server)
            completion = client.create_chat_completion(request)

        result = completion.verification

        self.assertTrue(result.valid, result.errors)
        self.assertEqual(
            [block.payload_state for block in result.blocks],
            [PayloadState.PAYLOAD_VERIFIED, PayloadState.PAYLOAD_VERIFIED],
        )
        self.assertEqual(
            [block.signed_block.block.type for block in result.blocks],
            [PROVIDER_RECEIVED_INPUT, PROVIDER_OUTPUT],
        )
        signed_turn = completion.artifact["turns"][0]
        self.assertEqual(len(request_numbers(signed_turn["request"])), NUMBER_COUNT)
        self.assertEqual(len(response_numbers(signed_turn["response"])), NUMBER_COUNT)

    def test_multiturn_signed_chain_verifies_all_request_and_response_blocks(self):
        first_request = build_chat_request()

        with SignedChatHttpServer(self.keys) as server:
            client = self._client(server)
            first_completion = client.create_chat_completion(first_request)
            second_request = build_chat_request(
                turn_index=1,
                previous_turns=[(first_request, first_completion.response)],
            )
            second_completion = client.create_chat_completion(second_request)

        result = second_completion.verification
        second_turn = second_completion.artifact["turns"][1]

        self.assertTrue(first_completion.verification.valid, first_completion.verification.errors)
        self.assertTrue(result.valid, result.errors)
        self.assertEqual([block.signed_block.block.seq for block in result.blocks], [0, 1, 2, 3])
        self.assertEqual(
            [block.signed_block.block.type for block in result.blocks],
            [
                PROVIDER_RECEIVED_INPUT,
                PROVIDER_OUTPUT,
                PROVIDER_RECEIVED_INPUT,
                PROVIDER_OUTPUT,
            ],
        )
        self.assertEqual(
            [block.payload_state for block in result.blocks],
            [PayloadState.PAYLOAD_VERIFIED] * 4,
        )
        self.assertEqual(len(second_completion.artifact["turns"]), 2)
        self.assertEqual(len(second_turn["request"]["messages"]), 3)
        self.assertEqual(request_numbers(second_turn["request"]), request_numbers(second_request))
        self.assertEqual(len(response_numbers(second_turn["response"])), NUMBER_COUNT)

    def test_tool_result_is_signed_as_own_block_between_model_turns(self):
        first_request = build_tool_call_request()
        tool_result = build_tool_result()

        with SignedChatHttpServer(self.keys) as server:
            client = self._client(server)
            tool_call_completion = client.create_chat_completion(first_request)
            second_request = build_tool_result_request(
                first_request,
                tool_call_completion.response,
                tool_result,
            )
            final_completion = client.create_chat_completion(second_request)

        result = final_completion.verification
        tool_payload = final_completion.artifact["payloads"]["2"]

        self.assertTrue(tool_call_completion.verification.valid, tool_call_completion.verification.errors)
        self.assertTrue(result.valid, result.errors)
        self.assertEqual([block.signed_block.block.seq for block in result.blocks], [0, 1, 2, 3, 4])
        self.assertEqual(
            [block.signed_block.block.type for block in result.blocks],
            [
                PROVIDER_RECEIVED_INPUT,
                PROVIDER_OUTPUT,
                TOOL_RESULT,
                PROVIDER_RECEIVED_INPUT,
                PROVIDER_OUTPUT,
            ],
        )
        self.assertEqual(
            [block.payload_state for block in result.blocks],
            [PayloadState.PAYLOAD_VERIFIED] * 5,
        )
        self.assertEqual(len(tool_result_numbers(tool_payload)), NUMBER_COUNT)
        self.assertEqual(tool_result_numbers(tool_payload), tool_result_numbers(tool_result))

    def test_tool_result_block_can_be_digest_only_when_payload_is_omitted(self):
        first_request = build_tool_call_request()
        tool_result = build_tool_result()

        with SignedChatHttpServer(self.keys) as server:
            client = self._client(server)
            tool_call_completion = client.create_chat_completion(first_request)
            second_request = build_tool_result_request(
                first_request,
                tool_call_completion.response,
                tool_result,
            )
            final_completion = client.create_chat_completion(second_request)

        artifact = deepcopy(final_completion.artifact)
        del artifact["payloads"]["2"]
        result = client.verify_artifact(
            artifact,
            payloads={
                0: first_request,
                1: tool_call_completion.response,
                3: second_request,
                4: final_completion.response,
            },
        )

        self.assertTrue(result.valid, result.errors)
        self.assertEqual(result.blocks[2].signed_block.block.type, TOOL_RESULT)
        self.assertEqual(result.blocks[2].payload_state, PayloadState.DIGEST_ONLY)
        self.assertEqual(
            [block.payload_state for block in result.blocks],
            [
                PayloadState.PAYLOAD_VERIFIED,
                PayloadState.PAYLOAD_VERIFIED,
                PayloadState.DIGEST_ONLY,
                PayloadState.PAYLOAD_VERIFIED,
                PayloadState.PAYLOAD_VERIFIED,
            ],
        )

    def test_response_can_return_multiple_tool_calls_and_sign_each_result_block(self):
        first_request = build_multi_tool_call_request()
        tool_results = build_tool_results(2)

        with SignedChatHttpServer(self.keys) as server:
            client = self._client(server)
            tool_call_completion = client.create_chat_completion(first_request)
            second_request = build_tool_result_request(
                first_request,
                tool_call_completion.response,
                tool_results,
            )
            final_completion = client.create_chat_completion(second_request)

        tool_calls = tool_call_completion.response["choices"][0]["message"]["tool_calls"]
        result = final_completion.verification

        self.assertEqual(len(tool_calls), 2)
        self.assertTrue(tool_call_completion.verification.valid, tool_call_completion.verification.errors)
        self.assertTrue(result.valid, result.errors)
        self.assertEqual([block.signed_block.block.seq for block in result.blocks], [0, 1, 2, 3, 4, 5])
        self.assertEqual(
            [block.signed_block.block.type for block in result.blocks],
            [
                PROVIDER_RECEIVED_INPUT,
                PROVIDER_OUTPUT,
                TOOL_RESULT,
                TOOL_RESULT,
                PROVIDER_RECEIVED_INPUT,
                PROVIDER_OUTPUT,
            ],
        )
        self.assertEqual(
            [block.payload_state for block in result.blocks],
            [PayloadState.PAYLOAD_VERIFIED] * 6,
        )
        self.assertEqual(
            tool_result_numbers(final_completion.artifact["payloads"]["2"]),
            tool_result_numbers(tool_results[0]),
        )
        self.assertEqual(
            tool_result_numbers(final_completion.artifact["payloads"]["3"]),
            tool_result_numbers(tool_results[1]),
        )

    def test_proxy_reordering_multiple_tool_results_breaks_followup_request_block(self):
        first_request = build_multi_tool_call_request()
        tool_results = build_tool_results(2)

        with SignedChatHttpServer(self.keys) as server:
            with JsonProxyHttpServer(
                target_base_url=server.openai_base_url,
                request_mutator=_reverse_tool_results,
            ) as proxy:
                client = self._client(proxy)
                tool_call_completion = client.create_chat_completion(first_request)
                second_request = build_tool_result_request(
                    first_request,
                    tool_call_completion.response,
                    tool_results,
                )
                final_completion = client.create_chat_completion(second_request)

        self.assertTrue(tool_call_completion.verification.valid, tool_call_completion.verification.errors)
        self.assertFalse(final_completion.verification.valid)
        self.assertEqual(len(final_completion.verification.blocks), 4)
        self.assertEqual(
            [block.signed_block.block.type for block in final_completion.verification.blocks],
            [
                PROVIDER_RECEIVED_INPUT,
                PROVIDER_OUTPUT,
                TOOL_RESULT,
                TOOL_RESULT,
            ],
        )
        self.assertEqual(
            final_completion.artifact["payloads"]["2"]["tool_call_id"],
            tool_results[1]["tool_call_id"],
        )
        self.assertEqual(
            final_completion.artifact["payloads"]["3"]["tool_call_id"],
            tool_results[0]["tool_call_id"],
        )
        self.assertIn("seq 4: payload digest mismatch", final_completion.verification.errors[0])

    def test_replaying_first_round_tool_signature_and_payload_in_second_round_is_rejected(self):
        first_request = build_tool_call_request(tool_round=0)
        second_request = build_tool_call_request(tool_round=1)

        with SignedChatHttpServer(self.keys) as server:
            client = self._client(server)
            first_tool_call = client.create_chat_completion(first_request)
            first_tool_results = build_tool_results_for_response(first_tool_call.response)
            first_followup_request = build_tool_result_request(
                first_request,
                first_tool_call.response,
                first_tool_results,
            )
            first_final = client.create_chat_completion(first_followup_request)
            second_tool_call = client.create_chat_completion(second_request)
            second_tool_results = build_tool_results_for_response(second_tool_call.response)
            second_followup_request = build_tool_result_request(
                second_request,
                second_tool_call.response,
                second_tool_results,
            )
            second_final = client.create_chat_completion(second_followup_request)

        artifact = deepcopy(second_final.artifact)
        tool_seqs = [
            signed["block"]["seq"]
            for signed in artifact["chain"]
            if signed["block"]["type"] == TOOL_RESULT
        ]
        first_tool_seq, second_tool_seq = tool_seqs[0], tool_seqs[-1]
        artifact["chain"][_chain_index_for_seq(artifact, second_tool_seq)] = deepcopy(
            artifact["chain"][_chain_index_for_seq(artifact, first_tool_seq)]
        )
        artifact["payloads"][str(second_tool_seq)] = deepcopy(artifact["payloads"][str(first_tool_seq)])

        result = client.verify_artifact(artifact)

        self.assertTrue(first_tool_call.verification.valid, first_tool_call.verification.errors)
        self.assertTrue(first_final.verification.valid, first_final.verification.errors)
        self.assertTrue(second_tool_call.verification.valid, second_tool_call.verification.errors)
        self.assertTrue(second_final.verification.valid, second_final.verification.errors)
        self.assertEqual(tool_seqs, [2, 7])
        self.assertFalse(result.valid)
        self.assertEqual(len(result.blocks), 7)
        self.assertIn("sequence gap", result.errors[0])

    @unittest.skipIf(OpenAI is None, "openai SDK is not installed")
    def test_standard_openai_sdk_parses_signed_completion_response(self):
        request = build_chat_request()

        with SignedChatHttpServer(self.keys, response_mode="openai-compatible") as server:
            openai_client = OpenAI(api_key="test-key", base_url=server.openai_base_url)
            completion = openai_client.chat.completions.create(**request)
            response = openai_response_to_dict(completion)
            verifier = self._client(server)
            result = verifier.verify_artifact(
                self._llm_sign_artifact(response),
                request=request,
                response=self._signed_openai_response(response),
            )

        self.assertEqual(completion.id, RESPONSE_ID)
        self.assertEqual(len(response_numbers(response)), NUMBER_COUNT)
        self.assertTrue(result.valid, result.errors)
        self.assertEqual(
            [block.payload_state for block in result.blocks],
            [PayloadState.PAYLOAD_VERIFIED, PayloadState.PAYLOAD_VERIFIED],
        )

    def test_proxy_without_modification_preserves_valid_signed_flow(self):
        request = build_chat_request()

        with SignedChatHttpServer(self.keys) as server:
            with JsonProxyHttpServer(target_base_url=server.openai_base_url) as proxy:
                client = self._client(proxy)
                completion = client.create_chat_completion(request)

        signed_turn = completion.artifact["turns"][0]
        self.assertTrue(completion.verification.valid, completion.verification.errors)
        self.assertEqual(request_numbers(signed_turn["request"]), request_numbers(request))
        self.assertEqual(len(response_numbers(signed_turn["response"])), NUMBER_COUNT)

    def test_proxy_request_modification_breaks_request_block_verification(self):
        request = build_chat_request()

        with SignedChatHttpServer(self.keys) as server:
            with JsonProxyHttpServer(
                target_base_url=server.openai_base_url,
                request_mutator=_modify_request_numbers,
            ) as proxy:
                client = self._client(proxy)
                completion = client.create_chat_completion(request)

        signed_turn = completion.artifact["turns"][0]
        self.assertFalse(completion.verification.valid)
        self.assertEqual(len(completion.verification.blocks), 0)
        self.assertIn("seq 0: payload digest mismatch", completion.verification.errors[0])
        self.assertNotEqual(request_numbers(signed_turn["request"]), request_numbers(request))
        self.assertEqual(
            request_numbers(signed_turn["request"])[0],
            request_numbers(request)[0] + 1,
        )

    def test_proxy_followup_request_modification_breaks_third_block_verification(self):
        first_request = build_chat_request()

        with SignedChatHttpServer(self.keys) as server:
            with JsonProxyHttpServer(
                target_base_url=server.openai_base_url,
                request_mutator=_modify_followup_request_numbers,
            ) as proxy:
                client = self._client(proxy)
                first_completion = client.create_chat_completion(first_request)
                second_request = build_chat_request(
                    turn_index=1,
                    previous_turns=[(first_request, first_completion.response)],
                )
                second_completion = client.create_chat_completion(second_request)

        signed_second_turn = second_completion.artifact["turns"][1]
        self.assertTrue(first_completion.verification.valid, first_completion.verification.errors)
        self.assertFalse(second_completion.verification.valid)
        self.assertEqual(len(second_completion.verification.blocks), 2)
        self.assertEqual(
            [block.signed_block.block.seq for block in second_completion.verification.blocks],
            [0, 1],
        )
        self.assertIn("seq 2: payload digest mismatch", second_completion.verification.errors[0])
        self.assertNotEqual(
            request_numbers(signed_second_turn["request"]),
            request_numbers(second_request),
        )

    def test_proxy_tool_result_modification_breaks_tool_block_verification(self):
        first_request = build_tool_call_request()
        tool_result = build_tool_result()

        with SignedChatHttpServer(self.keys) as server:
            with JsonProxyHttpServer(
                target_base_url=server.openai_base_url,
                request_mutator=_modify_tool_result_numbers,
            ) as proxy:
                client = self._client(proxy)
                tool_call_completion = client.create_chat_completion(first_request)
                second_request = build_tool_result_request(
                    first_request,
                    tool_call_completion.response,
                    tool_result,
                )
                final_completion = client.create_chat_completion(second_request)

        self.assertTrue(tool_call_completion.verification.valid, tool_call_completion.verification.errors)
        self.assertFalse(final_completion.verification.valid)
        self.assertEqual(len(final_completion.verification.blocks), 2)
        self.assertEqual(
            [block.signed_block.block.seq for block in final_completion.verification.blocks],
            [0, 1],
        )
        self.assertIn("seq 2: payload digest mismatch", final_completion.verification.errors[0])

    def test_proxy_dropping_one_of_multiple_tool_results_breaks_followup_request_block(self):
        first_request = build_multi_tool_call_request()
        tool_results = build_tool_results(2)

        with SignedChatHttpServer(self.keys) as server:
            with JsonProxyHttpServer(
                target_base_url=server.openai_base_url,
                request_mutator=_drop_second_tool_result,
            ) as proxy:
                client = self._client(proxy)
                tool_call_completion = client.create_chat_completion(first_request)
                second_request = build_tool_result_request(
                    first_request,
                    tool_call_completion.response,
                    tool_results,
                )
                final_completion = client.create_chat_completion(second_request)

        self.assertTrue(tool_call_completion.verification.valid, tool_call_completion.verification.errors)
        self.assertFalse(final_completion.verification.valid)
        self.assertEqual(len(final_completion.verification.blocks), 3)
        self.assertEqual(
            [block.signed_block.block.type for block in final_completion.verification.blocks],
            [PROVIDER_RECEIVED_INPUT, PROVIDER_OUTPUT, TOOL_RESULT],
        )
        self.assertIn("seq 3: payload digest mismatch", final_completion.verification.errors[0])

    def test_proxy_tampering_second_tool_result_breaks_second_tool_block(self):
        first_request = build_multi_tool_call_request()
        tool_results = build_tool_results(2)

        with SignedChatHttpServer(self.keys) as server:
            with JsonProxyHttpServer(
                target_base_url=server.openai_base_url,
                request_mutator=_modify_second_tool_result_numbers,
            ) as proxy:
                client = self._client(proxy)
                tool_call_completion = client.create_chat_completion(first_request)
                second_request = build_tool_result_request(
                    first_request,
                    tool_call_completion.response,
                    tool_results,
                )
                final_completion = client.create_chat_completion(second_request)

        self.assertTrue(tool_call_completion.verification.valid, tool_call_completion.verification.errors)
        self.assertFalse(final_completion.verification.valid)
        self.assertEqual(len(final_completion.verification.blocks), 3)
        self.assertEqual(
            [block.signed_block.block.seq for block in final_completion.verification.blocks],
            [0, 1, 2],
        )
        self.assertIn("seq 3: payload digest mismatch", final_completion.verification.errors[0])

    def test_proxy_response_modification_breaks_payload_verification(self):
        request = build_chat_request()

        with SignedChatHttpServer(self.keys) as server:
            with JsonProxyHttpServer(
                target_base_url=server.openai_base_url,
                response_mutator=_modify_artifact_response_numbers,
            ) as proxy:
                client = self._client(proxy)
                completion = client.create_chat_completion(request)

        self.assertFalse(completion.verification.valid)
        self.assertEqual(len(completion.verification.blocks), 1)
        self.assertEqual(
            completion.verification.blocks[0].payload_state,
            PayloadState.PAYLOAD_VERIFIED,
        )
        self.assertIn("payload digest mismatch", completion.verification.errors[0])

    def test_client_rejects_tampered_signed_output_payload(self):
        request = build_chat_request()

        with SignedChatHttpServer(self.keys) as server:
            client = self._client(server)
            completion = client.create_chat_completion(request)

        response = completion.artifact["turns"][0]["response"]
        numbers = response_numbers(response)
        numbers[0] += 1
        response["choices"][0]["message"]["content"] = numbers_content(numbers)

        result = client.verify_artifact(
            completion.artifact,
            request=request,
            response=response,
        )

        self.assertFalse(result.valid)
        self.assertIn("payload digest mismatch", result.errors[0])

    @unittest.skipIf(OpenAI is None, "openai SDK is not installed")
    def test_openai_sdk_signature_report_verifies_pinned_public_key_through_proxy(self):
        request = build_chat_request()

        with SignedChatHttpServer(
            self.keys,
            response_mode="openai-compatible",
        ) as server:
            with JsonProxyHttpServer(target_base_url=server.openai_base_url) as proxy:
                openai_client = OpenAI(api_key="test-key", base_url=proxy.openai_base_url)
                completion = openai_client.chat.completions.create(**request)
                report = verify_openai_response_signature(
                    completion,
                    public_key=self.keys.public_key,
                )

        self.assertEqual(
            openai_response_signature_summary(report),
            {
                "has_signature": True,
                "host_name": ISSUER,
                "valid": True,
            },
        )

    @unittest.skipIf(OpenAI is None, "openai SDK is not installed")
    def test_openai_sdk_signature_report_allows_unsigned_response(self):
        request = build_chat_request()

        with SignedChatHttpServer(
            self.keys,
            response_mode="openai-compatible-unsigned",
        ) as server:
            openai_client = OpenAI(api_key="test-key", base_url=server.openai_base_url)
            completion = openai_client.chat.completions.create(**request)
            report = verify_openai_response_signature(completion)

        self.assertEqual(completion.id, RESPONSE_ID)
        self.assertEqual(
            openai_response_signature_summary(report),
            {
                "has_signature": False,
                "host_name": None,
                "valid": None,
            },
        )

    @unittest.skipIf(OpenAI is None, "openai SDK is not installed")
    def test_openai_sdk_signature_report_reports_unknown_without_pinned_key(self):
        request = build_chat_request()

        with SignedChatHttpServer(self.keys, response_mode="openai-compatible") as server:
            openai_client = OpenAI(api_key="test-key", base_url=server.openai_base_url)
            completion = openai_client.chat.completions.create(**request)
            report = verify_openai_response_signature(completion)

        summary = openai_response_signature_summary(report)
        self.assertTrue(summary["has_signature"])
        self.assertEqual(summary["host_name"], ISSUER)
        self.assertIsNone(summary["valid"])

    def _client(self, server: SignedChatHttpServer) -> SignedChatClient:
        return SignedChatClient(
            endpoint=server.chat_completions_url,
            key_id=self.keys.key_id,
            public_key=self.keys.public_key,
        )

    def _llm_sign_artifact(self, response):
        llm_sign = response["llm_sign"]
        return llm_sign["artifact"]

    def _signed_openai_response(self, response):
        response = deepcopy(response)
        response.pop("llm_sign", None)
        return response


def _modify_request_numbers(request):
    numbers = request_numbers(request)
    numbers[0] += 1
    request["messages"][0]["content"] = numbers_content(numbers)
    return request


def _modify_followup_request_numbers(request):
    if len(request["messages"]) == 1:
        return request
    numbers = request_numbers(request)
    numbers[0] += 1
    request["messages"][-1]["content"] = numbers_content(numbers)
    return request


def _reverse_tool_results(request):
    tool_results = [message for message in request.get("messages", []) if message.get("role") == "tool"]
    if len(tool_results) < 2:
        return request
    reversed_tool_results = list(reversed(tool_results))
    tool_index = 0
    messages = []
    for message in request["messages"]:
        if message.get("role") == "tool":
            messages.append(reversed_tool_results[tool_index])
            tool_index += 1
        else:
            messages.append(message)
    request["messages"] = messages
    return request


def _modify_tool_result_numbers(request):
    for message in request.get("messages", []):
        if message.get("role") == "tool":
            numbers = tool_result_numbers(message)
            numbers[0] += 1
            message["content"] = numbers_content(numbers)
    return request


def _drop_second_tool_result(request):
    seen_tool_results = 0
    messages = []
    for message in request.get("messages", []):
        if message.get("role") == "tool":
            seen_tool_results += 1
            if seen_tool_results == 2:
                continue
        messages.append(message)
    request["messages"] = messages
    return request


def _modify_second_tool_result_numbers(request):
    seen_tool_results = 0
    for message in request.get("messages", []):
        if message.get("role") != "tool":
            continue
        seen_tool_results += 1
        if seen_tool_results == 2:
            numbers = tool_result_numbers(message)
            numbers[0] += 1
            message["content"] = numbers_content(numbers)
    return request


def _modify_artifact_response_numbers(envelope):
    response = envelope["artifact"]["turns"][0]["response"]
    numbers = response_numbers(response)
    numbers[0] += 1
    response["choices"][0]["message"]["content"] = numbers_content(numbers)
    return envelope


def _chain_index_for_seq(artifact, seq):
    for index, signed in enumerate(artifact["chain"]):
        if signed["block"]["seq"] == seq:
            return index
    raise AssertionError(f"missing chain block for seq {seq}")


if __name__ == "__main__":
    unittest.main()
