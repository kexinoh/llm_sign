import unittest

import llm_sign
from llm_sign.blocks import PROVIDER_OUTPUT, PROVIDER_RECEIVED_INPUT


class PublicApiTests(unittest.TestCase):
    def test_client_server_facades_sign_and_verify_single_turn(self):
        keys = llm_sign.server.generate_ed25519_key_pair()
        signer = llm_sign.server.signer_from_key_pair(keys)
        request, response = _turn_payload(0)

        artifact = llm_sign.server.sign_openai_chat_turn(
            request=request,
            response=response,
            signer=signer,
        )
        result = llm_sign.client.verify_with_public_key(
            artifact,
            issuer=llm_sign.server.DEFAULT_ISSUER,
            key_id=keys.key_id,
            public_key=keys.public_key,
        )

        # Signatures + chain links verify; payloads are reported as
        # ``digest_only`` because the artifact intentionally no longer
        # echoes the request/response bytes back (that would just be
        # transport overhead — see ``server.sign_openai_chat_turn``).
        # Callers that want full ``payload_verified`` should verify
        # the HTTP envelope via ``verify_openai_response*`` (which
        # pins the user-visible body) or pass the payloads explicitly.
        self.assertTrue(result.valid, result.errors)
        self.assertEqual(
            llm_sign.client.verification_summary(result),
            {
                "valid": True,
                "errors": [],
                "blocks": [
                    {
                        "seq": 0,
                        "type": PROVIDER_RECEIVED_INPUT,
                        "payload_state": "digest_only",
                    },
                    {
                        "seq": 1,
                        "type": PROVIDER_OUTPUT,
                        "payload_state": "digest_only",
                    },
                ],
            },
        )

    def test_client_server_facades_with_explicit_payloads(self):
        # The same artifact, but the caller supplies the original
        # request/response so the full payload digest comparison runs.
        # This is what audit consumers do offline: they kept the
        # bytes out-of-band, then ask the verifier to check them
        # against the artifact.
        keys = llm_sign.server.generate_ed25519_key_pair()
        signer = llm_sign.server.signer_from_key_pair(keys)
        request, response = _turn_payload(0)

        artifact = llm_sign.server.sign_openai_chat_turn(
            request=request,
            response=response,
            signer=signer,
        )
        result = llm_sign.client.verify_with_public_key(
            artifact,
            issuer=llm_sign.server.DEFAULT_ISSUER,
            key_id=keys.key_id,
            public_key=keys.public_key,
            payloads={0: request, 1: response},
        )

        self.assertTrue(result.valid, result.errors)
        self.assertEqual(
            [b.payload_state for b in result.blocks],
            ["payload_verified", "payload_verified"],
        )

    def test_server_facade_signs_multi_turn_artifact(self):
        keys = llm_sign.server.generate_ed25519_key_pair()
        signer = llm_sign.server.signer_from_key_pair(keys)

        artifact = llm_sign.server.sign_openai_chat_turns(
            turns=[_turn_payload(0), _turn_payload(1)],
            signer=signer,
        )
        result = llm_sign.client.verify_with_public_key(
            artifact,
            issuer=llm_sign.server.DEFAULT_ISSUER,
            key_id=keys.key_id,
            public_key=keys.public_key,
        )

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

    def test_optional_openai_response_signature_report_allows_unsigned_response(self):
        response = {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "choices": [],
        }

        report = llm_sign.client.verify_openai_response_signature(response)

        self.assertEqual(
            llm_sign.client.openai_response_signature_summary(report),
            {
                "has_signature": False,
                "host_name": None,
                "valid": None,
            },
        )


def _turn_payload(index):
    request = {
        "model": "gpt-4.1-mini",
        "messages": [{"role": "user", "content": f"Say hello {index}"}],
    }
    response = {
        "model": "gpt-4.1-mini",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": f"Hello {index}."},
            }
        ],
    }
    return request, response


if __name__ == "__main__":
    unittest.main()
