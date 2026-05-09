import unittest

from llm_sign import (
    Ed25519KeyPair,
    OpenAIChatInputProfile,
    OpenAIChatOutputProfile,
    PayloadState,
    StaticKeyPolicy,
    TranscriptSigner,
    verify_chain,
)
from llm_sign.blocks import PROVIDER_OUTPUT, PROVIDER_RECEIVED_INPUT, SignedBlock


class SignVerifyTests(unittest.TestCase):
    def setUp(self):
        self.key_pair = Ed25519KeyPair.generate()
        self.issuer = "provider.example"
        self.signer = TranscriptSigner(
            issuer=self.issuer,
            key_id=self.key_pair.key_id,
            private_key=self.key_pair.private_key,
        )
        self.key_policy = StaticKeyPolicy(
            {
                (
                    self.issuer,
                    self.key_pair.key_id,
                    "sha256-ed25519-v1",
                ): self.key_pair.public_key
            }
        )
        self.input_profile = OpenAIChatInputProfile()
        self.output_profile = OpenAIChatOutputProfile()
        self.profiles = {
            self.input_profile.profile_id: self.input_profile,
            self.output_profile.profile_id: self.output_profile,
        }

    def test_single_turn_chain_verifies(self):
        request = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "Say hello"}],
        }
        response = {
            "model": "gpt-4.1-mini",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "Hello."},
                }
            ],
        }
        b0 = self.signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=self.input_profile,
            payload=request,
        )
        b1 = self.signer.sign_payload(
            block_type=PROVIDER_OUTPUT,
            profile=self.output_profile,
            payload=response,
            previous=b0,
        )

        result = verify_chain(
            [b0, b1],
            key_policy=self.key_policy,
            profiles=self.profiles,
            payloads={0: request, 1: response},
        )

        self.assertTrue(result.valid, result.errors)
        self.assertEqual(
            [block.payload_state for block in result.blocks],
            [PayloadState.PAYLOAD_VERIFIED, PayloadState.PAYLOAD_VERIFIED],
        )

    def test_tampered_payload_fails(self):
        request = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "Say hello"}],
        }
        signed = self.signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=self.input_profile,
            payload=request,
        )
        tampered = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "Say goodbye"}],
        }

        result = verify_chain(
            [signed],
            key_policy=self.key_policy,
            profiles=self.profiles,
            payloads={0: tampered},
        )

        self.assertFalse(result.valid)
        self.assertIn("payload digest mismatch", result.errors[0])

    def test_tampered_signature_fails(self):
        request = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "Say hello"}],
        }
        signed = self.signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=self.input_profile,
            payload=request,
        )
        bad = SignedBlock(block=signed.block, signature=b"\x00" * 64)

        result = verify_chain(
            [bad],
            key_policy=self.key_policy,
            profiles=self.profiles,
            payloads={0: request},
        )

        self.assertFalse(result.valid)

    def test_multi_turn_chain_verifies(self):
        request1 = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "Remember alpha"}],
        }
        response1 = {
            "model": "gpt-4.1-mini",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "Remembered alpha."},
                }
            ],
        }
        request2 = {
            "model": "gpt-4.1-mini",
            "messages": [
                {"role": "user", "content": "Remember alpha"},
                {"role": "assistant", "content": "Remembered alpha."},
                {"role": "user", "content": "What did I ask you to remember?"},
            ],
        }
        response2 = {
            "model": "gpt-4.1-mini",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "Alpha."},
                }
            ],
        }

        b0 = self.signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=self.input_profile,
            payload=request1,
        )
        b1 = self.signer.sign_payload(
            block_type=PROVIDER_OUTPUT,
            profile=self.output_profile,
            payload=response1,
            previous=b0,
        )
        b2 = self.signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=self.input_profile,
            payload=request2,
            previous=b1,
        )
        b3 = self.signer.sign_payload(
            block_type=PROVIDER_OUTPUT,
            profile=self.output_profile,
            payload=response2,
            previous=b2,
        )

        result = verify_chain(
            [b0, b1, b2, b3],
            key_policy=self.key_policy,
            profiles=self.profiles,
            payloads={0: request1, 1: response1, 2: request2, 3: response2},
        )

        self.assertTrue(result.valid, result.errors)
        self.assertEqual(len(result.blocks), 4)

    def test_chain_rejects_cross_issuer_append(self):
        other_keys = Ed25519KeyPair.generate()
        other_signer = TranscriptSigner(
            issuer="other-provider.example",
            key_id=other_keys.key_id,
            private_key=other_keys.private_key,
        )
        key_policy = StaticKeyPolicy(
            {
                (
                    self.issuer,
                    self.key_pair.key_id,
                    "sha256-ed25519-v1",
                ): self.key_pair.public_key,
                (
                    "other-provider.example",
                    other_keys.key_id,
                    "sha256-ed25519-v1",
                ): other_keys.public_key,
            }
        )
        request = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "Say hello"}],
        }
        response = {
            "model": "gpt-4.1-mini",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "Hello."},
                }
            ],
        }
        b0 = self.signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=self.input_profile,
            payload=request,
        )
        b1 = other_signer.sign_payload(
            block_type=PROVIDER_OUTPUT,
            profile=self.output_profile,
            payload=response,
            previous=b0,
        )

        result = verify_chain(
            [b0, b1],
            key_policy=key_policy,
            profiles=self.profiles,
            payloads={0: request, 1: response},
        )

        self.assertFalse(result.valid)
        self.assertIn("issuer mismatch", result.errors[0])

    def test_missing_payload_is_digest_only_but_chain_valid(self):
        request = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "Say hello"}],
        }
        response = {
            "model": "gpt-4.1-mini",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "Hi"},
                }
            ],
        }
        input_block = self.signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=self.input_profile,
            payload=request,
        )
        output_block = self.signer.sign_payload(
            block_type=PROVIDER_OUTPUT,
            profile=self.output_profile,
            payload=response,
            previous=input_block,
        )

        # The chain itself is well-formed (input + output); the verifier
        # is just not given the input payload to re-canonicalize, so
        # that block stays in the digest_only state. The output is
        # checked against the actual response bytes.
        result = verify_chain(
            [input_block, output_block],
            key_policy=self.key_policy,
            profiles=self.profiles,
            payloads={1: response},
        )

        self.assertTrue(result.valid, result.errors)
        self.assertEqual(result.blocks[0].payload_state, PayloadState.DIGEST_ONLY)
        self.assertEqual(result.blocks[1].payload_state, PayloadState.PAYLOAD_VERIFIED)

    def test_chain_terminating_in_provider_received_input_is_rejected(self):
        # A relay that signs only the request (and never bothers to
        # produce or sign a response) leaves a chain whose last block
        # is provider_received_input. verify_chain must refuse it,
        # otherwise an attacker could ship a chain whose only
        # cryptographic guarantee is "the relay saw this prompt" while
        # the visible content was synthesized.
        request = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "Say hello"}],
        }
        signed = self.signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=self.input_profile,
            payload=request,
        )

        result = verify_chain(
            [signed],
            key_policy=self.key_policy,
            profiles=self.profiles,
        )

        self.assertFalse(result.valid)
        self.assertTrue(
            any(
                "must terminate with a provider_output block" in err
                for err in result.errors
            ),
            msg=result.errors,
        )


if __name__ == "__main__":
    unittest.main()
