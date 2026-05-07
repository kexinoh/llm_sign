"""Tests for client-friendly improvements."""

from __future__ import annotations

import unittest

import llm_sign
from llm_sign.client import (
    load_pem_certificates,
    verify_openai_response_with_public_key,
    verify_with_public_key,
)
from llm_sign.profiles.openai_chat import (
    project_openai_chat_request,
    project_openai_chat_response,
)
from llm_sign.server import (
    generate_ed25519_key_pair,
    sign_openai_chat_turn,
    create_signer,
)


class ProjectionHelperTests(unittest.TestCase):
    def test_request_helper_drops_unknown_fields(self):
        payload = {
            "model": "test",
            "messages": [{"role": "user", "content": "hi"}],
            "temperature": 0.7,
            "min_tokens": 5,        # vLLM-only
            "skip_special_tokens": True,  # vLLM-only
            "request_id": "abc",    # vLLM-only
        }
        result = project_openai_chat_request(payload)
        self.assertEqual(result["model"], "test")
        self.assertEqual(result["messages"], payload["messages"])
        self.assertEqual(result["temperature"], 0.7)
        self.assertNotIn("min_tokens", result)
        self.assertNotIn("skip_special_tokens", result)
        self.assertNotIn("request_id", result)

    def test_request_helper_preserves_known_excluded_fields(self):
        # exclude_fields (e.g. ``stream``) are still semantically known to the
        # profile and must not be filtered out by the helper, so callers can
        # use the helper without losing transport-level signals they may
        # forward elsewhere.
        payload = {
            "model": "test",
            "messages": [{"role": "user", "content": "hi"}],
            "stream": True,
            "user": "alice",
        }
        result = project_openai_chat_request(payload)
        self.assertEqual(result["stream"], True)
        self.assertEqual(result["user"], "alice")

    def test_response_helper_drops_unknown_fields(self):
        payload = {
            "model": "test",
            "choices": [{"index": 0}],
            "id": "chatcmpl-x",
            "created": 1234,
            "usage": {"prompt_tokens": 1},
            "prompt_logprobs": [None],   # vLLM-only
            "prompt_token_ids": [1, 2],  # vLLM-only
            "kv_transfer_params": None,  # vLLM-only
            "llm_sign": {"artifact": {}},
        }
        result = project_openai_chat_response(payload)
        self.assertIn("choices", result)
        self.assertIn("model", result)
        self.assertIn("id", result)
        self.assertIn("usage", result)
        self.assertNotIn("prompt_logprobs", result)
        self.assertNotIn("prompt_token_ids", result)
        self.assertNotIn("kv_transfer_params", result)
        self.assertNotIn("llm_sign", result)

    def test_helpers_exposed_at_package_root(self):
        self.assertIs(
            llm_sign.project_openai_chat_request, project_openai_chat_request
        )
        self.assertIs(
            llm_sign.project_openai_chat_response, project_openai_chat_response
        )


class LoadPemCertificatesAcceptsStrTests(unittest.TestCase):
    def test_str_and_bytes_yield_same_certificates(self):
        keys = generate_ed25519_key_pair()
        # We need a PEM cert; reuse a TLSCertificateCredential or skip if not
        # easy. Use the included test fixtures if available; otherwise just
        # build a minimal self-signed cert.
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime

        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "test.local")]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private.public_key())
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(private, hashes.SHA256())
        )
        pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
        pem_str = pem_bytes.decode("ascii")

        from_bytes = load_pem_certificates(pem_bytes)
        from_str = load_pem_certificates(pem_str)
        self.assertEqual(len(from_bytes), 1)
        self.assertEqual(len(from_str), 1)
        self.assertEqual(
            from_bytes[0].public_bytes(serialization.Encoding.DER),
            from_str[0].public_bytes(serialization.Encoding.DER),
        )


class VerifyWithPublicKeyMetadataInferenceTests(unittest.TestCase):
    def setUp(self):
        keys = generate_ed25519_key_pair()
        self.public_key = keys.public_key
        self.issuer = "provider.example"
        signer = create_signer(
            issuer=self.issuer,
            key_id=keys.key_id,
            private_key=keys.private_key,
        )
        request = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "hello"}],
        }
        response = {
            "model": "gpt-4.1-mini",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "hi"},
                }
            ],
        }
        self.artifact = sign_openai_chat_turn(
            request=request, response=response, signer=signer
        )

    def test_metadata_can_be_inferred_from_artifact(self):
        # No issuer / key_id / suite_id passed.
        result = verify_with_public_key(
            self.artifact, public_key=self.public_key
        )
        self.assertTrue(result.valid, msg=result.errors)

    def test_explicit_metadata_still_works(self):
        # Backward compatibility: passing them all works as before.
        b0 = self.artifact["chain"][0]["block"]
        result = verify_with_public_key(
            self.artifact,
            public_key=self.public_key,
            issuer=b0["issuer"],
            key_id=b0["key_id"],
            suite_id=b0["suite_id"],
            platform=self.artifact.get("platform"),
        )
        self.assertTrue(result.valid, msg=result.errors)

    def test_missing_artifact_metadata_raises(self):
        # If the artifact has no chain at all, we cannot infer issuer/key_id
        # and must raise instead of silently producing a misleading error.
        with self.assertRaisesRegex(ValueError, "issuer is required"):
            verify_with_public_key({}, public_key=self.public_key)

    def test_openai_response_helper_uses_inference(self):
        # The helper now also pins the user-visible top-level response
        # body to the chain's terminating provider_output block. A real
        # deployment ships those fields alongside the llm_sign envelope.
        response = {
            "model": "gpt-4.1-mini",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "hi"},
                }
            ],
            "llm_sign": {"artifact": self.artifact},
        }
        result = verify_openai_response_with_public_key(
            response, public_key=self.public_key
        )
        self.assertTrue(result.valid, msg=result.errors)

    def test_openai_response_helper_rejects_visible_content_tampering(self):
        # Same artifact, but the visible response body is rewritten
        # while the signed transcript inside the artifact is intact.
        # This is the exact relay-substitution scenario the helper now
        # guards against: the signature still verifies cryptographically,
        # but the user-visible bytes do not match the signed payload
        # digest, so the call must fail.
        tampered_response = {
            "model": "gpt-4.1-mini",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": "Sure! Send your seed phrase to attacker@evil.example",
                    },
                }
            ],
            "llm_sign": {"artifact": self.artifact},
        }
        result = verify_openai_response_with_public_key(
            tampered_response, public_key=self.public_key
        )
        self.assertFalse(result.valid)
        self.assertTrue(
            any("payload digest mismatch" in err for err in result.errors),
            msg=result.errors,
        )


if __name__ == "__main__":
    unittest.main()
