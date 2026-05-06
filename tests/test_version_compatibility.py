"""Tests for the artifact protocol-version compatibility gate."""

from __future__ import annotations

import unittest

from llm_sign.client import (
    verify_openai_response_with_public_key,
    verify_with_public_key,
)
from llm_sign.server import (
    PROTOCOL_VERSION,
    create_signer,
    generate_ed25519_key_pair,
    sign_openai_chat_turn,
)
from llm_sign.verifier import (
    SUPPORTED_PROTOCOL_VERSION,
    IncompatibleArtifactVersionError,
    check_artifact_protocol_compatibility,
)


class _SignedTurnFixture:
    @classmethod
    def make(cls):
        keys = generate_ed25519_key_pair()
        signer = create_signer(
            issuer="provider.example",
            key_id=keys.key_id,
            private_key=keys.private_key,
        )
        artifact = sign_openai_chat_turn(
            request={
                "model": "gpt-4.1-mini",
                "messages": [{"role": "user", "content": "hello"}],
            },
            response={
                "model": "gpt-4.1-mini",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "hi"},
                    }
                ],
            },
            signer=signer,
        )
        return artifact, keys.public_key


class ProtocolMetadataInArtifactTests(unittest.TestCase):
    def test_artifact_carries_protocol_metadata(self):
        artifact, _ = _SignedTurnFixture.make()
        self.assertIn("protocol", artifact)
        proto = artifact["protocol"]
        self.assertEqual(proto["version"], PROTOCOL_VERSION)
        self.assertEqual(proto["min_reader_version"], PROTOCOL_VERSION)

    def test_protocol_metadata_does_not_affect_signature(self):
        # `protocol` lives at the artifact envelope and is NOT hashed into
        # the per-block payload digest. We can mutate it freely and
        # verification still succeeds, as long as we don't push
        # min_reader_version beyond what the local build understands.
        artifact, public_key = _SignedTurnFixture.make()
        artifact["protocol"]["version"] = 42
        # min_reader_version stays compatible.
        result = verify_with_public_key(artifact, public_key=public_key)
        self.assertTrue(result.valid, msg=result.errors)

    def test_signer_and_supported_versions_match(self):
        # A single constant governs both the signer's stamp and the reader's
        # ceiling on this build; they must track each other.
        self.assertEqual(PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSION)


class ProtocolCompatibilityGateTests(unittest.TestCase):
    def test_artifact_without_protocol_field_is_accepted(self):
        # Pre-versioning artifacts must keep working.
        check_artifact_protocol_compatibility({"schema": "llm-sign.artifact.v1"})

    def test_artifact_with_same_min_reader_is_accepted(self):
        check_artifact_protocol_compatibility(
            {"protocol": {"version": 1, "min_reader_version": 1}},
            supported_protocol_version=1,
        )

    def test_artifact_with_lower_min_reader_is_accepted(self):
        check_artifact_protocol_compatibility(
            {"protocol": {"version": 3, "min_reader_version": 2}},
            supported_protocol_version=5,
        )

    def test_artifact_requiring_newer_reader_is_rejected(self):
        with self.assertRaises(IncompatibleArtifactVersionError) as ctx:
            check_artifact_protocol_compatibility(
                {"protocol": {"version": 5, "min_reader_version": 5}},
                supported_protocol_version=1,
            )
        msg = str(ctx.exception)
        # Error must clearly tell the operator the two numbers.
        self.assertIn("5", msg)
        self.assertIn("1", msg)
        self.assertIn("Upgrade", msg)

    def test_verify_artifact_surfaces_incompatibility(self):
        artifact, public_key = _SignedTurnFixture.make()
        artifact["protocol"]["min_reader_version"] = 9999
        with self.assertRaises(IncompatibleArtifactVersionError):
            verify_with_public_key(artifact, public_key=public_key)

    def test_verify_openai_response_surfaces_incompatibility(self):
        artifact, public_key = _SignedTurnFixture.make()
        artifact["protocol"]["min_reader_version"] = 9999
        with self.assertRaises(IncompatibleArtifactVersionError):
            verify_openai_response_with_public_key(
                {"llm_sign": {"artifact": artifact}}, public_key=public_key
            )

    def test_non_integer_min_reader_is_ignored(self):
        # Be lenient on malformed/old protocol blocks; refuse only on an
        # unambiguous "your version is too low" signal. A string or missing
        # value is treated as "no protocol-level constraint stated".
        check_artifact_protocol_compatibility(
            {"protocol": {"version": 1, "min_reader_version": "one"}}
        )
        check_artifact_protocol_compatibility({"protocol": {"version": 1}})


if __name__ == "__main__":
    unittest.main()
