"""Tests for the library-version compatibility check on artifacts."""

from __future__ import annotations

import unittest

import llm_sign
from llm_sign.client import (
    verify_openai_response_with_public_key,
    verify_with_public_key,
)
from llm_sign.server import (
    DEFAULT_MIN_VERIFIER_VERSION,
    create_signer,
    generate_ed25519_key_pair,
    sign_openai_chat_turn,
)
from llm_sign.verifier import (
    IncompatibleArtifactVersionError,
    check_artifact_version_compatibility,
)


class _SignedTurnFixture:
    """Reusable signed artifact for tests."""

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


class LibraryMetadataInArtifactTests(unittest.TestCase):
    def test_artifact_carries_library_metadata(self):
        artifact, _ = _SignedTurnFixture.make()
        self.assertIn("library", artifact)
        meta = artifact["library"]
        self.assertEqual(meta["name"], "llm_sign")
        self.assertEqual(meta["version"], llm_sign.__version__)
        self.assertEqual(
            meta["min_verifier_version"], DEFAULT_MIN_VERIFIER_VERSION
        )

    def test_library_metadata_does_not_affect_signature(self):
        # The library field lives at the artifact envelope, never enters the
        # per-block payload digest. We can mutate it freely and verification
        # still succeeds.
        artifact, public_key = _SignedTurnFixture.make()
        artifact["library"]["version"] = "9.9.9"
        # min_verifier_version stays compatible (we are >= 0.1.0)
        result = verify_with_public_key(artifact, public_key=public_key)
        self.assertTrue(result.valid, msg=result.errors)


class VersionCompatibilityCheckTests(unittest.TestCase):
    def test_artifact_without_library_field_is_accepted(self):
        # Pre-versioning artifacts must keep working.
        check_artifact_version_compatibility({"schema": "llm-sign.artifact.v1"})

    def test_artifact_with_lower_min_verifier_is_accepted(self):
        artifact = {
            "library": {
                "name": "llm_sign",
                "version": "0.1.0",
                "min_verifier_version": "0.0.1",
            }
        }
        check_artifact_version_compatibility(
            artifact, installed_version="0.1.0"
        )

    def test_artifact_with_equal_min_verifier_is_accepted(self):
        artifact = {
            "library": {
                "name": "llm_sign",
                "version": "0.5.2",
                "min_verifier_version": "0.5.0",
            }
        }
        check_artifact_version_compatibility(
            artifact, installed_version="0.5.0"
        )

    def test_artifact_requiring_newer_verifier_is_rejected(self):
        artifact = {
            "library": {
                "name": "llm_sign",
                "version": "0.5.0",
                "min_verifier_version": "0.5.0",
            }
        }
        with self.assertRaises(IncompatibleArtifactVersionError) as ctx:
            check_artifact_version_compatibility(
                artifact, installed_version="0.1.0"
            )
        # The error message must guide the operator to upgrade.
        msg = str(ctx.exception)
        self.assertIn("0.5.0", msg)  # required
        self.assertIn("0.1.0", msg)  # installed
        self.assertIn("upgrade", msg.lower())

    def test_verify_artifact_surfaces_incompatibility(self):
        # End-to-end: an honest signed artifact whose min_verifier_version was
        # bumped (simulating a future signer) must be rejected by verify_*.
        artifact, public_key = _SignedTurnFixture.make()
        artifact["library"]["min_verifier_version"] = "99.99.99"
        with self.assertRaises(IncompatibleArtifactVersionError):
            verify_with_public_key(artifact, public_key=public_key)

    def test_verify_openai_response_surfaces_incompatibility(self):
        artifact, public_key = _SignedTurnFixture.make()
        artifact["library"]["min_verifier_version"] = "99.99.99"
        with self.assertRaises(IncompatibleArtifactVersionError):
            verify_openai_response_with_public_key(
                {"llm_sign": {"artifact": artifact}}, public_key=public_key
            )


class VersionParsingTests(unittest.TestCase):
    def test_handles_local_and_prerelease_segments(self):
        # Local (+...) and prerelease (-...) suffixes must not break ordering.
        from llm_sign.verifier import _version_tuple

        self.assertEqual(_version_tuple("0.1.0"), (0, 1, 0))
        self.assertEqual(_version_tuple("0.1.0+local.dev"), (0, 1, 0))
        self.assertEqual(_version_tuple("0.1.0-rc1"), (0, 1, 0))
        self.assertLess(
            _version_tuple("0.1.0"), _version_tuple("0.2.0")
        )
        self.assertLess(
            _version_tuple("0.1.9"), _version_tuple("0.1.10")
        )


if __name__ == "__main__":
    unittest.main()
