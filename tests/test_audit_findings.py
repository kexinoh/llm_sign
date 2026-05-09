"""Regression coverage for the 2026-05 security audit findings.

These tests are written from the audit report verbatim. Each one fails on
pre-fix builds and passes only after the corresponding mitigation is in
place. The intent is to keep the report's PoCs as living guards so the
same class of regression cannot quietly come back.
"""

from __future__ import annotations

import unittest
from copy import deepcopy

from llm_sign import (
    Ed25519KeyPair,
    OpenAIChatInputProfile,
    OpenAIChatOutputProfile,
    StaticKeyPolicy,
    TranscriptSigner,
    verify_chain,
)
from llm_sign.blocks import PROVIDER_OUTPUT, PROVIDER_RECEIVED_INPUT
from llm_sign.client import (
    openai_response_signature_summary,
    verify_openai_response_signature,
    verify_openai_response_with_public_key,
)
from llm_sign.server import (
    attach_signed_artifact_to_openai_response,
    sign_openai_chat_turn,
    signer_from_key_pair,
)


ISSUER = "provider.example"


def _build_request_response():
    request = {
        "model": "gpt-4.1-mini",
        "messages": [{"role": "user", "content": "What is 2+2?"}],
    }
    response = {
        "model": "gpt-4.1-mini",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": "The answer is 4.",
                },
            }
        ],
    }
    return request, response


class AuditFinding1VisibleResponseSubstitutionTests(unittest.TestCase):
    """Audit finding #1: visible response body must match the signed transcript.

    In the vulnerable build a relay could keep the entire ``llm_sign``
    envelope intact (signature, certificate chain, artifact's internal
    ``turns``) and just rewrite ``response["choices"][...]["message"]
    ["content"]`` — the bytes the user actually reads. The verifier
    only canonicalized payloads coming from inside the artifact and
    therefore reported ``valid=True`` on a response whose visible
    content was attacker-controlled.
    """

    def setUp(self) -> None:
        self.keys = Ed25519KeyPair.generate()
        self.signer = signer_from_key_pair(self.keys, issuer=ISSUER)
        self.request, self.response = _build_request_response()
        artifact = sign_openai_chat_turn(
            request=self.request,
            response=self.response,
            signer=self.signer,
        )
        self.signed_response = dict(self.response)
        attach_signed_artifact_to_openai_response(
            self.signed_response, artifact=artifact,
        )

    def test_intact_response_verifies(self):
        result = verify_openai_response_with_public_key(
            self.signed_response, public_key=self.keys.public_key,
        )
        self.assertTrue(result.valid, msg=result.errors)

    def test_visible_choices_content_substitution_is_rejected(self):
        # Exact PoC from the audit report: artifact stays valid, only
        # the visible content is rewritten by the relay.
        tampered = deepcopy(self.signed_response)
        tampered["choices"][0]["message"]["content"] = (
            "Sure! Send your seed phrase to attacker@evil.example"
        )

        result = verify_openai_response_with_public_key(
            tampered, public_key=self.keys.public_key,
        )

        self.assertFalse(result.valid)
        self.assertTrue(
            any("payload digest mismatch" in err for err in result.errors),
            msg=result.errors,
        )

    def test_visible_model_substitution_is_rejected(self):
        # A relay swapping out the model field while leaving the
        # artifact intact: the user thinks they got gpt-4.1-mini's
        # answer when they actually got something else.
        tampered = deepcopy(self.signed_response)
        tampered["model"] = "evil-model-v0"

        result = verify_openai_response_with_public_key(
            tampered, public_key=self.keys.public_key,
        )

        self.assertFalse(result.valid)

    def test_signature_report_marks_substituted_response_invalid(self):
        # Same threat, observed through the non-raising report API
        # platform integrations call.
        tampered = deepcopy(self.signed_response)
        tampered["choices"][0]["message"]["content"] = "I am not actually signed."
        report = verify_openai_response_signature(
            tampered, public_key=self.keys.public_key,
        )
        summary = openai_response_signature_summary(report)
        self.assertEqual(summary["has_signature"], True)
        self.assertEqual(summary["valid"], False)


class AuditFinding2InputOnlyChainsTests(unittest.TestCase):
    """Audit finding #2: a chain with only an input block must not verify.

    In the vulnerable build ``verify_chain`` accepted any chain whose
    inter-block links and per-block signatures were valid, even if the
    chain ended in ``provider_received_input`` (i.e. the response was
    never signed). A relay could then echo the user's request back as
    a signed-looking artifact without producing any signed output,
    and ship arbitrary visible content alongside it.
    """

    def setUp(self) -> None:
        self.key_pair = Ed25519KeyPair.generate()
        self.issuer = ISSUER
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

    def test_chain_with_only_provider_received_input_is_rejected(self):
        request, _ = _build_request_response()
        input_block = self.signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=self.input_profile,
            payload=request,
        )

        result = verify_chain(
            [input_block],
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

    def test_chain_dropped_provider_output_at_tail_is_rejected(self):
        # Sign a full input+output turn, then forge a chain that only
        # carries the input block. This is a relay that signs the
        # request but synthesizes the visible response itself.
        request, response = _build_request_response()
        input_block = self.signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=self.input_profile,
            payload=request,
        )
        # Output block exists but is not included in the shipped chain.
        self.signer.sign_payload(
            block_type=PROVIDER_OUTPUT,
            profile=self.output_profile,
            payload=response,
            previous=input_block,
        )

        result = verify_chain(
            [input_block],  # output stripped before shipping
            key_policy=self.key_policy,
            profiles=self.profiles,
        )

        self.assertFalse(result.valid)


if __name__ == "__main__":
    unittest.main()
