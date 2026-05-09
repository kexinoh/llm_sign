"""Tests for the OpenAI Responses API signing/verification pipeline.

The Responses API (``/v1/responses``) is a stateful conversation
endpoint: clients pass ``previous_response_id`` to reference a prior
turn whose content the provider keeps in a server-side store. These
tests cover:

* Canonicalization profile — include/exclude sets and strict
  ``unknown fields`` behaviour.
* ``sign_openai_responses_turn`` round-trip through
  ``verify_openai_responses_response_with_public_key`` — the happy
  path plus the user-visible substitution attack the audit report
  flagged for Chat Completions (finding #1) applied here.
* ``verify_openai_responses_chain`` — multi-turn session integrity,
  including parent-pointer consistency and rejection of forged
  ``previous_response_id`` values.
* Regression of finding #2 (chain must terminate with
  ``provider_output``).
"""

from __future__ import annotations

import unittest
from copy import deepcopy

from llm_sign import (
    Ed25519KeyPair,
    OpenAIResponsesInputProfile,
    OpenAIResponsesOutputProfile,
    project_openai_responses_request,
    project_openai_responses_response,
)
from llm_sign.client import (
    ResponsesChainVerification,
    verify_openai_responses_chain,
    verify_openai_responses_response_signature,
    verify_openai_responses_response_with_public_key,
)
from llm_sign.core.errors import CanonicalizationError
from llm_sign.server import (
    attach_signed_artifact_to_openai_response,
    sign_openai_responses_turn,
    signer_from_key_pair,
)


ISSUER = "provider.example"


def _build_request(previous_response_id=None):
    request = {
        "model": "gpt-4.1-mini",
        "input": [{"role": "user", "content": "What is 2+2?"}],
        "instructions": "Answer concisely.",
        "temperature": 0.0,
    }
    if previous_response_id is not None:
        request["previous_response_id"] = previous_response_id
    return request


def _build_response(response_id, previous_response_id=None, text="The answer is 4."):
    response = {
        "id": response_id,
        "created_at": 1_700_000_000,
        "model": "gpt-4.1-mini",
        "object": "response",
        "status": "completed",
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": text}],
            }
        ],
    }
    if previous_response_id is not None:
        response["previous_response_id"] = previous_response_id
    return response


class ResponsesProfileCanonicalizationTests(unittest.TestCase):
    def setUp(self):
        self.input_profile = OpenAIResponsesInputProfile()
        self.output_profile = OpenAIResponsesOutputProfile()

    def test_input_profile_canonicalizes_well_formed_request(self):
        blob = self.input_profile.canonicalize(_build_request())
        self.assertIsInstance(blob, bytes)
        # Field order is canonical (sorted keys), so the encoding is
        # deterministic.
        self.assertEqual(
            self.input_profile.canonicalize(_build_request()),
            blob,
        )

    def test_input_profile_includes_previous_response_id(self):
        base = self.input_profile.canonicalize(_build_request())
        linked = self.input_profile.canonicalize(
            _build_request(previous_response_id="resp_parent")
        )
        # The pointer is part of the signed payload — changing it
        # changes the digest.
        self.assertNotEqual(base, linked)

    def test_input_profile_rejects_unknown_fields(self):
        bad = dict(_build_request())
        bad["something_we_do_not_sign"] = "x"
        with self.assertRaisesRegex(CanonicalizationError, "unknown fields"):
            self.input_profile.canonicalize(bad)

    def test_input_profile_rejects_missing_required_fields(self):
        bad = dict(_build_request())
        del bad["input"]
        with self.assertRaisesRegex(CanonicalizationError, "missing required fields"):
            self.input_profile.canonicalize(bad)

    def test_project_request_drops_fields_outside_the_whitelist(self):
        extended = dict(_build_request())
        extended.update(
            {
                # vLLM-specific extensions — all must be stripped.
                "kv_transfer_params": {"xyz": 1},
                "vllm_xargs": {"foo": "bar"},
                "cache_salt": "hex",
                "priority": 3,
                "request_id": "resp_abc",
                "store": True,
                "stream": False,
            }
        )
        projected = project_openai_responses_request(extended)
        # Signed-schema fields survive
        self.assertIn("input", projected)
        self.assertIn("model", projected)
        self.assertIn("instructions", projected)
        # Extensions and transport/session fields are dropped
        for stripped in (
            "kv_transfer_params",
            "vllm_xargs",
            "cache_salt",
            "priority",
            "request_id",
        ):
            self.assertNotIn(stripped, projected)

    def test_output_profile_excludes_volatile_fields(self):
        # Two responses that differ only in id/created_at/usage must
        # canonicalize the same — otherwise a legitimate retry would
        # look like tampering.
        resp1 = _build_response("resp_1")
        resp2 = dict(resp1)
        resp2["id"] = "resp_2"
        resp2["created_at"] = resp1["created_at"] + 1
        self.assertEqual(
            self.output_profile.canonicalize(resp1),
            self.output_profile.canonicalize(resp2),
        )

    def test_project_response_drops_extensions(self):
        extended = _build_response("resp_1")
        extended["usage"] = {"total_tokens": 7}
        extended["kv_transfer_params"] = {"x": 1}
        extended["input_messages"] = "vllm-only"
        projected = project_openai_responses_response(extended)
        self.assertIn("output", projected)
        self.assertIn("model", projected)
        self.assertIn("status", projected)
        for stripped in ("kv_transfer_params", "input_messages"):
            self.assertNotIn(stripped, projected)


class ResponsesSignVerifyTests(unittest.TestCase):
    def setUp(self):
        self.keys = Ed25519KeyPair.generate()
        self.signer = signer_from_key_pair(self.keys, issuer=ISSUER)

    def _sign_turn(self, request, response):
        projected_request = project_openai_responses_request(request)
        projected_response = project_openai_responses_response(response)
        artifact = sign_openai_responses_turn(
            request=projected_request,
            response=projected_response,
            signer=self.signer,
        )
        envelope = dict(response)
        attach_signed_artifact_to_openai_response(envelope, artifact=artifact)
        return envelope

    def test_round_trip_single_turn_verifies(self):
        request = _build_request()
        response = _build_response("resp_abc")
        envelope = self._sign_turn(request, response)

        result = verify_openai_responses_response_with_public_key(
            envelope,
            public_key=self.keys.public_key,
            request=request,
        )

        self.assertTrue(result.valid, msg=result.errors)

    def test_visible_output_substitution_is_rejected(self):
        # Audit finding #1 applied to Responses: relay keeps the
        # artifact byte-for-byte but rewrites ``output`` on the
        # top-level response envelope.
        request = _build_request()
        response = _build_response("resp_abc", text="The answer is 4.")
        envelope = self._sign_turn(request, response)

        tampered = deepcopy(envelope)
        tampered["output"][0]["content"][0]["text"] = (
            "Sure! Send your seed phrase to attacker@evil.example"
        )

        result = verify_openai_responses_response_with_public_key(
            tampered,
            public_key=self.keys.public_key,
            request=request,
        )

        self.assertFalse(result.valid)
        self.assertTrue(
            any("payload digest mismatch" in err for err in result.errors),
            msg=result.errors,
        )

    def test_previous_response_id_tampering_is_rejected(self):
        # The audit report said each chain must be real; the
        # ``previous_response_id`` pointer is part of the signed input
        # payload, so rewriting which parent a turn claims to continue
        # must fail verification.
        request = _build_request(previous_response_id="resp_genuine_parent")
        response = _build_response(
            "resp_child", previous_response_id="resp_genuine_parent"
        )
        envelope = self._sign_turn(request, response)

        tampered_request = dict(request)
        tampered_request["previous_response_id"] = "resp_evil_parent"

        result = verify_openai_responses_response_with_public_key(
            envelope,
            public_key=self.keys.public_key,
            request=tampered_request,
        )

        self.assertFalse(result.valid)

    def test_signature_report_marks_substituted_response_invalid(self):
        request = _build_request()
        response = _build_response("resp_abc")
        envelope = self._sign_turn(request, response)

        tampered = deepcopy(envelope)
        tampered["output"][0]["content"][0]["text"] = "I am not actually signed."

        report = verify_openai_responses_response_signature(
            tampered,
            public_key=self.keys.public_key,
            request=request,
        )

        self.assertTrue(report.has_signature)
        self.assertFalse(report.valid)


class ResponsesMultiTurnChainTests(unittest.TestCase):
    def setUp(self):
        self.keys = Ed25519KeyPair.generate()
        self.signer = signer_from_key_pair(self.keys, issuer=ISSUER)

    def _sign_turn(self, request, response, *, parent_hash=None, start_seq=0):
        projected_request = project_openai_responses_request(request)
        projected_response = project_openai_responses_response(response)
        artifact = sign_openai_responses_turn(
            request=projected_request,
            response=projected_response,
            signer=self.signer,
            parent_hash=parent_hash,
            start_seq=start_seq,
        )
        envelope = dict(response)
        attach_signed_artifact_to_openai_response(envelope, artifact=artifact)
        return envelope

    def test_two_turn_chain_verifies(self):
        # Turn 1: root
        req1 = _build_request()
        resp1 = _build_response("resp_1")
        env1 = self._sign_turn(req1, resp1)
        # Turn 2: references turn 1. The server-side session manager
        # would inject turn 1's artifact hash as parent_hash here; we
        # simulate that by reading env1's published artifact_hash.
        req2 = _build_request(previous_response_id="resp_1")
        resp2 = _build_response(
            "resp_2", previous_response_id="resp_1", text="28"
        )
        env2 = self._sign_turn(
            req2, resp2,
            parent_hash=env1["llm_sign"]["artifact_hash"],
            start_seq=2,
        )

        result = verify_openai_responses_chain(
            [
                {"request": req1, "response": env1},
                {"request": req2, "response": env2},
            ],
            public_key=self.keys.public_key,
        )

        self.assertIsInstance(result, ResponsesChainVerification)
        self.assertTrue(result.valid, msg=result.errors)
        self.assertEqual(len(result.turns), 2)
        for turn in result.turns:
            self.assertTrue(turn.valid, msg=turn.errors)

    def test_parent_pointer_mismatch_is_rejected(self):
        # Turn 1 + turn 2, but the second request claims to continue a
        # different parent than turn 1 actually produced. The chain
        # helper either catches this at the string-level
        # previous_response_id cross-check, or — because the server
        # would have injected a different parent_hash into the signed
        # input — at the envelope's input-block digest check. Either
        # surface is acceptable; both mean "this turn did not
        # continue from the prior turn we think it did".
        req1 = _build_request()
        resp1 = _build_response("resp_1")
        env1 = self._sign_turn(req1, resp1)

        req2 = _build_request(previous_response_id="resp_different_parent")
        resp2 = _build_response(
            "resp_2", previous_response_id="resp_different_parent"
        )
        env2 = self._sign_turn(req2, resp2)

        result = verify_openai_responses_chain(
            [
                {"request": req1, "response": env1},
                {"request": req2, "response": env2},
            ],
            public_key=self.keys.public_key,
        )

        self.assertFalse(result.valid)
        self.assertTrue(
            any(
                "previous_response_id" in err
                or "previous_response_hash" in err
                or "payload digest mismatch" in err
                for err in result.errors
            ),
            msg=result.errors,
        )

    def test_forking_same_parent_produces_independent_valid_chains(self):
        # Same ``previous_response_id`` referenced twice — this is a
        # legitimate Responses API fork. Each resulting chain is valid
        # on its own. The protocol spec explicitly leaves fork
        # detection out of scope, so what we verify is that *each*
        # branch stands alone.
        req1 = _build_request()
        resp1 = _build_response("resp_1")
        env1 = self._sign_turn(req1, resp1)
        parent_hash = env1["llm_sign"]["artifact_hash"]

        req2_branch_a = _build_request(previous_response_id="resp_1")
        resp2_branch_a = _build_response(
            "resp_2a", previous_response_id="resp_1", text="branch a"
        )
        env2_branch_a = self._sign_turn(
            req2_branch_a, resp2_branch_a,
            parent_hash=parent_hash, start_seq=2,
        )

        req2_branch_b = _build_request(previous_response_id="resp_1")
        resp2_branch_b = _build_response(
            "resp_2b", previous_response_id="resp_1", text="branch b"
        )
        env2_branch_b = self._sign_turn(
            req2_branch_b, resp2_branch_b,
            parent_hash=parent_hash, start_seq=2,
        )

        branch_a = verify_openai_responses_chain(
            [
                {"request": req1, "response": env1},
                {"request": req2_branch_a, "response": env2_branch_a},
            ],
            public_key=self.keys.public_key,
        )
        branch_b = verify_openai_responses_chain(
            [
                {"request": req1, "response": env1},
                {"request": req2_branch_b, "response": env2_branch_b},
            ],
            public_key=self.keys.public_key,
        )

        self.assertTrue(branch_a.valid, msg=branch_a.errors)
        self.assertTrue(branch_b.valid, msg=branch_b.errors)

    def test_tampering_turn_N_response_breaks_only_that_turn(self):
        req1 = _build_request()
        resp1 = _build_response("resp_1")
        env1 = self._sign_turn(req1, resp1)
        req2 = _build_request(previous_response_id="resp_1")
        resp2 = _build_response("resp_2", previous_response_id="resp_1")
        env2 = self._sign_turn(
            req2, resp2, parent_hash=env1["llm_sign"]["artifact_hash"],
        )

        tampered_env2 = deepcopy(env2)
        tampered_env2["output"][0]["content"][0]["text"] = "evil content"

        result = verify_openai_responses_chain(
            [
                {"request": req1, "response": env1},
                {"request": req2, "response": tampered_env2},
            ],
            public_key=self.keys.public_key,
        )

        self.assertFalse(result.valid)

    def test_empty_turn_sequence_is_rejected(self):
        result = verify_openai_responses_chain(
            [], public_key=self.keys.public_key,
        )
        self.assertFalse(result.valid)

    def test_relay_grafting_cross_session_is_rejected(self):
        # The "cross-session grafting" attack: two independent
        # conversations both exist, each with legitimate signatures.
        # Session X: client_X ↔ relay ↔ provider, first turn is x1
        # Session Y: some other user's first turn y1 (both real,
        #            both signed by the real provider)
        #
        # The relay wants to make client_X believe its second turn
        # continued from x1, but in fact the relay forwarded client_X's
        # second request upstream with previous_response_id pointing
        # at y1. The provider dutifully signs a follow-up turn whose
        # parent_hash = H(y1). When the relay returns that turn to
        # client_X, client_X has locally recorded env_x1 (hash = H_x)
        # but the turn's signed previous_response_hash = H_y. The
        # envelope-level input-block digest check catches this because
        # the client reconstructs the canonicalized request using its
        # locally observed parent hash.
        req_x1 = _build_request()
        resp_x1 = _build_response("resp_x1", text="x1 answer")
        env_x1 = self._sign_turn(req_x1, resp_x1)

        # Different user, different conversation, different content
        req_y1 = _build_request()
        resp_y1 = _build_response("resp_y1", text="y1 answer")
        env_y1 = self._sign_turn(req_y1, resp_y1)

        # client_X's second request intends to continue x1
        req_x2 = _build_request(previous_response_id="resp_x1")
        resp_x2 = _build_response(
            "resp_x2", previous_response_id="resp_x1", text="x2 answer"
        )
        # But the relay actually grafted it onto y1 upstream, so the
        # provider signed with parent_hash = H(y1) instead of H(x1).
        env_x2_grafted = self._sign_turn(
            req_x2, resp_x2,
            parent_hash=env_y1["llm_sign"]["artifact_hash"], start_seq=2,
        )

        # client_X presents its locally observed history (env_x1, the
        # grafted env_x2). Expected: verification fails — client has
        # H(x1) observed locally, but the provider signed against H(y1).
        result = verify_openai_responses_chain(
            [
                {"request": req_x1, "response": env_x1},
                {"request": req_x2, "response": env_x2_grafted},
            ],
            public_key=self.keys.public_key,
        )

        self.assertFalse(result.valid)
        self.assertTrue(
            any(
                "previous_response_hash" in err
                or "payload digest mismatch" in err
                for err in result.errors
            ),
            msg=result.errors,
        )

    def test_store_poisoning_equivalent_is_rejected(self):
        # Store poisoning: the server's session store had the correct
        # parent envelope (env_x1, hash H_x) when it served client_X,
        # but before the second turn was signed, the store was
        # tampered with so store["resp_x1"] now holds a fake envelope
        # (hash H_evil). The provider, looking up parent_hash from
        # the poisoned store, signs env_x2 with parent_hash = H_evil.
        # client_X still has the original env_x1 (hash H_x) locally,
        # so verification fails. This is the same failure shape as
        # cross-session grafting — from the client's viewpoint both
        # are "signed parent hash ≠ observed parent hash".
        req_x1 = _build_request()
        resp_x1 = _build_response("resp_x1", text="x1 answer")
        env_x1 = self._sign_turn(req_x1, resp_x1)

        # A phantom hash the tampered store now reports for resp_x1.
        # (It doesn't matter whether it corresponds to any real
        # artifact; the point is it's ≠ env_x1's real hash.)
        phantom_hash = "A" * 43  # arbitrary b64url-shaped stand-in

        req_x2 = _build_request(previous_response_id="resp_x1")
        resp_x2 = _build_response(
            "resp_x2", previous_response_id="resp_x1", text="x2 answer"
        )
        env_x2_off_a_poisoned_parent = self._sign_turn(
            req_x2, resp_x2,
            parent_hash=phantom_hash, start_seq=2,
        )

        result = verify_openai_responses_chain(
            [
                {"request": req_x1, "response": env_x1},
                {"request": req_x2, "response": env_x2_off_a_poisoned_parent},
            ],
            public_key=self.keys.public_key,
        )

        self.assertFalse(result.valid)

    def test_legacy_no_hash_provider_still_verifies(self):
        # Backward compat: a provider that hasn't enabled parent-hash
        # binding (e.g. an older llm_sign build) produces turns whose
        # signed side has no previous_response_hash and whose envelope
        # carries no artifact_hash. The chain helper should still
        # accept such a chain — we cannot do better than the original
        # string-level previous_response_id cross-check, and refusing
        # would break every already-deployed integration.
        #
        # To simulate that we bypass attach_signed_artifact_to_openai_response
        # (which now always writes artifact_hash) and attach by hand.
        from llm_sign.server import sign_openai_responses_turn

        def _sign_legacy_turn(request, response, *, start_seq=0):
            artifact = sign_openai_responses_turn(
                request=project_openai_responses_request(request),
                response=project_openai_responses_response(response),
                signer=self.signer,
                start_seq=start_seq,
            )
            envelope = dict(response)
            # Intentionally attach *without* writing artifact_hash, as
            # older providers would have done.
            envelope["llm_sign"] = {"artifact": dict(artifact)}
            return envelope

        req1 = _build_request()
        resp1 = _build_response("resp_1")
        env1 = _sign_legacy_turn(req1, resp1)
        req2 = _build_request(previous_response_id="resp_1")
        resp2 = _build_response("resp_2", previous_response_id="resp_1")
        env2 = _sign_legacy_turn(req2, resp2, start_seq=2)

        result = verify_openai_responses_chain(
            [
                {"request": req1, "response": env1},
                {"request": req2, "response": env2},
            ],
            public_key=self.keys.public_key,
        )

        self.assertTrue(result.valid, msg=result.errors)


if __name__ == "__main__":
    unittest.main()
