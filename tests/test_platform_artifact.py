import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from llm_sign import (
    Ed25519KeyPair,
    OpenAIChatInputProfile,
    OpenAIChatOutputProfile,
    StaticKeyPolicy,
    TranscriptSigner,
    verify_artifact,
)
from llm_sign.blocks import PROVIDER_OUTPUT, PROVIDER_RECEIVED_INPUT
from llm_sign.cli import main as cli_main


class PlatformArtifactTests(unittest.TestCase):
    def setUp(self):
        self.keys = Ed25519KeyPair.generate()
        self.issuer = "provider.example"
        self.signer = TranscriptSigner(
            issuer=self.issuer,
            key_id=self.keys.key_id,
            private_key=self.keys.private_key,
        )
        self.input_profile = OpenAIChatInputProfile()
        self.output_profile = OpenAIChatOutputProfile()

    def test_codex_cli_artifact_verifies(self):
        artifact = self._artifact("codex-cli")
        policy = StaticKeyPolicy(
            {
                (
                    self.issuer,
                    self.keys.key_id,
                    "sha256-ed25519-v1",
                ): self.keys.public_key
            }
        )

        result = verify_artifact(artifact, key_policy=policy)

        self.assertTrue(result.valid, result.errors)
        self.assertEqual(len(result.blocks), 2)

    def test_vllm_artifact_verifies_with_platform_override(self):
        artifact = self._artifact("unknown-platform")
        policy = StaticKeyPolicy(
            {
                (
                    self.issuer,
                    self.keys.key_id,
                    "sha256-ed25519-v1",
                ): self.keys.public_key
            }
        )

        result = verify_artifact(artifact, key_policy=policy, platform="vllm")

        self.assertTrue(result.valid, result.errors)

    def test_cli_verifies_artifact_json(self):
        artifact = self._artifact("kimi-cli")
        with tempfile.TemporaryDirectory() as tmp:
            artifact_path = Path(tmp) / "artifact.json"
            key_path = Path(tmp) / "public.pem"
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
            key_path.write_bytes(
                self.keys.public_key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        str(artifact_path),
                        "--issuer",
                        self.issuer,
                        "--public-key",
                        str(key_path),
                    ]
                )

        self.assertEqual(exit_code, 0)
        result = json.loads(stdout.getvalue())
        self.assertTrue(result["valid"])
        self.assertEqual(
            [block["payload_state"] for block in result["blocks"]],
            ["payload_verified", "payload_verified"],
        )

    def _artifact(self, platform):
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
        return {
            "schema": "llm-sign.artifact.v1",
            "platform": platform,
            "chain": [b0.to_dict(), b1.to_dict()],
            "turns": [{"request": request, "response": response}],
        }


if __name__ == "__main__":
    unittest.main()
