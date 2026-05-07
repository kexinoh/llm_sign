"""Static signed OpenAI-compatible response used by examples.

The fixture pairs a signed artifact with the Ed25519 public key that
signs it. Verification in the examples is performed by pinning that
public key directly; ``llm_sign`` does not use any CA / PKI trust chain.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives import serialization


# Ed25519 public key that signs the bundled artifact below. Clients
# "pin" it out of band exactly as they would pin a provider's
# TLS-served public key in a real deployment.
SUPPLIER_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=
-----END PUBLIC KEY-----
"""


def load_supplier_public_key() -> Any:
    return serialization.load_pem_public_key(SUPPLIER_PUBLIC_KEY_PEM.encode("ascii"))


SIGNED_CHAT_COMPLETION = json.loads(
    """
{
  "choices": [
    {
      "finish_reason": "stop",
      "index": 0,
      "message": {
        "content": "Hello.",
        "role": "assistant"
      }
    }
  ],
  "created": 0,
  "id": "chatcmpl-example-signed",
  "llm_sign": {
    "artifact": {
      "chain": [
        {
          "block": {
            "chain_id": "FE4XFw3wM7DE1l0dAs2P4g",
            "issuer": "provider.example",
            "key_id": "spki-sha256:oFCDfYUHBYLM9zlLCYiEfMMSy4glm4lImfbyOc8XkaU",
            "payload_digest": "2iaQQyogr9ycWANED6E7ZFd3RI1oODncQn47NO0j9XI",
            "prev_block_digest": null,
            "profile_id": "openai.chat-completions.input.v1",
            "seq": 0,
            "suite_id": "sha256-ed25519-v1",
            "type": "provider_received_input",
            "version": "1"
          },
          "block_digest": "484fpUJ9kC4PQJubj7ZhJ5ixGUfcH4oNZXmdjf22IMk",
          "signature": "wNH0XmaZqPY7GBhUiCZRU3tRmNXGIx55gDxoOeIz_oyddnDuhX47Qgd81t5JaJf6Gxt6JchKAS_vwmXuUgwjAg"
        },
        {
          "block": {
            "chain_id": "FE4XFw3wM7DE1l0dAs2P4g",
            "issuer": "provider.example",
            "key_id": "spki-sha256:oFCDfYUHBYLM9zlLCYiEfMMSy4glm4lImfbyOc8XkaU",
            "payload_digest": "TsMRpcsOGyOiuouOohbL8Eahe6vz0EexMYHcJaGhXwY",
            "prev_block_digest": "484fpUJ9kC4PQJubj7ZhJ5ixGUfcH4oNZXmdjf22IMk",
            "profile_id": "openai.chat-completions.output.v1",
            "seq": 1,
            "suite_id": "sha256-ed25519-v1",
            "type": "provider_output",
            "version": "1"
          },
          "block_digest": "PdhoRaZEh0i7u96pFjuOVXZJA6aY5erDJ2YtbKLIR8g",
          "signature": "AdUCbBXbix9dwxfjnJR-UEktr3HcRxZ9CyyDx763ZSPrthTGlKOakvIx-OGEKDnq9G3woeOA_f0x83ZYn7GyCw"
        }
      ],
      "platform": "openai-compatible",
      "schema": "llm-sign.artifact.v1",
      "turns": [
        {
          "request": {
            "messages": [
              {
                "content": "Say hello",
                "role": "user"
              }
            ],
            "model": "gpt-4.1-mini",
            "temperature": 0
          },
          "response": {
            "choices": [
              {
                "finish_reason": "stop",
                "index": 0,
                "message": {
                  "content": "Hello.",
                  "role": "assistant"
                }
              }
            ],
            "created": 0,
            "id": "chatcmpl-example-signed",
            "model": "gpt-4.1-mini",
            "object": "chat.completion"
          }
        }
      ]
    }
  },
  "model": "gpt-4.1-mini",
  "object": "chat.completion"
}
"""
)


def assistant_message(response: Mapping[str, Any]) -> str:
    choices = response.get("choices", [])
    if not choices:
        return ""
    message = choices[0].get("message", {})
    return message.get("content", "")
