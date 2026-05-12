"""Static signed OpenAI-compatible response used by examples.

The fixture ships both the signed artifact and the provider's TLS
certificate (at ``llm_sign.certificate_chain``). The client verifies
the artifact by reading the signing public key out of that certificate.
No CA / PKI validation is performed.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


# Provider self-signed Ed25519 certificate. Its embedded public key is
# the one that produced the signatures in the artifact below, so the
# signed ``key_id`` matches ``spki-sha256(certificate public key)``.
SUPPLIER_CERTIFICATE_CHAIN_PEM = [
    """-----BEGIN CERTIFICATE-----
MIIBAzCBtqADAgECAgEBMAUGAytlcDAbMRkwFwYDVQQDDBBwcm92aWRlci5leGFt
cGxlMB4XDTI0MDEwMTAwMDAwMFoXDTQ0MDEwMTAwMDAwMFowGzEZMBcGA1UEAwwQ
cHJvdmlkZXIuZXhhbXBsZTAqMAUGAytlcAMhAAOhB7/zzhC+HXDdGOdLwJln5NYw
m6UNXx3chmQSVTG4ox8wHTAbBgNVHREEFDASghBwcm92aWRlci5leGFtcGxlMAUG
AytlcANBAA4qX4NimZAdNgpxktWMc/j5aHVLTzdyU/lb+mEpJkkJdikSl1nUC1S2
syU81pYjaIjuRoC3I5HyFBjkjMsdnQc=
-----END CERTIFICATE-----
""",
]

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

SIGNED_CHAT_COMPLETION["llm_sign"]["certificate_chain"] = SUPPLIER_CERTIFICATE_CHAIN_PEM


def assistant_message(response: Mapping[str, Any]) -> str:
    choices = response.get("choices", [])
    if not choices:
        return ""
    message = choices[0].get("message", {})
    return message.get("content", "")
