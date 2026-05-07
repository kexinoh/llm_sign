"""Call an OpenAI-compatible API and verify the returned signed artifact.

Trust model: the client pins the provider's transcript-signing public key
out of band (e.g. read from the provider's published TLS certificate).
This example looks for a PEM file at ``OPENAI_PUBLIC_KEY`` (a PEM public
key, or a PEM certificate whose public key is used).
"""

import os
from pathlib import Path

import llm_sign
from cryptography.hazmat.primitives import serialization
from openai import OpenAI


def _load_pinned_public_key():
    path = os.getenv("OPENAI_PUBLIC_KEY")
    if not path:
        return None
    data = Path(path).read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in data:
        certificates = llm_sign.client.load_pem_certificates(data)
        if not certificates:
            raise ValueError(f"no certificates found in {path}")
        return certificates[0].public_key()
    return serialization.load_pem_public_key(data)


completion = OpenAI(
    base_url=os.getenv("OPENAI_BASE_URL") or None,
).chat.completions.create(
    model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
    messages=[{"role": "user", "content": "Reply with exactly: signed hello"}],
    temperature=0,
)

public_key = _load_pinned_public_key()
report = llm_sign.client.verify_openai_response_signature(
    completion,
    public_key=public_key,
)

print(report)

if completion.choices:
    print(f"assistant: {completion.choices[0].message.content}")

raise SystemExit(1 if report.has_signature and report.valid is False else 0)
