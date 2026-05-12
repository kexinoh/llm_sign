"""Call an OpenAI-compatible API and verify the returned signed artifact.

The client does not need any certificate or public key file on disk.
The provider is expected to ship its TLS certificate alongside the
signed artifact, at ``response["llm_sign"]["certificate_chain"]``. The
verifier reads the signing public key out of that certificate. A relay
that tampers with the request, response, or artifact cannot forge a
valid signature because it does not hold the provider's private key.
"""

import os

import llm_sign
from openai import OpenAI


completion = OpenAI(
    base_url=os.getenv("OPENAI_BASE_URL") or None,
).chat.completions.create(
    model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
    messages=[{"role": "user", "content": "Reply with exactly: signed hello"}],
    temperature=0,
)

report = llm_sign.client.verify_openai_response_signature(completion)
print(report)

if completion.choices:
    print(f"assistant: {completion.choices[0].message.content}")

raise SystemExit(1 if report.has_signature and report.valid is False else 0)
