# llm_sign examples

These examples show how to verify OpenAI-compatible signed transcript
artifacts with the public `llm_sign.client.*` APIs.

**Trust model.** The threat is relay / middleman tampering. The
client's own HTTPS session only authenticates whichever relay it
talks to, so the client cannot read the real provider's public key
from its TLS handshake. The provider therefore ships its TLS
certificate chain inside the signed response at
`llm_sign.certificate_chain`, and the client authenticates that chain
the same way an HTTPS client authenticates a server certificate —
standard TLS / X.509 validation against the system trust store, with
SAN name matching. The transcript is then verified against the
validated leaf's public key.

A relay cannot forge a valid signature because it does not hold the
provider's TLS private key; swapping the embedded chain fails chain
validation and/or the SPKI-`key_id` check.

See
[`../spec/provider-certificate-binding.md`](../spec/provider-certificate-binding.md)
for the full specification.

## Setup

From the repository root:

```sh
python3 -m pip install -e .
```

For the real OpenAI SDK example:

```sh
python3 -m pip install -e ".[openai]"
export OPENAI_API_KEY="..."
```

## Offline verification

Runs without network access:

```sh
python3 example/offline_openai_chat_verify.py
```

The bundled response uses a **self-signed** Ed25519 provider
certificate (the public Web PKI does not currently accept Ed25519),
so the example passes `verify_tls=False` to trust the embedded
certificate directly. Production deployments should omit that flag
and let `llm_sign` validate the provider certificate against the
system TLS trust store.

## OpenAI SDK verification flow

Calls `client.chat.completions.create(...)` and passes the OpenAI SDK
response directly to
`llm_sign.client.verify_openai_response_signature(...)`. No keys or
certificates need to be configured on the client side: the response
carries the provider's certificate, and the verifier authenticates it
against the system TLS trust store. If the response has no
`llm_sign.artifact`, the example still prints the assistant message
and returns success.

The verification report always includes:

- `has_signature`: whether the response carried `llm_sign.artifact`.
- `host_name`: the issuer claimed by the signed blocks, or `null`.
- `valid`: `true` for a valid signature, `false` for anything that
  failed (bad signature, untrusted chain, wrong host, missing
  certificate), and `null` when there was no signature to verify.

```sh
python3 example/openai_client_verify.py
```

Optional model / endpoint override:

```sh
OPENAI_MODEL="gpt-4.1-mini" python3 example/openai_client_verify.py
OPENAI_BASE_URL="https://api.openai.com/v1" python3 example/openai_client_verify.py
```

## Tamper detection

Shows that changing a returned signed payload fails verification:

```sh
python3 example/tamper_detection.py
```
