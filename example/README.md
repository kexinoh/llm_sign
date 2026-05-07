# llm_sign examples

These examples show how to verify OpenAI-compatible signed transcript
artifacts with the public `llm_sign.client.*` APIs.

**Trust model.** `llm_sign` does not implement a PKI / CA trust chain.
A client verifies a provider by **pinning the provider's transcript
signing public key** out of band — exactly the same public key that is
embedded in the provider's TLS certificate. The examples below take
that pinned public key and verify signatures against it.

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

Runs without network access and verifies a bundled signed OpenAI Chat
Completions response against a bundled pinned public key:

```sh
python3 example/offline_openai_chat_verify.py
```

## OpenAI SDK verification flow

Calls `client.chat.completions.create(...)` and passes the OpenAI SDK
response directly to
`llm_sign.client.verify_openai_response_signature(...)`. Verification is
optional: if the response has no `llm_sign.artifact`, the example still
prints the assistant message and returns success. If a pinned public
key is provided via `OPENAI_PUBLIC_KEY`, the example verifies the
signature against it; without a pinned key, the report marks
`valid=None` ("signed, but nothing to check it against").

The verification report always includes:

- `has_signature`: whether the response carried `llm_sign.artifact`.
- `host_name`: the issuer claimed by the signed blocks, or `null`.
- `valid`: `true` for a valid signature, `false` for a bad signature,
  and `null` when there was no signature to verify or no pinned key.

```sh
OPENAI_PUBLIC_KEY=./provider-cert.pem \
  python3 example/openai_client_verify.py
```

`OPENAI_PUBLIC_KEY` accepts either a PEM public key or a PEM
certificate (the certificate's public key is used).

Optional model override:

```sh
OPENAI_MODEL="gpt-4.1-mini" python3 example/openai_client_verify.py
```

Optional endpoint override:

```sh
OPENAI_BASE_URL="https://api.openai.com/v1" python3 example/openai_client_verify.py
```

## Tamper detection

Shows that changing a returned signed payload fails verification:

```sh
python3 example/tamper_detection.py
```
