# llm_sign examples

These examples show how to verify OpenAI-compatible signed transcript
artifacts with the public `llm_sign.client.*` APIs.

**Trust model.** The threat is relay / middleman tampering. The client's
own HTTPS session only authenticates whichever relay it talks to, so
the client cannot read the real provider's public key from its TLS
handshake. Instead, the provider ships its TLS certificate inside the
signed response itself, at `llm_sign.certificate_chain`. The client
reads the signing public key out of that certificate and verifies the
artifact against it.

A relay cannot forge a valid signature because it does not hold the
provider's private key; swapping the embedded certificate would cause
the signed `key_id` to no longer match the leaf public key, so
verification also fails.

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

Runs without network access. The bundled response carries the
provider's certificate inline; the verifier uses it automatically:

```sh
python3 example/offline_openai_chat_verify.py
```

## OpenAI SDK verification flow

Calls `client.chat.completions.create(...)` and passes the OpenAI SDK
response directly to
`llm_sign.client.verify_openai_response_signature(...)`. No keys or
certificates need to be configured on the client side. If the response
has no `llm_sign.artifact`, the example still prints the assistant
message and returns success.

The verification report always includes:

- `has_signature`: whether the response carried `llm_sign.artifact`.
- `host_name`: the issuer claimed by the signed blocks, or `null`.
- `valid`: `true` for a valid signature, `false` for a bad signature,
  and `null` when there was no signature to verify.

```sh
python3 example/openai_client_verify.py
```

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
