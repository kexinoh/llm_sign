# llm_sign examples

These examples show how to verify OpenAI-compatible signed transcript artifacts
with the public `llm_sign.client.*` APIs.

Important boundary: client examples do not sign locally. They assume the
OpenAI-compatible response already includes `llm_sign.artifact` and the
supplier-provided `llm_sign.certificate_chain`. The client verifies that
certificate chain against TLS trust anchors, then verifies the transcript
signature with the supplier certificate public key.

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
Completions response:

```sh
python3 example/offline_openai_chat_verify.py
```

## OpenAI SDK verification flow

Calls `client.chat.completions.create(...)` and passes the OpenAI SDK response
directly to `llm_sign.client.verify_openai_response_signature(...)`.
Verification is optional: if the response has no `llm_sign.artifact`, the
example still prints the assistant message and returns success. If signature
data is present, it validates the supplier certificate chain against the system
TLS trust store and verifies the artifact with the supplier certificate public
key. No provider public key is configured out of band.

The verification report always includes:

- `has_signature`: whether the response carried `llm_sign.artifact`.
- `host_name`: the host name claimed by the signed blocks, or `null`.
- `valid`: `true` for a valid signature, `false` for a bad signature, and
  `null` when there was no signature to verify.

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
