# Verifier Artifact Format

## Purpose

This package is intended to be embedded by tools such as Codex CLI, Kimi CLI,
vLLM-compatible servers, and other OpenAI-compatible clients. Providers use
`llm_sign.vendor`; clients use `llm_sign.client` or the `llm-sign-verify` CLI.

The threat model is middleman / relay tampering. A client that talks
through a relay cannot learn the real provider's public key from its
own TLS session. `llm_sign` solves this by having the provider sign
transcripts with the same private key that terminates its own TLS
endpoint, and ship the corresponding TLS certificate alongside the
signed response. The client reads the provider's public key out of that
certificate and verifies the signature directly — no CA trust chain,
no revocation checks, no PKI.

For vLLM, the provider side can load the same TLS files passed to `vllm serve`:

```sh
vllm serve "/path/to/model" \
  --ssl-certfile "/etc/letsencrypt/live/example.com/fullchain.pem" \
  --ssl-keyfile "/etc/letsencrypt/live/example.com/privkey.pem"
```

Those files may contain RSA, ECDSA, or Ed25519 keys. The package infers the
signing suite from the private key and derives `key_id` from the leaf
certificate SPKI.

## Artifact Object

```json
{
  "schema": "llm-sign.artifact.v1",
  "platform": "codex-cli",
  "chain": [],
  "turns": []
}
```

Fields:

```text
schema    Artifact schema identifier. Current value: llm-sign.artifact.v1.
platform  Adapter name, such as codex-cli, kimi-cli, vllm, or openai-compatible.
chain     Ordered signed block list. Each item is SignedBlock.to_dict().
turns     Optional OpenAI-compatible turn payloads for payload verification.
payloads  Optional seq-indexed payload object. Overrides missing turn payloads.
```

## OpenAI-Compatible Response Envelope

For OpenAI-compatible APIs, a signed response carries both the artifact
and the provider's TLS certificate under a provider extension field:

```json
{
  "id": "chatcmpl-...",
  "object": "chat.completion",
  "choices": [],
  "llm_sign": {
    "artifact": {
      "schema": "llm-sign.artifact.v1",
      "platform": "openai-compatible",
      "chain": [],
      "turns": []
    },
    "certificate_chain": [
      "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\\n"
    ]
  }
}
```

`llm_sign.certificate_chain` is an ordered PEM certificate list with the
provider transcript-signing certificate first. The client extracts the
provider's public key from the leaf certificate and verifies the
signature against it. The field is **not** a trust chain — no CA
validation, no revocation check is performed. Tampering is prevented by
the signed `key_id` field: a relay that swaps the certificate would
cause `key_id` to no longer match the new leaf's SPKI, so verification
fails.

Clients that want to keep working with providers that do not yet
support this extension can call
`llm_sign.client.verify_openai_response_signature(...)`. That helper
returns a report with `has_signature`, `host_name`, and `valid`.
Unsigned responses produce `has_signature: false` and `valid: null`;
signed responses with an embedded provider certificate produce
`valid: true / false`; a signed response that cannot be verified (no
embedded certificate and no pinned public key) produces `valid: false`.

## Turn Payloads

For OpenAI-compatible chat completions, each turn MAY include:

```json
{
  "request": {
    "model": "gpt-4.1-mini",
    "messages": [{"role": "user", "content": "Say hello"}]
  },
  "response": {
    "model": "gpt-4.1-mini",
    "choices": [
      {
        "index": 0,
        "finish_reason": "stop",
        "message": {"role": "assistant", "content": "Hello."}
      }
    ]
  }
}
```

The adapter maps turn payloads to sequence numbers:

```text
seq 2n     request  -> provider_received_input
seq 2n + 1 response -> provider_output
```

If payloads are absent, the verifier can still validate signatures and chain
links. The block payload state will be `digest_only`.

## CLI Verification

Static-key verification pins a bare public key (or a PEM certificate
that carries one):

```sh
llm-sign-verify artifact.json \
  --issuer provider.example \
  --public-key provider-cert.pem
```

The command writes compact JSON:

```json
{
  "valid": true,
  "errors": [],
  "blocks": [
    {
      "seq": 0,
      "type": "provider_received_input",
      "payload_state": "payload_verified"
    }
  ]
}
```

The process exits with status `0` when the artifact is valid and `1` otherwise.
