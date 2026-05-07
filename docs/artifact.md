# Verifier Artifact Format

## Purpose

This package is intended to be embedded by tools such as Codex CLI, Kimi CLI,
vLLM-compatible servers, and other OpenAI-compatible clients. Providers use
`llm_sign.vendor`; clients use `llm_sign.client` or the `llm-sign-verify` CLI.

The package does not depend on internal platform logs. Integrations SHOULD emit
the normalized artifact contract below.

`llm_sign` does not ship a PKI / CA trust chain. Clients establish trust
by **pinning the provider's transcript-signing public key** out of band.
When the provider signs with the same private key that terminates its
TLS endpoint, the public key embedded in its TLS certificate is a
natural pin.

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

For OpenAI-compatible APIs, a signed response can carry the artifact under a
provider extension field:

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

The optional `llm_sign.certificate_chain` is a convenience field: a
place for the provider to publish its TLS certificate so a client can
read the public key out of it on first use. It is **discovery material
only** and is not signed. `llm_sign` does not validate it, does not
walk it to a trust anchor, and does not consult revocation sources.

Clients that must keep working with providers that do not yet support this
extension can call `llm_sign.client.verify_openai_response_signature(...)`.
That helper returns a report with `has_signature`, `host_name`, and `valid`.
Unsigned responses produce `has_signature: false` and `valid: null`;
signed responses verified against a pinned `public_key` produce
`valid: true` or `valid: false`; signed responses without a pinned
public key produce `valid: null` (nothing to verify against).

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
