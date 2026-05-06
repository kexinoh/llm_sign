# Verifier Artifact Format

## Purpose

This package is intended to be embedded by tools such as Codex CLI, Kimi CLI,
vLLM-compatible servers, and other OpenAI-compatible clients. Providers use
`llm_sign.vendor`; clients use `llm_sign.client` or the `llm-sign-verify` CLI.

The package does not depend on internal platform logs. Integrations SHOULD emit
the normalized artifact contract below.

In relay deployments, the client may connect to an intermediary rather than the
LLM supplier. In that case the intermediary TLS certificate is only transport
security for the client-to-intermediary hop. It is not the transcript signing
identity. The supplier SHOULD return its issuer certificate chain together with
the first signed response, and verifiers SHOULD validate that supplier chain
against their configured TLS or deployment trust anchors before using the leaf
certificate public key to verify transcript signatures.

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

`llm_sign.certificate_chain` is an ordered PEM certificate chain with the
supplier transcript signing certificate first. It is discovery material, not a
signed field. A verifier MUST still validate the chain to a configured trust
anchor and MUST check that the leaf certificate SPKI-derived `key_id` matches
the signed blocks before accepting the artifact.

For relay or gateway deployments, the `certificate_chain` belongs to the LLM
supplier, not to the intermediary that delivered the HTTPS response. The
intermediary may forward or cache this field, but it does not become the signer
unless it signs its own artifact as a distinct issuer.

Clients that must keep working with providers that do not yet support this
extension can call `llm_sign.client.verify_openai_response_signature(...)`. That
helper returns a report with `has_signature`, `host_name`, and `valid`.
Unsigned responses produce `has_signature: false` and `valid: null` instead of a
verification exception; signed but invalid responses produce `valid: false`.

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

Static-key verification is available for deployments that intentionally pin a
bare public key:

```sh
llm-sign-verify artifact.json \
  --issuer provider.example \
  --public-key provider-ed25519-public.pem
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

For X.509 verification, pass the supplier certificate chain as discovery
material and one or more trust anchors. If a relay response contains
`llm_sign.certificate_chain`, write that supplier chain to a PEM file before
calling the CLI:

```sh
llm-sign-verify artifact.json \
  --issuer example.com \
  --certificate-chain supplier-chain.pem \
  --trust-anchor root-ca.pem \
  --tls-server-name-mode
```

`--tls-server-name-mode` binds the block issuer to the leaf certificate DNS name
and permits `serverAuth` certificates. Without that flag, the verifier expects
the dedicated transcript-signing issuer extension and EKU.
