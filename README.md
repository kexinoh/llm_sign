# llm_sign

`llm_sign` defines a provider-signed transcript chain for LLM interactions.

The project specifies cryptographic claims over canonicalized LLM interaction
semantics. The core v1 protocol defines digest construction, block encoding,
signature semantics, chain validation, verifier failure behavior, and an
X.509/TLS-style CA profile for authenticating transcript signing keys. It
deliberately avoids binding the protocol to a transport format, vendor API
schema, or tokenizer representation.

Start here:

- [spec/normalization.md](spec/normalization.md)
- [spec/issuer-pki.md](spec/issuer-pki.md)
- [docs/artifact.md](docs/artifact.md)

## Package Layout

```text
src/llm_sign/
  client/     Client-facing verification facade.
  server/     Server/provider-facing signing facade.
  core/       Protocol encoding, block signing, and chain verification.
  profiles/   Canonicalization profiles, including OpenAI Chat Completions.
  keys/       Static Ed25519 and X.509 CA-mode key policies.
  platforms/  Codex CLI, Kimi CLI, vLLM, and OpenAI-compatible adapters.
  vendor/     Backward-compatible provider TLS helpers.
  verifier.py High-level artifact verification API.
  cli.py      llm-sign-verify console entry point.
```

Preferred application entry points are `llm_sign.client.*` for verification and
`llm_sign.server.*` for signing. Compatibility shims remain at
`llm_sign.blocks`, `llm_sign.openai`, `llm_sign.keys`, `llm_sign.pki`, and
`llm_sign.vendor`.

For vLLM-style providers, load the same files passed to `vllm serve`:

```python
import llm_sign

credential = llm_sign.server.TLSCertificateCredential.from_files(
    ssl_certfile="/etc/letsencrypt/live/example.com/fullchain.pem",
    ssl_keyfile="/etc/letsencrypt/live/example.com/privkey.pem",
)
signer = credential.signer()
```

The certificate key type determines the default signing suite. The built-in
suites cover RSA-PSS/SHA-256, P-256 ECDSA/SHA-256, and Ed25519/SHA-256. New
suites can be registered without changing the chain verification logic.

For relay or gateway deployments, the client does not need a manually imported
supplier public key. The OpenAI-compatible response can include both
`llm_sign.artifact` and the supplier `llm_sign.certificate_chain`. The verifier
validates that chain against configured trust anchors and then verifies the
artifact under the supplier leaf certificate public key. The relay's HTTPS
certificate authenticates the transport hop only; it is not the supplier signing
identity.

Clients that need backward compatibility with unsigned providers can use
`llm_sign.client.verify_openai_response_signature(...)`. It returns an optional
signature report instead of raising when the response has no `llm_sign` data:
`has_signature` says whether signature data exists, `host_name` is the
claimed supplier host name, and `valid` is `true`, `false`, or `null` when there was
no signature to verify.

## Python Usage

Install in editable mode:

```sh
python3 -m pip install -e .
```

Sign and verify an OpenAI Chat Completions compatible turn:

```python
import llm_sign

keys = llm_sign.server.generate_ed25519_key_pair()
issuer = "provider.example"
signer = llm_sign.server.create_signer(
    issuer=issuer,
    key_id=keys.key_id,
    private_key=keys.private_key,
)

request = {
    "model": "gpt-4.1-mini",
    "messages": [{"role": "user", "content": "Say hello"}],
}
response = {
    "model": "gpt-4.1-mini",
    "choices": [
        {
            "index": 0,
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": "Hello."},
        }
    ],
}

artifact = llm_sign.server.sign_openai_chat_turn(
    request=request,
    response=response,
    signer=signer,
)
result = llm_sign.client.verify_with_public_key(
    artifact,
    issuer=issuer,
    key_id=keys.key_id,
    public_key=keys.public_key,
)

assert result.valid, result.errors
```

Multi-turn chains can be produced with `llm_sign.server.sign_openai_chat_turns`.
The tests include a four-block input/output/input/output conversation.

## Examples

Runnable examples live in [example/](example/):

- `offline_openai_chat_verify.py` verifies a bundled signed OpenAI-compatible
  response without network access.
- `openai_client_verify.py` calls an OpenAI-compatible endpoint with the OpenAI SDK,
  reports `has_signature`, `host_name`, and `valid`, and continues when the
  endpoint does not yet return `llm_sign` data.
- `tamper_detection.py` shows payload digest mismatch detection after a signed
  response is modified.

Run tests:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

Verify a platform artifact with a pinned public key:

```sh
llm-sign-verify artifact.json \
  --issuer provider.example \
  --public-key provider-ed25519-public.pem
```

Verify an artifact with a supplier certificate chain. In relay deployments,
extract this chain from `llm_sign.certificate_chain` in the first signed
response:

```sh
llm-sign-verify artifact.json \
  --issuer example.com \
  --certificate-chain supplier-chain.pem \
  --trust-anchor root-ca.pem \
  --tls-server-name-mode
```
