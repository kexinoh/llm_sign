# llm_sign

[![PyPI version](https://img.shields.io/pypi/v/llm-sign.svg)](https://pypi.org/project/llm-sign/)
[![Python versions](https://img.shields.io/pypi/pyversions/llm-sign.svg)](https://pypi.org/project/llm-sign/)
[![License](https://img.shields.io/pypi/l/llm-sign.svg)](https://github.com/kexinoh/llm_sign/blob/master/LICENSE)

**Cryptographic provenance for LLM responses.** `llm_sign` lets an LLM
provider attach a provider-signed transcript to every OpenAI-compatible
response, so a downstream client can verify, end-to-end, that the
request it sent and the response it got back have not been tampered
with on the wire — and that they came from a specific provider
identity bound to a TLS certificate.

- Zero impact when disabled. Unsigned responses stay byte-identical to
  upstream.
- OpenAI-compatible. Works today with vLLM-style providers via an
  official vLLM integration.
- Transport-agnostic. The signature lives in the response JSON, so it
  survives HTTPS relays, proxies, and gateways.

## Install

```sh
pip install llm-sign
```

## Quickstart (client): verify a signed response

You called an OpenAI-compatible endpoint that supports `llm_sign`. Its
response JSON carries an extra `llm_sign` field. With just the
provider's public key, you can verify the entire request/response pair
in one call:

```python
import json
from llm_sign.client import (
    load_pem_certificates,
    verify_openai_response_with_public_key,
)

# The provider's certificate (or leaf of their signing chain).
with open("provider-cert.pem") as f:
    public_key = load_pem_certificates(f.read())[0].public_key()

# The raw HTTP response body from the provider.
response = json.loads(http_body)

result = verify_openai_response_with_public_key(
    response,
    public_key=public_key,
)

if result.valid:
    print("authentic:", response["choices"][0]["message"]["content"])
else:
    print("rejected :", result.errors)
```

**What this actually checks.** The signed payload covers both the
request (what you asked) and the response (what the model said).
Mutating a single character of either side — the user prompt, the
assistant content, the model name, the temperature — flips `valid`
to `False`.

### Works with older providers too

Not every endpoint signs responses. For clients that want to accept
both signed and unsigned providers, use the non-raising variant:

```python
from llm_sign.client import verify_openai_response_signature

report = verify_openai_response_signature(response)

report.has_signature   # True  / False
report.host_name       # provider host name, if signed
report.valid           # True / False / None (None = no signature to check)
```

## Quickstart (provider): sign a response

If you run your own OpenAI-compatible API and already have a TLS
certificate for your host, signing is a few lines:

```python
import llm_sign

credential = llm_sign.server.TLSCertificateCredential.from_files(
    ssl_certfile="/etc/letsencrypt/live/api.example.com/fullchain.pem",
    ssl_keyfile="/etc/letsencrypt/live/api.example.com/privkey.pem",
)
signer = credential.signer()

artifact = llm_sign.server.sign_openai_chat_turn(
    request=request_dict,     # your OpenAI-compatible request body
    response=response_dict,   # your OpenAI-compatible response body
    signer=signer,
)

# Attach to the HTTP response that goes on the wire:
response_dict["llm_sign"] = {
    "artifact": artifact,
    "certificate_chain": credential.certificate_chain_pem(),
}
```

The issuer (provider identity claimed in the signature) is derived
from your certificate's SAN/CN, so it matches your TLS server name
automatically. RSA, P-256 ECDSA, and Ed25519 keys are all supported.

### Just want to play without a real cert?

```python
import llm_sign

keys = llm_sign.server.generate_ed25519_key_pair()
signer = llm_sign.server.create_signer(
    issuer="demo.local",
    key_id=keys.key_id,
    private_key=keys.private_key,
)

artifact = llm_sign.server.sign_openai_chat_turn(
    request={"model": "demo", "messages": [{"role": "user", "content": "hi"}]},
    response={"model": "demo", "choices": [
        {"index": 0, "finish_reason": "stop",
         "message": {"role": "assistant", "content": "Hello."}},
    ]},
    signer=signer,
)

# Verify with the matching public key.
result = llm_sign.client.verify_with_public_key(
    artifact, public_key=keys.public_key,
)
assert result.valid, result.errors
```

## Using llm_sign with vLLM

vLLM has first-class support for `llm_sign` since the
[kexinoh/vllm](https://github.com/kexinoh/vllm) integration. Enable it
with two environment variables pointing at your TLS material:

```sh
pip install vllm llm-sign

export VLLM_LLM_SIGN_ENABLED=1
export VLLM_LLM_SIGN_CERTFILE=/path/to/cert.pem
export VLLM_LLM_SIGN_KEYFILE=/path/to/key.pem

vllm serve meta-llama/Meta-Llama-3-8B-Instruct
```

Every non-streaming `/v1/chat/completions` response now carries an
`llm_sign` field. When the env var is unset, responses are
byte-identical to upstream vLLM: no schema changes, no new keys, no
client breakage.

## Relay and gateway setups

For deployments where the client talks to a relay that re-serves a
supplier's signed artifacts, you can pin the relay's trust anchors
and let the verifier check the full certificate chain automatically:

```python
from llm_sign.client import (
    load_pem_certificates,
    verify_openai_response_with_certificate_chain,
)

with open("root-ca.pem", "rb") as f:
    trust_anchors = load_pem_certificates(f.read())

result = verify_openai_response_with_certificate_chain(
    response,
    trust_anchors=trust_anchors,
)
```

The supplier's leaf + chain come from the signed response itself;
the relay's HTTPS certificate only authenticates the transport hop,
not the supplier signing identity.

## Command-line verifier

```sh
llm-sign-verify artifact.json \
  --issuer api.example.com \
  --certificate-chain supplier-chain.pem \
  --trust-anchor root-ca.pem \
  --tls-server-name-mode
```

Handy for CI checks, audit logs, or post-hoc forensics.

## Protocol and versioning

Every artifact carries a tiny `protocol` block:

```json
{
  "protocol": {"version": 1, "min_reader_version": 1},
  ...
}
```

Readers refuse artifacts whose `min_reader_version` is higher than
what they understand, with a clear "please upgrade llm_sign"
message. The protocol integer is explicitly **decoupled** from the
Python package version: bug fixes, refactors, and new helpers never
bump it; only wire-format changes do.

## Learn more

- [spec/normalization.md](spec/normalization.md) — canonical JSON and
  digest construction
- [spec/issuer-pki.md](spec/issuer-pki.md) — X.509 issuer profile and
  TLS identity binding
- [docs/artifact.md](docs/artifact.md) — signed artifact envelope
- [example/](example/) — runnable scripts, including offline verify
  and tamper-detection demos

## License

Apache-2.0. See [LICENSE](LICENSE).
