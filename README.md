# llm_sign

[![PyPI version](https://img.shields.io/pypi/v/llm-sign.svg)](https://pypi.org/project/llm-sign/)
[![Python versions](https://img.shields.io/pypi/pyversions/llm-sign.svg)](https://pypi.org/project/llm-sign/)
[![License](https://img.shields.io/pypi/l/llm-sign.svg)](https://github.com/kexinoh/llm_sign/blob/master/LICENSE)

**Cryptographic provenance for LLM responses.** `llm_sign` lets an LLM
provider attach a provider-signed transcript to every OpenAI-compatible
response, so a downstream client can verify, end-to-end, that the
request it sent and the response it got back have not been tampered
with on the wire — even when a relay sits between them.

- Zero impact when disabled. Unsigned responses stay byte-identical to
  upstream.
- OpenAI-compatible. Works today with vLLM-style providers via an
  official vLLM integration.
- Transport-agnostic. The signature lives in the response JSON, so it
  survives HTTPS relays, proxies, and gateways.

## Threat model and trust

The threat is a middleman / relay that sits between the client and the
real LLM provider (for example a paid gateway or an API aggregator).
The client's own HTTPS session only authenticates the **relay**, not
the provider, so a plain TLS connection cannot tell the client whether
the request actually reached the provider or whether the response was
tampered with along the way.

`llm_sign` closes this gap by having the provider sign every turn with
the private key that terminates its own TLS endpoint, and **embed its
TLS certificate in the signed response** at
`response["llm_sign"]["certificate_chain"]`. The client reads the
provider's public key straight out of that certificate and uses it to
verify the artifact.

- The relay cannot forge a signature because it does not hold the
  provider's private key.
- The relay cannot substitute a different certificate either: the
  signed `key_id` field is an SPKI hash of the public key that signed
  the blocks, so any replacement certificate whose public key does not
  match that hash fails verification.

There is **no PKI / CA trust chain** in `llm_sign`. The certificate is
used purely as a transport for the provider's public key.

## Install

```sh
pip install llm-sign
```

> The PyPI distribution is `llm-sign` (hyphen), the Python import name
> is `llm_sign` (underscore) — matching the usual Python packaging
> convention (e.g. `scikit-learn` / `sklearn`, `typing-extensions` /
> `typing_extensions`).

```python
import llm_sign
```

## Quickstart (client): verify a signed response

The provider ships its certificate inside the response. The client has
nothing to configure:

```python
import json
import llm_sign

response = json.loads(http_body)  # raw response from the (possibly relayed) endpoint

result = llm_sign.client.verify_openai_response(response)

if result.valid:
    print("authentic:", response["choices"][0]["message"]["content"])
else:
    print("rejected :", result.errors)
```

**What this actually checks.** The signed payload covers both the
request (what you asked) and the response (what the model said).
Mutating a single character of either side — the user prompt, the
assistant content, the model name, the temperature — or swapping the
embedded provider certificate flips `valid` to `False`.

### Works with older providers too

Not every endpoint signs responses. For clients that want to accept
both signed and unsigned providers, use the non-raising variant:

```python
report = llm_sign.client.verify_openai_response_signature(response)

report.has_signature   # True  / False
report.host_name       # provider host name, if signed
report.valid           # True / False / None (None = no signature to check)
```

### Pinning a known provider key (TOFU)

If you want to lock the client to a specific provider identity across
sessions — i.e. not trust whatever certificate a future response might
carry — pin the public key the first time you see it:

```python
from llm_sign.client import (
    public_key_from_openai_response,
    verify_openai_response_with_public_key,
)

pinned = public_key_from_openai_response(first_response)  # extract once
# ... store pinned ...

result = verify_openai_response_with_public_key(later_response, public_key=pinned)
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

# Attach the artifact plus the provider certificate to the HTTP response:
llm_sign.server.attach_signed_artifact_to_openai_response(
    response_dict,
    artifact=artifact,
    credential=credential,
)
```

The issuer (provider identity claimed in the signature) is derived
from your certificate's SAN/CN, so it matches your TLS server name
automatically. RSA, P-256 ECDSA, and Ed25519 keys are all supported.

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

## Command-line verifier

For offline / audit use, the CLI takes a pinned public key (or a PEM
certificate whose public key is used):

```sh
llm-sign-verify artifact.json \
  --issuer api.example.com \
  --public-key provider-cert.pem
```

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
- [docs/artifact.md](docs/artifact.md) — signed artifact envelope
- [example/](example/) — runnable scripts, including offline verify
  and tamper-detection demos

## License

Apache-2.0. See [LICENSE](LICENSE).
