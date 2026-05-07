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
- No new PKI. The client authenticates the provider certificate using
  the same TLS / X.509 rules a browser uses against an HTTPS server.

## Threat model

The threat is a middleman / relay between the client and the real LLM
provider (for example a paid gateway or an API aggregator). The
client's own HTTPS session authenticates only the relay, so plain TLS
alone cannot tell the client whether the request actually reached the
provider or whether the response was tampered with on the way back.

`llm_sign` closes this gap by having the provider sign every turn
with its TLS private key, and ship its TLS certificate chain inside
the signed response at `response["llm_sign"]["certificate_chain"]`.
The client validates that chain the same way an HTTPS client
validates a server certificate — standard X.509 path validation
against the system TLS trust store, with SAN name matching — and then
verifies the transcript against the validated leaf's public key.

- The relay cannot forge a signature because it does not hold the
  provider's TLS private key.
- The relay cannot substitute a different certificate either: the
  signed `key_id` field is an SPKI-SHA256 of the signer's public key,
  and the client cross-checks it against the validated leaf's SPKI.

The full specification of this binding lives in
[`spec/provider-certificate-binding.md`](spec/provider-certificate-binding.md).

## Install

```sh
pip install llm-sign
```

## Quickstart (client): verify a signed response

The provider ships its certificate inside the response. The default
verifier authenticates it against the system TLS trust store:

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

**What this actually checks.** The client runs the standard TLS /
X.509 server-certificate validation algorithm on the embedded chain
(system trust store + SAN match for the expected host), cross-checks
the signed `key_id` against the validated leaf's SPKI, and then
verifies the transcript signature. Mutating the request, the
response, or the transcript flips `valid` to `False`; swapping the
embedded chain for one not rooted in the trust store fails chain
validation; swapping the leaf for one under a different key fails the
`key_id` match.

### Private / self-signed providers

If the provider does not use a Web PKI certificate, pass an explicit
trust anchor set or opt into trust-on-first-use:

```python
# Private CA
from llm_sign.client import verify_openai_response
result = verify_openai_response(response, trust_anchors=my_root_certs)

# Self-signed / local dev (trust embedded cert as-is)
result = verify_openai_response(response, verify_tls=False)
```

### Works with older providers too

Not every endpoint signs responses. For clients that want to accept
both signed and unsigned providers, use the non-raising variant:

```python
report = llm_sign.client.verify_openai_response_signature(response)

report.has_signature   # True  / False
report.host_name       # provider host name, if signed
report.valid           # True / False / None (None = no signature to check)
```

### Pinning a known provider key

If you have the provider's public key out of band and want to skip
certificate handling entirely:

```python
from llm_sign.client import verify_openai_response_with_public_key
result = verify_openai_response_with_public_key(response, public_key=pinned)
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

# Attach the artifact plus the provider certificate chain to the HTTP response:
llm_sign.server.attach_signed_artifact_to_openai_response(
    response_dict,
    artifact=artifact,
    credential=credential,
)
```

The issuer (provider identity claimed in the signature) is derived
from your certificate's SAN/CN so it matches your TLS server name
automatically. RSA and P-256 ECDSA certificates verify under the
system Web PKI out of the box; Ed25519 certificates are supported by
the signing suites but currently require a private trust anchor set
because the public Web PKI does not yet accept them.

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
certificate whose public key is used). It does not run the TLS chain
check — pass in the key you already trust:

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
what they understand, with a clear "please upgrade llm_sign" message.
The protocol integer is explicitly **decoupled** from the Python
package version: bug fixes, refactors, and new helpers never bump it;
only wire-format changes do.

## Learn more

- [spec/normalization.md](spec/normalization.md) — canonical JSON and
  digest construction
- [spec/provider-certificate-binding.md](spec/provider-certificate-binding.md)
  — certificate authentication and key binding
- [docs/artifact.md](docs/artifact.md) — signed artifact envelope
- [example/](example/) — runnable scripts, including offline verify
  and tamper-detection demos

## License

Apache-2.0. See [LICENSE](LICENSE).
