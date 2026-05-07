# llm_sign

[![PyPI version](https://img.shields.io/pypi/v/llm-sign.svg)](https://pypi.org/project/llm-sign/)
[![Python versions](https://img.shields.io/pypi/pyversions/llm-sign.svg)](https://pypi.org/project/llm-sign/)
[![License](https://img.shields.io/pypi/l/llm-sign.svg)](https://github.com/kexinoh/llm_sign/blob/master/LICENSE)

## What we are doing (and why)

**In one line: `llm_sign` exists to stop the "relay / gateway / API
aggregator" sitting between you and an LLM provider from silently
swapping the model, rewriting response content, or fabricating a
response the provider never actually produced.**

Almost every real LLM deployment today looks like this:

```
your client  ──HTTPS──▶  relay / gateway / aggregator  ──HTTPS──▶  the real model provider (e.g. vLLM)
```

Your HTTPS session only proves "I really did connect to the relay". It
**cannot** prove any of these:

- whether the relay quietly downgraded your requested `gpt-x-large` to a
  cheaper small model and returned that result instead;
- whether the relay edited, deleted, or rewrote parts of the response
  body on the way back;
- whether the response you got was actually produced by the provider at
  all, or was just made up by the relay;
- whether the request you sent reached the provider unchanged.

**`llm_sign` closes exactly this gap.** The mechanism:

1. The real provider signs every `(request, response)` turn
   end-to-end with **its own TLS private key**, and ships its **TLS
   certificate chain** alongside the signature inside the response
   JSON, under `response["llm_sign"]`.
2. The client validates that chain using the **same standard X.509
   path validation a browser uses against an HTTPS server** — against
   the system TLS trust store, with SAN name matching — and then
   verifies the transcript signature against the validated leaf
   certificate's public key.
3. Because the relay does **not** hold the provider's TLS private key,
   the relay cannot:
   - change the content (any edit to the visible response body —
     `choices`, `model`, ...  — is detected: the high-level
     `verify_openai_response*` APIs pin the user-visible body to the
     chain's terminating `provider_output` block, so a relay that
     leaves the artifact intact and only rewrites visible fields is
     rejected with `payload digest mismatch`);
   - swap the model (the model name and output are inside the signed
     transcript);
   - ship a chain that omits the response (a chain whose last block is
     `provider_received_input` is rejected — every signed input must
     be closed by a signed `provider_output`);
   - fabricate a "provider response" (no way to produce a valid
     signature);
   - swap the certificate either (the signed `key_id` is the
     SPKI-SHA256 of the signer's public key and is cross-checked
     against the validated leaf's SPKI).

Note that we deliberately did **not** invent a new PKI, run our own
CA, or define custom OIDs / EKUs. The trust root is just the system
Web PKI trust store: any ordinary HTTPS certificate on the provider
(Let's Encrypt, a corporate CA, whatever) works out of the box with
the default client configuration.

The full threat model and wire-format specification live in
[`spec/provider-certificate-binding.md`](spec/provider-certificate-binding.md).

### This threat is not hypothetical

Recent work measures, in the wild, exactly the relay-layer misbehavior
that `llm_sign` is designed to defend against:

- **"Real Money, Fake Models: Deceptive Model Claims in Shadow APIs"**
  ([arXiv:2603.01919](https://arxiv.org/abs/2603.01919) ·
  [alphaXiv](https://www.alphaxiv.org/overview/2603.01919)) —
  documents third-party "shadow API" resellers that charge for a
  premium model while silently routing traffic to a cheaper or
  different model. This is the **model-substitution** attack listed
  above, observed on real commercial endpoints.
- **"Your Agent Is Mine: Measuring Malicious Intermediary Attacks on
  the LLM Supply Chain"**
  ([arXiv:2604.08407](https://arxiv.org/abs/2604.08407) ·
  [alphaXiv](https://www.alphaxiv.org/abs/2604.08407)) —
  measures malicious intermediaries across the LLM supply chain that
  modify, redirect, or hijack agent traffic between the client and
  the true provider. This is the **relay-tampering / response-forgery**
  attack class.

Both papers establish that a plain `client ──HTTPS──▶ relay ──HTTPS──▶
provider` topology provides the client with **no** cryptographic
evidence about which model actually answered, or whether the answer was
modified en route. `llm_sign` provides exactly that missing evidence.

---


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
