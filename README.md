# llm_sign

[![PyPI version](https://img.shields.io/pypi/v/llm-sign.svg)](https://pypi.org/project/llm-sign/)
[![Python versions](https://img.shields.io/pypi/pyversions/llm-sign.svg)](https://pypi.org/project/llm-sign/)
[![License](https://img.shields.io/pypi/l/llm-sign.svg)](https://github.com/kexinoh/llm_sign/blob/master/LICENSE)

## What we are doing (and why)

**一句话：我们在防止 LLM API 的"中转站 / relay / 聚合网关"偷偷替换模型、
篡改响应内容，或者伪造一次根本没发生过的对话。**

今天绝大多数调用 LLM 的链路都是：

```
你的客户端  ──HTTPS──▶  中转站 / 网关 / 聚合商  ──HTTPS──▶  真正的模型提供方 (例如 vLLM)
```

你的 HTTPS 只能证明"我确实连到了中转站"，**完全无法证明**：

- 中转站有没有把你指定的 `gpt-x-large` 悄悄换成一个更便宜的小模型再把结果返回给你；
- 中转站有没有在响应里改几个字、删几段内容、或者直接重写答案；
- 中转站返回的这条响应，是不是它自己编的、根本没去问过真正的 provider；
- 你发出去的 request，到达 provider 时是不是还是原样。

**`llm_sign` 要解决的就是这件事。** 做法是：

1. 真正的模型提供方（provider）用它**自己的 TLS 私钥**，对每一轮
   `(request, response)` 做端到端签名，把签名和自己的 **TLS 证书链**
   一起塞进响应 JSON 的 `response["llm_sign"]` 字段里。
2. 客户端拿到响应后，用**和浏览器验 HTTPS 服务器证书完全一样的标准
   X.509 路径校验**（系统 TLS 根证书 + SAN 匹配）去验那条证书链，
   然后用验证过的叶子证书公钥去验签 transcript。
3. 中转站**不持有** provider 的 TLS 私钥，所以它：
   - 改不了内容（一改签名就挂）；
   - 换不了模型（响应里的模型名 / 输出都在签名覆盖范围内）；
   - 伪造不了一条"provider 的响应"（签不出合法签名）；
   - 换不了证书（签名里的 `key_id` 是公钥 SPKI-SHA256，和叶子证书交叉绑死）。

注意我们**没有**发明新的 PKI、没有自建 CA、没有自定义 OID / EKU。
信任根就是系统里那套 Web PKI 根证书——provider 只要有一张正常的
HTTPS 证书（Let's Encrypt 之类都行），客户端默认配置就能验。

一句话版威胁模型 + 完整协议写在
[`spec/provider-certificate-binding.md`](spec/provider-certificate-binding.md)。

---

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
