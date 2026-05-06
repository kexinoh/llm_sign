# LLM_SIGN Project - Complete Code Analysis

## Executive Summary

**NO PROXY, NO MONKEY-PATCHING, NO HTTP SERVER**

`llm_sign` is **NOT** a signing proxy or request interception framework. It is a **pure cryptographic library** for creating and verifying signed transcript artifacts. The actual deployment mechanism is entirely up to the provider/client - this library provides only the signing and verification primitives.

---

## Project Purpose

`llm_sign` defines a cryptographic protocol and reference implementation for:
1. **Server-side**: LLM providers to sign their request/response turns
2. **Client-side**: Clients to verify those signed transcripts
3. **Relay deployments**: Intermediate proxies to pass through signatures using TLS certificate chains

The protocol is **provider-agnostic** and **transport-agnostic** - it does NOT bind to specific APIs or deployment models.

---

## Architecture Overview

```
src/llm_sign/
├── core/              # Cryptographic primitives
│   ├── blocks.py      # Block signing/verification logic
│   ├── crypto.py      # Signature suites (Ed25519, RSA-PSS, ECDSA)
│   ├── encoding.py    # Binary encoding (not JSON-specific)
│   └── profiles.py    # Canonicalization interface
├── profiles/          # Protocol implementations
│   └── openai_chat.py # OpenAI Chat Completions canonicalization
├── platforms/         # Artifact format adapters
│   ├── openai_compatible.py  # Generic OpenAI format
│   ├── vllm.py               # vLLM (inherits from OpenAI)
│   ├── codex_cli.py          # Codex CLI (inherits from OpenAI)
│   └── kimi_cli.py           # Kimi CLI (inherits from OpenAI)
├── keys/              # Key policy implementations
│   ├── ed25519.py     # Ed25519 keys + static policy
│   └── x509.py        # X.509 certificate chains
├── server/            # Signing APIs (provider-side)
│   └── __init__.py    # sign_openai_chat_turn(), create_artifact()
├── client/            # Verification APIs (client-side)
│   └── __init__.py    # verify_openai_response_signature(), etc.
├── cli.py             # CLI tool: llm-sign-verify
└── verifier.py        # High-level verification API
```

---

## Platform Adapters

All platform adapters are **just data mappers** - they extract JSON payloads from platform-specific artifact formats.

### `src/llm_sign/platforms/openai_compatible.py`

**Purpose**: Extract request/response payloads from OpenAI-format artifacts

```python
class OpenAICompatibleAdapter:
    def payloads_from_artifact(self, artifact):
        """Extract indexed payloads from artifact turns"""
        # Maps artifact.turns[index] -> payloads[index*2] (request)
        #                            -> payloads[index*2+1] (response)
```

**What it does**:
- Parses nested JSON structures
- Handles both flat and chained turn formats
- Returns a dict mapping sequence numbers to payloads
- **No HTTP, no signing, no transport** - just JSON extraction

### `src/llm_sign/platforms/vllm.py`

```python
class VllmAdapter(OpenAICompatibleAdapter):
    name = "vllm"
    aliases = ("vllm-openai", "vllm-chat")
```

**Just inherits** from OpenAICompatibleAdapter. No custom logic. All three CLI adapters (vllm, codex, kimi) are identical.

### `src/llm_sign/platforms/codex_cli.py` & `src/llm_sign/platforms/kimi_cli.py`

Same pattern - trivial subclasses with just name/aliases.

---

## Core APIs - Server Side (SIGNING)

Located in: `src/llm_sign/server/__init__.py`

### 1. Generate Keys

```python
def generate_ed25519_key_pair() -> Ed25519KeyPair:
    """Generate an Ed25519 transcript signing key pair."""
```

**No key storage, no key distribution** - caller manages this.

### 2. Create Signer

```python
def create_signer(
    *,
    issuer: str,
    key_id: str,
    private_key: Any,
    suite_id: Optional[str] = None,
) -> TranscriptSigner:
    """Create a transcript signer for a provider-controlled private key."""
```

Returns a `TranscriptSigner` object (from core). That's it.

### 3. Sign a Single Turn

```python
def sign_openai_chat_turn(
    *,
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    signer: TranscriptSigner,
) -> Dict[str, Any]:
    """Sign one OpenAI-compatible Chat Completions request/response turn."""
```

Takes plain JSON dicts, returns artifact JSON with signatures. Example:

```json
{
  "schema": "llm-sign.artifact.v1",
  "platform": "openai-compatible",
  "chain": [
    {
      "block": { ... },
      "block_digest": "...",
      "signature": "..."
    },
    ...
  ],
  "turns": [
    {
      "request": { "model": "gpt-4", ... },
      "response": { "choices": [...], ... }
    }
  ]
}
```

**No HTTP involvement whatsoever**. The provider calls this function and must independently:
- Decide what to include in the response JSON
- Decide if/where to put `llm_sign.artifact`
- Implement their own HTTP server/endpoint

### 4. Sign Multiple Turns

```python
def sign_openai_chat_turns(
    *,
    turns: Iterable[Tuple[Mapping[str, Any], Mapping[str, Any]]],
    signer: TranscriptSigner,
) -> Dict[str, Any]:
```

Chains multiple turns into one artifact with linked signatures.

### 5. Create Artifact

```python
def create_artifact(
    *,
    chain: Sequence[SignedBlock],
    turns: Optional[Sequence[Mapping[str, Any]]] = None,
    payloads: Optional[Mapping[int, Any]] = None,
    platform: str = OPENAI_COMPATIBLE_PLATFORM,
) -> Dict[str, Any]:
```

Wraps signed blocks and metadata into final artifact.

---

## Core APIs - Client Side (VERIFICATION)

Located in: `src/llm_sign/client/__init__.py`

### 1. Trust a Public Key

```python
def trust_public_key(
    *,
    issuer: str,
    key_id: str,
    public_key: Any,
    suite_id: Optional[str] = None,
) -> StaticKeyPolicy:
```

Pre-configure a trusted provider public key out-of-band.

### 2. Verify with Known Key

```python
def verify_with_public_key(
    artifact: Mapping[str, Any],
    *,
    issuer: str,
    key_id: str,
    public_key: Any,
    suite_id: Optional[str] = None,
    platform: Optional[str] = None,
    payloads: Optional[Mapping[int, Any]] = None,
) -> ChainVerification:
```

Verify an artifact using pre-distributed public key.

### 3. Extract Artifact from Response

```python
def artifact_from_openai_response(response: Mapping[str, Any]) -> Mapping[str, Any]:
    """Extract llm_sign.artifact from an OpenAI-compatible response."""
```

Just extracts nested JSON field.

### 4. Load System Certificates

```python
def load_system_trust_anchors() -> list[x509.Certificate]:
    """Load PEM certificates from the Python/OpenSSL default TLS trust paths."""
```

Reads system CA bundle (from `/etc/ssl/certs/` or Python's ssl module).

### 5. Verify with Certificate Chain

```python
def verify_openai_response_with_certificate_chain(
    response: Mapping[str, Any],
    *,
    trust_anchors: Sequence[x509.Certificate],
    payloads: Optional[Mapping[int, Any]] = None,
    platform: Optional[str] = None,
    issuer_binding: str = "tls-server-name",
    allow_tls_server_auth: bool = True,
    validation_time: Any = None,
    revocation_mode: str = "soft_fail",
    revoked_serials: Optional[Iterable[int]] = None,
    expected_issuer: Optional[str] = None,
) -> ChainVerification:
```

For relay deployments:
- Extract supplier certificate chain from response
- Validate chain against trust anchors
- Verify artifact using leaf cert public key
- **No HTTP involved** - response is plain dict

### 6. Graceful Verification (Optional Signature)

```python
def verify_openai_response_signature(
    response: Any,
    *,
    trust_anchors: Optional[Sequence[x509.Certificate]] = None,
    ...
) -> OpenAIResponseSignatureReport:
```

Returns:
```python
@dataclass(frozen=True)
class OpenAIResponseSignatureReport:
    has_signature: bool        # Did response include llm_sign.artifact?
    host_name: Optional[str]   # Provider claimed in signature
    valid: Optional[bool]      # True/False/None (no sig = None)
```

**Backward compatible** - unsigned responses are OK (valid=None).

---

## CLI Tool

Located in: `src/llm_sign/cli.py`

**Binary**: `llm-sign-verify` (entry point in pyproject.toml)

```bash
llm-sign-verify artifact.json \
  --issuer provider.example \
  --public-key provider-ed25519-public.pem
```

Reads JSON file, verifies against pre-configured key, outputs JSON result:

```json
{
  "valid": true,
  "errors": [],
  "blocks": [
    {
      "seq": 0,
      "type": "provider_received_input",
      "payload_state": "verified"
    }
  ]
}
```

Exit code: 0 if valid, 1 if invalid. **No HTTP server**.

---

## Test Infrastructure

The test directory includes **MOCK HTTP SERVERS** for testing only. These are NOT part of the library:

### `tests/e2e_support/server.py` - Mock Signing Server

```python
class SignedChatHttpServer:
    """Test helper that serves HTTP responses with signatures."""
    
    def __init__(self, keys, host="127.0.0.1", response_mode="artifact-envelope"):
        self._service = SignedChatService(keys=keys)
        self._server = ThreadingHTTPServer((host, 0), handler_class)
```

**Purpose**: Test that the client verification APIs work correctly.

**Response modes**:
- `"artifact-envelope"`: Returns `{"artifact": {...}}`
- `"openai-compatible"`: Returns OpenAI response with `llm_sign` field
- `"openai-compatible-unsigned"`: Returns plain unsigned response

**Used by**: `test_e2e_signed_client_flow.py`

**Location**: `tests/e2e_support/` - NOT in src/ - NOT deployed

### `tests/e2e_support/proxy.py` - Mock JSON Proxy

```python
class JsonProxyHttpServer:
    """Test helper that proxies HTTP requests with optional mutation."""
    
    def __init__(
        self,
        target_base_url: str,
        request_mutator: Optional[JsonMutator] = None,
        response_mutator: Optional[JsonMutator] = None,
    ):
```

**Purpose**: Test scenarios where responses are tampered with (to verify tamper detection).

**Functionality**:
- Receives HTTP POST, reads JSON
- Optionally mutates request (if `request_mutator` provided)
- Forwards to upstream URL
- Optionally mutates response (if `response_mutator` provided)
- Returns to client

**Example test use case**:
```python
def tamper_response(resp):
    resp["choices"][0]["message"]["content"] = "TAMPERED"
    return resp

proxy = JsonProxyHttpServer(
    target_base_url="https://api.openai.com/v1",
    response_mutator=tamper_response
)
# Client calls proxy -> proxy signs -> proxy tampers -> verification should fail
```

**Location**: `tests/e2e_support/` - NOT in src/ - NOT deployed

---

## Does This Project Do ANY of These?

### ❌ Implement a Signing Proxy?

**No.** The test support includes mock proxies for testing, but there's no production proxy server in the `src/` directory. The library only provides:
- Pure functions to sign artifacts
- Pure functions to verify artifacts
- No HTTP server or request routing

A provider who wants a proxy would build one separately using the signing API.

### ❌ Monkey-Patch SDKs?

**No.** The library does not import or patch:
- OpenAI SDK
- Any other LLM SDK
- Any HTTP libraries
- Any system modules

It only uses:
- Standard library (`json`, `http.server` for tests only, `ssl`)
- `cryptography` package

Example client code (from `example/openai_client_verify.py`):
```python
from openai import OpenAI
import llm_sign

client = OpenAI(api_key="...")
completion = client.chat.completions.create(...)

# Verify the response - calling llm_sign directly, not patching OpenAI
report = llm_sign.client.verify_openai_response_signature(completion)
```

The OpenAI SDK is used normally. `llm_sign` is just a verification library.

### ❌ Intercept HTTP Requests?

**No.** The library never:
- Creates or intercepts HTTP connections
- Patches urllib/requests/httpx
- Modifies headers/bodies in transit
- Uses proxies

It only:
- Takes JSON dicts as input
- Returns JSON dicts as output
- Optionally reads system TLS certificates (for verification)

---

## Actual Deployment Mechanisms

This is a **library**, not a framework. Deployment depends on the use case:

### Scenario 1: LLM Provider (Signing Side)

Provider implements their own HTTP server using any framework (FastAPI, Flask, etc.):

```python
from fastapi import FastAPI
import llm_sign

app = FastAPI()
signer = llm_sign.server.create_signer(...)

@app.post("/v1/chat/completions")
def chat_completions(request: dict):
    # Call the LLM
    response = call_my_llm(request)
    
    # Sign the turn
    artifact = llm_sign.server.sign_openai_chat_turn(
        request=request,
        response=response,
        signer=signer,
    )
    
    # Return response with signature
    return {
        **response,
        "llm_sign": {"artifact": artifact}
    }
```

This is **provider's responsibility**, not llm_sign's.

### Scenario 2: Client (Verification Side)

Client uses normal OpenAI SDK and just verifies responses:

```python
from openai import OpenAI
import llm_sign

client = OpenAI()
response = client.chat.completions.create(...)

# Verify - optional, backward compatible
report = llm_sign.client.verify_openai_response_signature(response)
if report.has_signature and report.valid is False:
    raise Exception("Bad signature!")
```

This is **client's responsibility**, not llm_sign's.

### Scenario 3: Relay/Gateway (Transparent Proxy)

A relay between client and provider could:
1. Call `llm_sign.client.verify_openai_response_signature()` on upstream response
2. Extract certificate chain
3. Pass through to downstream client

But **llm_sign doesn't provide the proxy** - the relay operator builds one.

---

## What llm_sign DOES Provide

1. **Cryptographic Primitives**
   - Binary block encoding (canonical, deterministic)
   - Signature creation/verification
   - Block chaining (Merkle-like chains)

2. **Profiles** (Canonicalization Rules)
   - How to hash an OpenAI request (field ordering, numeric precision, etc.)
   - How to hash an OpenAI response
   - How to hash tool results

3. **Data Serialization**
   - JSON artifact format
   - Signed block structure

4. **Key Policies**
   - Static key policy (hardcoded public key)
   - X.509 policy (certificate chain validation, CRL check, issuer binding)

5. **Verification Logic**
   - Verify signatures
   - Verify chain continuity
   - Check payload digests
   - Report errors clearly

---

## Example Artifacts

### Unsigned OpenAI Response (from tests)

```json
{
  "choices": [{"message": {"content": "Hello."}}],
  "model": "gpt-4.1-mini"
}
```

### With llm_sign Artifact

```json
{
  "choices": [{"message": {"content": "Hello."}}],
  "model": "gpt-4.1-mini",
  "llm_sign": {
    "artifact": {
      "schema": "llm-sign.artifact.v1",
      "platform": "openai-compatible",
      "chain": [
        {
          "block": {
            "version": "1",
            "suite_id": "sha256-ed25519-v1",
            "chain_id": "FE4XFw3wM7DE1l0dAs2P4g",
            "seq": 0,
            "issuer": "provider.example",
            "key_id": "spki-sha256:oFCDfYUHBYLM9zlLCYiEfMMSy4glm4lImfbyOc8XkaU",
            "type": "provider_received_input",
            "profile_id": "openai.chat-completions.input.v1",
            "prev_block_digest": null,
            "payload_digest": "2iaQQyogr9ycWANED6E7ZFd3RI1oODncQn47NO0j9XI"
          },
          "block_digest": "484fpUJ9kC4PQJubj7ZhJ5ixGUfcH4oNZXmdjf22IMk",
          "signature": "wNH0XmaZqPY7GBhUiCZRU3tRmNXGIx55gDxoOeIz_oyddnDuhX47Qgd81t5JaJf6Gxt6JchKAS_vwmXuUgwjAg"
        },
        {
          "block": {
            "seq": 1,
            "type": "provider_output",
            "prev_block_digest": "484fpUJ9kC4PQJubj7ZhJ5ixGUfcH4oNZXmdjf22IMk",
            ...
          },
          "signature": "..."
        }
      ],
      "turns": [
        {
          "request": {...},
          "response": {...}
        }
      ]
    },
    "certificate_chain": ["-----BEGIN CERTIFICATE-----...", "..."]
  }
}
```

---

## Dependencies

```toml
dependencies = ["cryptography>=42"]

[project.optional-dependencies]
openai = ["openai>=1"]
```

- `cryptography`: For all crypto operations
- `openai` (optional): Only needed for examples, not for the core library

---

## Entry Points

In `pyproject.toml`:

```toml
[project.scripts]
llm-sign-verify = "llm_sign.cli:main"
```

Single CLI binary. No server entry point.

---

## What Does EACH File Do?

### `src/llm_sign/__init__.py`
Public API facade. Exports types and functions for normal use.

### `src/llm_sign/server/__init__.py`
Provider-facing signing API:
- `generate_ed25519_key_pair()`
- `create_signer()`
- `sign_openai_chat_turn()`, `sign_openai_chat_turns()`
- `create_artifact()`

### `src/llm_sign/client/__init__.py`
Client-facing verification API:
- `verify_with_public_key()`
- `trust_public_key()`
- `verify_openai_response_signature()`
- `verify_openai_response_with_certificate_chain()`
- `artifact_from_openai_response()`
- `certificate_chain_from_openai_response()`
- `load_system_trust_anchors()`

### `src/llm_sign/core/blocks.py`
Low-level signing primitives:
- `Block` dataclass (the data to be signed)
- `SignedBlock` (block + signature + digest)
- `TranscriptSigner` (does the actual signing)
- `sign_payload()` (low-level signing function)

### `src/llm_sign/core/crypto.py`
Signature suite implementations (Ed25519, RSA-PSS, ECDSA).

### `src/llm_sign/core/encoding.py`
Binary encoding (block digest, payload digest, field encoding).

### `src/llm_sign/core/profiles.py`
Canonicalization interface.

### `src/llm_sign/profiles/openai_chat.py`
Specific canonicalization for OpenAI Chat Completions format.

### `src/llm_sign/platforms/base.py`
Protocol definition and adapter registry.

### `src/llm_sign/platforms/openai_compatible.py`
Adapter for OpenAI-compatible platforms (extracts payloads from artifact).

### `src/llm_sign/platforms/vllm.py`, `codex_cli.py`, `kimi_cli.py`
Simple subclasses, no custom logic.

### `src/llm_sign/keys/ed25519.py`
Ed25519 key pair generation and static key policy.

### `src/llm_sign/keys/x509.py`
X.509 certificate handling and validation policy.

### `src/llm_sign/cli.py`
Command-line tool: reads artifact from file, verifies with provided key.

### `src/llm_sign/verifier.py`
High-level verification orchestration.

---

## Summary: What Would a Real Deployment Look Like?

**NOT this project**. This project is just the library.

A real deployment would have:

```
provider-api-server/  (built by provider, not llm_sign)
├── Dockerfile
├── requirements.txt
│   ├── fastapi
│   ├── uvicorn
│   ├── llm-sign
│   ├── other-deps...
├── app.py
│   ├── Generate signing key pair
│   ├── Create TranscriptSigner
│   ├── For each request:
│   │   ├── Call LLM
│   │   ├── Call llm_sign.server.sign_openai_chat_turn()
│   │   ├── Return response with llm_sign.artifact
```

And:

```
client-code/  (built by client)
├── requirements.txt
│   ├── openai
│   ├── llm-sign
├── main.py
│   ├── Call OpenAI SDK (or compatible)
│   ├── Get response
│   ├── Call llm_sign.client.verify_openai_response_signature()
│   ├── Check signature status
```

`llm_sign` **provides the primitives only**. The framework, server, routing, certificate management, key distribution - all that is up to the provider/client.

---

## Conclusion

| Aspect | Answer |
|--------|--------|
| Is it a proxy? | **No** |
| Does it monkey-patch? | **No** |
| Does it intercept HTTP? | **No** |
| Is it a library? | **Yes** |
| What does it do? | Cryptographic signing and verification of LLM transcripts |
| How is it deployed? | Providers call signing functions; clients call verification functions |
| Does it include a server? | **No** (tests have mock servers for testing only) |
| What does it require from providers? | Use the signing API; embed artifact in response; implement their own HTTP server |
| What does it require from clients? | Use the verification API; pass response JSON to verification functions |
