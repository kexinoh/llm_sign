# LLM_SIGN Complete Analysis - Executive Summary

## The Question

> Does this project implement a signing proxy? Does it monkey-patch SDKs? Does it intercept HTTP requests? What are the actual deployment mechanisms beyond just a library?

## The Answer

**NONE OF THE ABOVE.** This is a pure cryptographic library with no server, no proxy, no interception, no monkey-patching.

---

## What Is LLM_SIGN?

A **reference implementation** of a cryptographic protocol for:
1. **Providers** to digitally sign OpenAI-compatible LLM request/response pairs
2. **Clients** to verify those signatures
3. **Relay operators** to validate signatures using X.509 certificate chains

**All using pure functions.** No framework, no HTTP server, no deployment infrastructure.

---

## Files You Requested - The Actual Content

### 1. `src/llm_sign/platforms/openai_compatible.py`
**84 lines.** Extracts request/response payloads from artifact JSON. That's it.
- **Method**: `payloads_from_artifact()` - maps artifact.turns to indexed JSON dict
- **Purpose**: Canonicalization interface for verification
- **No HTTP**: Just JSON field extraction

### 2. `src/llm_sign/platforms/vllm.py`
**9 lines.** Inherits from `OpenAICompatibleAdapter`. No custom logic.
```python
class VllmAdapter(OpenAICompatibleAdapter):
    name = "vllm"
    aliases = ("vllm-openai", "vllm-chat")
```

### 3. `src/llm_sign/platforms/codex_cli.py`
**9 lines.** Same as vllm - inherits, adds names only.

### 4. `src/llm_sign/platforms/kimi_cli.py`
**9 lines.** Same as vllm and codex - inherits, adds names only.

### 5. Proxy/Middleware/Request Interception
**DOES NOT EXIST in `src/`.** Only test infrastructure in `tests/e2e_support/`:
- `tests/e2e_support/proxy.py` - Mock HTTP proxy for testing (test helper only)
- `tests/e2e_support/server.py` - Mock HTTP server for testing (test helper only)
- **Neither is deployed.** Both are in `tests/` directory.

### 6. Server's Main `__init__.py`
`src/llm_sign/server/__init__.py` - **140 lines**
- `generate_ed25519_key_pair()` - Generate signing keys
- `create_signer()` - Create TranscriptSigner object
- `sign_openai_chat_turn()` - Sign 1 turn (pure function)
- `sign_openai_chat_turns()` - Sign N turns (pure function)
- `create_artifact()` - Build artifact envelope (pure function)

**All pure functions. JSON in → JSON out. No I/O, no HTTP.**

### 7. Client `__init__.py`
`src/llm_sign/client/__init__.py` - **390 lines**
- `verify_openai_response_signature()` - Optional verification (backward compatible)
- `verify_with_public_key()` - Verify with hardcoded key
- `verify_openai_response_with_certificate_chain()` - X.509 validation
- `artifact_from_openai_response()` - Extract artifact field
- `load_system_trust_anchors()` - Load system CAs
- `trust_public_key()` - Create static key policy

**All pure functions. No HTTP, no SDK modifications.**

### 8. Examples Directory
`example/` contains:
- `openai_client_verify.py` - Use OpenAI SDK normally, then call verification
- `offline_openai_chat_verify.py` - Verify bundled artifact offline
- `tamper_detection.py` - Show how tampering is detected
- `_signed_openai_fixture.py` - Static signed response for testing

**No patching, no interception.** Just verification function calls.

---

## Architecture: What Actually Exists

### In Source Code (`src/llm_sign/`)

```
src/llm_sign/
├── __init__.py              # Public API facade
├── server/
│   └── __init__.py          # Signing APIs (5 pure functions)
├── client/
│   └── __init__.py          # Verification APIs (7+ functions)
├── cli.py                   # CLI tool (llm-sign-verify)
├── core/
│   ├── blocks.py            # Block signing/verification
│   ├── crypto.py            # Signature suites (Ed25519, RSA-PSS, ECDSA)
│   ├── encoding.py          # Binary encoding
│   └── profiles.py          # Canonicalization interface
├── profiles/
│   └── openai_chat.py       # OpenAI Chat Completions canonicalization
├── platforms/
│   ├── base.py              # Adapter registry
│   ├── openai_compatible.py # Generic OpenAI adapter (84 lines)
│   ├── vllm.py              # vLLM (9 lines - trivial)
│   ├── codex_cli.py         # Codex (9 lines - trivial)
│   └── kimi_cli.py          # Kimi (9 lines - trivial)
├── keys/
│   ├── ed25519.py           # Ed25519 keys
│   └── x509.py              # X.509 certificates
└── vendor/
    └── tls.py               # TLS helpers
```

**NO HTTP SERVER, NO MIDDLEWARE, NO FRAMEWORK**

### Test Infrastructure (`tests/e2e_support/`)

```
tests/e2e_support/
├── server.py                # Mock HTTP server for testing only
├── proxy.py                 # Mock proxy for testing tampering only
└── [NOT DEPLOYED]
```

These are **test helpers only**, used to verify the signing/verification APIs work.

---

## Deployment Model: Three Scenarios

### Scenario 1: Provider Implements Signing

Provider builds their own HTTP server (using any framework):

```python
from fastapi import FastAPI
import llm_sign

app = FastAPI()
signer = llm_sign.server.create_signer(issuer="provider.example", ...)

@app.post("/v1/chat/completions")
def chat_completions(request: dict):
    response = call_my_llm(request)
    artifact = llm_sign.server.sign_openai_chat_turn(
        request=request,
        response=response,
        signer=signer,
    )
    return {
        **response,
        "llm_sign": {"artifact": artifact}
    }
```

**llm_sign provides only the `sign_openai_chat_turn()` function.**
**Everything else (FastAPI, routing, HTTP server) is provider's code.**

### Scenario 2: Client Implements Verification

Client uses OpenAI SDK normally, verifies responses optionally:

```python
from openai import OpenAI
import llm_sign

client = OpenAI(api_key="...")
response = client.chat.completions.create(...)

report = llm_sign.client.verify_openai_response_signature(response)
if report.has_signature and not report.valid:
    raise Exception("Invalid signature")
```

**llm_sign provides only the `verify_openai_response_signature()` function.**
**No SDK modifications, no interception, no monkey-patching.**

### Scenario 3: Relay Implements Transparent Proxy

Relay operator builds their own proxy:

```python
import llm_sign

@app.post("/v1/chat/completions")
def proxy_chat_completions(request: dict):
    upstream_response = upstream_api.chat.completions.create(request)
    
    # Verify upstream
    report = llm_sign.client.verify_openai_response_signature(upstream_response)
    
    # Pass through to client
    return upstream_response
```

**llm_sign provides only verification functions.**
**Relay operator implements the proxy framework.**

---

## Key Characteristics

### What It IS
- ✓ Pure cryptographic library
- ✓ JSON-based protocol implementation
- ✓ Ed25519/RSA-PSS/ECDSA signature support
- ✓ X.509 certificate validation
- ✓ Backward compatible (unsigned responses OK)
- ✓ CLI tool for offline verification
- ✓ Well-documented protocol (spec/ directory)

### What It IS NOT
- ✗ HTTP proxy or reverse proxy
- ✗ Request/response middleware
- ✗ Server framework (FastAPI, Flask, Django, etc.)
- ✗ Monkey-patching any libraries
- ✗ SDK wrapper or wrapper replacement
- ✗ Deployment framework (Docker, K8s config, etc.)
- ✗ Key management system
- ✗ Certificate authority or PKI system
- ✗ Any kind of runtime interception

---

## Dependencies

```toml
# Core library
dependencies = ["cryptography>=42"]

# Optional (for examples only)
[project.optional-dependencies]
openai = ["openai>=1"]
```

**NO:**
- requests, httpx, urllib
- FastAPI, Flask, Django
- uvicorn, gunicorn
- Any HTTP/proxy libraries

**YES:**
- Standard library only
- cryptography (for crypto operations)

---

## Entry Points

In `pyproject.toml`:
```toml
[project.scripts]
llm-sign-verify = "llm_sign.cli:main"
```

**Single CLI binary only. No server entry point.**

---

## The Real Question: Who Deploys What?

### LLM_SIGN Deploys
- `llm_sign.server.sign_openai_chat_turn()` - Callable function
- `llm_sign.client.verify_openai_response_signature()` - Callable function
- `llm_sign-verify` - CLI tool

### Provider/Client/Relay Deploys
- HTTP server (FastAPI, Flask, etc.)
- Routing and request handling
- Key management and rotation
- Certificate generation (if using X.509)
- Rate limiting, authentication, logging
- Container orchestration

**llm_sign is the library. The framework/server/proxy is someone else's code.**

---

## Summary Table

| Aspect | Status | Notes |
|--------|--------|-------|
| **Is it a proxy?** | ❌ NO | Only test mocks for testing |
| **Is it a server?** | ❌ NO | Only test mocks for testing |
| **Does it patch SDKs?** | ❌ NO | Never imports/modifies any SDKs |
| **Does it intercept HTTP?** | ❌ NO | Never touches HTTP layer |
| **Is it a middleware?** | ❌ NO | No framework integration |
| **Is it a library?** | ✅ YES | Pure Python library |
| **Does it sign transcripts?** | ✅ YES | Via `sign_openai_chat_turn()` |
| **Does it verify signatures?** | ✅ YES | Via `verify_openai_response_signature()` |
| **Can it work offline?** | ✅ YES | CLI tool, pure functions |
| **What does it require?** | Cryptography only | No framework needed |

---

## Conclusion

`llm_sign` is a **pure cryptographic protocol library**. It defines:

1. **How to canonicalize** OpenAI Chat Completions requests/responses
2. **How to sign** those canonicalized forms with Ed25519/RSA-PSS/ECDSA
3. **How to chain** signatures into Merkle-like chains
4. **How to verify** signatures and detect tampering
5. **How to validate** certificate chains for relay deployments

But it does **NOT** provide:
- HTTP server
- Proxy framework
- Middleware implementation
- Request interception
- SDK monkey-patching
- Deployment infrastructure

The provider/client/relay operator must build all of that themselves using this library's APIs.

---

## Documentation Files Created

For your reference, analysis documents have been created:

1. **CODE_ANALYSIS_DETAILED.md** - Complete architectural breakdown
2. **CODE_SNIPPETS_ACTUAL.md** - All relevant code excerpts
3. **QUICK_REFERENCE_VISUAL.txt** - Visual summary with ASCII formatting
4. **ARCHITECTURE_SUMMARY.md** - (Previously created)
5. **COMPREHENSIVE_ANALYSIS.md** - (Previously created)

All saved to the repository root.
