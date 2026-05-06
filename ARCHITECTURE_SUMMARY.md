# LLM_SIGN Architecture Summary

## What This Project Actually Is

A **complete cryptographic framework** for signing and verifying LLM request-response turns. Think of it as "end-to-end encryption for LLM transcripts" with full PKI support.

## Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                        llm_sign Package                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐ │
│  │ SERVER SIDE      │  │ CLIENT SIDE      │  │ CLI TOOL     │ │
│  ├──────────────────┤  ├──────────────────┤  ├──────────────┤ │
│  │ • Sign turns     │  │ • Verify         │  │ llm-sign-    │ │
│  │ • Create signer  │  │ • Check chain    │  │ verify       │ │
│  │ • Ed25519 key    │  │ • X.509 PKI      │  │ artifact.json│ │
│  │   generation     │  │ • System trust   │  │              │ │
│  │ • Multi-turn     │  │ • Report status  │  │ Flags:       │ │
│  │   chains         │  │ • Relay support  │  │ --issuer     │ │
│  └──────────────────┘  └──────────────────┘  │ --public-key │ │
│         ↓                       ↑             │ --cert-chain │ │
│                                              └──────────────┘ │
│                    ┌─────────────────┐                         │
│                    │  PLATFORMS      │                         │
│                    ├─────────────────┤                         │
│                    │ • OpenAI compat │ (base for all)          │
│                    │ • Codex CLI     │                         │
│                    │ • Kimi/Moonshot │                         │
│                    │ • vLLM          │                         │
│                    └─────────────────┘                         │
│                            ↓                                   │
│            ┌───────────────────────────────┐                  │
│            │ CANONICALIZATION PROFILES     │                  │
│            ├───────────────────────────────┤                  │
│            │ • OpenAI Input (v1)           │                  │
│            │ • OpenAI Output (v1)          │                  │
│            │ • Tool Results (v1)           │                  │
│            │ • Custom profiles supported   │                  │
│            └───────────────────────────────┘                  │
│                            ↓                                   │
│       ┌────────────────────────────────────────┐              │
│       │ SIGNATURE SUITES                       │              │
│       ├────────────────────────────────────────┤              │
│       │ • Ed25519/SHA-256 (recommended)        │              │
│       │ • RSA-PSS/SHA-256                      │              │
│       │ • ECDSA-P256/SHA-256                   │              │
│       │ • Extensible (register new suites)     │              │
│       └────────────────────────────────────────┘              │
│                            ↓                                   │
│       ┌────────────────────────────────────────┐              │
│       │ KEY POLICIES                           │              │
│       ├────────────────────────────────────────┤              │
│       │ • StaticKeyPolicy (pinned key)         │              │
│       │ • X509KeyPolicy (PKI chains)           │              │
│       │   - Chain validation                   │              │
│       │   - EKU enforcement                    │              │
│       │   - Revocation checking                │              │
│       │   - Time-bound validation              │              │
│       └────────────────────────────────────────┘              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow: Direct Signing

```
Provider Side:
─────────────

1. Generate/Load Key
   └─ TLSCertificateCredential.from_files(cert, key)
      or Ed25519KeyPair.generate()

2. Create Signer
   └─ create_signer(issuer, key_id, private_key)

3. Sign Turn
   └─ sign_openai_chat_turn(request, response, signer)
      ├─ Canonicalize request (OpenAIChatInputProfile)
      ├─ Canonicalize response (OpenAIChatOutputProfile)
      ├─ Create signed blocks with chain linkage
      └─ Return artifact JSON

4. Response Envelope
   ┌─ {
   │    "id": "...",
   │    "choices": [...],
   │    "llm_sign": {
   │      "artifact": {...}   ← artifact from step 3
   │    }
   │ }
   └─ Send to client


Client Side:
────────────

1. Receive Response

2. Extract Artifact
   └─ artifact_from_openai_response(response)

3. Verify Signature
   └─ verify_with_public_key(
        artifact,
        issuer="provider.example",
        key_id=keys.key_id,
        public_key=keys.public_key
      )
      ├─ Load platform adapter (OpenAI-compatible)
      ├─ Load signed blocks from chain
      ├─ Extract payloads from artifact
      ├─ Verify each block:
      │  ├─ Canonicalize payload
      │  ├─ Check payload digest
      │  ├─ Verify signature with key policy
      │  └─ Verify prev_block_digest chain linkage
      └─ Return ChainVerification(valid, errors, blocks)

4. Use Result
   ├─ if result.valid: Accept response
   └─ else: Log errors, reject
```

## Data Flow: Relay with Certificate Chain

```
Provider
  │
  └─→ Signs turn + includes llm_sign.certificate_chain
      (provider's certificate proving signing key)
  
       │
       ↓
Relay/Gateway
  │
  └─→ Forwards UNCHANGED (relay's HTTPS cert ≠ provider's signing cert)
       (relay only authenticates transport, NOT the provider)
  
       │
       ↓
Client
  │
  ├─→ verify_openai_response_with_certificate_chain(response)
  │   ├─ Extract certificate chain from response
  │   ├─ Validate chain against trust anchors
  │   │  (chain must end at a root cert client trusts)
  │   ├─ Extract public key from validated chain
  │   ├─ Verify artifact signature with that key
  │   └─ Return ChainVerification
  │
  └─→ Now client knows provider signed it, NOT relay
```

## Artifact Structure

```json
{
  "schema": "llm-sign.artifact.v1",
  "platform": "openai-compatible",
  
  "chain": [
    {
      "block": {
        "version": "v1",
        "suite_id": "sha256-ed25519-v1",
        "chain_id": "AAAA...",
        "seq": 0,
        "issuer": "provider.example",
        "key_id": "spki-sha256:...",
        "type": "provider_received_input",
        "profile_id": "openai.chat-completions.input.v1",
        "prev_block_digest": null,
        "payload_digest": "XXXX..."
      },
      "signature": "YYYY...",
      "block_digest": "ZZZZ..."
    },
    {
      "block": {
        "seq": 1,
        "type": "provider_output",
        "prev_block_digest": "ZZZZ...",  ← chains to previous block
        ...
      },
      "signature": "YYYY...",
      "block_digest": "ZZZZ2..."
    }
  ],
  
  "turns": [
    {
      "request": { ... },
      "response": { ... }
    }
  ],
  
  "payloads": {
    "0": { ... },  ← request for block seq 0
    "1": { ... }   ← response for block seq 1
  }
}
```

## Verification Output

```python
ChainVerification(
    valid: bool,
    errors: list[str],  # Per-block error details
    blocks: list[VerifiedBlock]  # Each with payload_state
)

# payload_state values:
"PAYLOAD_VERIFIED"     # Digest matches canonicalized payload
"PAYLOAD_MISMATCH"     # Digest doesn't match (tampered)
"PAYLOAD_MISSING"      # No payload to verify (digest-only, e.g., tool results)
```

## Key Features (Overlooked Items)

### 1. **Multi-Turn Chains**
Signatures link across multiple turns via block digests. Breaking any single block breaks all subsequent blocks.

### 2. **Tool Call Result Blocks**
Tool results get their own `tool_result` blocks. Server can:
- Sign with full payload: Client verifies exact result
- Sign digest-only: Client verifies result was committed to, even if payload omitted from artifact

### 3. **Relay/Gateway Support**
Certificate chain in response lets client validate provider's key even when traffic routes through untrusted relay. Relay's HTTPS cert is irrelevant to signature validity.

### 4. **Payload Flexibility**
Payloads can be:
- **Embedded:** In artifact (turns, payloads dicts)
- **External:** Provided separately by client (proxy scenario where original payloads unavailable in artifact)
- **Digest-only:** No payload, only digest verification (tool results, sensitive data)

### 5. **No Middleware/Interception**
Library is **explicit**, not implicit. Providers call signing functions directly. No monkey-patching or auto-interception of OpenAI SDK or HTTP.

### 6. **Test Infrastructure with Tampering**
Comprehensive tests verify that:
- Request tampering breaks request block signature
- Response tampering breaks response block signature
- Tool result reordering breaks followup request block (because block digest chain breaks)
- Proxy/relay scenarios work when artifacts unchanged
- Proxy tampering is caught

### 7. **X.509 PKI with Custom OIDs**
```
LLM_SIGN_ISSUER_OID = "1.3.6.1.4.1.55555.1.1"        # Issuer extension
LLM_SIGN_TRANSCRIPT_EKU_OID = "1.3.6.1.4.1.55555.1.2" # Transcript EKU
```
Allows issuer binding to either:
- TLS DNS name (serverAuth cert)
- Custom X.509 extension

### 8. **Revocation Support**
```python
X509KeyPolicy(
    revocation_mode="hard_fail",     # or "soft_fail"
    revoked_serials=[12345, 67890]   # Explicitly revoked certs
)
```

### 9. **Time-Bound Validation**
Validate certificates as if checks happened at specific time (for forensics/audits).

### 10. **Backward Compatibility with Unsigned**
```python
report = verify_openai_response_signature(response)
# Non-breaking: has_signature=False, valid=None if no signature
# Applications can: if report.has_signature and not report.valid: reject
```

## Entry Points

```bash
# CLI Verification
llm-sign-verify artifact.json \
  --issuer provider.example \
  --public-key public-key.pem
  [--platform openai-compatible]
  [--key-id override-id]

# With Certificate Chain
llm-sign-verify artifact.json \
  --issuer example.com \
  --certificate-chain provider-chain.pem \
  --trust-anchor root-ca.pem \
  --tls-server-name-mode
```

## Python APIs

```python
import llm_sign

# SERVER: Sign a turn
keys = llm_sign.Ed25519KeyPair.generate()
signer = llm_sign.server.create_signer(
    issuer="provider.example",
    key_id=keys.key_id,
    private_key=keys.private_key
)
artifact = llm_sign.server.sign_openai_chat_turn(
    request=request,
    response=response,
    signer=signer
)

# CLIENT: Verify
result = llm_sign.client.verify_with_public_key(
    artifact,
    issuer="provider.example",
    key_id=keys.key_id,
    public_key=keys.public_key
)
assert result.valid

# CLIENT: Relay with X.509
result = llm_sign.client.verify_openai_response_with_certificate_chain(
    response,
    trust_anchors=trust_anchors
)
```

## What's NOT There

- ❌ No HTTP middleware
- ❌ No OpenAI SDK monkey-patching
- ❌ No built-in gateway server
- ❌ No database for keys
- ❌ No certificate generation
- ❌ No key rotation built-in

**Why?** It's a library, not a framework. Providers integrate per their needs.

## Deployment Patterns

### Pattern 1: Direct Integration
```
Provider Signs → Client Verifies with pinned key
```

### Pattern 2: Certificate Chain via Relay
```
Provider Signs + Includes Cert Chain → Relay forwards → Client validates chain
```

### Pattern 3: vLLM with TLS
```python
credential = TLSCertificateCredential.from_files(
    ssl_certfile="/etc/letsencrypt/live/api.example.com/fullchain.pem",
    ssl_keyfile="/etc/letsencrypt/live/api.example.com/privkey.pem"
)
signer = credential.signer()
artifact = sign_openai_chat_turn(request, response, signer)
response["llm_sign"] = {
    "artifact": artifact,
    "certificate_chain": credential.certificate_chain_pem()
}
```

## Test Coverage

- 20+ E2E test methods
- Multi-turn chains
- Tool result blocks
- Proxy tampering scenarios
- Relay with X.509
- OpenAI SDK integration
- Signature suite validation
- PKI chain validation
- Canonicalization validation
- Backward compatibility

**Key insight:** Tests prove that even tiny tampers (1 char in response) break signature. Tampering is caught.

---

## One-Sentence Summary

**LLM_SIGN lets LLM providers cryptographically sign transcripts and clients verify them end-to-end, even through untrusted relays, using full X.509 PKI infrastructure.**
