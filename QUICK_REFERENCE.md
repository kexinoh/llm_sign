# LLM_SIGN Quick Reference Guide

## What Each Module Does

### `src/llm_sign/server/` - Provider Signing
**For:** LLM providers wanting to cryptographically sign responses
- `generate_ed25519_key_pair()` - Create signing key
- `create_signer(issuer, key_id, private_key)` - Build signer instance
- `sign_openai_chat_turn(request, response, signer)` - Sign single turn
- `sign_openai_chat_turns(turns, signer)` - Sign multi-turn chain
- `create_artifact(chain, turns, payloads, platform)` - Build JSON artifact
- **No middleware.** Call these explicitly.

### `src/llm_sign/client/` - Client Verification
**For:** Applications verifying signed LLM responses
- `verify_with_public_key(artifact, issuer, key_id, public_key)` - Direct verification
- `verify_openai_response_signature(response)` - Non-breaking check (allows unsigned)
- `verify_openai_response_with_certificate_chain(response, trust_anchors)` - X.509 chain verification
- `artifact_from_openai_response(response)` - Extract artifact
- `certificate_chain_from_openai_response(response)` - Extract certificate chain
- `host_name_from_artifact(artifact)` - Get issuer/host name
- `trust_public_key(issuer, key_id, public_key)` - Build StaticKeyPolicy
- `x509_key_policy_from_certificate_chain(chain, trust_anchors)` - Build X509KeyPolicy
- `load_system_trust_anchors()` - Get OS CA bundle
- `verification_summary(result)` - Format for JSON output
- `openai_response_signature_summary(report)` - Format report for JSON
- `openai_response_to_dict(value)` - Convert OpenAI SDK object to dict

### `src/llm_sign/platforms/` - Multi-Platform Support
**What:** Adapters that handle different LLM platforms
- **All inherit from `OpenAICompatibleAdapter`**
- `CodexCliAdapter` - Codex CLI format → OpenAI-compatible contract
- `KimiCliAdapter` - Kimi/Moonshot → OpenAI-compatible contract
- `VllmAdapter` - vLLM → OpenAI-compatible contract
- `get_platform_adapter(name)` - Registry lookup

**Each adapter provides:**
- `profiles()` - Canonicalization rules for platform
- `payloads_from_artifact(artifact)` - Extract seq→payload mappings

### `src/llm_sign/core/` - Core Protocol
**What:** Low-level block signing and verification (don't use directly, use server/client)
- `Block` - Signed commitment unit
- `SignedBlock` - Block + signature
- `TranscriptSigner` - Signs payloads into blocks
- `verify_chain()` - Verify entire block chain
- `sign_payload()` - Sign single payload
- Signature suites: Ed25519, RSA-PSS, ECDSA-P256

### `src/llm_sign/profiles/` - Canonicalization
**What:** Rules for converting payloads to canonical form before signing
- `OpenAIChatInputProfile` - Request canonicalization (25+ fields)
- `OpenAIChatOutputProfile` - Response canonicalization (4 key fields)
- `OpenAIToolResultProfile` - Tool result canonicalization
- `canonical_json_bytes(value)` - Strict canonical JSON

**Key rule:** Same input always produces identical bytes (no randomness, sorted keys, no spaces)

### `src/llm_sign/keys/` - Key Policies
**What:** Strategies for resolving which key to use for verification
- `Ed25519KeyPair` - Generate Ed25519 key pair
- `StaticKeyPolicy` - In-memory key lookup (tests, pinned key)
- `X509KeyPolicy` - Certificate chain validation
  - Validates chain to trust anchors
  - Checks EKU (Extended Key Usage)
  - Supports revocation checking
  - Time-bound validation
  - Custom LLM_SIGN OIDs

### `src/llm_sign/vendor/` - Infrastructure Integration
**What:** Helpers for deployment scenarios
- `TLSCertificateCredential` - Load TLS cert+key, auto-detect signing suite
  - `.from_files(certfile, keyfile, issuer, password)`
  - `.signer()` - Get TranscriptSigner
  - `.certificate_chain_pem()` - Export for response envelope
  - **Use case:** vLLM integration (cert/key already available via CLI args)

### `src/llm_sign/cli.py` - Command-Line Verification
**Entry point:** `llm-sign-verify`
```bash
llm-sign-verify artifact.json --issuer provider.example --public-key key.pem
llm-sign-verify artifact.json --issuer example.com --certificate-chain chain.pem --trust-anchor root.pem --tls-server-name-mode
```

### `src/llm_sign/verifier.py` - High-Level Verification
**What:** Bridges artifacts and verification
- `load_signed_blocks(artifact)` - Extract chain
- `verify_artifact(artifact, key_policy, platform, payloads)` - Full verification

---

## Data Structures

### Artifact JSON (v1 schema)
```json
{
  "schema": "llm-sign.artifact.v1",
  "platform": "openai-compatible",
  "chain": [
    {
      "block": {
        "version": "v1",
        "suite_id": "sha256-ed25519-v1",
        "chain_id": "...",
        "seq": 0,
        "issuer": "provider.example",
        "key_id": "spki-sha256:...",
        "type": "provider_received_input",
        "profile_id": "openai.chat-completions.input.v1",
        "prev_block_digest": null,
        "payload_digest": "..."
      },
      "signature": "...",
      "block_digest": "..."
    },
    // More blocks...
  ],
  "turns": [
    { "request": {...}, "response": {...} },
    // More turns...
  ],
  "payloads": {
    "0": {...},  // Matches block seq
    "1": {...}
  }
}
```

### ChainVerification Result
```python
ChainVerification(
    valid: bool,                    # True if all blocks valid and properly chained
    errors: list[str],              # Per-block error messages
    blocks: list[VerifiedBlock]     # Each block's state
)

# VerifiedBlock has:
VerifiedBlock.payload_state  # "PAYLOAD_VERIFIED", "PAYLOAD_MISMATCH", "PAYLOAD_MISSING"
VerifiedBlock.signed_block   # Original SignedBlock
```

### OpenAIResponseSignatureReport
```python
OpenAIResponseSignatureReport(
    has_signature: bool,    # True if llm_sign.artifact present
    host_name: Optional[str],  # Issuer from block
    valid: Optional[bool]   # True/False if signature checked, None if unsigned
)
```

---

## Signature Suites

| Suite ID | Algorithm | Private Key | Public Key | Use Case |
|----------|-----------|-------------|-----------|----------|
| `sha256-ed25519-v1` | Ed25519/SHA-256 | Ed25519PrivateKey | Ed25519PublicKey | **Recommended** (fast, compact) |
| `sha256-rsa-pss-v1` | RSA-PSS/SHA-256 | RSAPrivateKey | RSAPublicKey | Enterprise (existing RSA infra) |
| `sha256-ecdsa-p256-v1` | ECDSA-P256/SHA-256 | EllipticCurvePrivateKey (P-256) | EllipticCurvePublicKey (P-256) | Alternative |

**Auto-detection:** If suite_id not specified, inferred from key type.

---

## Common Workflows

### Pattern 1: Sign and Verify (Direct)
```python
import llm_sign

# Provider
keys = llm_sign.Ed25519KeyPair.generate()
signer = llm_sign.server.create_signer(
    issuer="provider.example",
    key_id=keys.key_id,
    private_key=keys.private_key
)
artifact = llm_sign.server.sign_openai_chat_turn(request, response, signer)

# Client
result = llm_sign.client.verify_with_public_key(
    artifact,
    issuer="provider.example",
    key_id=keys.key_id,
    public_key=keys.public_key
)
if result.valid:
    print("✓ Signature verified")
else:
    print("✗ Signature invalid:", result.errors)
```

### Pattern 2: Relay with Certificate Chain
```python
import llm_sign
from cryptography import x509

# Provider: Include certificate chain
response["llm_sign"] = {
    "artifact": artifact,
    "certificate_chain": [cert.public_bytes(...).decode() for cert in chain]
}

# Client: Verify against trust anchors
trust_anchors = llm_sign.client.load_system_trust_anchors()
result = llm_sign.client.verify_openai_response_with_certificate_chain(
    response,
    trust_anchors=trust_anchors
)
assert result.valid
```

### Pattern 3: vLLM Integration
```python
from llm_sign.vendor import TLSCertificateCredential
import llm_sign

# Startup
credential = TLSCertificateCredential.from_files(
    ssl_certfile="/etc/letsencrypt/live/api.example.com/fullchain.pem",
    ssl_keyfile="/etc/letsencrypt/live/api.example.com/privkey.pem"
)
signer = credential.signer()

# Per-request
artifact = llm_sign.server.sign_openai_chat_turn(request, response, signer)
response_dict["llm_sign"] = {
    "artifact": artifact,
    "certificate_chain": credential.certificate_chain_pem()
}
```

### Pattern 4: CLI Verification
```bash
# Public key
llm-sign-verify artifact.json \
  --issuer provider.example \
  --public-key provider-key.pem

# Certificate chain
llm-sign-verify artifact.json \
  --issuer example.com \
  --certificate-chain provider-chain.pem \
  --trust-anchor root.pem \
  --tls-server-name-mode

# Output: JSON with valid, errors, blocks
```

### Pattern 5: Backward-Compatible Verification (Allows Unsigned)
```python
import llm_sign

response = client.chat.completions.create(...)

report = llm_sign.client.verify_openai_response_signature(response)

print(f"Has signature: {report.has_signature}")
print(f"Host: {report.host_name}")
print(f"Valid: {report.valid}")  # None if no signature

# Application logic
if report.has_signature and report.valid is False:
    raise Exception("Signature verification failed")
```

---

## CLI Examples

```bash
# Verify with public key file
llm-sign-verify artifact.json \
  --issuer provider.example \
  --public-key provider-ed25519-public.pem

# Verify with key ID override
llm-sign-verify artifact.json \
  --issuer provider.example \
  --public-key provider-public.pem \
  --key-id my-custom-key-id

# Verify with X.509 certificate chain
llm-sign-verify artifact.json \
  --issuer example.com \
  --certificate-chain provider-fullchain.pem \
  --trust-anchor root-ca.pem \
  --trust-anchor intermediate-ca.pem

# TLS server name mode (bind to cert DNS, allow serverAuth EKU)
llm-sign-verify artifact.json \
  --issuer example.com \
  --certificate-chain provider-chain.pem \
  --trust-anchor root.pem \
  --tls-server-name-mode

# Override platform adapter
llm-sign-verify artifact.json \
  --issuer provider.example \
  --public-key key.pem \
  --platform vllm

# All outputs are JSON
llm-sign-verify artifact.json --issuer p.com --public-key k.pem | jq '.valid'
```

---

## Block Types

```python
PROVIDER_RECEIVED_INPUT = "provider_received_input"  # Client request
PROVIDER_OUTPUT = "provider_output"                  # Provider response
TOOL_RESULT = "tool_result"                          # Tool call result
```

Sequence pattern for multi-turn:
```
seq 0: PROVIDER_RECEIVED_INPUT  (turn 1 request)
seq 1: PROVIDER_OUTPUT          (turn 1 response)
seq 2: PROVIDER_RECEIVED_INPUT  (turn 2 request with turn 1 response)
seq 3: PROVIDER_OUTPUT          (turn 2 response)
```

Tool results get inserted between turns:
```
seq 0-1: Turn 1 (request + response with tool call)
seq 2:   TOOL_RESULT            (tool execution result)
seq 3-4: Turn 2 (request with tool result + response)
```

---

## Troubleshooting

### "unresolved, ambiguous, expired, or untrusted key"
- Key not in policy
- Suite ID mismatch
- Certificate not trusted or expired

### "payload digest mismatch"
- Payload was modified
- Canonicalization rule changed
- Profile_id incompatible

### "non-genesis block must have prev_block_digest"
- Block at seq>0 missing chain linkage
- Chain was modified (block removed/inserted)

### "duplicate JSON object key"
- Payload has duplicate keys (invalid canonical form)
- Canonicalization function should have caught this

### "unsupported platform adapter"
- Check `--platform` flag value
- Available: openai-compatible, codex-cli, kimi-cli, vllm

---

## Testing

```bash
cd /Users/xiangfanwu/Documents/GitHub/llm_sign
python -m pytest tests/test_e2e_signed_client_flow.py -v
python -m pytest tests/test_sign_verify.py -v
python -m pytest tests/test_pki.py -v
```

Key test scenarios:
- E2E signed flow verifies
- Multi-turn chains link correctly
- Tool results signed as separate blocks
- Proxy tampering is caught
- Relay with X.509 works
- Unsigned responses don't error (backward compat)
- OpenAI SDK integration works
