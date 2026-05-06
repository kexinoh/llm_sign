# LLM_SIGN Comprehensive Project Analysis

## Executive Summary

`llm_sign` is a **complete cryptographic infrastructure for signing and verifying LLM transcript chains**. It's not just a protocol specification—it includes production-ready server-side signing APIs, client-side verification APIs, platform-specific adapters, a CLI tool, and comprehensive test infrastructure with proxy/relay support.

The project implements a **provider-signed transcript chain architecture** where LLM providers cryptographically commit to request-response turns, allowing clients to verify that responses haven't been tampered with or substituted. It's designed for OpenAI-compatible APIs but abstracts the transport and canonicalization layers.

---

## 1. PLATFORMS ADAPTERS (src/llm_sign/platforms/)

### Overview
The platforms module provides pluggable adapters for different LLM providers and integration frameworks. **All adapters inherit from `OpenAICompatibleAdapter`**.

### Adapters

#### 1.1 OpenAI Compatible Adapter (`openai_compatible.py`)
**What it does:** Core adapter for OpenAI Chat Completions API format.

**Key methods:**
- `profiles()` → Returns mapping of canonicalization profiles (input, output, tool results)
- `payloads_from_artifact(artifact)` → Extracts seq-indexed payloads from artifact
  - Handles two modes:
    1. **Non-chained mode:** Maps turns[n].request → seq 2n, turns[n].response → seq 2n+1
    2. **Chained mode:** Extracts payloads from artifact chain blocks, reconstructing from turns

**Profiles used:**
- `OpenAIChatInputProfile` - canonicalizes request payloads
- `OpenAIChatOutputProfile` - canonicalizes response payloads
- `OpenAIToolResultProfile` - canonicalizes tool call result blocks

#### 1.2 Codex CLI Adapter (`codex_cli.py`)
**What it does:** Simple wrapper extending OpenAICompatibleAdapter
- `name = "codex-cli"`
- `aliases = ("codex",)`
- Accepts OpenAI-compatible artifact contract (decouples from Codex internal formats)

#### 1.3 Kimi CLI Adapter (`kimi_cli.py`)
**What it does:** Wrapper for Moonshot/Kimi
- `name = "kimi-cli"`
- `aliases = ("kimi", "moonshot")`

#### 1.4 vLLM Adapter (`vllm.py`)
**What it does:** Support for vLLM server in OpenAI-compatible mode
- `name = "vllm"`
- `aliases = ("vllm-openai", "vllm-chat")`

### PlatformAdapter Protocol
```python
class PlatformAdapter(Protocol):
    name: str
    aliases: tuple[str, ...]
    
    def profiles(self) -> Mapping[str, Profile]
    def payloads_from_artifact(artifact: Mapping[str, Any]) -> Mapping[int, Any]
```

### Platform Registry
```python
get_platform_adapter(name: str) -> PlatformAdapter
```
- Case-insensitive lookup with underscore/dash normalization
- Raises `ValueError` if platform not found

---

## 2. SERVER APIS (src/llm_sign/server/__init__.py)

### Purpose
Server-side signing APIs for producing transcript artifacts. Designed for LLM providers to sign request/response turns.

### Key Functions

#### 2.1 Key Generation
```python
def generate_ed25519_key_pair() -> Ed25519KeyPair
```
- Generates fresh Ed25519 signing key pair
- Returns: `private_key`, `public_key`, `key_id` (SPKI SHA-256)

#### 2.2 Signer Creation
```python
def create_signer(
    issuer: str,
    key_id: str,
    private_key: Any,
    suite_id: Optional[str] = None
) -> TranscriptSigner
```
- Creates a `TranscriptSigner` instance for signing payloads
- `suite_id` auto-inferred from private key type if not specified
- Supports: Ed25519, RSA-PSS, P-256 ECDSA

```python
def signer_from_key_pair(
    key_pair: Ed25519KeyPair,
    issuer: str = DEFAULT_ISSUER
) -> TranscriptSigner
```
- Convenience wrapper around `create_signer`

#### 2.3 OpenAI Chat Completions Signing
```python
def sign_openai_chat_turn(
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    signer: TranscriptSigner
) -> Dict[str, Any]
```
- Signs single request-response turn
- Returns artifact JSON with schema v1

```python
def sign_openai_chat_turns(
    turns: Iterable[Tuple[Mapping[str, Any], Mapping[str, Any]]],
    signer: TranscriptSigner
) -> Dict[str, Any]
```
- Signs multiple turns into one chained artifact
- Each turn gets input block (seq 2n) and output block (seq 2n+1)
- Maintains chain of digests linking blocks

#### 2.4 Artifact Construction
```python
def create_artifact(
    chain: Sequence[SignedBlock],
    turns: Optional[Sequence[Mapping[str, Any]]] = None,
    payloads: Optional[Mapping[int, Any]] = None,
    platform: str = "openai-compatible"
) -> Dict[str, Any]
```
- Builds JSON artifact envelope with:
  - `schema`: "llm-sign.artifact.v1"
  - `platform`: adapter name
  - `chain`: list of signed blocks
  - `turns`: (optional) request/response pairs
  - `payloads`: (optional) seq→payload mappings

### TLS Certificate Integration
```python
# Via vendor module
credential = TLSCertificateCredential.from_files(
    ssl_certfile="/etc/letsencrypt/live/example.com/fullchain.pem",
    ssl_keyfile="/etc/letsencrypt/live/example.com/privkey.pem",
    issuer=None  # auto-extracted from cert SAN/CN
)
signer = credential.signer()
```
- Automatically detects signing suite from certificate key type
- Extracts issuer from TLS cert DNS identity
- Exports certificate chain for relay deployments

---

## 3. CLIENT APIS (src/llm_sign/client/__init__.py)

### Purpose
Client-side verification APIs for validating transcript artifacts. Handles both direct verification and relay/gateway scenarios.

### Key Verification APIs

#### 3.1 Simple Public Key Verification
```python
def verify_with_public_key(
    artifact: Mapping[str, Any],
    issuer: str,
    key_id: str,
    public_key: Any,
    suite_id: Optional[str] = None,
    platform: Optional[str] = None,
    payloads: Optional[Mapping[int, Any]] = None
) -> ChainVerification
```
- Verifies artifact against pinned public key
- Returns: `ChainVerification` object with validity and per-block errors

#### 3.2 X.509 Certificate Chain Verification
```python
def verify_openai_response_with_certificate_chain(
    response: Mapping[str, Any],
    trust_anchors: Sequence[x509.Certificate],
    payloads: Optional[Mapping[int, Any]] = None,
    platform: Optional[str] = None,
    issuer_binding: str = "tls-server-name",
    allow_tls_server_auth: bool = True,
    validation_time: Any = None,
    revocation_mode: str = "soft_fail",
    revoked_serials: Optional[Iterable[int]] = None,
    expected_issuer: Optional[str] = None
) -> ChainVerification
```
- Extracts certificate chain from response
- Validates chain against trust anchors
- Supports two issuer binding modes:
  - `"tls-server-name"`: Bind to TLS certificate DNS identity + allow serverAuth EKU
  - `"llm-sign-extension"`: Use LLM_SIGN_ISSUER_OID X.509 extension
- **Relay scenario:** Certificate chain in `llm_sign.certificate_chain` is supplier's cert, validates up to configured trust anchors

#### 3.3 Backward-Compatible Verification
```python
def verify_openai_response_signature(
    response: Any,
    trust_anchors: Optional[Sequence[x509.Certificate]] = None,
    payloads: Optional[Mapping[int, Any]] = None,
    platform: Optional[str] = None,
    issuer_binding: str = "tls-server-name",
    ...
) -> OpenAIResponseSignatureReport
```
- Returns `OpenAIResponseSignatureReport(has_signature, host_name, valid)`
- `valid=None` if no signature present (unsigned responses allowed)
- `valid=False` if signature verification failed
- Auto-loads system TLS trust anchors if none provided
- **Non-breaking:** Returns report instead of raising on unsigned responses

#### 3.4 Key Policy Builders
```python
def trust_public_key(
    issuer: str,
    key_id: str,
    public_key: Any,
    suite_id: Optional[str] = None
) -> StaticKeyPolicy
```
- Creates in-memory key policy for single trusted key

```python
def x509_key_policy_from_certificate_chain(
    certificate_chain: Sequence[x509.Certificate],
    trust_anchors: Sequence[x509.Certificate],
    issuer_binding: str = "tls-server-name",
    allow_tls_server_auth: bool = True,
    validation_time: Any = None,
    revocation_mode: str = "soft_fail",
    revoked_serials: Optional[Iterable[int]] = None,
    expected_issuer: Optional[str] = None
) -> X509KeyPolicy
```
- Builds X.509 key policy from certificate chain
- Handles chain completion with trust anchors
- Validates time, revocation, EKU constraints

### Artifact Extraction APIs
```python
def artifact_from_openai_response(response: Mapping[str, Any]) -> Mapping[str, Any]
def certificate_chain_from_openai_response(response: Mapping[str, Any], required: bool = True) -> Optional[list[x509.Certificate]]
def host_name_from_artifact(artifact: Mapping[str, Any]) -> Optional[str]
```

### Response Processing
```python
def openai_response_to_dict(value: Any) -> dict[str, Any]
```
- Converts OpenAI SDK response object (ChatCompletion) to plain dict
- Calls `model_dump(mode="json")` for Pydantic v2
- Merges `model_extra` fields
- Fallback to `to_dict()` method

### Summary Functions
```python
def verification_summary(result: ChainVerification) -> Dict[str, Any]
def openai_response_signature_summary(report: OpenAIResponseSignatureReport) -> Dict[str, Any]
```

### System Trust
```python
def load_system_trust_anchors() -> list[x509.Certificate]
```
- Loads from Python's SSL default paths
- De-duplicates by SHA-256 fingerprint
- Used as default when no trust anchors specified

---

## 4. MIDDLEWARE, HOOKS, INTERCEPTORS, MONKEY-PATCHING

### Analysis: **NONE FOUND**

The project does **NOT** implement:
- ❌ Monkey-patching of OpenAI SDK
- ❌ HTTP middleware/interceptors
- ❌ Automatic request/response hooks
- ❌ Proxy server implementations (test-only)

**Why:**
- **Design principle:** Library integrates with existing APIs, doesn't intercept them
- **Integration model:** Applications explicitly call signing/verification functions
- **Flexibility:** Allows use in gateways/relays without forcing specific framework

**Test-only proxy:** `tests/e2e_support/proxy.py` implements `JsonProxyHttpServer` for testing relay scenarios, but it's NOT part of production code.

---

## 5. PROXY/GATEWAY IMPLEMENTATIONS

### Production Code: **NONE**

### Test Support: `JsonProxyHttpServer` (tests/e2e_support/proxy.py)

**What it does:**
- Simulates HTTP relay/gateway between client and server
- Can mutate requests and responses via callbacks
- Tests signature validation under proxy tampering scenarios

**Usage:**
```python
with JsonProxyHttpServer(
    target_base_url="http://provider:8000/v1",
    request_mutator=lambda req: {**req, "model": "modified"},  # optional
    response_mutator=lambda resp: resp,  # optional
) as proxy:
    url = proxy.chat_completions_url  # e.g., "http://127.0.0.1:12345/v1/chat/completions"
```

**Tests that use it:**
- Proxy request modification breaks request block verification
- Proxy tool result reordering breaks followup verification
- Proxy response modification breaks payload verification

### Real-World Pattern: Relay with Certificate Chain

Described in README but not implemented in core:
```
1. Provider signs artifact
2. Provider includes llm_sign.certificate_chain in response
3. Relay/Gateway forwards unchanged
4. Client validates chain against trust anchors
   (HTTPS to relay authenticates relay only, not provider)
5. Signature validates provider's signing key from chain
```

---

## 6. CLI TOOL (src/llm_sign/cli.py)

### Entry Point
```bash
llm-sign-verify artifact.json \
  --issuer provider.example \
  --public-key provider-ed25519-public.pem
```

**Console script defined in pyproject.toml:**
```
[project.scripts]
llm-sign-verify = "llm_sign.cli:main"
```

### Options

#### Public Key Mode
```bash
llm-sign-verify artifact.json \
  --issuer REQUIRED \
  --public-key PEM_OR_DER \
  --key-id <optional, defaults to SPKI SHA-256> \
  --platform <optional, override adapter>
```

#### Certificate Chain Mode
```bash
llm-sign-verify artifact.json \
  --issuer REQUIRED \
  --certificate-chain cert.pem \
  --trust-anchor root-ca.pem \
  --trust-anchor intermediate-ca.pem \
  --tls-server-name-mode <flag>
```
- `--tls-server-name-mode`: Bind issuer to cert DNS identity, allow serverAuth EKU
- Can provide multiple `--trust-anchor` files

### Output Format
JSON with structure:
```json
{
  "valid": true,
  "errors": [],
  "blocks": [
    {
      "seq": 0,
      "type": "provider_received_input",
      "payload_state": "PAYLOAD_VERIFIED"
    },
    ...
  ]
}
```

### Exit Code
- `0`: Valid artifact
- `1`: Invalid artifact

---

## 7. TESTS (tests/)

### Test Structure

#### E2E Tests (`test_e2e_signed_client_flow.py` - 908 lines, 20+ test methods)

**Core scenarios tested:**
1. Single-turn signed flow verifies end-to-end
2. Multi-turn chain maintains signatures across turns
3. Tool call results signed as separate blocks
4. Tool digest-only blocks (payload omitted)
5. Multiple tool calls in single turn
6. Proxy tampering scenarios:
   - Request modification breaks verification
   - Response modification breaks verification
   - Tool result reordering breaks verification
   - Tool result substitution breaks verification
7. Relay with supplier certificate chain
8. Backward compatibility with unsigned responses
9. OpenAI SDK integration

**Client test helpers:**
- `SignedChatClient`: Static key verification
- `CertificateChainSignedChatClient`: X.509 chain verification

**Server test helpers:**
- `SignedChatHttpServer`: Mock server returning signed responses
- `JsonProxyHttpServer`: Relay/gateway proxy

#### Platform Tests (`test_platform_artifact.py`)
- Artifact payload extraction for different platforms
- Chained vs. non-chained artifact handling

#### Signature Suite Tests (`test_sign_verify.py`)
- Block signing and verification
- Digest computation
- Payload canonicalization
- Error handling (tampered blocks, invalid digests)

#### PKI Tests (`test_pki.py`)
- X.509 certificate chain validation
- Certificate issuer extraction
- Key ID computation
- Trust anchor resolution
- Revocation checking

#### Canonicalization Tests (`test_openai_profile.py`)
- OpenAI Chat Completions input/output canonicalization
- Unknown field detection
- Required field validation

#### Vendor Tests (`test_vendor_tls.py`)
- TLS certificate credential loading
- Private key/certificate validation
- Issuer extraction from certificate

#### Public API Tests (`test_public_api.py`)
- Module exports
- Import paths
- Backward compatibility shims

### Test Support Modules

**`tests/e2e_support/`:**
- `server.py`: `SignedChatService` and `SignedChatHttpServer` with threading
- `client.py`: `SignedChatClient` and `CertificateChainSignedChatClient`
- `proxy.py`: `JsonProxyHttpServer` for gateway testing
- `payloads.py`: Test data builders
- `constants.py`: Shared test constants

---

## 8. EXAMPLES (example/)

### 1. Offline Verification (`offline_openai_chat_verify.py`)
- **What:** Verify bundled signed response without network
- **Uses:** `certificate_chain_from_openai_response`, `verify_openai_response_signature`
- **Pattern:** Self-signed fixture, load trust anchor from chain

### 2. OpenAI Client Verification (`openai_client_verify.py`)
- **What:** Call real OpenAI-compatible endpoint, verify signature
- **Uses:** OpenAI Python SDK + `verify_openai_response_signature`
- **Pattern:** Non-breaking verification (returns report, allows unsigned)
- **Config:** `OPENAI_API_KEY`, `OPENAI_MODEL`, `OPENAI_BASE_URL`

### 3. Tamper Detection (`tamper_detection.py`)
- **What:** Show signature verification failure after payload modification
- **Pattern:** Modify artifact turns, verify fails with `valid=False`

### Shared Fixture (`_signed_openai_fixture.py`)
- Pre-signed OpenAI-compatible response for reproducible testing
- Ed25519-signed with test key

---

## 9. VENDOR MODULE (src/llm_sign/vendor/)

### TLS Certificate Credential (`vendor/tls.py`)

**Use case:** vLLM-style integrations where provider already receives `--ssl-certfile` and `--ssl-keyfile`

```python
@dataclass(frozen=True)
class TLSCertificateCredential:
    issuer: str
    key_id: str
    suite_id: str
    private_key: Any
    certificate_chain: Sequence[x509.Certificate]
    
    @classmethod
    def from_files(
        cls,
        ssl_certfile: Union[str, Path],
        ssl_keyfile: Union[str, Path],
        issuer: Optional[str] = None,
        password: Optional[bytes] = None
    ) -> TLSCertificateCredential
    
    def signer(self) -> TranscriptSigner
    def certificate_chain_pem(self) -> list[str]
```

**Capabilities:**
- Loads certificate chain from PEM certfile
- Loads private key from PEM keyfile
- Auto-detects signing suite (Ed25519, RSA, ECDSA) from key type
- Validates private key matches certificate
- Extracts issuer from certificate SAN or CN
- Returns `TranscriptSigner` for immediate use
- Exports chain as PEM strings for response envelope

**Validation:**
- Raises `VerificationError` if key doesn't match cert
- Raises `ValueError` if cert has no DNS subject identity

---

## 10. CORE PROTOCOL PRIMITIVES (src/llm_sign/core/)

### blocks.py: Block Structure and Signing

**Block types (constants):**
```python
PROVIDER_RECEIVED_INPUT = "provider_received_input"
PROVIDER_OUTPUT = "provider_output"
TOOL_RESULT = "tool_result"
```

**Block dataclass:**
```python
@dataclass(frozen=True)
class Block:
    version: str              # Protocol version
    suite_id: str             # Signing suite (e.g., "sha256-ed25519-v1")
    chain_id: bytes           # Random 16+ byte chain identifier
    seq: int                  # Sequence number (0-indexed)
    issuer: str               # Provider identifier
    key_id: str               # Key identifier within issuer
    type: str                 # Block type (see above)
    profile_id: str           # Canonicalization profile
    prev_block_digest: Optional[bytes]  # Digest of previous block (None for seq=0)
    payload_digest: bytes     # SHA-256 digest of canonicalized payload
```

**SignedBlock:**
```python
@dataclass(frozen=True)
class SignedBlock:
    block: Block
    signature: bytes          # Signature over block digest
```

**TranscriptSigner:**
```python
class TranscriptSigner:
    def __init__(
        self,
        issuer: str,
        key_id: str,
        private_key: Any,
        suite_id: Optional[str] = None
    ):
        # Infer suite_id from private key if not specified
    
    def sign_payload(
        self,
        block_type: str,
        profile: Profile,
        payload: Mapping[str, Any],
        previous: Optional[SignedBlock] = None
    ) -> SignedBlock:
        # 1. Canonicalize payload using profile
        # 2. Compute payload digest
        # 3. Create block with chain linkage
        # 4. Sign block digest
        # 5. Return SignedBlock
```

### crypto.py: Signature Suites

**Registered suites:**
1. `Ed25519Sha256Suite` (suite_id: `sha256-ed25519-v1`)
   - Private: `Ed25519PrivateKey`
   - Public: `Ed25519PublicKey`
   - Signing: Direct ED25519

2. `RsaPssSha256Suite` (suite_id: `sha256-rsa-pss-v1`)
   - Private: `RSAPrivateKey` (2048+ bits)
   - Public: `RSAPublicKey`
   - Signing: RSA-PSS with DIGEST_LENGTH salt

3. `EcdsaP256Sha256Suite` (suite_id: `sha256-ecdsa-p256-v1`)
   - Private: `EllipticCurvePrivateKey` (P-256)
   - Public: `EllipticCurvePublicKey` (P-256)
   - Signing: ECDSA with SHA-256

**Suite inference:**
```python
def infer_suite_for_private_key(private_key: Any) -> str
def infer_suite_for_public_key(public_key: Any) -> str
```

**Suite registration (extensible):**
```python
def register_signature_suite(suite: SignatureSuite) -> None
def supported_suite_ids() -> tuple[str, ...]
```

### encoding.py: Block and Payload Encoding

**Wire format:**
- Field-tagged length-prefixed encoding
- Binary encoding for variable-length data
- Supports proper Unicode handling

**Functions:**
```python
def block_digest(suite_id: str, encoded_block: bytes) -> bytes
def payload_digest(suite_id: str, canonicalized_payload: bytes) -> bytes
```

### profiles.py: Profile Protocol

```python
class Profile(Protocol):
    profile_id: str
    def canonicalize(self, payload: Mapping[str, Any]) -> bytes
```

All profiles:
- Accept request or response payload
- Return canonicalized UTF-8 JSON bytes
- Validate required/unknown fields
- Reject non-finite numbers, duplicates

---

## 11. CANONICALIZATION PROFILES (src/llm_sign/profiles/)

### OpenAI Chat Completions Profiles

#### OpenAIChatInputProfile
- **ID:** `openai.chat-completions.input.v1`
- **Fields included:** 25+ including messages, model, temperature, tools, etc.
- **Fields excluded:** user, stream, metadata, store (transport/metadata)
- **Required:** messages, model

#### OpenAIChatOutputProfile
- **ID:** `openai.chat-completions.output.v1`
- **Fields included:** choices, model, response_format
- **Fields excluded:** created, id, usage, system_fingerprint (transport metadata)
- **Required:** choices, model

#### OpenAIToolResultProfile
- **ID:** `openai.chat-completions.tool-result.v1`
- **Canonicalizes tool call result message objects**

### Canonical JSON (`canonical_json.py`)

**Format:**
```json
{
  "key1":"value1","key2":"value2"
}
```
- UTF-8 encoded
- Sorted keys
- No spaces after separators
- Duplicate key detection
- Non-finite number rejection (NaN, Infinity)
- Unicode allowed (not ASCII-only)

**Validation:**
```python
def canonical_json_bytes(value: Any) -> bytes
def project_mapping(
    payload: Mapping,
    include: Set[str],
    exclude: Set[str],
    required: Set[str],
    profile_name: str
) -> MutableMapping
```

---

## 12. KEY POLICIES (src/llm_sign/keys/)

### StaticKeyPolicy
**Use case:** Tests, direct verification with pinned public key

```python
class StaticKeyPolicy(KeyPolicy):
    def __init__(self, keys: Mapping[Tuple[str, str, str], Any]):
        # Key lookup: (issuer, key_id, suite_id) → public_key
```

### X509KeyPolicy
**Use case:** Production deployments with certificate chains

**Features:**
- Chain validation against trust anchors
- Issuer binding modes:
  - `tls-server-name`: Issuer = TLS certificate DNS identity
  - `llm-sign-extension`: Issuer = X.509 extension value
- Extended Key Usage enforcement:
  - Optional TLS serverAuth (`id-kp-serverAuth`)
  - Custom LLM transcript EKU (`1.3.6.1.4.1.55555.1.2`)
- Validation time control (expired cert detection)
- Revocation checking (soft_fail or hard_fail)
- Revoked serial number list support

**Certificate parsing:**
```python
def certificate_key_id(cert: x509.Certificate) -> str
def load_pem_certificates(data: bytes) -> list[x509.Certificate]
```

**Custom X.509 OIDs:**
```python
LLM_SIGN_ISSUER_OID = "1.3.6.1.4.1.55555.1.1"        # Issuer extension
LLM_SIGN_TRANSCRIPT_EKU_OID = "1.3.6.1.4.1.55555.1.2" # Transcript EKU
```

---

## 13. VERIFIER (src/llm_sign/verifier.py)

**High-level artifact verification:**

```python
def load_signed_blocks(artifact: Mapping[str, Any]) -> list[SignedBlock]
def verify_artifact(
    artifact: Mapping[str, Any],
    key_policy: KeyPolicy,
    platform: Optional[str] = None,
    payloads: Optional[Mapping[int, Any]] = None
) -> ChainVerification
```

**Flow:**
1. Load platform adapter (default: openai-compatible)
2. Extract signed blocks from artifact
3. Load payloads from artifact + explicit overrides
4. Verify chain with platform's profiles and key policy
5. Return ChainVerification with validity and per-block status

**Payload modes:**
- **Embedded:** Extracted from artifact.payloads and artifact.turns
- **External:** Passed as explicit parameter (for relay scenarios)
- **Merged:** External payloads override embedded

---

## 14. FULL INTEGRATION FLOW

### Server (Provider) Side

```python
import llm_sign

# 1. Load or generate signing key
keys = llm_sign.Ed25519KeyPair.generate()

# 2. Create signer
signer = llm_sign.server.create_signer(
    issuer="provider.example",
    key_id=keys.key_id,
    private_key=keys.private_key,
)

# 3. After LLM completion, sign the turn
artifact = llm_sign.server.sign_openai_chat_turn(
    request=request,
    response=response,
    signer=signer,
)

# 4. Include in OpenAI-compatible response
return {
    "id": "chatcmpl-xxx",
    "object": "chat.completion",
    "created": ...,
    "model": ...,
    "choices": [...],
    "llm_sign": {
        "artifact": artifact,
        # Optional for relay: certificate_chain
    }
}
```

### Client (Verifier) Side - Direct

```python
import llm_sign

# Response from OpenAI-compatible API
response = client.chat.completions.create(...)

# Verify with pinned public key
result = llm_sign.client.verify_with_public_key(
    artifact=llm_sign.client.artifact_from_openai_response(response),
    issuer="provider.example",
    key_id=keys.key_id,
    public_key=keys.public_key,
)

assert result.valid, result.errors
```

### Client Side - Via Relay with Certificate Chain

```python
import llm_sign

# Response from relay/gateway
response = client.chat.completions.create(...)

# Load system TLS trust anchors
trust_anchors = llm_sign.client.load_system_trust_anchors()

# Verify provider's signature via certificate chain
result = llm_sign.client.verify_openai_response_with_certificate_chain(
    response,
    trust_anchors=trust_anchors,
)

assert result.valid, result.errors
```

### vLLM Integration

```python
from llm_sign.vendor import TLSCertificateCredential
import llm_sign

# At vLLM startup, create credential
credential = TLSCertificateCredential.from_files(
    ssl_certfile="/etc/letsencrypt/live/api.example.com/fullchain.pem",
    ssl_keyfile="/etc/letsencrypt/live/api.example.com/privkey.pem",
)

# Get signer
signer = credential.signer()

# At each completion
artifact = llm_sign.server.sign_openai_chat_turn(
    request=request,
    response=response,
    signer=signer,
)

# Include in response
response_dict["llm_sign"] = {
    "artifact": artifact,
    "certificate_chain": credential.certificate_chain_pem(),
}
```

---

## 15. ADVANCED FEATURES

### Multi-Turn Chains
```python
artifact = llm_sign.server.sign_openai_chat_turns(
    turns=[
        (turn1_request, turn1_response),
        (turn2_request, turn2_response),
        # ...
    ],
    signer=signer,
)
```
- Each turn gets 2 blocks (input seq 2n, output seq 2n+1)
- Blocks linked via `prev_block_digest`
- Single artifact with all turns + full chain

### Tool Call Results
- Tool results signed as separate `tool_result` blocks
- Sequence: input → output (with tool call) → tool_result (digest-only)
- Allows server to commit to tool use without full result payload

### Payload Verification Modes
1. **Embedded:** Payloads in artifact (turns or payloads dict)
2. **External:** Client provides payloads (proxy scenario)
3. **Digest-only:** No payload, only digest validation (tool results)

### Revocation Support
```python
key_policy = llm_sign.X509KeyPolicy(
    trust_anchors=trust_anchors,
    certificate_chains=chains,
    revocation_mode="hard_fail",  # or "soft_fail"
    revoked_serials=[12345, 67890],
)
```

### Time-Bound Validation
```python
key_policy = llm_sign.X509KeyPolicy(
    trust_anchors=trust_anchors,
    certificate_chains=chains,
    validation_time=datetime(2025, 6, 1),  # Validate as of specific time
)
```

---

## 16. ENTRY POINTS & CONSOLE SCRIPTS

From `pyproject.toml`:
```toml
[project.scripts]
llm-sign-verify = "llm_sign.cli:main"
```

**Only one console script:**
- `llm-sign-verify`: Artifact verification CLI

**No auto-signing tools** (by design—providers implement signing per their needs)

---

## 17. WHAT'S MISSING / NOT IMPLEMENTED

✅ **What IS implemented:**
- Complete signing and verification protocols
- Server-side APIs for signing
- Client-side APIs for verification
- Three signature suites (Ed25519, RSA-PSS, ECDSA)
- X.509 PKI support
- Multi-turn chain support
- Tool result blocks
- Platform adapters for multiple LLMs
- CLI verification tool
- Comprehensive test suite with relay testing

❌ **What is NOT implemented (by design):**
- No HTTP middleware or auto-interception
- No OpenAI SDK monkey-patching
- No built-in gateway/relay server (pattern in docs, not implementation)
- No database or persistent key storage
- No certificate generation tools
- No key rotation mechanisms
- No audit logging
- No performance optimizations (not needed at current scale)

**Rationale:** Library, not framework. Providers integrate signing per their architecture.

---

## 18. PROJECT STATISTICS

- **Lines of code:** ~5,000 (src) + ~3,000 (tests) = ~8,000 total
- **Python files:** 31 total (26 src + 13 test/support)
- **Test methods:** 20+ in E2E, 30+ total across all test files
- **Platforms supported:** 4 adapters (OpenAI-compatible, Codex, Kimi, vLLM)
- **Signature suites:** 3 (Ed25519, RSA-PSS, ECDSA-P256)
- **X.509 features:** Full chain validation, EKU, revocation, time-based
- **Dependencies:** Only `cryptography>=42` (+ optional `openai>=1`)

---

## 19. BACKWARD COMPATIBILITY

**Compatibility shims** (in root module, map to new locations):
```python
from llm_sign import blocks       # → core.blocks
from llm_sign import openai       # → profiles.openai_chat + vendor
from llm_sign import keys         # → keys.ed25519 + keys.x509
from llm_sign import pki          # → keys.x509
from llm_sign import vendor       # → vendor
```

Allows old imports to work while new code uses `llm_sign.client` and `llm_sign.server`.

---

## 20. DESIGN PHILOSOPHY

1. **Protocol-centric:** Specification-first, multiple implementations possible
2. **Non-intrusive:** Library doesn't intercept or modify providers
3. **Flexible canonicalization:** Profiles abstract payload format
4. **Platform-agnostic:** Adapters support multiple LLM platforms
5. **End-to-end verification:** Clients validate all the way to provider key
6. **Relay-friendly:** Certificate chains enable gateway deployments
7. **Extensible:** New signature suites and profiles can be registered
8. **Test-first:** Comprehensive E2E tests with proxy/tampering scenarios
9. **Production-ready:** X.509 PKI, revocation, time validation all supported

