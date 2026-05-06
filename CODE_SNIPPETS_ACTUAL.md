# LLM_SIGN: Actual Code Snippets

## File-by-File Breakdown with Full Code

---

## 1. Platform Adapters - All Tiny!

### `src/llm_sign/platforms/openai_compatible.py` (84 lines)

```python
"""Adapter for OpenAI Chat Completions compatible artifacts."""

class OpenAICompatibleAdapter:
    name = "openai-compatible"
    aliases = ("openai", "chat-completions", "chat-completion")

    def __init__(self) -> None:
        self.input_profile = OpenAIChatInputProfile()
        self.output_profile = OpenAIChatOutputProfile()
        self.tool_result_profile = OpenAIToolResultProfile()

    def profiles(self) -> Mapping[str, Profile]:
        return {
            self.input_profile.profile_id: self.input_profile,
            self.output_profile.profile_id: self.output_profile,
            self.tool_result_profile.profile_id: self.tool_result_profile,
        }

    def payloads_from_artifact(self, artifact: Mapping[str, Any]) -> Mapping[int, Any]:
        """Extract request/response payloads from artifact turns, indexed by seq"""
        payloads: Dict[int, Any] = {}
        
        # Handle chain turns first
        if artifact.get("chain"):
            self._payloads_from_chain_turns(artifact, turns, payloads)
            return payloads
        
        # Standard turns: turn[0] = seq 0 (request), seq 1 (response), etc.
        for index, turn in enumerate(artifact.get("turns", [])):
            request = turn.get("request", turn.get("input"))
            response = turn.get("response", turn.get("output"))
            if request is not None:
                payloads.setdefault(index * 2, request)      # seq 0, 2, 4, ...
            if response is not None:
                payloads.setdefault(index * 2 + 1, response)  # seq 1, 3, 5, ...
        
        return payloads
```

**That's it. Just JSON extraction. 84 total lines.**

### `src/llm_sign/platforms/vllm.py` (9 lines)

```python
"""vLLM artifact adapter for OpenAI-compatible chat completions."""

from .openai_compatible import OpenAICompatibleAdapter


class VllmAdapter(OpenAICompatibleAdapter):
    name = "vllm"
    aliases = ("vllm-openai", "vllm-chat")
```

**Just a name change. No custom logic.**

### `src/llm_sign/platforms/codex_cli.py` (9 lines)

```python
"""Codex CLI artifact adapter."""

from .openai_compatible import OpenAICompatibleAdapter


class CodexCliAdapter(OpenAICompatibleAdapter):
    name = "codex-cli"
    aliases = ("codex",)
```

**Same pattern.**

### `src/llm_sign/platforms/kimi_cli.py` (9 lines)

```python
"""Kimi CLI artifact adapter."""

from .openai_compatible import OpenAICompatibleAdapter


class KimiCliAdapter(OpenAICompatibleAdapter):
    name = "kimi-cli"
    aliases = ("kimi", "moonshot")
```

**All identical.**

---

## 2. Server API - Signing Functions

### `src/llm_sign/server/__init__.py` (Core Functions)

```python
def generate_ed25519_key_pair() -> Ed25519KeyPair:
    """Generate an Ed25519 transcript signing key pair."""
    return Ed25519KeyPair.generate()


def create_signer(
    *,
    issuer: str,
    key_id: str,
    private_key: Any,
    suite_id: Optional[str] = None,
) -> TranscriptSigner:
    """Create a transcript signer for a provider-controlled private key."""
    return TranscriptSigner(
        issuer=issuer,
        key_id=key_id,
        private_key=private_key,
        suite_id=suite_id,
    )


def sign_openai_chat_turn(
    *,
    request: Mapping[str, Any],
    response: Mapping[str, Any],
    signer: TranscriptSigner,
) -> Dict[str, Any]:
    """Sign one OpenAI-compatible Chat Completions request/response turn."""
    return sign_openai_chat_turns(
        turns=[(request, response)],
        signer=signer,
    )


def sign_openai_chat_turns(
    *,
    turns: Iterable[Tuple[Mapping[str, Any], Mapping[str, Any]]],
    signer: TranscriptSigner,
) -> Dict[str, Any]:
    """Sign OpenAI-compatible Chat Completions turns into one artifact."""
    
    input_profile = OpenAIChatInputProfile()
    output_profile = OpenAIChatOutputProfile()
    chain: List[SignedBlock] = []
    artifact_turns: List[Dict[str, Any]] = []
    last_block: Optional[SignedBlock] = None

    for request, response in turns:
        # Sign request as input block
        input_block = signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=input_profile,
            payload=request,
            previous=last_block,  # Links to previous block
        )
        
        # Sign response as output block
        output_block = signer.sign_payload(
            block_type=PROVIDER_OUTPUT,
            profile=output_profile,
            payload=response,
            previous=input_block,  # Links to input block
        )
        
        chain.extend([input_block, output_block])
        artifact_turns.append({"request": dict(request), "response": dict(response)})
        last_block = output_block

    return create_artifact(chain=chain, turns=artifact_turns)


def create_artifact(
    *,
    chain: Sequence[SignedBlock],
    turns: Optional[Sequence[Mapping[str, Any]]] = None,
    payloads: Optional[Mapping[int, Any]] = None,
    platform: str = OPENAI_COMPATIBLE_PLATFORM,
) -> Dict[str, Any]:
    """Build the standard JSON artifact envelope from signed blocks."""
    
    artifact: Dict[str, Any] = {
        "schema": ARTIFACT_SCHEMA,  # "llm-sign.artifact.v1"
        "platform": platform,       # "openai-compatible"
        "chain": [block.to_dict() for block in chain],
    }
    if turns is not None:
        artifact["turns"] = list(turns)
    if payloads is not None:
        artifact["payloads"] = {str(seq): payload for seq, payload in payloads.items()}
    return artifact
```

**All pure functions. No I/O, no HTTP, no persistence.**

---

## 3. Client API - Verification Functions

### `src/llm_sign/client/__init__.py` (Core Functions)

```python
def verify_openai_response_signature(
    response: Any,
    *,
    trust_anchors: Optional[Sequence[x509.Certificate]] = None,
    payloads: Optional[Mapping[int, Any]] = None,
    platform: Optional[str] = None,
    issuer_binding: str = "tls-server-name",
    allow_tls_server_auth: bool = True,
    validation_time: Any = None,
    revocation_mode: str = "soft_fail",
    revoked_serials: Optional[Iterable[int]] = None,
    expected_issuer: Optional[str] = None,
) -> OpenAIResponseSignatureReport:
    """Verify a response if it carries llm_sign data; unsigned responses are allowed."""
    
    # Convert response to dict if it's an SDK object
    response_data = openai_response_to_dict(response)
    
    # Try to extract artifact
    artifact = _optional_artifact_from_openai_response(response_data)
    if artifact is None:
        # No signature - that's OK
        return OpenAIResponseSignatureReport(
            has_signature=False,
            host_name=None,
            valid=None,
        )
    
    # Extract claimed host from first block
    host_name = host_name_from_artifact(artifact)
    
    try:
        # Load system trust anchors if not provided
        if trust_anchors is None:
            trust_anchors = load_system_trust_anchors()
        
        # Extract certificate chain from response
        certificate_chain = certificate_chain_from_openai_response(response_data)
        
        # Create X.509 validation policy
        key_policy = x509_key_policy_from_certificate_chain(
            certificate_chain,
            trust_anchors=trust_anchors,
            issuer_binding=issuer_binding,
            allow_tls_server_auth=allow_tls_server_auth,
            validation_time=validation_time,
            revocation_mode=revocation_mode,
            revoked_serials=revoked_serials,
            expected_issuer=expected_issuer,
        )
        
        # Verify artifact
        verification = verify_artifact(
            artifact,
            key_policy=key_policy,
            platform=platform,
            payloads=payloads,
        )
    except Exception:
        # Signature present but verification failed
        return OpenAIResponseSignatureReport(
            has_signature=True,
            host_name=host_name,
            valid=False,
        )

    # Signature present and valid
    return OpenAIResponseSignatureReport(
        has_signature=True,
        host_name=host_name,
        valid=verification.valid,
    )


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
    """Verify an artifact against one trusted public key."""
    
    return verify_artifact(
        artifact,
        key_policy=trust_public_key(
            issuer=issuer,
            key_id=key_id,
            public_key=public_key,
            suite_id=suite_id,
        ),
        platform=platform,
        payloads=payloads,
    )


def trust_public_key(
    *,
    issuer: str,
    key_id: str,
    public_key: Any,
    suite_id: Optional[str] = None,
) -> StaticKeyPolicy:
    """Build a static verifier policy for one trusted transcript signing key."""
    
    resolved_suite_id = suite_id or infer_suite_for_public_key(public_key)
    return StaticKeyPolicy({(issuer, key_id, resolved_suite_id): public_key})


@dataclass(frozen=True)
class OpenAIResponseSignatureReport:
    """Optional verification status for an OpenAI-compatible response."""
    
    has_signature: bool         # Did response include llm_sign.artifact?
    host_name: Optional[str]    # Provider claimed in signature
    valid: Optional[bool]       # True/False/None (no sig = None)
```

**All pure functions, no HTTP, backward compatible.**

---

## 4. Example Usage

### From `example/openai_client_verify.py`

```python
def main() -> int:
    # Standard OpenAI SDK usage
    from openai import OpenAI
    import llm_sign

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit("Set OPENAI_API_KEY before running this example")

    request = {
        "model": os.environ.get("OPENAI_MODEL", "gpt-4.1-mini"),
        "messages": [{"role": "user", "content": "Reply with exactly: signed hello"}],
        "temperature": 0,
    }

    # Use OpenAI SDK normally
    client_kwargs: dict[str, Any] = {"api_key": api_key}
    if os.environ.get("OPENAI_BASE_URL"):
        client_kwargs["base_url"] = os.environ["OPENAI_BASE_URL"]
    client = OpenAI(**client_kwargs)
    completion = client.chat.completions.create(**request)

    # Just pass response to llm_sign verification
    report = llm_sign.client.verify_openai_response_signature(completion)
    print(
        json.dumps(
            llm_sign.client.openai_response_signature_summary(report),
            indent=2,
            sort_keys=True,
        )
    )
    
    # Backward compatible: unsigned responses return valid=None, not error
    exit_code = 1 if report.has_signature and report.valid is False else 0

    # Print the actual response
    message = completion.choices[0].message.content if completion.choices else None
    if message:
        print(f"assistant: {message}")
    return exit_code
```

**That's it. No monkey-patching, no interception. Just verification function calls.**

---

## 5. CLI Tool

### `src/llm_sign/cli.py`

```python
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="llm-sign-verify")
    parser.add_argument("artifact", help="Path to signed transcript artifact JSON")
    parser.add_argument("--platform", help="Override artifact platform adapter")
    parser.add_argument("--issuer", required=True, help="Expected signing issuer")
    parser.add_argument("--key-id", help="Expected key id; defaults to SPKI SHA-256")
    parser.add_argument("--public-key", help="Public key PEM/DER")
    parser.add_argument("--certificate-chain", help="Issuer certificate chain PEM")
    parser.add_argument("--trust-anchor", action="append", help="Trust anchor PEM")
    args = parser.parse_args(argv)

    # Read artifact from file
    artifact = _load_json(Path(args.artifact))
    
    # Create key policy
    if args.certificate_chain:
        key_policy = X509KeyPolicy(
            trust_anchors=_load_certificates_from_paths(args.trust_anchor),
            certificate_chains=[_load_certificates(Path(args.certificate_chain))],
            issuer_binding=(
                "tls-server-name" if args.tls_server_name_mode else "llm-sign-extension"
            ),
            allow_tls_server_auth=args.tls_server_name_mode,
            expected_issuer=args.issuer,
        )
    else:
        public_key = _load_public_key(Path(args.public_key))
        key_id = args.key_id or spki_sha256_key_id(public_key)
        suite_id = infer_suite_for_public_key(public_key)
        key_policy = StaticKeyPolicy({(args.issuer, key_id, suite_id): public_key})
    
    # Verify
    result = verify_artifact(artifact, key_policy=key_policy, platform=args.platform)

    # Output JSON result
    output: dict[str, Any] = {
        "valid": result.valid,
        "errors": result.errors,
        "blocks": [
            {
                "seq": block.signed_block.block.seq,
                "type": block.signed_block.block.type,
                "payload_state": block.payload_state,
            }
            for block in result.blocks
        ],
    }
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0 if result.valid else 1
```

**Command-line tool. Reads file, verifies, outputs JSON. That's all.**

---

## 6. Test Infrastructure (NOT DEPLOYED)

### `tests/e2e_support/server.py` - Mock HTTP Server

```python
class SignedChatHttpServer:
    """Test helper HTTP server that signs responses."""
    
    def __init__(
        self,
        keys: Optional[Ed25519KeyPair] = None,
        host: str = "127.0.0.1",
        response_mode: str = "artifact-envelope",
        signer: Optional[TranscriptSigner] = None,
    ) -> None:
        self._service = SignedChatService(keys=keys, signer=signer)
        self._response_mode = response_mode
        self._server = ThreadingHTTPServer((host, 0), self._handler_class())
        self._thread = Thread(target=self._server.serve_forever, daemon=True)

    @property
    def openai_base_url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}/v1"

    def __enter__(self) -> "SignedChatHttpServer":
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def _handler_class(self):
        service = self._service
        response_mode = self._response_mode

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if self.path != "/v1/chat/completions":
                    self.send_error(404)
                    return
                try:
                    request = _read_json(self)
                    if response_mode == "artifact-envelope":
                        artifact = service.create_chat_completion_artifact(request)
                        _write_json(self, 200, {"artifact": artifact})
                    elif response_mode == "openai-compatible":
                        response = service.create_openai_chat_completion(request)
                        _write_json(self, 200, response)
                    elif response_mode == "openai-compatible-unsigned":
                        response = service.create_unsigned_openai_chat_completion(request)
                        _write_json(self, 200, response)
                except Exception as exc:
                    _write_json(self, 400, {"error": str(exc)})

            def log_message(self, format, *args) -> None:
                return

        return Handler
```

**Used ONLY for testing. Not part of deployed library.**

### `tests/e2e_support/proxy.py` - Mock Proxy

```python
class JsonProxyHttpServer:
    """Test helper that proxies JSON requests with optional mutation."""
    
    def __init__(
        self,
        *,
        target_base_url: str,
        host: str = "127.0.0.1",
        request_mutator: Optional[JsonMutator] = None,
        response_mutator: Optional[JsonMutator] = None,
    ) -> None:
        self._target_base_url = target_base_url.rstrip("/")
        self._request_mutator = request_mutator
        self._response_mutator = response_mutator
        self._server = ThreadingHTTPServer((host, 0), self._handler_class())
        self._thread = Thread(target=self._server.serve_forever, daemon=True)

    @property
    def openai_base_url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}/v1"

    def __enter__(self) -> "JsonProxyHttpServer":
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def _handler_class(self):
        target_base_url = self._target_base_url
        request_mutator = self._request_mutator
        response_mutator = self._response_mutator

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                try:
                    # Read incoming request
                    inbound = _read_json(self)
                    
                    # Optionally mutate request
                    outbound = request_mutator(dict(inbound)) if request_mutator else dict(inbound)
                    
                    # Forward to target
                    target_response = _post_json(
                        _target_url(target_base_url, self.path),
                        outbound,
                    )
                    
                    # Optionally mutate response
                    proxied = (
                        response_mutator(dict(target_response))
                        if response_mutator
                        else dict(target_response)
                    )
                    
                    # Return to client
                    _write_json(self, 200, proxied)
                except Exception as exc:
                    _write_json(self, 502, {"error": str(exc)})

            def log_message(self, format, *args) -> None:
                return

        return Handler
```

**Used ONLY for testing tampering scenarios. Not part of deployed library.**

---

## 7. No Other HTTP Code

Search results confirmed there is NO:
- FastAPI, Flask, or Django usage in `src/`
- No uvicorn, gunicorn, or ASGI server setup
- No request/response middleware
- No monkey-patching
- No proxy frameworks
- No interceptors

The `http.server` import only appears in tests for the mock servers.

---

## Summary: What's Actually There?

### In `src/llm_sign/`
- **server/__init__.py**: 5 pure functions for signing
- **client/__init__.py**: 7+ functions for verification
- **cli.py**: 1 CLI tool
- **core/**: Cryptographic primitives (blocks, crypto, encoding)
- **profiles/**: Canonicalization logic
- **platforms/**: 4 trivial JSON mappers (one real impl, 3 subclasses)
- **keys/**: Key handling

### In `tests/`
- **e2e_support/server.py**: Mock HTTP server (testing only)
- **e2e_support/proxy.py**: Mock proxy (testing only)

### Entry Points
- **llm-sign-verify** CLI binary (offline verification tool)

### That's It
No framework, no server, no middleware, no interception, no monkey-patching.
