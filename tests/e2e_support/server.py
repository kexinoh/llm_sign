import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from typing import Any, Mapping, Optional

from llm_sign import (
    Ed25519KeyPair,
    OpenAIChatInputProfile,
    OpenAIChatOutputProfile,
    OpenAIToolResultProfile,
    TranscriptSigner,
)
from llm_sign.blocks import PROVIDER_OUTPUT, PROVIDER_RECEIVED_INPUT, TOOL_RESULT

from tests.e2e_support.constants import ISSUER, RESPONSE_ID
from tests.e2e_support.payloads import build_chat_response, build_tool_call_response_for_request


class SignedChatHttpServer:
    def __init__(
        self,
        keys: Optional[Ed25519KeyPair] = None,
        host: str = "127.0.0.1",
        response_mode: str = "artifact-envelope",
        signer: Optional[TranscriptSigner] = None,
    ) -> None:
        self._service = SignedChatService(keys=keys, signer=signer)
        self._response_mode = response_mode
        self._server = _ThreadingHTTPServer((host, 0), self._handler_class())
        self._thread = Thread(target=self._server.serve_forever, daemon=True)

    @property
    def openai_base_url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}/v1"

    @property
    def chat_completions_url(self) -> str:
        return f"{self.openai_base_url}/chat/completions"

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
                    else:
                        raise ValueError(f"unsupported response mode: {response_mode}")
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    _write_json(self, 400, {"error": str(exc)})

            def log_message(self, format, *args) -> None:
                return

        return Handler


class SignedChatService:
    def __init__(
        self,
        *,
        keys: Optional[Ed25519KeyPair] = None,
        signer: Optional[TranscriptSigner] = None,
    ) -> None:
        if signer is None:
            if keys is None:
                raise ValueError("keys or signer is required")
            signer = TranscriptSigner(
                issuer=ISSUER,
                key_id=keys.key_id,
                private_key=keys.private_key,
            )
        self.signer = signer
        self.input_profile = OpenAIChatInputProfile()
        self.output_profile = OpenAIChatOutputProfile()
        self.tool_result_profile = OpenAIToolResultProfile()
        self._chain = []
        self._turns = []
        self._payloads = {}
        self._signed_tool_call_ids = set()
        self._lock = Lock()

    def create_chat_completion_artifact(self, request: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            response = self._response_for_request(request)
            return self._append_turn_artifact(request, response)

    def create_openai_chat_completion(self, request: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            response = self._openai_response(self._response_for_request(request))
            artifact = self._append_turn_artifact(request, response)
            response["llm_sign"] = {"artifact": artifact}
            return response

    def create_unsigned_openai_chat_completion(self, request: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            response = self._openai_response(self._response_for_request(request))
            self._turns.append({"request": dict(request), "response": dict(response)})
            return response

    def _append_turn_artifact(
        self,
        request: Mapping[str, Any],
        response: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._append_tool_results(request)
        input_block = self.signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=self.input_profile,
            payload=request,
            previous=self._chain[-1] if self._chain else None,
        )
        output_block = self.signer.sign_payload(
            block_type=PROVIDER_OUTPUT,
            profile=self.output_profile,
            payload=response,
            previous=input_block,
        )
        self._chain.extend([input_block, output_block])
        self._payloads[str(input_block.block.seq)] = dict(request)
        self._payloads[str(output_block.block.seq)] = dict(response)
        self._turns.append({"request": dict(request), "response": dict(response)})
        return {
            "schema": "llm-sign.artifact.v1",
            "platform": "openai-compatible",
            "chain": [block.to_dict() for block in self._chain],
            "turns": list(self._turns),
            "payloads": dict(self._payloads),
        }

    def _openai_response(self, response: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "id": RESPONSE_ID,
            "object": "chat.completion",
            "created": 0,
            "model": response["model"],
            "choices": response["choices"],
        }

    def _append_tool_results(self, request: Mapping[str, Any]) -> None:
        for message in request.get("messages", []):
            if message.get("role") != "tool":
                continue
            tool_call_id = message.get("tool_call_id")
            if tool_call_id in self._signed_tool_call_ids:
                continue
            tool_block = self.signer.sign_payload(
                block_type=TOOL_RESULT,
                profile=self.tool_result_profile,
                payload=message,
                previous=self._chain[-1] if self._chain else None,
            )
            self._chain.append(tool_block)
            self._payloads[str(tool_block.block.seq)] = dict(message)
            self._signed_tool_call_ids.add(tool_call_id)

    def _response_for_request(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if request.get("tools") and not _contains_tool_result(request):
            return build_tool_call_response_for_request(request)
        return build_chat_response(len(self._turns))


class _ThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True


def _read_json(handler: BaseHTTPRequestHandler) -> Mapping[str, Any]:
    content_length = int(handler.headers.get("Content-Length", "0"))
    raw_body = handler.rfile.read(content_length)
    payload = json.loads(raw_body.decode("utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("request body must be a JSON object")
    return payload


def _write_json(handler: BaseHTTPRequestHandler, status: int, payload: Mapping[str, Any]) -> None:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _contains_tool_result(request: Mapping[str, Any]) -> bool:
    return any(message.get("role") == "tool" for message in request.get("messages", []))
