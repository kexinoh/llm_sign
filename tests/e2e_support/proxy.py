import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any, Callable, Mapping, Optional
from urllib import request as urllib_request


JsonMutator = Callable[[dict[str, Any]], dict[str, Any]]


class JsonProxyHttpServer:
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
        self._server = _ThreadingHTTPServer((host, 0), self._handler_class())
        self._thread = Thread(target=self._server.serve_forever, daemon=True)

    @property
    def openai_base_url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}/v1"

    @property
    def chat_completions_url(self) -> str:
        return f"{self.openai_base_url}/chat/completions"

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
                    inbound = _read_json(self)
                    outbound = request_mutator(dict(inbound)) if request_mutator else dict(inbound)
                    target_response = _post_json(
                        _target_url(target_base_url, self.path),
                        outbound,
                    )
                    proxied = (
                        response_mutator(dict(target_response))
                        if response_mutator
                        else dict(target_response)
                    )
                    _write_json(self, 200, proxied)
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    _write_json(self, 502, {"error": str(exc)})

            def log_message(self, format, *args) -> None:
                return

        return Handler


class _ThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True


def _read_json(handler: BaseHTTPRequestHandler) -> Mapping[str, Any]:
    content_length = int(handler.headers.get("Content-Length", "0"))
    raw_body = handler.rfile.read(content_length)
    payload = json.loads(raw_body.decode("utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("request body must be a JSON object")
    return payload


def _post_json(url: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib_request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib_request.urlopen(request, timeout=5) as response:
        result = json.loads(response.read().decode("utf-8"))
    if not isinstance(result, Mapping):
        raise ValueError("target response body must be a JSON object")
    return result


def _target_url(target_base_url: str, path: str) -> str:
    if target_base_url.endswith("/v1") and path.startswith("/v1/"):
        path = path[len("/v1") :]
    return f"{target_base_url}{path}"


def _write_json(handler: BaseHTTPRequestHandler, status: int, payload: Mapping[str, Any]) -> None:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
