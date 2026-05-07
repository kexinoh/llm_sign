#!/usr/bin/env python3
"""Benchmark the llm_sign signing pipeline in isolation.

Simulates the exact sequence a server such as vLLM runs per chat completion:

    project_openai_chat_request(req_dict)
    project_openai_chat_response(resp_dict)
    sign_openai_chat_turn(request=..., response=..., signer=...)
    envelope = {"artifact": ..., "certificate_chain": [...]}

Each stage is timed so we can see who dominates. Several payload sizes are
covered, in particular the 200,000-character ("20w") request that is hard
to test through a real vLLM server (its default max_model_len is far below).

Usage:
    sign_bench.py [--repeats N] [--warmup W] [--certfile ...] [--keyfile ...]

Default certificates are the RSA-2048 ones shipped in this directory.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import statistics
import time

import llm_sign
from llm_sign import project_openai_chat_request, project_openai_chat_response
from llm_sign.server import (
    TLSCertificateCredential,
    attach_signed_artifact_to_openai_response,
    sign_openai_chat_turn,
)


HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_CERT = HERE.parent / "certs" / "rsa" / "cert.pem"
DEFAULT_KEY = HERE.parent / "certs" / "rsa" / "key.pem"


def build_request(user_chars: int) -> dict:
    user_content = ("The quick brown fox jumps over the lazy dog. " * (user_chars // 44 + 1))[:user_chars]
    return {
        "model": "Qwen2.5-0.5B-Instruct",
        "messages": [
            {"role": "system", "content": "You are a concise assistant."},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.0,
        "top_p": 1.0,
        "max_tokens": 32,
        "seed": 42,
        "stream": False,
    }


def build_response(assistant_chars: int, user_chars: int) -> dict:
    content = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * (assistant_chars // 58 + 1))[:assistant_chars]
    return {
        "id": "chatcmpl-bench",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "Qwen2.5-0.5B-Instruct",
        "system_fingerprint": "bench",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content,
                    "refusal": None,
                    "annotations": None,
                    "audio": None,
                    "function_call": None,
                    "tool_calls": [],
                    "reasoning": None,
                    "reasoning_content": None,
                },
                "finish_reason": "stop",
                "logprobs": None,
                "stop_reason": None,
                "token_ids": None,
            }
        ],
        "usage": {
            "prompt_tokens": user_chars // 4,
            "completion_tokens": assistant_chars // 4,
            "total_tokens": user_chars // 4 + assistant_chars // 4,
        },
        "service_tier": None,
    }


def measure(name: str, fn, repeats: int, warmup: int) -> list[float]:
    for _ in range(warmup):
        fn()
    lats = []
    for _ in range(repeats):
        t0 = time.perf_counter_ns()
        fn()
        t1 = time.perf_counter_ns()
        lats.append((t1 - t0) / 1e6)
    lats.sort()
    n = len(lats)

    def pct(p: float) -> float:
        return lats[min(n - 1, int(p * n))]

    print(
        f"  {name:<36s} "
        f"mean={statistics.mean(lats):8.3f}ms "
        f"median={lats[n // 2]:8.3f}ms "
        f"p90={pct(0.9):8.3f}ms "
        f"p99={pct(0.99):8.3f}ms "
        f"min={lats[0]:8.3f}ms  "
        f"max={lats[-1]:8.3f}ms"
    )
    return lats


def bench_scenario(
    label: str,
    user_chars: int,
    assistant_chars: int,
    credential: TLSCertificateCredential,
    signer,
    repeats: int,
    warmup: int,
) -> None:
    print(f"\n=== {label} (user_chars={user_chars:,}, assistant_chars={assistant_chars}) ===")

    req = build_request(user_chars)
    resp = build_response(assistant_chars, user_chars)

    req_json = json.dumps(req).encode()
    resp_json = json.dumps(resp).encode()
    print(f"  raw JSON sizes:  request={len(req_json):,}B  response={len(resp_json):,}B")

    req_projected = project_openai_chat_request(req)
    resp_projected = project_openai_chat_response(resp)
    pj_req_size = len(json.dumps(req_projected).encode())
    pj_resp_size = len(json.dumps(resp_projected).encode())
    print(f"  projected sizes: request={pj_req_size:,}B  response={pj_resp_size:,}B")

    measure("project_request", lambda: project_openai_chat_request(req), repeats, warmup)
    measure("project_response", lambda: project_openai_chat_response(resp), repeats, warmup)

    measure(
        "sign_openai_chat_turn",
        lambda: sign_openai_chat_turn(request=req_projected, response=resp_projected, signer=signer),
        repeats,
        warmup,
    )

    def full_old_api():
        rq = project_openai_chat_request(req)
        rs = project_openai_chat_response(resp)
        art = sign_openai_chat_turn(request=rq, response=rs, signer=signer)
        envelope = {"artifact": art}
        chain = credential.certificate_chain_pem()
        if chain:
            envelope["certificate_chain"] = chain
        return envelope

    measure("FULL pipeline (manual envelope)", full_old_api, repeats, warmup)

    def full_new_api():
        rq = project_openai_chat_request(req)
        rs = project_openai_chat_response(resp)
        art = sign_openai_chat_turn(request=rq, response=rs, signer=signer)
        envelope: dict = {}
        attach_signed_artifact_to_openai_response(envelope, artifact=art, credential=credential)
        return envelope

    measure("FULL pipeline (attach helper)", full_new_api, repeats, warmup)

    measure("json.dumps response (baseline cost)", lambda: json.dumps(resp), repeats, warmup)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=20)
    ap.add_argument("--warmup", type=int, default=3)
    ap.add_argument("--certfile", default=str(DEFAULT_CERT))
    ap.add_argument("--keyfile", default=str(DEFAULT_KEY))
    args = ap.parse_args()

    cred = TLSCertificateCredential.from_files(
        ssl_certfile=args.certfile, ssl_keyfile=args.keyfile,
    )
    signer = cred.signer()
    suite_id = (
        getattr(signer, "suite_id", None)
        or getattr(getattr(signer, "_suite", None), "suite_id", None)
        or "?"
    )
    print(f"llm_sign version: {llm_sign.__version__}")
    print(f"signer suite: {suite_id!r}")
    print(f"cert chain PEM count: {len(cred.certificate_chain_pem())}")
    chain_bytes = sum(len(pem.encode()) for pem in cred.certificate_chain_pem())
    print(f"cert chain bytes: {chain_bytes}")
    print(f"repeats={args.repeats}  warmup={args.warmup}")

    scenarios = [
        ("tiny (baseline)",        200,     128),
        ("typical",                1_000,   512),
        ("5K user",                5_000,   512),
        ("20K user",               20_000,  512),
        ("50K user",               50_000,  512),
        ("100K user",              100_000, 512),
        ("200K user, 32 response", 200_000, 128),
        ("200K user, 2K response", 200_000, 2_000),
    ]
    for label, uc, ac in scenarios:
        bench_scenario(label, uc, ac, cred, signer, args.repeats, args.warmup)


if __name__ == "__main__":
    main()
