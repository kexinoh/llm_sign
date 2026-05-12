#!/usr/bin/env python3
"""Extra benchmarks for very-large requests.

Covers the case where "20w" is interpreted as 200,000 *tokens* rather than
200,000 characters: with Qwen-class tokenizers (~3-4 chars/token) that is
roughly 800,000 characters of input.

Usage:
    sign_bench_xl.py [--certfile ...] [--keyfile ...]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import statistics
import time

import llm_sign
from llm_sign import project_openai_chat_request, project_openai_chat_response
from llm_sign.server import TLSCertificateCredential, sign_openai_chat_turn


HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_CERT = HERE.parent / "certs" / "rsa" / "cert.pem"
DEFAULT_KEY = HERE.parent / "certs" / "rsa" / "key.pem"


def build(user_chars: int, asst_chars: int):
    uc = ("The quick brown fox jumps over the lazy dog. " * (user_chars // 44 + 1))[:user_chars]
    ac = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * (asst_chars // 58 + 1))[:asst_chars]
    req = {
        "model": "Qwen2.5-0.5B-Instruct",
        "messages": [
            {"role": "system", "content": "You are a concise assistant."},
            {"role": "user", "content": uc},
        ],
        "temperature": 0.0, "top_p": 1.0, "max_tokens": 32, "seed": 42, "stream": False,
    }
    resp = {
        "id": "x", "object": "chat.completion", "created": 0, "model": "Qwen2.5-0.5B-Instruct",
        "system_fingerprint": "b",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant", "content": ac, "refusal": None, "annotations": None,
                "audio": None, "function_call": None, "tool_calls": [],
                "reasoning": None, "reasoning_content": None,
            },
            "finish_reason": "stop", "logprobs": None, "stop_reason": None, "token_ids": None,
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        "service_tier": None,
    }
    return req, resp


def measure(label, fn, n, warmup=2):
    for _ in range(warmup):
        fn()
    xs = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        xs.append((time.perf_counter_ns() - t0) / 1e6)
    xs.sort()

    def pct(p):
        return xs[min(len(xs) - 1, int(p * len(xs)))]

    print(
        f"  {label:<32s} n={n:>3} mean={statistics.mean(xs):8.3f}ms "
        f"median={xs[len(xs) // 2]:8.3f}ms p90={pct(0.9):8.3f}ms p99={pct(0.99):8.3f}ms "
        f"min={xs[0]:8.3f}ms max={xs[-1]:8.3f}ms"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--certfile", default=str(DEFAULT_CERT))
    ap.add_argument("--keyfile", default=str(DEFAULT_KEY))
    args = ap.parse_args()

    cred = TLSCertificateCredential.from_files(ssl_certfile=args.certfile, ssl_keyfile=args.keyfile)
    signer = cred.signer()

    def full(req, resp):
        rq = project_openai_chat_request(req)
        rs = project_openai_chat_response(resp)
        art = sign_openai_chat_turn(request=rq, response=rs, signer=signer)
        return {"artifact": art, "certificate_chain": cred.certificate_chain_pem()}

    cases = [
        ("200K chars  (~50K tokens)",   200_000,  128),
        ("400K chars  (~100K tokens)",  400_000,  128),
        ("800K chars  (~200K tokens)",  800_000,  128),
        ("800K chars + 4K response",    800_000, 4_000),
    ]
    print(f"llm_sign {llm_sign.__version__}")
    for lbl, uc, ac in cases:
        req, resp = build(uc, ac)
        req_b = len(json.dumps(req).encode())
        resp_b = len(json.dumps(resp).encode())
        print(f"\n=== {lbl}  (request JSON={req_b:,}B, response JSON={resp_b:,}B) ===")
        n = 20 if uc <= 400_000 else 10
        measure("FULL pipeline", lambda: full(req, resp), n, warmup=2)
        rq = project_openai_chat_request(req)
        rs = project_openai_chat_response(resp)
        measure(
            "sign_openai_chat_turn only",
            lambda: sign_openai_chat_turn(request=rq, response=rs, signer=signer),
            n,
            warmup=2,
        )


if __name__ == "__main__":
    main()
