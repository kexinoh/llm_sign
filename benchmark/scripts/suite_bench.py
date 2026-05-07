#!/usr/bin/env python3
"""Compare sign-pipeline latency across signature suites: RSA / ECDSA / Ed25519.

Uses three pre-shipped self-signed test certificates (CN=test.local) to swap
the underlying signer while keeping the rest of the pipeline identical.
``llm_sign.infer_suite_for_private_key`` auto-selects the matching suite,
so no library changes are required to switch.

Also measures the raw asymmetric ``key.sign()`` cost on a 32-byte digest-
sized message, to isolate the algorithm overhead from canonical-JSON +
SHA-256 serialization (which is linear in payload size).

Usage:
    suite_bench.py
"""
from __future__ import annotations

import json
import pathlib
import statistics
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key

import llm_sign
from llm_sign import project_openai_chat_request, project_openai_chat_response
from llm_sign.core.crypto import infer_suite_for_private_key
from llm_sign.server import TLSCertificateCredential, sign_openai_chat_turn


HERE = pathlib.Path(__file__).resolve().parent
CERTS = HERE.parent / "certs"

SUITES = [
    ("RSA-2048",   CERTS / "rsa" / "cert.pem",     CERTS / "rsa" / "key.pem"),
    ("ECDSA-P256", CERTS / "ecdsa" / "cert.pem",   CERTS / "ecdsa" / "key.pem"),
    ("Ed25519",    CERTS / "ed25519" / "cert.pem", CERTS / "ed25519" / "key.pem"),
]

SCENARIOS = [
    ("tiny (~700 B resp)",            200,      128),
    ("typical (1K req / 512 resp)",   1_000,    512),
    ("20K req",                       20_000,   512),
    ("200K req, 128 resp",            200_000,  128),
    ("200K req, 2K resp",             200_000,  2_000),
    ("800K req (~200K tok), 128 resp", 800_000, 128),
]


def build_req_resp(user_chars: int, asst_chars: int):
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


def percentile(xs, p):
    s = sorted(xs)
    return s[min(len(s) - 1, int(p * len(s)))]


def measure(fn, n, warmup=3):
    for _ in range(warmup):
        fn()
    xs = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        xs.append((time.perf_counter_ns() - t0) / 1e6)
    return xs


def main() -> None:
    print(f"llm_sign {llm_sign.__version__}")
    print()

    creds = []
    for label, cf, kf in SUITES:
        cred = TLSCertificateCredential.from_files(ssl_certfile=str(cf), ssl_keyfile=str(kf))
        signer = cred.signer()
        # ``infer_suite_for_private_key`` is the library's own helper for
        # mapping a private key to the public suite id string. Prefer it
        # over reaching into the signer's internals.
        key_obj = load_pem_private_key(pathlib.Path(kf).read_bytes(), password=None)
        suite_id = infer_suite_for_private_key(key_obj)
        chain_bytes = sum(len(p.encode()) for p in cred.certificate_chain_pem())
        creds.append((label, cred, signer, suite_id))
        print(
            f"  [{label:<12}] suite={suite_id:<24}  cert PEM bytes={chain_bytes}"
        )
    print()

    print(
        f"{'scenario':<32} {'suite':<14} {'mean':>10} {'median':>10} "
        f"{'p90':>10} {'p99':>10} {'chain B':>8}"
    )
    print("-" * 104)

    for sc_label, uc, ac in SCENARIOS:
        req, resp = build_req_resp(uc, ac)
        req_b = len(json.dumps(req).encode())
        resp_b = len(json.dumps(resp).encode())
        first = True
        for label, cred, signer, _ in creds:

            def full(_req=req, _resp=resp, _signer=signer, _cred=cred):
                a = project_openai_chat_request(_req)
                b = project_openai_chat_response(_resp)
                art = sign_openai_chat_turn(request=a, response=b, signer=_signer)
                return {"artifact": art, "certificate_chain": _cred.certificate_chain_pem()}

            n = 20 if uc <= 200_000 else 12
            xs = measure(full, n, warmup=3)
            chain_b = sum(len(p.encode()) for p in cred.certificate_chain_pem())
            sc_col = sc_label if first else ""
            first = False
            print(
                f"{sc_col:<32} {label:<14} "
                f"{statistics.mean(xs):>8.3f}ms "
                f"{sorted(xs)[len(xs) // 2]:>8.3f}ms "
                f"{percentile(xs, 0.9):>8.3f}ms "
                f"{percentile(xs, 0.99):>8.3f}ms "
                f"{chain_b:>8}"
            )
        print(f"  (request JSON={req_b:,}B, response JSON={resp_b:,}B)")

    # Pure asymmetric signature micro-benchmark.
    #
    # The bench mirrors what ``SignatureSuite.sign_digest`` does in
    # ``llm_sign/core/crypto.py``:
    #   * RSA-PSS-SHA256: ``PSS(MGF1(SHA256), salt_length=DIGEST_LENGTH)``
    #     over a pre-hashed 32-byte digest (``utils.Prehashed``).
    #   * ECDSA-P256-SHA256: ``ec.ECDSA(utils.Prehashed(SHA256()))`` over
    #     the same 32-byte digest.
    #   * Ed25519: ``private_key.sign(digest)``, which internally uses the
    #     PureEdDSA construction over the raw input.
    #
    # Using ``Prehashed`` isolates the asymmetric operation from the
    # SHA-256 pass, which otherwise dominates for tiny inputs and would
    # double-count against the canonical-JSON + SHA-256 cost already
    # captured in the full-pipeline numbers above.
    print("\n--- pure asymmetric sign() on a 32-byte digest (mirrors SignatureSuite.sign_digest) ---")
    digest = b"\x00" * 32
    rsa_padding = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.DIGEST_LENGTH,
    )
    prehashed_sha256 = utils.Prehashed(hashes.SHA256())
    for label, cf, kf in SUITES:
        key = load_pem_private_key(pathlib.Path(kf).read_bytes(), password=None)
        if isinstance(key, rsa.RSAPrivateKey):
            def sign_fn(_k=key):
                _k.sign(digest, rsa_padding, prehashed_sha256)
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            def sign_fn(_k=key):
                _k.sign(digest, ec.ECDSA(prehashed_sha256))
        elif isinstance(key, ed25519.Ed25519PrivateKey):
            def sign_fn(_k=key):
                _k.sign(digest)
        else:
            print(f"  [{label}] unsupported")
            continue
        xs = measure(sign_fn, 1000, warmup=50)
        print(
            f"  [{label:<12}] n=1000 mean={statistics.mean(xs) * 1000:7.1f}us "
            f"median={sorted(xs)[500] * 1000:7.1f}us  p99={percentile(xs, 0.99) * 1000:7.1f}us"
        )


if __name__ == "__main__":
    main()
