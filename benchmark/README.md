# `llm_sign` benchmarks

Runtime measurements for the `llm_sign` signing pipeline, in isolation from
any specific server integration (vLLM, etc.). Three benchmark scripts cover
three different angles:

| Script | Focus |
|---|---|
| `scripts/sign_bench.py`     | Per-stage and end-to-end pipeline cost across 8 payload sizes (up to 200 KB request) |
| `scripts/sign_bench_xl.py`  | Stress test up to ~200 K-token requests (~800 KB JSON) |
| `scripts/suite_bench.py`    | Same pipeline, three signature suites: RSA-2048 / ECDSA-P256 / Ed25519 |

The current results captured on a Linux container (Python 3.13, CPython,
default OpenSSL via `cryptography`) live in `results/` and are reproducible
with a single command:

```bash
cd benchmark
python scripts/sign_bench.py    --repeats 20 --warmup 3 > results/sign_bench.txt
python scripts/sign_bench_xl.py                          > results/sign_bench_xl.txt
python scripts/suite_bench.py                            > results/suite_bench.txt
```

The scripts use the throwaway test certificates shipped under `certs/` by
default; you can point any of them at a real cert/key pair via
`--certfile` / `--keyfile`.

## TL;DR (numbers from `results/`)

### 1. Pipeline scaling vs. payload size (RSA-2048, default suite)

`scripts/sign_bench.py` results, mean of 20 runs after 3 warm-ups:

| User content       | Request JSON | FULL pipeline mean | p99      |
|--------------------|-------------:|-------------------:|---------:|
| 200 chars          | 425 B        | 0.62 ms            | 0.86 ms  |
| 1 KB               | 1.2 KB       | 0.63 ms            | 0.88 ms  |
| 5 KB               | 5.2 KB       | 0.64 ms            | 0.91 ms  |
| 20 KB              | 20 KB        | 0.69 ms            | 0.96 ms  |
| 50 KB              | 50 KB        | 0.80 ms            | 1.04 ms  |
| 100 KB             | 100 KB       | 1.01 ms            | 1.26 ms  |
| **200 K chars (~50 K tok)**  | **200 KB**     | **1.36 ms**            | **1.60 ms**  |
| 200 K + 2 K response | 200 KB     | 1.37 ms            | 1.61 ms  |

Stage breakdown at 200 KB:

| Stage                                            | mean      |
|--------------------------------------------------|----------:|
| `project_openai_chat_request` (whitelist)        | 0.001 ms  |
| `project_openai_chat_response`                   | 0.001 ms  |
| `sign_openai_chat_turn` (canonical JSON + sign)  | 1.33 ms   |
| Envelope assembly (`certificate_chain_pem()`)    | ~0.01 ms  |
| Total                                            | ~1.36 ms  |
| Reference: `json.dumps(response)` (Python stdlib)| 0.004 ms  |

Two envelope shapes are measured:
- **manual envelope** — `{"artifact": ..., "certificate_chain": ...}` set by
  hand (the older code path used by the deployed vLLM PR);
- **attach helper** — `attach_signed_artifact_to_openai_response(envelope,
  artifact=..., credential=...)` (the helper added to `llm_sign.server`).

Both are within noise of each other.

### 2. Going larger: 200 K-token requests (`scripts/sign_bench_xl.py`)

| Input size                        | Pipeline mean | p99      |
|-----------------------------------|--------------:|---------:|
| 200 K chars (~50 K tok)           | 1.35 ms       | 1.58 ms  |
| 400 K chars (~100 K tok)          | 2.10 ms       | 2.33 ms  |
| **800 K chars (~200 K tok)**            | **3.60 ms**       | **3.83 ms**  |
| 800 K chars + 4 K response        | 3.62 ms       | 3.65 ms  |

The cost is dominated by canonical-JSON serialization + SHA-256 over the
full payload, which is linear in bytes. The asymmetric signature itself is
a constant (see §3 below).

### 3. Signature suite comparison (`scripts/suite_bench.py`)

Full pipeline mean across the same scenarios but with three different signer
suites (chosen automatically by `infer_suite_for_private_key` based on the
key type):

| Scenario                       | RSA-2048   | **ECDSA-P256** | Ed25519    | ECDSA / RSA |
|--------------------------------|-----------:|---------------:|-----------:|------------:|
| tiny (~700 B response)         | 0.62 ms    | **0.17 ms**    | 0.18 ms    | **−73%**    |
| typical (1 KB / 512 response)  | 0.63 ms    | **0.17 ms**    | 0.18 ms    | **−73%**    |
| 20 KB request                  | 0.75 ms    | **0.28 ms**    | 0.24 ms    | **−63%**    |
| 200 K chars                    | 1.34 ms    | **0.88 ms**    | 0.88 ms    | **−34%**    |
| 800 K chars (~200 K tok)       | 3.56 ms    | **3.06 ms**    | 3.07 ms    | **−14%**    |

Pure `key.sign()` cost on a 32-byte (digest-sized) message, n=1000:

| Suite        | mean    | p99     | cert PEM size |
|--------------|--------:|--------:|--------------:|
| RSA-2048     | 245 µs  | 494 µs  | 1115 B        |
| **ECDSA-P256** | **22 µs** | 26 µs   | 579 B         |
| Ed25519      | 31 µs   | 35 µs   | 493 B         |

ECDSA and Ed25519 are statistically indistinguishable on the full pipeline.
ECDSA wins by ~10 µs on the signature itself; Ed25519 is generally faster
on verification (not measured here), and produces the smallest certificates.

### Practical implications

- For small/typical payloads the pipeline is bottlenecked by the asymmetric
  signature, so picking ECDSA-P256 over RSA-2048 cuts pipeline latency by
  roughly **3-4×**.
- For very large payloads (≥ 200 KB) the bottleneck shifts to canonical-JSON
  + SHA-256, so the algorithm choice contributes a smaller fraction.
- The whitelist projection (`project_openai_chat_{request,response}`) is
  effectively free.
- Switching algorithms requires no code change in `llm_sign` — only the
  certificate/key passed to `TLSCertificateCredential.from_files`.

## Layout

```
benchmark/
├── README.md                ← you are here
├── certs/                   throwaway self-signed test certs (CN=test.local)
│   ├── rsa/{cert,key}.pem       RSA-2048
│   ├── ecdsa/{cert,key}.pem     ECDSA-P256 (prime256v1)
│   └── ed25519/{cert,key}.pem   Ed25519
├── scripts/
│   ├── sign_bench.py        per-stage + end-to-end pipeline (8 sizes)
│   ├── sign_bench_xl.py     up to ~200K-token (~800KB) inputs
│   └── suite_bench.py       RSA / ECDSA / Ed25519 comparison
└── results/
    ├── sign_bench.txt       captured stdout, current results
    ├── sign_bench_xl.txt
    └── suite_bench.txt
```

## Notes on the test certificates

The `certs/` subtree contains only self-signed test material with the
subject `CN=test.local`. They are intended **purely** as fixtures for the
benchmark scripts and example code; do not deploy them or reuse the
private keys for anything that matters. To regenerate from scratch:

```bash
# RSA-2048
openssl req -new -x509 -newkey rsa:2048 -keyout certs/rsa/key.pem \
  -out certs/rsa/cert.pem -days 365 -nodes -subj "/CN=test.local"

# ECDSA-P256
openssl req -new -x509 -newkey ec:<(openssl ecparam -name prime256v1) \
  -keyout certs/ecdsa/key.pem -out certs/ecdsa/cert.pem -days 365 \
  -nodes -subj "/CN=test.local"

# Ed25519
openssl req -new -x509 -newkey ed25519 -keyout certs/ed25519/key.pem \
  -out certs/ed25519/cert.pem -days 365 -nodes -subj "/CN=test.local"
```

## Reproducibility & methodology notes

- All measurements use `time.perf_counter_ns()`. Each scenario does a few
  warm-up calls before the timed loop; default repeats are 20 for the main
  scripts and 1000 for the pure-`sign()` micro-benchmark.
- Results are sensitive to the host CPU, OpenSSL build, and Python
  version. Treat the absolute numbers as ballpark; the relative ratios
  (between suites and between sizes) are robust.
- The benchmarks do **not** spin up a real server, so they exclude any
  HTTP / serialization overhead inherent to the integration target. For
  end-to-end measurements through a real chat-completions endpoint, see
  the integration tests in the consumer's repo (e.g. the `llm_sign`
  integration in vLLM).
