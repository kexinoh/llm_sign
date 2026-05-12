"""Command-line verifier for signed transcript artifacts.

Trust is established by pinning the provider's public key: pass its
PEM/DER encoded public key (or the PEM certificate that carries it) via
``--public-key``. No CA / PKI trust chain validation is performed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from .core.crypto import infer_suite_for_public_key
from .keys.ed25519 import StaticKeyPolicy, spki_sha256_key_id
from .keys.tls import load_pem_certificates
from .verifier import verify_artifact


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="llm-sign-verify")
    parser.add_argument("artifact", help="Path to signed transcript artifact JSON")
    parser.add_argument("--platform", help="Override artifact platform adapter")
    parser.add_argument("--issuer", required=True, help="Expected signing issuer")
    parser.add_argument("--key-id", help="Expected key id; defaults to SPKI SHA-256")
    parser.add_argument(
        "--public-key",
        required=True,
        help=(
            "Path to the pinned signer public key. Accepts a PEM/DER public "
            "key, or a PEM certificate (the certificate's public key is used)."
        ),
    )
    args = parser.parse_args(argv)

    artifact = _load_json(Path(args.artifact))
    public_key = _load_public_key(Path(args.public_key))
    key_id = args.key_id or spki_sha256_key_id(public_key)
    suite_id = infer_suite_for_public_key(public_key)
    key_policy = StaticKeyPolicy({(args.issuer, key_id, suite_id): public_key})
    result = verify_artifact(artifact, key_policy=key_policy, platform=args.platform)

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


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_public_key(path: Path):
    data = path.read_bytes()
    # Accept a PEM certificate directly: use its embedded public key.
    if b"-----BEGIN CERTIFICATE-----" in data:
        certificates = load_pem_certificates(data)
        if not certificates:
            raise ValueError(f"no certificates found in {path}")
        return certificates[0].public_key()
    # Otherwise treat as a PEM or DER public key.
    try:
        return serialization.load_pem_public_key(data)
    except ValueError:
        return serialization.load_der_public_key(data)


if __name__ == "__main__":
    sys.exit(main())
