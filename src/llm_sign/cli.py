"""Command-line verifier for signed transcript artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from .core.crypto import infer_suite_for_public_key
from .keys.ed25519 import StaticKeyPolicy, spki_sha256_key_id
from .keys.x509 import X509KeyPolicy, load_pem_certificates
from .verifier import verify_artifact


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="llm-sign-verify")
    parser.add_argument("artifact", help="Path to signed transcript artifact JSON")
    parser.add_argument("--platform", help="Override artifact platform adapter")
    parser.add_argument("--issuer", required=True, help="Expected signing issuer")
    parser.add_argument("--key-id", help="Expected key id; defaults to SPKI SHA-256")
    parser.add_argument("--public-key", help="Public key PEM/DER")
    parser.add_argument("--certificate-chain", help="Issuer certificate chain PEM")
    parser.add_argument("--trust-anchor", action="append", help="Trust anchor PEM")
    parser.add_argument(
        "--tls-server-name-mode",
        action="store_true",
        help="Bind issuer to TLS DNS name and allow serverAuth certificates",
    )
    args = parser.parse_args(argv)

    artifact = _load_json(Path(args.artifact))
    if args.certificate_chain:
        if not args.trust_anchor:
            parser.error("--certificate-chain requires at least one --trust-anchor")
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
        if not args.public_key:
            parser.error("either --public-key or --certificate-chain is required")
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
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError:
        key = serialization.load_der_public_key(data)
    return key


def _load_certificates(path: Path):
    certificates = load_pem_certificates(path.read_bytes())
    if not certificates:
        raise ValueError(f"no certificates found in {path}")
    return certificates


def _load_certificates_from_paths(paths: list[str]):
    certificates = []
    for path in paths:
        certificates.extend(_load_certificates(Path(path)))
    return certificates


if __name__ == "__main__":
    sys.exit(main())
