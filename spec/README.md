# Spec

This directory contains the protocol specification for LLM transcript signing.

Current documents:

- [normalization.md](normalization.md): core v1 protocol, canonicalization
  profile requirements, block digests, signatures, chain validation, container
  requirements, and verifier conformance.

The repository also includes a Python implementation under `src/llm_sign` and
unittest coverage under `tests`.

Verifier artifact integration is documented in [../docs/artifact.md](../docs/artifact.md).

Trust between signer and verifier is established by reading the
signer's public key out of the TLS certificate the provider ships
alongside its signed response (`llm_sign.certificate_chain`). This
addresses middleman / relay tampering without introducing a CA or PKI:
the relay does not hold the provider's private key and cannot forge a
signature, and the signed `key_id` is an SPKI hash of the certificate
public key so the certificate cannot be swapped out without breaking
verification.
