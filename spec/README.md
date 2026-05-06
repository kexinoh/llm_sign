# Spec

This directory contains the protocol specification for LLM transcript signing.

Current documents:

- [normalization.md](normalization.md): core v1 protocol, canonicalization
  profile requirements, block digests, signatures, chain validation, container
  requirements, and verifier conformance.
- [issuer-pki.md](issuer-pki.md): X.509/TLS-style CA trust profile for
  authenticating transcript signing keys, including relay scenarios where the
  supplier certificate chain is returned with the signed response.

The repository also includes a Python implementation under `src/llm_sign` and
unittest coverage under `tests`.

Verifier artifact integration is documented in [../docs/artifact.md](../docs/artifact.md).
