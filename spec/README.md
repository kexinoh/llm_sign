# Spec

This directory contains the protocol specification for LLM transcript signing.

Current documents:

- [normalization.md](normalization.md): core v1 protocol, canonicalization
  profile requirements, block digests, signatures, chain validation, container
  requirements, and verifier conformance.

The repository also includes a Python implementation under `src/llm_sign` and
unittest coverage under `tests`.

Verifier artifact integration is documented in [../docs/artifact.md](../docs/artifact.md).

Note: `llm_sign` does not ship a PKI / CA trust profile. Trust between
signer and verifier is established by pinning the signer's public key
out of band (for example reading it from the provider's published TLS
certificate). The baseline key policy is therefore
`llm_sign.keys.ed25519.StaticKeyPolicy`; no certification path
validation is performed.
