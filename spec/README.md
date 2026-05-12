# Spec

This directory contains the protocol specification for LLM transcript signing.

Current documents:

- [normalization.md](normalization.md): core v1 protocol, canonicalization
  profile requirements, block digests, signatures, chain validation,
  container requirements, and verifier conformance.
- [provider-certificate-binding.md](provider-certificate-binding.md):
  how a verifier obtains and authenticates the transcript-signing
  public key from a TLS certificate embedded in the signed response,
  reusing standard TLS / X.509 server-certificate validation without
  defining a new PKI.

The repository also includes a Python implementation under
`src/llm_sign` and unittest coverage under `tests`.

Verifier artifact integration is documented in
[../docs/artifact.md](../docs/artifact.md).
