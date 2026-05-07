# LLM Transcript Signing Core Protocol

## Abstract

This document specifies version 1 of the LLM transcript signing protocol. The
protocol binds canonicalized LLM interaction payloads to an ordered sequence of
signed blocks. It defines digest construction, block encoding, signature input,
chain validation, payload verification states, and extension rules.

The protocol is independent of any transport protocol, vendor API schema,
tokenizer representation, or model execution environment.

## 1. Introduction

Applications that exchange LLM transcripts often need a verifiable statement
that a provider received or returned a particular interaction payload. Transport
security alone does not provide a portable transcript artifact. This protocol
therefore signs transcript statements as durable objects.

Each block contains a digest of a profile-canonicalized payload and a reference
to the preceding block. The resulting chain provides issuer authentication,
payload integrity, and ordering integrity for the signed statements.

Issuer public keys are resolved by a verifier-defined key policy. The baseline
key policy authenticates the provider certificate the response envelope
carries using the standard TLS / X.509 server-certificate validation
procedure (see `spec/provider-certificate-binding.md`); the transcript
signature is then verified under the leaf public key of that certificate.

## 2. Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", and
"MAY" in this document are to be interpreted as described in BCP 14 [RFC2119]
[RFC8174] when, and only when, they appear in all capitals.

The following terms are used in this document:

```text
octet              An 8-bit byte.
payload            An interaction object covered by a profile.
canonical payload  Deterministic octets produced by a profile.
profile            Canonicalization rules for one payload class.
block              Signed statement metadata excluding the signature.
signed block       A block and its signature octets.
chain              Ordered sequence of signed blocks sharing a chain_id.
issuer             Entity that signs a block.
key policy         Rules for resolving issuer signing keys.
verifier           Implementation that validates signed blocks.
```

`block_digest` and `payload_digest` denote raw hash output octets. Hex, Base64,
and Base64url encodings are presentation or container encodings and are not
hashed unless a profile explicitly includes them as payload material.

## 3. Protocol Overview

The protocol has four processing stages:

```text
1. A profile canonicalizes a payload into canonical payload octets.
2. A signing suite computes a payload digest over the canonical payload.
3. A block commits to the payload digest and the previous block digest.
4. The issuer signs the block digest.
```

Validation reverses those steps. A verifier validates the chain position,
resolves the issuer key, verifies the block signature, and, when payload
material is available, recomputes the canonical payload digest.

This protocol does not prove which model binary executed, which runtime
environment was used, that the provider used only the signed input, that a
provider followed external policy, or that a provider did not create multiple
valid forks of a chain.

## 4. Cryptographic Suites

A signing suite specifies:

```text
suite_id        Stable identifier for the hash and signature algorithms.
H               Collision-resistant hash function.
Sig             Digital signature algorithm.
signature_bytes Deterministic encoding of a signature.
public_key      Deterministic encoding of a verification key.
```

Implementations claiming baseline version 1 interoperability MUST implement at
least one of these signing suites. Verifiers intended for general platform
interoperability SHOULD implement all of them:

```text
sha256-ed25519-v1    Ed25519 over block_digest_i, as specified by [RFC8032]
sha256-rsa-pss-v1    RSASSA-PSS with SHA-256 over block_digest_i
sha256-ecdsa-p256-v1 ECDSA P-256 with SHA-256 over block_digest_i
```

For `sha256-ed25519-v1`, the signed message is `block_digest_i` exactly and
Ed25519ph is not used. For RSA-PSS and ECDSA suites, the signature algorithm
input is `block_digest_i` and the suite hash is SHA-256.

Verifiers MUST reject any signed block whose `suite_id` is unsupported.

Issuer keys are identified by `(issuer, key_id, suite_id)`. A verifier MUST
resolve this tuple under its key policy to exactly one trusted public key before
accepting a signature. If key resolution returns zero keys, multiple keys, an
expired key, or a key outside the verifier policy, verification MUST fail.

The baseline key policy obtains the provider's public key from the TLS
certificate the provider ships alongside its signed response (see
`docs/artifact.md` and
[`spec/provider-certificate-binding.md`](provider-certificate-binding.md)).
That certificate MUST be authenticated the same way an HTTPS client
authenticates a server certificate: standard X.509 chain validation
against a set of trust anchors, with the expected host matched against
the leaf's subjectAltName. No new PKI is introduced.

Transport TLS authentication of an intermediary connection alone MUST
NOT be treated as transcript signature verification. When a transcript
is delivered through a relay or gateway the client-visible TLS
connection authenticates only that relay hop; the signed block must
still be independently verified by the public key extracted from the
authenticated provider certificate.

The signed `key_id` MUST be an SPKI-SHA256 binding to the leaf public
key of that provider certificate, so that a verifier can detect any
substitution between the authenticated certificate and the key that
actually produced the signature.

## 5. Primitive Encoding

All integer encodings in this section are unsigned and big-endian. `len64(x)` is
the 8-octet unsigned big-endian length of `x` in octets. Values whose length
cannot be represented in 64 bits MUST be rejected.

```text
text(s)        = 0x01 || len64(UTF8(s)) || UTF8(s)
uint64(n)      = 0x02 || n as 8-octet unsigned big-endian integer
bytes(b)       = 0x03 || len64(b) || b
null           = 0x04
field(name, v) = text(name) || v
```

Primitive decoders MUST consume exactly the expected octets. Unknown type tags,
missing octets, trailing octets, and length prefixes that exceed the available
input MUST be rejected.

All signed text fields MUST contain valid UTF-8 and MUST NOT be Unicode
normalized before hashing. Identifier fields, including `suite_id`, `issuer`,
`key_id`, `type`, and `profile_id`, MUST be 1 to 128 octets after UTF-8 encoding
and MUST contain only printable ASCII octets from `0x21` through `0x7e`.

`seq` MUST be in the range `0 <= seq <= 2^64 - 1`. Negative, fractional, and
non-finite numeric values MUST be rejected before encoding.

## 6. Payload Digest Computation

For profile `p` and payload `X`:

```text
canonical_payload = C_p(X)
payload_digest    = H(
  text("llm-sign.payload.v1") ||
  text(suite_id) ||
  text(p) ||
  bytes(canonical_payload)
)
```

`C_p` MUST be deterministic. For the same semantic input, conforming
implementations of the same profile MUST produce identical canonical payload
octets or reject the input.

`payload_digest` MUST have exactly the output length of `H` for `suite_id`.
Digest comparisons MUST compare raw digest octets.

## 7. Canonicalization Profiles

A profile specifies how to transform one class of LLM interaction payloads into
canonical payload octets. Each profile MUST specify:

```text
profile_id
profile versioning policy
input data model
included semantic material
excluded non-semantic material
canonical byte encoding
map ordering rules
array ordering rules
string encoding rules
numeric encoding rules
unknown-field handling
rejection rules
positive test vectors
negative test vectors
```

Any profile change that can alter canonical payload octets MUST use a new
`profile_id`. A profile implementation MUST NOT silently accept a payload
outside its declared input data model.

Included material MUST cover every value that can affect the model-visible
interaction or the transcript meaning. This includes messages, roles, system or
developer instructions, tool declarations, selected model identifier, and
generation controls when those controls affect output semantics.

Excluded material SHOULD be limited to transport metadata, request identifiers,
accounting fields, latency measurements, and values that do not affect the
model-visible interaction or transcript meaning.

Free-form text is semantic material. Canonicalization MUST preserve it exactly
as provided by the profile input. A profile MUST NOT trim, rewrite, summarize,
translate, reorder, or reinterpret free-form text.

Profiles MUST reject ambiguous inputs, including:

```text
duplicate map keys
invalid text encodings
non-finite numbers
unsupported payload variants
values outside the declared input domain
unknown fields not explicitly classified by the profile
multiple equivalent encodings for the same semantic value
```

## 8. Signed Block Format

Each signed statement is a block:

```text
B_i = (
  version,
  suite_id,
  chain_id,
  seq,
  issuer,
  key_id,
  type,
  profile_id,
  prev_block_digest,
  payload_digest
)
```

The fields are defined as follows:

```text
version           Protocol version. This document defines "1".
suite_id          Signing suite identifier.
chain_id          Raw octets identifying a transcript chain.
seq               Zero-based sequence number.
issuer            Stable identifier for the signing issuer.
key_id            Issuer key identifier.
type              Block type.
profile_id        Canonicalization profile used for the payload.
prev_block_digest Digest of B_(i-1), or null when seq == 0.
payload_digest    Digest of the canonicalized payload.
```

`chain_id` MUST contain at least 16 octets generated with at least 128 bits of
unpredictability or collision resistance. `version`, `suite_id`, and `chain_id`
MUST remain constant within a chain.

`payload_digest` and non-null `prev_block_digest` MUST have exactly the output
length of `H` for `suite_id`.

Only the fields listed in `B_i` are signed. Wrapper metadata MUST NOT be
presented as signed unless it is included in a signed payload profile or in a
future signed block version.

## 9. Block Encoding and Signature Input

`encode_block(B_i)` is the concatenation of these fields in the listed order:

```text
field("version",           text(version))
field("suite_id",          text(suite_id))
field("chain_id",          bytes(chain_id))
field("seq",               uint64(seq))
field("issuer",            text(issuer))
field("key_id",            text(key_id))
field("type",              text(type))
field("profile_id",        text(profile_id))
field("prev_block_digest", null | bytes(prev_block_digest))
field("payload_digest",    bytes(payload_digest))
```

No field may be omitted. No extra field may be included in `encode_block`.

```text
block_digest_i = H(
  text("llm-sign.block.v1") ||
  text(suite_id) ||
  bytes(encode_block(B_i))
)

signature_i = Sign(sk_issuer, block_digest_i)
```

A signed block is:

```text
SB_i = (
  block,
  signature
)
```

The signature is not part of `encode_block`. A container MAY include
`block_digest_i` as a cache. Verifiers MUST recompute `block_digest_i` and MUST
ignore or reject any cached digest that differs from the recomputed value.

## 10. Container Requirements

This document does not define a mandatory container format. A container that
carries signed blocks MUST preserve every signed field without loss.

Container decoders MUST enforce these rules before verification:

```text
byte fields decode to exact raw octets
text fields decode to exact UTF-8 strings
null is distinguishable from empty bytes
integers decode without rounding or precision loss
unknown wrapper metadata is not treated as signed
duplicate field names in a container object are rejected
```

If a container carries both payload material and a signed block, the payload is
trusted only after profile canonicalization and digest comparison. A container
field named like a signed field is not signed unless it is part of `B_i` and
covered by `encode_block`.

## 11. Baseline Block Types

Version 1 defines these block types:

```text
provider_received_input
provider_output
```

`provider_received_input` states that the provider received a payload whose
canonical digest equals `payload_digest` under `profile_id`.

`provider_output` states that the provider returned a payload whose canonical
digest equals `payload_digest` under `profile_id`.

A baseline chain MUST start with a `provider_received_input` block at
`seq == 0`. A minimal baseline chain has exactly two blocks:

```text
seq 0: provider_received_input
seq 1: provider_output
```

A multi-turn chain MAY append additional turn pairs. In the baseline profile,
each additional turn is encoded as a `provider_received_input` block followed by
a `provider_output` block:

```text
seq 2n:     provider_received_input
seq 2n + 1: provider_output
```

The payload of each `provider_received_input` block is the canonicalized request
submitted for that turn. For OpenAI Chat Completions compatible payloads, that
request normally contains the conversation messages supplied to the provider for
the current turn.

Extensions MAY define additional block types. A baseline verifier that does not
understand an additional block type MUST reject the chain rather than skip the
block.

## 12. Chain Validation

A verifier MUST validate a chain as an ordered sequence from `seq == 0`. A block
with `seq > 0` is not chain-valid unless every preceding block in the same chain
has already been verified.

For every accepted chain:

```text
all blocks have version == "1"
all blocks have the same suite_id
all blocks have the same chain_id
the first block has seq == 0
the first block has prev_block_digest == null
each later block has seq == previous.seq + 1
each later block has prev_block_digest == block_digest(previous.block)
no two distinct blocks have the same seq
```

An implementation MAY receive blocks out of order. It MUST reject duplicate
sequence numbers unless the duplicate blocks have identical `encode_block`
outputs and identical signature octets. Identical duplicates MAY be ignored
after the first copy.

For version 1, `provider_received_input` and `provider_output` MUST be signed by
the same `issuer` unless an extension specifies multi-issuer semantics.

## 13. Payload Verification States

Signature and chain validation do not by themselves prove that a verifier has
seen the payload. A verifier MUST report one of these payload states for each
block:

```text
payload_verified = payload was present and matched payload_digest
digest_only      = payload was absent, but signature and chain checks passed
payload_invalid  = payload was present and did not match payload_digest
```

A block with `payload_invalid` MUST make the chain invalid for every claim that
depends on that payload.

## 14. Verification Procedures

### 14.1. Provider Input Receipt

To verify a provider input receipt, the verifier MUST:

```text
1. Parse the signed block and reject malformed encodings.
2. Check block.version == "1".
3. Check block.suite_id identifies a supported signing suite.
4. Check block.type == "provider_received_input".
5. Check block.chain_id has at least 16 octets.
6. Check block.seq == 0.
7. Check block.prev_block_digest == null.
8. Check block.profile_id == p.
9. Check digest and signature lengths for block.suite_id.
10. Resolve (issuer, key_id, suite_id) under key policy.
11. Recompute payload_digest(suite_id, p, C_p(client_input)).
12. Compare the recomputed digest to block.payload_digest.
13. Recompute block_digest(block).
14. Verify signature over the recomputed block digest.
```

### 14.2. Later Blocks

To verify each later block, the verifier MUST:

```text
1. Reject malformed encodings.
2. Check block.version == "1".
3. Check block.suite_id == previous.suite_id.
4. Check block.chain_id == previous.chain_id.
5. Check block.seq == previous.seq + 1.
6. Check block.prev_block_digest == block_digest(previous.block).
7. Check block.profile_id identifies a supported profile.
8. Check block.type is supported in the current chain position.
9. Check digest and signature lengths for block.suite_id.
10. Resolve (issuer, key_id, suite_id) under key policy.
11. Recompute block_digest(block).
12. Verify signature over the recomputed block digest.
13. If payload is present, verify its canonical digest.
14. If payload is absent, report digest_only.
```

Digest equality checks SHOULD use constant-time comparison where practical.

## 15. Failure Conditions

Verification MUST reject the signed block or chain when any of these conditions
is encountered:

```text
unknown version
unsupported signing suite
unsupported profile
unsupported block type
malformed primitive encoding
trailing or missing primitive octets
invalid UTF-8 in signed text
identifier outside the allowed octet range
integer outside the uint64 range
digest length mismatch
signature length mismatch
unresolved, ambiguous, expired, or untrusted key
key policy validation failure
signature verification failure
payload digest mismatch
chain_id mismatch
sequence gap
sequence duplicate with non-identical block bytes
prev_block_digest mismatch
genesis block with non-null prev_block_digest
non-genesis block with null prev_block_digest
```

Implementations MUST NOT recover by rewriting fields, normalizing text,
reordering payload content, dropping unknown semantic material, or substituting a
different profile.

## 16. Extension Points

Extensions MAY define new profiles, block types, signing suites, and container
formats. An extension MUST specify:

```text
stable identifier
versioning policy
new signed fields, if any
canonical encoding rules
validation rules
failure behavior
interoperability test vectors
```

Extensions MUST NOT change the meaning of existing version 1 fields. If new
signed fields are required, the extension MUST define a new block `version` or a
new block type whose payload commits to the extension data.

Unknown extensions are critical by default. A verifier MUST reject a chain that
requires an extension it does not support.

## 17. Security Considerations

The signed block authenticates only the fields covered by `encode_block`.
Container metadata and cached digests are not signed by the transcript
signature unless a profile or extension explicitly commits to them.

In relay deployments the provider's TLS certificate chain carried in
the response envelope is the verifier's channel for obtaining the
provider's signing public key. The verifier MUST authenticate that
chain under the TLS / X.509 rules of the trust anchors it is
configured with, and MUST check that the validated leaf's
SubjectPublicKeyInfo hashes to the signed `key_id`. A relay cannot
forge a valid signature because it does not hold the provider's
private key, and cannot swap the embedded chain for one it controls
unless it also controls the DNS name bound to the signed `issuer`
under those trust anchors.

Profile design is security-critical. Omitting model-visible material from a
profile can cause different interactions to share the same canonical payload.
Profiles therefore need negative test vectors for ambiguous inputs and MUST
reject unsupported variants.

The protocol detects tampering within one presented chain. It does not prevent a
valid issuer from producing multiple valid chains for related interactions.
Deployments that require fork detection need an external transparency or audit
mechanism.

Key compromise affects every block that verifies under the compromised key and
the applicable validation time policy. Verifiers SHOULD apply a revocation or
transparency policy appropriate to their deployment.

## 18. IANA Considerations

This document makes no request of IANA.

Future specifications that define public registries for signing suites, block
types, profile identifiers, or extension identifiers SHOULD provide IANA
registration procedures.

## 19. Conformance

A core encoder conforms to this specification only if it produces the exact
primitive encodings, payload digests, block encodings, and block digests defined
above.

A core verifier conforms only if it implements the failure handling rules,
rejects unsupported critical semantics, and reports payload verification states
without conflating `digest_only` with `payload_verified`.

A profile implementation conforms only if it implements the profile's positive
and negative test vectors and rejects every ambiguous input class required by
this specification and by the profile.

A baseline version 1 verifier conforms only if it supports
`sha256-ed25519-v1`, `provider_received_input`, `provider_output`, the baseline
chain rules, and a key policy that obtains the signer's public key from the
response-embedded provider certificate under the binding in
[`spec/provider-certificate-binding.md`](provider-certificate-binding.md).

## 20. References

### 20.1. Normative References

[RFC2119]
: Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels",
  BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997,
  <https://www.rfc-editor.org/info/rfc2119>.

[RFC8032]
: Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm
  (EdDSA)", RFC 8032, DOI 10.17487/RFC8032, January 2017,
  <https://www.rfc-editor.org/info/rfc8032>.

[RFC8174]
: Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words",
  BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017,
  <https://www.rfc-editor.org/info/rfc8174>.

### 20.2. Informative References

[RFC5652]
: Housley, R., "Cryptographic Message Syntax (CMS)", STD 70, RFC 5652,
  DOI 10.17487/RFC5652, September 2009,
  <https://www.rfc-editor.org/info/rfc5652>.

[RFC7515]
: Jones, M., Bradley, J., and N. Sakimura, "JSON Web Signature (JWS)",
  RFC 7515, DOI 10.17487/RFC7515, May 2015,
  <https://www.rfc-editor.org/info/rfc7515>.

[RFC9052]
: Schaad, J., "CBOR Object Signing and Encryption (COSE): Structures and
  Process", STD 96, RFC 9052, DOI 10.17487/RFC9052, August 2022,
  <https://www.rfc-editor.org/info/rfc9052>.
