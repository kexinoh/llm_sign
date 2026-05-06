# Issuer PKI Profile for LLM Transcript Signing

## Abstract

This document specifies certificate authority profiles for authenticating issuer
public keys used by the LLM transcript signing protocol. The profile uses X.509
certification path validation. It does not use a TLS session as the transcript
signature.

## 1. Introduction

The LLM transcript signing core protocol identifies issuer keys by
`(issuer, key_id, suite_id)`. This document defines a CA-based key policy for
resolving that tuple to a trusted public key.

The term "SSL" is historical. Implementations of this profile use modern X.509
PKI processing. A TLS connection certificate, by itself, is not sufficient to
verify a transcript; the transcript block signature still has to verify under
the certificate public key.

## 2. Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", and
"MAY" in this document are to be interpreted as described in BCP 14 [RFC2119]
[RFC8174] when, and only when, they appear in all capitals.

The following terms are used in this document:

```text
trust anchor        Configured root CA certificate or equivalent trust root.
issuing CA          CA certificate that signs an issuer certificate.
issuer certificate  End-entity certificate for transcript signing.
relay               Intermediary that forwards a signed provider response.
SPKI                SubjectPublicKeyInfo from an X.509 certificate.
certificate path    Ordered issuer certificate to trust anchor chain.
validation time     Time used for validity and revocation checks.
```

## 3. Trust Model

A verifier authenticates `(issuer, key_id, suite_id)` by validating an issuer
certificate path to a configured trust anchor and by determining that the issuer
certificate is authorized for transcript signing.

The TLS WebPKI root store MAY be used only when verifier policy explicitly
allows it. Product-specific or deployment-specific trust anchors are RECOMMENDED
for dedicated transcript-signing deployments. For compatibility with vLLM-style
OpenAI-compatible servers, verifier policy MAY authorize an HTTPS server
certificate for transcript signing when the server certificate private key is
also used to sign the transcript blocks.

The certificate path establishes authorization of a public key for a transcript
signing issuer identity. It does not establish that a model executed, that a
network session was secure, or that a provider complied with external policy.

When a client receives a signed response through a relay, the relay's TLS
certificate authenticates only the client-to-relay transport connection. The
verifier MUST NOT treat the relay TLS certificate as the supplier transcript
signing certificate unless the relay is itself the signed block issuer. The
supplier certificate path has to be discovered separately, commonly from a
certificate chain returned in the signed-response envelope.

## 4. Identifier Binding

In CA mode, `key_id` is derived from the issuer certificate SPKI:

```text
key_id = "spki-sha256:" || base64url_no_pad(SHA-256(DER(SPKI)))
```

`base64url_no_pad` uses the URL-safe Base64 alphabet of [RFC4648] without `=`
padding.

The `key_id` field in a signed block MUST equal this derived value. A verifier
MUST reject a certificate whose derived `key_id` does not exactly match the
signed block.

The issuer certificate MUST bind the block `issuer` value through a dedicated
critical X.509 extension:

```text
id-pe-llmSignIssuer = deployment-assigned OID
value               = UTF8String containing the exact block issuer string
critical            = true
```

The signed block `issuer` string MUST exactly equal the decoded extension value.
Unicode normalization, case folding, trimming, percent decoding, and DNS name
matching MUST NOT be applied.

Until public OIDs are assigned, deployments MUST allocate extension and EKU OIDs
under an enterprise arc they control and publish those OIDs with their
conformance profile and test vectors. Symbolic names in this document are not
wire values.

## 5. Issuer Certificate Profile

An issuer certificate is an X.509 end-entity certificate used to verify
transcript signatures. It MUST satisfy all of the following requirements:

```text
BasicConstraints CA == false
KeyUsage includes digitalSignature
ExtendedKeyUsage includes id-kp-llmSignTranscript
id-pe-llmSignIssuer extension is present and critical
SPKI public key is compatible with the block suite_id
certificate validity interval covers validation_time
certificate path validates to a configured trust anchor
revocation status is acceptable under verifier policy
```

The dedicated extended key usage is:

```text
id-kp-llmSignTranscript = deployment-assigned OID
```

`id-kp-llmSignTranscript` is the preferred authorization signal. A verifier MAY
also accept `serverAuth` when, and only when, verifier policy explicitly enables
TLS server certificate compatibility mode. `clientAuth`, `codeSigning`, or
`emailProtection` alone MUST NOT authorize transcript signing.

For `sha256-ed25519-v1`, the issuer certificate SPKI MUST contain an Ed25519
public key. For `sha256-rsa-pss-v1`, the SPKI MUST contain an RSA public key.
For `sha256-ecdsa-p256-v1`, the SPKI MUST contain a P-256 public key. Ed25519
algorithm identifiers and X.509 encodings are specified by [RFC8410].
Certificate chain signatures MAY use other algorithms accepted by verifier
policy.

Transcript signing keys SHOULD be dedicated keys. Reusing an HTTPS server TLS
private key for transcript signing is permitted only in TLS server certificate
compatibility mode.

## 6. TLS Server Certificate Compatibility Mode

Some platforms, including vLLM deployments, already receive a TLS certificate
chain and private key through options such as `--ssl-certfile` and
`--ssl-keyfile`. In this mode, the provider MAY use that private key to sign
transcript blocks.

When this mode is enabled, the verifier MUST still validate a certificate path
to a configured trust anchor and MUST verify the transcript block signature. The
block `issuer` value MUST match a DNS name in the leaf certificate subjectAltName
extension. If subjectAltName is absent, verifier policy MAY fall back to the
certificate subject common name.

The block `key_id` remains:

```text
key_id = "spki-sha256:" || base64url_no_pad(SHA-256(DER(SPKI)))
```

This compatibility mode authenticates the transcript signer as the TLS server
certificate identity. It does not by itself prove that the HTTPS session carrying
the response was the same session that produced the transcript artifact.

In relay deployments, TLS server certificate compatibility mode applies to the
supplier certificate chain presented as discovery material, not to the
client-visible relay TLS certificate. The block `issuer` value MUST match the
DNS identity in the supplier leaf certificate, and the transcript signature MUST
verify under the supplier leaf public key.

## 7. CA Certificate Requirements

Every CA certificate in the certification path MUST satisfy normal PKIX CA
requirements, including:

```text
BasicConstraints CA == true
KeyUsage includes keyCertSign
path length constraints are enforced
name constraints are enforced when present
certificate validity interval covers validation_time
certificate signature algorithm is accepted by verifier policy
revocation status is acceptable under verifier policy
```

Verifier policy MUST define accepted certificate signature algorithms and key
sizes. Baseline CA-mode verifiers MUST reject certificate paths that use MD5 or
SHA-1 certificate signatures.

Certificate path validation is performed according to the applicable PKIX rules
in [RFC5280], as further constrained by this profile.

## 8. Validation Time and Revocation

The verifier MUST establish `validation_time` before path validation.

For online verification, `validation_time` SHOULD be the verifier current
trusted time. For historical verification after certificate expiry, the verifier
MUST use a trusted timestamp, transparency log inclusion time, or another
deployment-defined evidence source. A timestamp asserted only by the transcript
signer MUST NOT be used as the certificate validation time.

Verifier policy MUST define one of these revocation modes:

```text
hard_fail = unknown, unavailable, revoked, or stale status is invalid
soft_fail = revoked status is invalid; unavailable status is policy-dependent
```

Production CA-mode verifiers SHOULD use `hard_fail`. Revocation checks SHOULD
cover the issuer certificate and every non-root CA certificate in the path.

Supported revocation mechanisms MAY include CRLs, OCSP [RFC6960], stapled
revocation responses, or transparency-log-based deployment policy. This profile
defines validation requirements, not a network protocol for fetching status.

## 9. Certificate Discovery

A signed block container or response envelope MAY include a `certificate_chain`
wrapper field. For OpenAI-compatible response envelopes, this can appear as
`llm_sign.certificate_chain` next to `llm_sign.artifact`. The field is not
signed by the transcript signature and MUST be treated only as a candidate path
for validation.

In relay scenarios, the supplier SHOULD provide this certificate chain in the
first signed response for a conversation or session. The relay MAY forward or
cache the supplier chain, but forwarding the chain does not make the relay a
trusted issuer. A verifier MUST validate the supplied path to a configured trust
anchor before using any public key from it.

If the container does not include a path, the verifier MAY use a local cache,
issuer metadata, or deployment-specific discovery. Regardless of discovery
method, the verifier MUST apply the same path validation, issuer binding,
`key_id` binding, key usage, EKU, validity, and revocation checks.

A verifier MUST NOT trust a bare public key or a leaf certificate without a
valid path to a configured trust anchor, unless verifier policy explicitly
configures that key as a local trust anchor outside CA mode.

A verifier MUST NOT derive the supplier signing key from the TLS peer
certificate of an intermediary connection. That certificate can only identify
the endpoint that transported the response to the client.

## 10. CA-Mode Key Resolution

To resolve `(issuer, key_id, suite_id)` in CA mode, the verifier MUST:

```text
1. Collect candidate issuer certificate paths.
2. Reject paths without exactly one end-entity issuer certificate.
3. Derive key_id from the issuer certificate SPKI.
4. Check derived key_id == block.key_id.
5. Check the issuer extension exactly equals block.issuer.
6. Check the issuer certificate is authorized for transcript signing.
7. Check the issuer certificate SPKI is compatible with block.suite_id.
8. Validate the certificate path to a configured trust anchor.
9. Validate certificate time and revocation status under policy.
10. Return exactly one trusted public key.
```

If this procedure returns zero keys or more than one key, verification MUST
fail.

After key resolution succeeds, the verifier MUST still recompute the block
digest and verify the transcript signature as specified by the core protocol.

## 11. Failure Conditions

CA-mode verification MUST reject a candidate key when any of these conditions is
encountered:

```text
missing certificate path when no other discovery source is configured
certificate path does not reach a configured trust anchor
issuer certificate has CA == true
CA certificate has CA != true
missing digitalSignature key usage on issuer certificate
missing keyCertSign key usage on a CA certificate
missing id-kp-llmSignTranscript EKU outside TLS compatibility mode
missing serverAuth EKU in TLS compatibility mode
missing or non-critical id-pe-llmSignIssuer extension outside TLS compatibility mode
issuer extension mismatch
key_id mismatch
SPKI algorithm incompatible with suite_id
certificate expired or not yet valid at validation_time
revoked certificate
unknown revocation status under hard_fail policy
disallowed certificate signature algorithm
ambiguous key resolution
```

Implementations MUST NOT recover by falling back to an unsigned wrapper field or
to TLS server identity unless TLS server certificate compatibility mode is
explicitly enabled.

## 12. Security Considerations

This profile separates transcript signature verification from HTTPS transport
authentication. TLS server certificate compatibility mode intentionally allows a
server certificate key to make durable transcript claims. Deployments using that
mode SHOULD understand that compromise or rotation of the HTTPS key also affects
transcript signing.

Revocation policy affects historical validation. A verifier that accepts stale
or unavailable revocation status can accept signatures made with a revoked key.
Deployments SHOULD specify how revocation evidence is retained for later
verification.

The certificate chain carried in a container is not signed by the transcript
signature. It is only a discovery aid. Trust is established solely by
certification path validation and the binding checks in this profile.

For relay deployments, an attacker that controls the relay can replace the
candidate `certificate_chain` field, but cannot make verification succeed unless
the replacement chain validates to an accepted trust anchor and the signed
blocks verify under its leaf public key with matching `issuer`, `key_id`, and
`suite_id`.

## 13. IANA Considerations

This document makes no request of IANA.

Deployments that use private OIDs for `id-kp-llmSignTranscript` and
`id-pe-llmSignIssuer` MUST publish the selected OIDs with their conformance
profile. A future public specification SHOULD request stable OID assignments.

## 14. Conformance

A CA-mode verifier conforms to this profile only if it implements:

```text
SPKI-derived key_id binding
issuer extension binding
dedicated transcript-signing EKU enforcement
TLS server certificate compatibility checks when that mode is enabled
certificate path validation to configured trust anchors
validity interval checking
revocation policy enforcement
core transcript signature verification after key resolution
```

An implementation that only checks a TLS connection certificate or only compares
DNS names without verifying the transcript block signature does not conform to
this profile.

## 15. References

### 15.1. Normative References

[RFC2119]
: Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels",
  BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997,
  <https://www.rfc-editor.org/info/rfc2119>.

[RFC4648]
: Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", RFC 4648,
  DOI 10.17487/RFC4648, October 2006,
  <https://www.rfc-editor.org/info/rfc4648>.

[RFC5280]
: Cooper, D., Santesson, S., Farrell, S., Boeyen, S., Housley, R., and W. Polk,
  "Internet X.509 Public Key Infrastructure Certificate and Certificate
  Revocation List (CRL) Profile", RFC 5280, DOI 10.17487/RFC5280, May 2008,
  <https://www.rfc-editor.org/info/rfc5280>.

[RFC6960]
: Santesson, S., Myers, M., Ankney, R., Malpani, A., Galperin, S., and C. Adams,
  "X.509 Internet Public Key Infrastructure Online Certificate Status Protocol -
  OCSP", RFC 6960, DOI 10.17487/RFC6960, June 2013,
  <https://www.rfc-editor.org/info/rfc6960>.

[RFC8174]
: Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words",
  BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017,
  <https://www.rfc-editor.org/info/rfc8174>.

[RFC8410]
: Josefsson, S. and J. Schaad, "Algorithm Identifiers for Ed25519, Ed448,
  X25519, and X448 for Use in the Internet X.509 Public Key Infrastructure",
  RFC 8410, DOI 10.17487/RFC8410, August 2018,
  <https://www.rfc-editor.org/info/rfc8410>.

### 15.2. Informative References

[RFC3161]
: Adams, C., Cain, P., Pinkas, D., and R. Zuccherato, "Internet X.509 Public
  Key Infrastructure Time-Stamp Protocol (TSP)", RFC 3161,
  DOI 10.17487/RFC3161, August 2001,
  <https://www.rfc-editor.org/info/rfc3161>.

[RFC8446]
: Rescorla, E., "The Transport Layer Security (TLS) Protocol Version 1.3",
  RFC 8446, DOI 10.17487/RFC8446, August 2018,
  <https://www.rfc-editor.org/info/rfc8446>.
