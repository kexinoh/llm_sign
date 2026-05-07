# Provider Certificate Binding for LLM Transcript Signing

## Abstract

This document specifies how a verifier obtains and authenticates an
LLM transcript-signing public key from a TLS certificate that the
provider embeds in its signed response. The procedure reuses the
standard TLS / X.509 server-certificate validation algorithm; it does
not define a new PKI.

## 1. Introduction

The core protocol
([`spec/normalization.md`](normalization.md)) identifies a signer by
`(issuer, key_id, suite_id)` and delegates key resolution to a
verifier-defined key policy. The motivating threat model is a relay
or gateway that sits between the client and the LLM provider: the
client's own HTTPS connection authenticates only the relay, not the
provider.

Rather than invent a separate PKI, this profile has the provider ship
its TLS server certificate inside the signed response, and the
verifier authenticate that certificate under the same rules an HTTPS
client would use during a TLS handshake. The transcript signature is
then verified under the leaf public key of the validated certificate.

## 2. Conventions and Definitions

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT",
and "MAY" in this document are to be interpreted as described in BCP
14 [RFC2119] [RFC8174] when, and only when, they appear in all
capitals.

```text
provider certificate     X.509 end-entity certificate the provider uses
                         for TLS termination, reused as the transcript
                         signing identity.
certificate chain        Ordered list of X.509 certificates, leaf first.
trust anchor             Root CA certificate trusted by the verifier,
                         typically a system TLS trust store entry.
expected host            DNS name the verifier expects the provider
                         certificate to be issued for.
SPKI                     SubjectPublicKeyInfo of an X.509 certificate.
relay                    Intermediary that forwards a signed provider
                         response to the client.
```

## 3. Trust Model

The verifier trusts exactly what a correctly configured HTTPS client
would trust: a provider certificate that chains, under the verifier's
configured trust anchors, to a valid TLS server certificate for the
expected host.

A relay cannot forge a transcript signature: the signature is produced
by the provider's TLS private key, which the relay does not possess.
A relay cannot substitute the embedded certificate for one it
controls unless it also controls the expected host under the
verifier's trust anchors, which is out of scope for this profile.

This profile does not authenticate anything about the underlying
transport connection to the relay, and it does not assert that a
particular model executed, that a provider followed external policy,
or that a provider did not produce multiple valid transcripts for
related interactions.

## 4. Envelope Binding

A signed response envelope MUST carry the provider certificate chain
as an ordered list of PEM strings, leaf first. For OpenAI-compatible
envelopes the field is `llm_sign.certificate_chain`.

The envelope field is not itself covered by the transcript signature;
it is material for the verifier to authenticate the signer. The
binding between the signed transcript and the envelope is enforced by
the `key_id` check in Section 6.

## 5. Certificate Authentication

A verifier MUST authenticate the embedded certificate chain using the
standard TLS / X.509 server-certificate validation algorithm of
[RFC5280] and [RFC6125], with:

```text
1. certificate path validation to a verifier-configured trust anchor;
2. validity interval check against validation_time;
3. signature algorithm and key size acceptance under verifier policy;
4. name matching of expected_host against the leaf certificate
   subjectAltName DNS entries, with wildcard matching as in RFC 6125;
5. basicConstraints, keyUsage, and extendedKeyUsage conformance for a
   TLS server certificate;
6. revocation status under verifier policy.
```

Trust anchors are typically the system TLS trust store. Deployments
MAY supply a dedicated anchor set for private / self-hosted providers.

The verifier SHOULD set `validation_time` to its current trusted wall
clock. A timestamp asserted only by the signer MUST NOT be used.

Verifiers SHOULD reject signature algorithms and key sizes no longer
considered safe for Web PKI (for example MD5 or SHA-1 certificate
signatures).

Ed25519 keys MAY be used for transcript signing. Because the TLS Web
PKI does not currently allow Ed25519 intermediates on the public
Internet, deployments that use Ed25519 signers typically run under a
private trust anchor set or opt into trust-on-first-use (Section 8).

## 6. Key Binding

After Section 5 succeeds, let `leaf` be the validated leaf
certificate. The verifier MUST compute:

```text
expected_key_id = "spki-sha256:" || base64url_no_pad(
    SHA-256(DER(SubjectPublicKeyInfo(leaf)))
)
```

`base64url_no_pad` uses the URL-safe Base64 alphabet of [RFC4648]
without `=` padding.

The verifier MUST compare `expected_key_id` to the `key_id` carried
by every block whose signature it intends to verify, and MUST reject
the block on mismatch. The verifier MUST also check that the leaf
SPKI algorithm is compatible with the signed `suite_id`.

Once the key binding checks pass, the verifier uses the leaf's public
key to verify the transcript block signature as defined by the core
protocol.

## 7. Issuer Identity

The signed `issuer` field carries the provider identity, typically a
DNS name. Verifiers SHOULD require `issuer` to equal `expected_host`
(and therefore to be present in the leaf certificate subjectAltName).

When the client application has a prior expectation of the provider
identity (for example because it chose which provider to call), the
verifier SHOULD pin `expected_host` to that identity rather than
reading it from the artifact.

## 8. Trust-on-First-Use Mode

Deployments that cannot use the Web PKI — self-signed providers, local
development, private Ed25519 hierarchies — MAY opt out of Section 5 by
declaring a TOFU key policy that:

```text
1. Skips certificate path validation;
2. Accepts the leaf public key from the first response in a session;
3. Requires every subsequent block in that session to satisfy the key
   binding check in Section 6 against the accepted leaf.
```

A TOFU verifier MUST make the TOFU decision explicit to its caller and
MUST NOT silently downgrade from Section 5 to TOFU on validation
failure.

## 9. Failure Conditions

Certificate-bound verification MUST reject a candidate key when any of
these conditions is encountered:

```text
missing certificate chain
empty certificate chain
certificate path does not reach a configured trust anchor
certificate expired or not yet valid at validation_time
expected_host does not match the leaf subjectAltName
leaf is not a conformant TLS server certificate
certificate or CA uses a disallowed signature algorithm or key size
revoked certificate (under verifier revocation policy)
leaf SPKI-SHA256 does not equal the signed key_id
leaf SPKI algorithm is incompatible with the signed suite_id
```

Failure MUST NOT be recovered by falling back to unsigned transport
security, to the client-visible TLS peer certificate, or to TOFU
(Section 8) unless TOFU was explicitly selected by verifier policy
before the request.

## 10. Security Considerations

This profile inherits the security properties of Web PKI. Verifiers
that use the system TLS trust store inherit both its strengths and
its weaknesses (including any CA misissuance affecting the expected
host).

An attacker who controls the network between client and provider but
does not control the expected host's Web PKI identity cannot forge or
substitute a transcript: the signature requires the provider private
key, and the certificate check requires a trusted chain for the
expected host.

An attacker who does control the expected host's Web PKI identity
(for example through CA compromise) can impersonate the provider for
both TLS and transcript signing. Deployments that must resist such
attackers SHOULD additionally pin the provider public key out of band
and use :func:`verify_openai_response_with_public_key` (or the
equivalent pinned-key policy) instead of relying on Web PKI alone.

The envelope-carried certificate chain is not signed by the
transcript signature. It is authenticated only by Section 5 and by
the SPKI binding in Section 6.

## 11. IANA Considerations

This document makes no request of IANA.

## 12. References

### 12.1. Normative References

[RFC2119]
: Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels",
  BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997,
  <https://www.rfc-editor.org/info/rfc2119>.

[RFC4648]
: Josefsson, S., "The Base16, Base32, and Base64 Data Encodings",
  RFC 4648, DOI 10.17487/RFC4648, October 2006,
  <https://www.rfc-editor.org/info/rfc4648>.

[RFC5280]
: Cooper, D., Santesson, S., Farrell, S., Boeyen, S., Housley, R., and W. Polk,
  "Internet X.509 Public Key Infrastructure Certificate and Certificate
  Revocation List (CRL) Profile", RFC 5280, DOI 10.17487/RFC5280, May 2008,
  <https://www.rfc-editor.org/info/rfc5280>.

[RFC6125]
: Saint-Andre, P. and J. Hodges, "Representation and Verification of
  Domain-Based Application Service Identity within Internet Public
  Key Infrastructure Using X.509 (PKIX) Certificates in the Context
  of Transport Layer Security (TLS)", RFC 6125,
  DOI 10.17487/RFC6125, March 2011,
  <https://www.rfc-editor.org/info/rfc6125>.

[RFC8174]
: Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words",
  BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017,
  <https://www.rfc-editor.org/info/rfc8174>.

### 12.2. Informative References

[RFC8446]
: Rescorla, E., "The Transport Layer Security (TLS) Protocol Version 1.3",
  RFC 8446, DOI 10.17487/RFC8446, August 2018,
  <https://www.rfc-editor.org/info/rfc8446>.
