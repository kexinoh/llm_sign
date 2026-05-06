import datetime as dt
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtensionOID, NameOID

from llm_sign import OpenAIChatInputProfile, TranscriptSigner, verify_chain
from llm_sign.blocks import PROVIDER_RECEIVED_INPUT
from llm_sign.cli import main as cli_main
from llm_sign.pki import (
    LLM_SIGN_ISSUER_OID,
    LLM_SIGN_TRANSCRIPT_EKU_OID,
    X509KeyPolicy,
    certificate_key_id,
    der_utf8_string,
)


class PkiTests(unittest.TestCase):
    def test_x509_ca_key_policy_verifies_transcript_signature(self):
        issuer = "provider.example"
        root_key, root_cert = _root_ca()
        leaf_key, leaf_cert = _issuer_cert(root_key, root_cert, issuer)
        profile = OpenAIChatInputProfile()
        request = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "hello"}],
        }
        signer = TranscriptSigner(
            issuer=issuer,
            key_id=certificate_key_id(leaf_cert),
            private_key=leaf_key,
        )
        signed = signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=profile,
            payload=request,
        )
        policy = X509KeyPolicy(
            trust_anchors=[root_cert],
            certificate_chains=[[leaf_cert, root_cert]],
            validation_time=dt.datetime.now(dt.timezone.utc),
        )

        result = verify_chain(
            [signed],
            key_policy=policy,
            profiles={profile.profile_id: profile},
            payloads={0: request},
        )

        self.assertTrue(result.valid, result.errors)

    def test_x509_ca_key_policy_rejects_wrong_issuer_binding(self):
        root_key, root_cert = _root_ca()
        leaf_key, leaf_cert = _issuer_cert(root_key, root_cert, "provider.example")
        profile = OpenAIChatInputProfile()
        request = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "hello"}],
        }
        signer = TranscriptSigner(
            issuer="other.example",
            key_id=certificate_key_id(leaf_cert),
            private_key=leaf_key,
        )
        signed = signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=profile,
            payload=request,
        )
        policy = X509KeyPolicy(
            trust_anchors=[root_cert],
            certificate_chains=[[leaf_cert, root_cert]],
            validation_time=dt.datetime.now(dt.timezone.utc),
        )

        result = verify_chain(
            [signed],
            key_policy=policy,
            profiles={profile.profile_id: profile},
            payloads={0: request},
        )

        self.assertFalse(result.valid)

    def test_x509_ca_key_policy_rejects_path_length_violation(self):
        issuer = "provider.example"
        root_key, root_cert = _root_ca(path_length=0)
        intermediate_key, intermediate_cert = _intermediate_ca(root_key, root_cert)
        leaf_key, leaf_cert = _issuer_cert(intermediate_key, intermediate_cert, issuer)
        profile = OpenAIChatInputProfile()
        request = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "hello"}],
        }
        signer = TranscriptSigner(
            issuer=issuer,
            key_id=certificate_key_id(leaf_cert),
            private_key=leaf_key,
        )
        signed = signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=profile,
            payload=request,
        )
        policy = X509KeyPolicy(
            trust_anchors=[root_cert],
            certificate_chains=[[leaf_cert, intermediate_cert, root_cert]],
            validation_time=dt.datetime.now(dt.timezone.utc),
        )

        result = verify_chain(
            [signed],
            key_policy=policy,
            profiles={profile.profile_id: profile},
            payloads={0: request},
        )

        self.assertFalse(result.valid)

    def test_cli_x509_mode_rejects_unexpected_issuer(self):
        root_key, root_cert = _root_ca()
        leaf_key, leaf_cert = _issuer_cert(root_key, root_cert, "evil.example")
        profile = OpenAIChatInputProfile()
        request = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "hello"}],
        }
        signer = TranscriptSigner(
            issuer="evil.example",
            key_id=certificate_key_id(leaf_cert),
            private_key=leaf_key,
        )
        signed = signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=profile,
            payload=request,
        )
        artifact = {
            "schema": "llm-sign.artifact.v1",
            "platform": "openai-compatible",
            "chain": [signed.to_dict()],
            "payloads": {"0": request},
        }

        with tempfile.TemporaryDirectory() as tmp:
            artifact_path = Path(tmp) / "artifact.json"
            chain_path = Path(tmp) / "chain.pem"
            root_path = Path(tmp) / "root.pem"
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
            chain_path.write_bytes(
                leaf_cert.public_bytes(serialization.Encoding.PEM)
                + root_cert.public_bytes(serialization.Encoding.PEM)
            )
            root_path.write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        str(artifact_path),
                        "--issuer",
                        "victim.example",
                        "--certificate-chain",
                        str(chain_path),
                        "--trust-anchor",
                        str(root_path),
                    ]
                )

        self.assertEqual(exit_code, 1)
        result = json.loads(stdout.getvalue())
        self.assertFalse(result["valid"])


def _root_ca(path_length=1):
    key = Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "llm-sign test root")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                crl_sign=True,
            ),
            critical=True,
        )
        .sign(private_key=key, algorithm=None)
    )
    return key, cert


def _intermediate_ca(root_key, root_cert):
    key = Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "llm-sign intermediate")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=180))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                crl_sign=True,
            ),
            critical=True,
        )
        .sign(private_key=root_key, algorithm=None)
    )
    return key, cert


def _issuer_cert(root_key, root_cert, issuer):
    key = Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                crl_sign=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([LLM_SIGN_TRANSCRIPT_EKU_OID]),
            critical=False,
        )
        .add_extension(
            x509.UnrecognizedExtension(LLM_SIGN_ISSUER_OID, der_utf8_string(issuer)),
            critical=True,
        )
        .sign(private_key=root_key, algorithm=None)
    )
    cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
    return key, cert


if __name__ == "__main__":
    unittest.main()
