import datetime as dt
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from llm_sign import (
    OpenAIChatInputProfile,
    OpenAIChatOutputProfile,
    StaticKeyPolicy,
    verify_chain,
)
from llm_sign.blocks import PROVIDER_OUTPUT, PROVIDER_RECEIVED_INPUT
from llm_sign.vendor import TLSCertificateCredential


class VendorTlsTests(unittest.TestCase):
    """``TLSCertificateCredential`` reuses SSL material for signing.

    The certificate is a container for a public key; trust is established
    by pinning that public key via ``StaticKeyPolicy``.
    """

    def test_vllm_tls_rsa_certificate_signs_and_verifies(self):
        root_key, root_cert = _rsa_root_ca()
        leaf_key, leaf_cert = _rsa_server_cert(root_key, root_cert, "vllm.example")
        with tempfile.TemporaryDirectory() as tmp:
            certfile = Path(tmp) / "fullchain.pem"
            keyfile = Path(tmp) / "privkey.pem"
            certfile.write_bytes(
                leaf_cert.public_bytes(serialization.Encoding.PEM)
                + root_cert.public_bytes(serialization.Encoding.PEM)
            )
            keyfile.write_bytes(
                leaf_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )

            credential = TLSCertificateCredential.from_files(
                ssl_certfile=certfile,
                ssl_keyfile=keyfile,
            )

        self.assertEqual(credential.issuer, "vllm.example")
        self.assertEqual(credential.suite_id, "sha256-rsa-pss-v1")

        input_profile = OpenAIChatInputProfile()
        output_profile = OpenAIChatOutputProfile()
        request_payload = {
            "model": "Qwen/Qwen3-Coder",
            "messages": [{"role": "user", "content": "hello"}],
        }
        response_payload = {
            "model": "Qwen/Qwen3-Coder",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "hi"},
                }
            ],
        }
        signer = credential.signer()
        input_block = signer.sign_payload(
            block_type=PROVIDER_RECEIVED_INPUT,
            profile=input_profile,
            payload=request_payload,
        )
        output_block = signer.sign_payload(
            block_type=PROVIDER_OUTPUT,
            profile=output_profile,
            payload=response_payload,
            previous=input_block,
        )
        public_key = leaf_cert.public_key()
        policy = StaticKeyPolicy(
            {(credential.issuer, credential.key_id, credential.suite_id): public_key}
        )

        result = verify_chain(
            [input_block, output_block],
            key_policy=policy,
            profiles={
                input_profile.profile_id: input_profile,
                output_profile.profile_id: output_profile,
            },
            payloads={0: request_payload, 1: response_payload},
        )

        self.assertTrue(result.valid, result.errors)

    def test_tls_credential_exposes_certificate_chain_pem_roundtrip(self):
        root_key, root_cert = _rsa_root_ca()
        leaf_key, leaf_cert = _rsa_server_cert(root_key, root_cert, "vllm.example")
        with tempfile.TemporaryDirectory() as tmp:
            certfile = Path(tmp) / "fullchain.pem"
            keyfile = Path(tmp) / "privkey.pem"
            certfile.write_bytes(
                leaf_cert.public_bytes(serialization.Encoding.PEM)
                + root_cert.public_bytes(serialization.Encoding.PEM)
            )
            keyfile.write_bytes(
                leaf_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )

            credential = TLSCertificateCredential.from_files(
                ssl_certfile=certfile,
                ssl_keyfile=keyfile,
            )

        pems = credential.certificate_chain_pem()
        self.assertEqual(len(pems), 2)
        self.assertIn("-----BEGIN CERTIFICATE-----", pems[0])


def _rsa_root_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test root")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return key, cert


def _rsa_server_cert(root_key, root_cert, dns_name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_name)])
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
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_name)]), critical=False)
        .sign(private_key=root_key, algorithm=hashes.SHA256())
    )
    return key, cert


if __name__ == "__main__":
    unittest.main()
