"""Verify a signed OpenAI-compatible chat completion without network access.

The bundled fixture uses a self-signed provider certificate (Ed25519),
which is not routable to a public CA root, so we pass
``verify_tls=False`` to skip the TLS chain check and trust the
response-embedded certificate directly (TOFU). In production, omit
``verify_tls=False`` and let ``llm_sign`` validate the provider
certificate against the system TLS trust store the same way an HTTPS
client would.
"""

from __future__ import annotations

import json

#--------- llm_sign verification core: this offline example only shows verification.
import llm_sign
#---------

from _signed_openai_fixture import SIGNED_CHAT_COMPLETION


def main() -> int:
    #--------- llm_sign verification core: verify against the embedded provider cert.
    report = llm_sign.client.verify_openai_response_signature(
        SIGNED_CHAT_COMPLETION,
        verify_tls=False,
    )
    print(
        json.dumps(
            llm_sign.client.openai_response_signature_summary(report),
            indent=2,
            sort_keys=True,
        )
    )
    exit_code = 0 if report.valid else 1
    #---------
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
