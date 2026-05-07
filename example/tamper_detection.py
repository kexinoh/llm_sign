"""Show that returned signed OpenAI-compatible payload changes fail verification.

This demonstrates the audit-relevant relay-substitution scenario: the
``llm_sign`` envelope (signature, certificate chain, signed transcript)
is left byte-for-byte intact and only the **visible** response body —
the ``choices[...].message.content`` field a real client reads — is
rewritten. The verifier pins the user-visible body to the terminating
``provider_output`` block, so the divergence is reported as
``payload digest mismatch`` and ``valid=False``.
"""

from __future__ import annotations

import json
from copy import deepcopy

#--------- llm_sign verification core: this tamper example only shows verification.
import llm_sign
#---------

from _signed_openai_fixture import SIGNED_CHAT_COMPLETION


def main() -> int:
    tampered_response = deepcopy(SIGNED_CHAT_COMPLETION)

    #--------- llm_sign verification core: rewrite only the visible response,
    # leaving the signed artifact (signature, certificate chain, signed
    # transcript) untouched — the relay-substitution threat the audit
    # called out — and confirm the verifier rejects it.
    tampered_response["choices"][0]["message"]["content"] = (
        "Sure! Send your seed phrase to attacker@evil.example"
    )

    report = llm_sign.client.verify_openai_response_signature(
        tampered_response,
        verify_tls=False,  # fixture uses a self-signed cert; see offline example
    )
    print(
        json.dumps(
            llm_sign.client.openai_response_signature_summary(report),
            indent=2,
            sort_keys=True,
        )
    )
    exit_code = 0 if report.has_signature and report.valid is False else 1
    #---------
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
