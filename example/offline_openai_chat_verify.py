"""Verify a signed OpenAI-compatible chat completion without network access."""

from __future__ import annotations

import json

#--------- llm_sign verification core: this offline example only shows verification.
import llm_sign
#---------

from _signed_openai_fixture import SIGNED_CHAT_COMPLETION


def main() -> int:
    #--------- llm_sign verification core: parse supplier chain and report signature status.
    certificate_chain = llm_sign.client.certificate_chain_from_openai_response(
        SIGNED_CHAT_COMPLETION
    )
    report = llm_sign.client.verify_openai_response_signature(
        SIGNED_CHAT_COMPLETION,
        trust_anchors=[certificate_chain[-1]],
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
