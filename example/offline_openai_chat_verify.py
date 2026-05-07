"""Verify a signed OpenAI-compatible chat completion without network access.

The client pins the provider's transcript-signing public key directly.
There is no CA / PKI validation: trust is in the pinned key.
"""

from __future__ import annotations

import json

#--------- llm_sign verification core: this offline example only shows verification.
import llm_sign
#---------

from _signed_openai_fixture import SIGNED_CHAT_COMPLETION, load_supplier_public_key


def main() -> int:
    #--------- llm_sign verification core: verify with the pinned supplier public key.
    public_key = load_supplier_public_key()
    report = llm_sign.client.verify_openai_response_signature(
        SIGNED_CHAT_COMPLETION,
        public_key=public_key,
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
