"""Show that returned signed OpenAI-compatible payload changes fail verification."""

from __future__ import annotations

import json
from copy import deepcopy

#--------- llm_sign verification core: this tamper example only shows verification.
import llm_sign
#---------

from _signed_openai_fixture import SIGNED_CHAT_COMPLETION, load_supplier_public_key


def main() -> int:
    tampered_response = deepcopy(SIGNED_CHAT_COMPLETION)

    #--------- llm_sign verification core: tamper with signed payload and report failure.
    tampered = llm_sign.client.artifact_from_openai_response(tampered_response)
    tampered["turns"][0]["response"]["choices"][0]["message"]["content"] = "Goodbye."

    public_key = load_supplier_public_key()
    report = llm_sign.client.verify_openai_response_signature(
        tampered_response,
        public_key=public_key,
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
