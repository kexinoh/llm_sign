"""Call an OpenAI-compatible API and verify the returned signed artifact."""

import json
import os

import llm_sign
from openai import OpenAI


completion = OpenAI(
    base_url=os.getenv("OPENAI_BASE_URL") or None,
).chat.completions.create(
    model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
    messages=[{"role": "user", "content": "Reply with exactly: signed hello"}],
    temperature=0,
)

report = llm_sign.client.verify_openai_response_signature(completion)

print(report)

if completion.choices:
    print(f"assistant: {completion.choices[0].message.content}")

raise SystemExit(1 if report.has_signature and report.valid is False else 0)