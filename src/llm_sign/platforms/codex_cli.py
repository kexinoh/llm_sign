"""Codex CLI artifact adapter.

The adapter intentionally accepts an OpenAI-compatible artifact contract. Codex
integrations can emit provider request and response payloads without coupling
this package to Codex internal log formats.
"""

from .openai_compatible import OpenAICompatibleAdapter


class CodexCliAdapter(OpenAICompatibleAdapter):
    name = "codex-cli"
    aliases = ("codex",)
