"""Kimi CLI artifact adapter."""

from .openai_compatible import OpenAICompatibleAdapter


class KimiCliAdapter(OpenAICompatibleAdapter):
    name = "kimi-cli"
    aliases = ("kimi", "moonshot")
