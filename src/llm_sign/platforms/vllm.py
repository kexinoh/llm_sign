"""vLLM artifact adapter for OpenAI-compatible chat completions."""

from .openai_compatible import OpenAICompatibleAdapter


class VllmAdapter(OpenAICompatibleAdapter):
    name = "vllm"
    aliases = ("vllm-openai", "vllm-chat")
