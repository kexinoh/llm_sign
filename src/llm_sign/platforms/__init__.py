"""Platform artifact adapters for verifier integrations."""

from .base import PlatformAdapter, get_platform_adapter
from .codex_cli import CodexCliAdapter
from .kimi_cli import KimiCliAdapter
from .openai_compatible import OpenAICompatibleAdapter
from .vllm import VllmAdapter

__all__ = [
    "CodexCliAdapter",
    "KimiCliAdapter",
    "OpenAICompatibleAdapter",
    "PlatformAdapter",
    "VllmAdapter",
    "get_platform_adapter",
]
