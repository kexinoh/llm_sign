"""Platform adapter registry."""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from llm_sign.core.profiles import Profile


class PlatformAdapter(Protocol):
    name: str
    aliases: tuple[str, ...]

    def profiles(self) -> Mapping[str, Profile]:
        """Return profile implementations required by this adapter."""

    def payloads_from_artifact(self, artifact: Mapping[str, Any]) -> Mapping[int, Any]:
        """Extract seq-indexed payloads from a platform artifact."""


def get_platform_adapter(name: str) -> PlatformAdapter:
    from .codex_cli import CodexCliAdapter
    from .kimi_cli import KimiCliAdapter
    from .openai_compatible import OpenAICompatibleAdapter
    from .vllm import VllmAdapter

    adapters: tuple[PlatformAdapter, ...] = (
        OpenAICompatibleAdapter(),
        CodexCliAdapter(),
        KimiCliAdapter(),
        VllmAdapter(),
    )
    normalized = name.lower().replace("_", "-")
    for adapter in adapters:
        names = (adapter.name,) + adapter.aliases
        if normalized in names:
            return adapter
    raise ValueError(f"unsupported platform adapter: {name}")
