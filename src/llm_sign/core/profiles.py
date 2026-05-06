"""Payload canonicalization profile interfaces."""

from __future__ import annotations

from typing import Any, Protocol


class Profile(Protocol):
    profile_id: str

    def canonicalize(self, payload: Any) -> bytes:
        """Return deterministic canonical payload octets."""
