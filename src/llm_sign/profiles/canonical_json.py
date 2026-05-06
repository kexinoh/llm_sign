"""Strict canonical JSON helpers used by profiles."""

from __future__ import annotations

import json
import math
from typing import Any, Iterable, Mapping, MutableMapping, Set

from llm_sign.core.errors import CanonicalizationError


def loads_no_duplicates(data: str) -> Any:
    def hook(pairs: Iterable[tuple]) -> dict:
        out = {}
        for key, value in pairs:
            if key in out:
                raise CanonicalizationError(f"duplicate JSON object key: {key}")
            out[key] = value
        return out

    return json.loads(data, object_pairs_hook=hook)


def canonical_json_bytes(value: Any) -> bytes:
    _validate_json_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def project_mapping(
    payload: Mapping[str, Any],
    *,
    include: Set[str],
    exclude: Set[str],
    required: Set[str],
    profile_name: str,
) -> MutableMapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise CanonicalizationError(f"{profile_name} payload must be an object")

    unknown = set(payload) - include - exclude
    if unknown:
        joined = ", ".join(sorted(unknown))
        raise CanonicalizationError(f"{profile_name} contains unknown fields: {joined}")

    missing = required - set(payload)
    if missing:
        joined = ", ".join(sorted(missing))
        raise CanonicalizationError(f"{profile_name} missing required fields: {joined}")

    return {key: payload[key] for key in sorted(include) if key in payload}


def _validate_json_value(value: Any) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("non-finite JSON number")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, Mapping):
        seen = set()
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("JSON object keys must be strings")
            if key in seen:
                raise CanonicalizationError(f"duplicate JSON object key: {key}")
            seen.add(key)
            _validate_json_value(item)
        return
    raise CanonicalizationError(f"unsupported JSON value type: {type(value).__name__}")
