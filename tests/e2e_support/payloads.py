import json
import random
from typing import Any, Mapping

from tests.e2e_support.constants import (
    INPUT_SEED,
    MODEL,
    NUMBER_COUNT,
    OUTPUT_SEED,
    SECOND_TOOL_CALL_ID,
    SECOND_TOOL_NAME,
    TOOL_CALL_ID,
    TOOL_NAME,
)


def build_chat_request(
    turn_index: int = 0,
    previous_turns: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = None,
) -> dict[str, Any]:
    messages = []
    for request, response in previous_turns or []:
        messages.append(request["messages"][-1])
        messages.append(response["choices"][0]["message"])
    messages.append({"role": "user", "content": numbers_content(input_numbers(turn_index))})
    return {
        "model": MODEL,
        "messages": messages,
        "temperature": 0,
        "seed": INPUT_SEED + turn_index,
    }


def build_chat_response(turn_index: int = 0) -> dict[str, Any]:
    return {
        "model": MODEL,
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": numbers_content(output_numbers(turn_index)),
                },
            }
        ],
    }


def build_tool_call_request(tool_count: int = 1, tool_round: int = 0) -> dict[str, Any]:
    request = build_chat_request()
    request["tools"] = [_tool_definition(index, tool_round) for index in range(tool_count)]
    _, tool_name = _tool_identity(0, tool_round)
    request["tool_choice"] = {
        "type": "function",
        "function": {"name": tool_name},
    }
    if tool_count > 1:
        request["parallel_tool_calls"] = True
    return request


def build_multi_tool_call_request(tool_round: int = 0) -> dict[str, Any]:
    return build_tool_call_request(tool_count=2, tool_round=tool_round)


def build_tool_call_response(tool_count: int = 1, tool_round: int = 0) -> dict[str, Any]:
    return _build_tool_call_response([_tool_call(index, tool_round) for index in range(tool_count)])


def build_tool_call_response_for_request(request: Mapping[str, Any]) -> dict[str, Any]:
    tool_calls = [
        _tool_call_for_name(index, tool["function"]["name"])
        for index, tool in enumerate(request.get("tools", []))
    ]
    return _build_tool_call_response(tool_calls)


def _build_tool_call_response(tool_calls: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "model": MODEL,
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": tool_calls,
                },
            }
        ],
    }


def build_tool_results_for_response(response: Mapping[str, Any]) -> list[dict[str, Any]]:
    tool_calls = response["choices"][0]["message"].get("tool_calls", [])
    return [
        {
            "role": "tool",
            "tool_call_id": tool_call["id"],
            "name": tool_call["function"]["name"],
            "content": numbers_content(output_numbers(index)),
        }
        for index, tool_call in enumerate(tool_calls)
    ]


def build_tool_result(index: int = 0) -> dict[str, Any]:
    tool_call_id, tool_name = _tool_identity(index)
    return {
        "role": "tool",
        "tool_call_id": tool_call_id,
        "name": tool_name,
        "content": numbers_content(output_numbers(index)),
    }


def build_tool_results(count: int) -> list[dict[str, Any]]:
    return [build_tool_result(index) for index in range(count)]


def build_tool_result_request(
    first_request: Mapping[str, Any],
    tool_call_response: Mapping[str, Any],
    tool_result: Any,
) -> dict[str, Any]:
    tool_results = tool_result if isinstance(tool_result, list) else [tool_result]
    return {
        "model": MODEL,
        "messages": [
            first_request["messages"][-1],
            tool_call_response["choices"][0]["message"],
            *[dict(result) for result in tool_results],
        ],
        "temperature": 0,
    }


def input_numbers(turn_index: int = 0) -> list[int]:
    return random_numbers(seed=INPUT_SEED + turn_index)


def output_numbers(turn_index: int = 0) -> list[int]:
    return random_numbers(seed=OUTPUT_SEED + turn_index)


def random_numbers(*, seed: int, count: int = NUMBER_COUNT) -> list[int]:
    rng = random.Random(seed)
    return [rng.randint(0, 999_999) for _ in range(count)]


def numbers_content(numbers: list[int]) -> str:
    return json.dumps({"numbers": numbers}, separators=(",", ":"))


def request_numbers(request: Mapping[str, Any]) -> list[int]:
    return json.loads(request["messages"][-1]["content"])["numbers"]


def response_numbers(response: Mapping[str, Any]) -> list[int]:
    return json.loads(response["choices"][0]["message"]["content"])["numbers"]


def tool_result_numbers(tool_result: Mapping[str, Any]) -> list[int]:
    return json.loads(tool_result["content"])["numbers"]


def _tool_definition(index: int, tool_round: int = 0) -> dict[str, Any]:
    _, tool_name = _tool_identity(index, tool_round)
    return {
        "type": "function",
        "function": {
            "name": tool_name,
            "description": "Return deterministic random numbers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer"},
                    "seed": {"type": "integer"},
                },
                "required": ["count", "seed"],
            },
        },
    }


def _tool_call(index: int, tool_round: int = 0) -> dict[str, Any]:
    tool_call_id, tool_name = _tool_identity(index, tool_round)
    return _tool_call_for_identity(index, tool_call_id, tool_name)


def _tool_call_for_name(index: int, tool_name: str) -> dict[str, Any]:
    return _tool_call_for_identity(index, f"call_{tool_name}", tool_name)


def _tool_call_for_identity(index: int, tool_call_id: str, tool_name: str) -> dict[str, Any]:
    return {
        "id": tool_call_id,
        "type": "function",
        "function": {
            "name": tool_name,
            "arguments": json.dumps(
                {"count": NUMBER_COUNT, "seed": OUTPUT_SEED + index},
                separators=(",", ":"),
            ),
        },
    }


def _tool_identity(index: int, tool_round: int = 0) -> tuple[str, str]:
    suffix = "" if tool_round == 0 else f"_round_{tool_round}"
    if index == 0:
        return f"{TOOL_CALL_ID}{suffix}", f"{TOOL_NAME}{suffix}"
    if index == 1:
        return f"{SECOND_TOOL_CALL_ID}{suffix}", f"{SECOND_TOOL_NAME}{suffix}"
    return f"call_deterministic_extra_{index}{suffix}", f"deterministic_extra_{index}{suffix}"
