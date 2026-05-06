import unittest

from llm_sign.errors import CanonicalizationError
from llm_sign.openai import OpenAIChatInputProfile, OpenAIChatOutputProfile


class OpenAIProfileTests(unittest.TestCase):
    def test_input_profile_is_stable_and_excludes_transport_metadata(self):
        profile = OpenAIChatInputProfile()
        first = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "hello"}],
            "temperature": 0.2,
            "metadata": {"trace": "a"},
            "stream": True,
        }
        second = {
            "stream": False,
            "metadata": {"trace": "b"},
            "temperature": 0.2,
            "messages": [{"content": "hello", "role": "user"}],
            "model": "gpt-4.1-mini",
        }
        self.assertEqual(profile.canonicalize(first), profile.canonicalize(second))

    def test_input_profile_rejects_unknown_fields(self):
        profile = OpenAIChatInputProfile()
        with self.assertRaises(CanonicalizationError):
            profile.canonicalize(
                {
                    "model": "gpt-4.1-mini",
                    "messages": [{"role": "user", "content": "hello"}],
                    "made_up": True,
                }
            )

    def test_input_profile_changes_when_message_changes(self):
        profile = OpenAIChatInputProfile()
        base = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "hello"}],
        }
        changed = {
            "model": "gpt-4.1-mini",
            "messages": [{"role": "user", "content": "hello!"}],
        }
        self.assertNotEqual(profile.canonicalize(base), profile.canonicalize(changed))

    def test_output_profile_excludes_openai_accounting_fields(self):
        profile = OpenAIChatOutputProfile()
        first = {
            "id": "chatcmpl-a",
            "object": "chat.completion",
            "created": 1,
            "model": "gpt-4.1-mini",
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "hi"},
                }
            ],
            "usage": {"total_tokens": 3},
        }
        second = {
            "id": "chatcmpl-b",
            "object": "chat.completion",
            "created": 2,
            "model": "gpt-4.1-mini",
            "choices": [
                {
                    "message": {"content": "hi", "role": "assistant"},
                    "finish_reason": "stop",
                    "index": 0,
                }
            ],
            "usage": {"total_tokens": 99},
        }
        self.assertEqual(profile.canonicalize(first), profile.canonicalize(second))


if __name__ == "__main__":
    unittest.main()
