"""Exceptions raised by llm_sign."""


class LlmSignError(Exception):
    """Base exception for llm_sign."""


class EncodingError(LlmSignError):
    """Primitive or container encoding is invalid."""


class CanonicalizationError(LlmSignError):
    """A payload cannot be canonicalized under the selected profile."""


class VerificationError(LlmSignError):
    """A signature, digest, key, or chain validation check failed."""
