"""
Custom exceptions for PANDA crypto operations.

All exceptions inherit from PandaError for consistent error handling.
"""


class PandaError(Exception):
    """Base exception for all PANDA SDK errors."""
    pass


class KeyNotFoundError(PandaError):
    """Raised when an encryption key cannot be found for the given KID."""
    pass


class EnvelopeVersionError(PandaError):
    """Raised when an unsupported envelope version is encountered."""
    pass


class UnsupportedAlgorithmError(PandaError):
    """Raised when an unsupported encryption algorithm is specified."""
    pass


class EnvelopeError(PandaError):
    """Base for every envelope-related error.

    Exists so a caller can catch all of them under one name. It did not
    before: MalformedEnvelopeError was defined twice — once here and once in
    envelope.py — as two unrelated classes. The name exported from
    panda.crypto was this one, while the parser and the cipher raised the
    other, so `except panda.crypto.MalformedEnvelopeError` caught nothing and
    the exception escaped as an unhandled error.
    """
    pass


class MalformedEnvelopeError(EnvelopeError):
    """Raised when the envelope format is invalid or corrupted."""
    pass


class AuthenticationFailedError(PandaError):
    """Raised when ciphertext authentication fails (tampering detected)."""
    pass


class InvalidTokenError(PandaError):
    """Raised when the PANDA access token is invalid."""
    pass


class EncryptionError(PandaError):
    """Raised when encryption operation fails."""
    pass


class CryptoProviderError(PandaError):
    """Raised when a key provider operation fails."""
    pass
