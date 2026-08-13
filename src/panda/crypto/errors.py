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


class MalformedEnvelopeError(PandaError):
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
