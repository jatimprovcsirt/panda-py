"""
Crypto module for PANDA SDK.

Provides core cryptographic operations for field-level encryption.
"""

from .cipher import FieldCipher
from .envelope import Envelope, EnvelopeError, MalformedEnvelopeError
from .keys import (
    KeyProvider,
    LocalKeyProvider,
    VaultKeyProvider,
    InfisicalKeyProvider,
    create_key_provider
)
from .errors import (
    PandaError,
    KeyNotFoundError,
    EnvelopeVersionError,
    UnsupportedAlgorithmError,
    MalformedEnvelopeError,
    AuthenticationFailedError,
    InvalidTokenError,
    EncryptionError,
    CryptoProviderError
)

__all__ = [
    # Main cipher
    "FieldCipher",

    # Envelope
    "Envelope",
    "EnvelopeError",
    "MalformedEnvelopeError",

    # Key providers
    "KeyProvider",
    "LocalKeyProvider",
    "VaultKeyProvider",
    "InfisicalKeyProvider",
    "create_key_provider",

    # Errors
    "PandaError",
    "KeyNotFoundError",
    "EnvelopeVersionError",
    "UnsupportedAlgorithmError",
    "MalformedEnvelopeError",
    "AuthenticationFailedError",
    "InvalidTokenError",
    "EncryptionError",
    "CryptoProviderError",
]
