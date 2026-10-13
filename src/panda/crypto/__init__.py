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
from .token import (
    TOKEN_PATTERN,
    DEMO_TOKEN,
    DEFAULT_VALIDATION_URL,
    LOCAL_ENVIRONMENTS,
    validate_token,
    validate_token_format,
    is_demo_token,
    is_local_environment,
)

__all__ = [
    # Main cipher
    "FieldCipher",

    # Access token gate
    "TOKEN_PATTERN",
    "DEMO_TOKEN",
    "DEFAULT_VALIDATION_URL",
    "LOCAL_ENVIRONMENTS",
    "validate_token",
    "validate_token_format",
    "is_demo_token",
    "is_local_environment",

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
