"""
PANDA - Private And Secure Data Access SDK for Python

Field-level encryption and masking for sensitive personal data.
"""

# Kept in step with pyproject.toml by hand, because nothing enforces it.
# It said 0.1.0 while pyproject.toml said 0.2.0, so anything reading
# panda.__version__ at runtime got a number matching neither the tag nor
# the published release.
__version__ = "0.2.7"

from .crypto import (
    FieldCipher,
    Envelope,
    LocalKeyProvider,
    VaultKeyProvider,
    InfisicalKeyProvider,
    create_key_provider,
    KeyNotFoundError,
    AuthenticationFailedError,
    EncryptionError
)
from .masking import Masker, MaskingConfig
from .blind_index import BlindIndexer
from .audit import AuditLogger, ConsoleAuditLogger, NullAuditLogger
from .telemetry import TelemetryClient
from .storage import TLSVerifier, MySqlAdapter, PostgresAdapter

__all__ = [
    # Version
    "__version__",

    # Core crypto
    "FieldCipher",
    "Envelope",
    "LocalKeyProvider",
    "VaultKeyProvider",
    "InfisicalKeyProvider",
    "create_key_provider",

    # Errors
    "KeyNotFoundError",
    "AuthenticationFailedError",
    "EncryptionError",

    # Masking
    "Masker",
    "MaskingConfig",

    # Blind Index
    "BlindIndexer",

    # Audit
    "AuditLogger",
    "ConsoleAuditLogger",
    "NullAuditLogger",

    # Telemetry
    "TelemetryClient",

    # Storage
    "TLSVerifier",
    "MySqlAdapter",
    "PostgresAdapter",
]
