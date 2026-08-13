"""
FastAPI integration for PANDA SDK.

Provides FastAPI dependency injection for encryption/decryption.
"""

from fastapi import FastAPI, Depends
from typing import Optional, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from pydantic import BaseModel, Field

from ..crypto import FieldCipher, create_key_provider
from ..masking import Masker, MaskingConfig


class PandaFastAPI:
    """
    FastAPI integration for PANDA SDK.

    Usage:
        from fastapi import FastAPI
        from panda.integrations.fastapi import PandaFastAPI

        app = FastAPI()
        panda = PandaFastAPI(app)

        # Or with manual init:
        panda = PandaFastAPI()
        panda.init_app(app)

        # Then use in routes:
        @app.post("/encrypt")
        def encrypt_endpoint(data: str, cipher: FieldCipher = Depends(panda.get_cipher)):
            envelope = cipher.encrypt(data, kid="my-key")
            return {"envelope": envelope.to_dict()}
    """

    def __init__(self, app: Optional[FastAPI] = None):
        """
        Initialize the PandaFastAPI extension.

        Args:
            app: Optional FastAPI application instance
        """
        self._cipher: Optional[FieldCipher] = None
        self._key_provider = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app: FastAPI) -> None:
        """
        Initialize the extension with a FastAPI app.

        Args:
            app: FastAPI application instance
        """
        # Set up app state
        if not hasattr(app.state, "panda"):
            app.state.panda = self

        # Create cipher instance
        self._create_cipher(app)

    def _create_cipher(self, app: FastAPI) -> None:
        """Create FieldCipher instance from app configuration."""
        # Configuration from app.state or environment
        driver = getattr(app.state, "PANDA_KEY_PROVIDER_DRIVER", None) or "local"
        config = getattr(app.state, "PANDA_CONFIG", {})

        # Also check environment variables for common config
        import os
        if not config.get("vaultUrl") and os.environ.get("PANDA_VAULT_URL"):
            config["vaultUrl"] = os.environ.get("PANDA_VAULT_URL")
            config["vaultToken"] = os.environ.get("PANDA_VAULT_TOKEN")

        self._key_provider = create_key_provider(driver, config)
        self._cipher = FieldCipher(self._key_provider)

    @property
    def cipher(self) -> FieldCipher:
        """Get the FieldCipher instance."""
        if self._cipher is None:
            # Create with defaults
            self._cipher = FieldCipher(create_key_provider("local"))
        return self._cipher

    def get_cipher(self) -> FieldCipher:
        """
        Dependency injection getter for FastAPI routes.

        Returns:
            FieldCipher instance

        Example:
            @app.get("/encrypt")
            def encrypt_endpoint(
                data: str,
                cipher: FieldCipher = Depends(panda.get_cipher)
            ):
                envelope = cipher.encrypt(data, kid="my-key")
                return envelope.to_dict()
        """
        return self.cipher

    def encrypt(self, plaintext: str, kid: str, **kwargs) -> Dict[str, Any]:
        """
        Encrypt a plaintext value and return envelope dict.

        Args:
            plaintext: String to encrypt
            kid: Key identifier
            **kwargs: Additional arguments (actor, field, etc.)

        Returns:
            Dictionary representation of the envelope
        """
        envelope = self.cipher.encrypt(plaintext, kid, **kwargs)
        return envelope.to_dict()

    def decrypt(self, envelope_dict: Dict[str, Any], **kwargs) -> str:
        """
        Decrypt an envelope and return masked value.

        Args:
            envelope_dict: Dictionary representation of the envelope
            **kwargs: Additional arguments (actor, field, masking_config)

        Returns:
            Masked plaintext string
        """
        from ..crypto import Envelope
        envelope = Envelope.from_dict(envelope_dict)
        return self.cipher.decrypt(envelope, **kwargs)

    def decrypt_raw(self, envelope_dict: Dict[str, Any], **kwargs) -> str:
        """
        Decrypt an envelope and return full plaintext.

        Args:
            envelope_dict: Dictionary representation of the envelope
            **kwargs: Additional arguments (actor, field)

        Returns:
            Full unmasked plaintext string
        """
        from ..crypto import Envelope
        envelope = Envelope.from_dict(envelope_dict)
        return self.cipher.decrypt_raw(envelope, **kwargs)

    def mask(self, plaintext: str, config: Optional[MaskingConfig] = None) -> str:
        """
        Mask a plaintext string.

        Args:
            plaintext: String to mask
            config: Optional masking configuration

        Returns:
            Masked string
        """
        return Masker.mask(plaintext, config)


# Pydantic models for API requests/responses (only available if pydantic is installed)
try:
    from pydantic import BaseModel, Field

    class EncryptRequest(BaseModel):
        """Request model for encryption endpoints."""
        plaintext: str = Field(..., description="Plaintext to encrypt")
        kid: str = Field(..., description="Key identifier to use")
        actor: str = Field(default="system", description="Actor for audit log")
        field: str = Field(default="unknown", description="Field name for audit log")

    class DecryptRequest(BaseModel):
        """Request model for decryption endpoints."""
        envelope: Dict[str, Any] = Field(..., description="Envelope dictionary")
        actor: str = Field(default="system", description="Actor for audit log")
        field: str = Field(default="unknown", description="Field name for audit log")
        raw: bool = Field(default=False, description="Return raw plaintext instead of masked")

    class EncryptResponse(BaseModel):
        """Response model for encryption endpoints."""
        envelope: Dict[str, Any]
        success: bool = True

    class DecryptResponse(BaseModel):
        """Response model for decryption endpoints."""
        value: str
        masked: bool = True
        success: bool = True

    __all__ = [
        "PandaFastAPI",
        "EncryptRequest",
        "DecryptRequest",
        "EncryptResponse",
        "DecryptResponse",
    ]

except ImportError:
    # pydantic not installed
    __all__ = ["PandaFastAPI"]
