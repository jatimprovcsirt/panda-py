"""
Flask integration for PANDA SDK.

Provides Flask extension for encryption/decryption in Flask applications.
"""

from flask import Flask, current_app
from typing import Optional, Dict, Any

from ..crypto import FieldCipher, create_key_provider
from ..masking import Masker, MaskingConfig


class PandaFlask:
    """
    Flask extension for PANDA SDK.

    Usage:
        from flask import Flask
        from panda.integrations.flask import PandaFlask

        app = Flask(__name__)
        panda = PandaFlask(app)

        # Or with factory pattern:
        panda = PandaFlask()
        panda.init_app(app)

    Configuration:
        app.config["PANDA_KEY_PROVIDER_DRIVER"] = "local"  # or "vault", "infisical"
        app.config["PANDA_CONFIG"] = {
            # Provider-specific configuration
        }
    """

    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize the PandaFlask extension.

        Args:
            app: Optional Flask application instance
        """
        self._cipher: Optional[FieldCipher] = None
        self._key_provider = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """
        Initialize the extension with a Flask app.

        Args:
            app: Flask application instance
        """
        # Default configuration
        app.config.setdefault("PANDA_KEY_PROVIDER_DRIVER", "local")
        app.config.setdefault("PANDA_CONFIG", {})

        # Create cipher instance
        self._create_cipher(app)

        # Store cipher in app config
        app.extensions = getattr(app, "extensions", {})
        app.extensions["panda"] = self

    def _create_cipher(self, app: Flask) -> None:
        """Create FieldCipher instance from app configuration."""
        driver = app.config.get("PANDA_KEY_PROVIDER_DRIVER", "local")
        config = app.config.get("PANDA_CONFIG", {})

        self._key_provider = create_key_provider(driver, config)
        self._cipher = FieldCipher(self._key_provider)

    @property
    def cipher(self) -> FieldCipher:
        """Get the FieldCipher instance."""
        if self._cipher is None:
            # Try to get from current app
            if current_app:
                return current_app.extensions["panda"].cipher
        return self._cipher

    def encrypt(self, plaintext: str, kid: str, **kwargs) -> str:
        """
        Encrypt a plaintext value.

        Args:
            plaintext: String to encrypt
            kid: Key identifier
            **kwargs: Additional arguments (actor, field, etc.)

        Returns:
            JSON string of the encrypted envelope
        """
        envelope = self.cipher.encrypt(plaintext, kid, **kwargs)
        return envelope.to_json()

    def decrypt(self, envelope_json: str, **kwargs) -> str:
        """
        Decrypt an envelope and return masked value.

        Args:
            envelope_json: JSON string of the envelope
            **kwargs: Additional arguments (actor, field, masking_config)

        Returns:
            Masked plaintext string
        """
        from ..crypto import Envelope
        envelope = Envelope.from_json(envelope_json)
        return self.cipher.decrypt(envelope, **kwargs)

    def decrypt_raw(self, envelope_json: str, **kwargs) -> str:
        """
        Decrypt an envelope and return full plaintext.

        Args:
            envelope_json: JSON string of the envelope
            **kwargs: Additional arguments (actor, field)

        Returns:
            Full unmasked plaintext string
        """
        from ..crypto import Envelope
        envelope = Envelope.from_json(envelope_json)
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
