"""
Django integration for PANDA SDK.

Provides model fields and middleware for Django applications.
"""

from typing import Optional, Any
from django.db import models
from django.core.exceptions import ValidationError
import json

from ..crypto import FieldCipher, Envelope, create_key_provider
from ..masking import Masker, MaskingConfig


class EncryptedField(models.TextField):
    """
    Django model field for encrypted data.

    Automatically encrypts on save and returns masked value on retrieval.
    Use get_decrypted() method to retrieve full plaintext.

    Usage:
        class Citizen(models.Model):
            nik = EncryptedField(kid='nik-key')
            name = models.CharField(max_length=200)

    To get raw value:
        citizen.nik  # Returns masked value
        citizen.get_decrypted_nik()  # Returns full plaintext
    """

    description = "Encrypted field using PANDA envelope format"

    def __init__(self, kid: str, masking_config: Optional[MaskingConfig] = None, **kwargs):
        """
        Initialize the encrypted field.

        Args:
            kid: Key identifier to use for encryption
            masking_config: Optional masking configuration
            **kwargs: Additional TextField arguments
        """
        self.kid = kid
        self.masking_config = masking_config or MaskingConfig()
        kwargs.setdefault("blank", True)
        kwargs.setdefault("null", True)
        super().__init__(**kwargs)

    def deconstruct(self):
        """Return field deconstruction for Django migrations."""
        name, path, args, kwargs = super().deconstruct()
        kwargs["kid"] = self.kid
        if self.masking_config:
            kwargs["masking_config"] = self.masking_config
        return name, path, args, kwargs

    def from_db_value(self, value, expression, connection):
        """Convert database value to Python object."""
        if value is None:
            return None
        return self._decrypt_and_mask(value)

    def to_python(self, value):
        """Convert value to Python object."""
        if value is None:
            return None
        if isinstance(value, str):
            # Try to parse as envelope JSON
            try:
                envelope = Envelope.from_json(value)
                return self._decrypt_and_mask(value)
            except Exception:
                # Not an envelope, return as-is
                return value
        return value

    def get_prep_value(self, value):
        """Convert Python object to database value."""
        if value is None:
            return None

        # If already an envelope JSON, return as-is
        try:
            Envelope.from_json(value)
            return value
        except Exception:
            pass

        # Encrypt the value
        cipher = self._get_cipher()
        envelope = cipher.encrypt(str(value), self.kid)
        return envelope.to_json()

    def _decrypt_and_mask(self, envelope_json: str) -> str:
        """Decrypt envelope and return masked value."""
        try:
            envelope = Envelope.from_json(envelope_json)
            cipher = self._get_cipher()
            return cipher.decrypt(envelope, masking_config=self.masking_config)
        except Exception:
            # If decryption fails, return the raw value
            return envelope_json

    def _get_cipher(self) -> FieldCipher:
        """Get or create a FieldCipher instance."""
        from django.conf import settings

        # Try to get cipher from app state
        if not hasattr(self, "_cipher_instance"):
            provider_driver = getattr(settings, "PANDA_KEY_PROVIDER_DRIVER", "local")
            config = getattr(settings, "PANDA_CONFIG", {})
            key_provider = create_key_provider(provider_driver, config)
            self._cipher_instance = FieldCipher(key_provider)

        return self._cipher_instance


class EncryptedFieldMixin:
    """
    Mixin for Django models to add encrypted field helpers.

    Usage:
        class Citizen(models.Model, EncryptedFieldMixin):
            nik = EncryptedField(kid='nik-key')
    """

    def get_decrypted_for_field(self, field_name: str) -> Optional[str]:
        """
        Get the decrypted (raw) value for an encrypted field.

        Args:
            field_name: Name of the encrypted field

        Returns:
            Decrypted plaintext or None if field is None
        """
        envelope_json = getattr(self, field_name)
        if envelope_json is None:
            return None

        try:
            envelope = Envelope.from_json(envelope_json)
            field = self._meta.get_field(field_name)
            cipher = field._get_cipher()
            return cipher.decrypt_raw(envelope)
        except Exception:
            return None

    def __getattr__(self, name: str) -> Any:
        """Provide get_decrypted_<field> methods dynamically."""
        if name.startswith("get_decrypted_") and hasattr(self, "_meta"):
            field_name = name.replace("get_decrypted_", "")
            if field_name in self._meta.get_all_field_names():
                return lambda: self.get_decrypted_for_field(field_name)
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")


class PandaMiddleware:
    """
    Django middleware for PANDA integration.

    Adds PANDA cipher instance to request for use in views.
    """

    def __init__(self, get_response):
        """Initialize middleware."""
        self.get_response = get_response
        self._cipher: Optional[FieldCipher] = None

    def __call__(self, request):
        """Process request and add cipher."""
        from django.conf import settings

        if self._cipher is None:
            provider_driver = getattr(settings, "PANDA_KEY_PROVIDER_DRIVER", "local")
            config = getattr(settings, "PANDA_CONFIG", {})
            key_provider = create_key_provider(provider_driver, config)
            self._cipher = FieldCipher(key_provider)

        request.panda_cipher = self._cipher
        response = self.get_response(request)
        return response
