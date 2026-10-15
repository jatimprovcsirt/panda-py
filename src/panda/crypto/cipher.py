"""
Field cipher for PANDA SDK.

Implements AES-256-GCM field-level encryption and decryption.
"""

import os
import base64
import time
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from ..telemetry import count
from .keys import KeyProvider
from .envelope import Envelope
from .errors import (
    EnvelopeVersionError,
    UnsupportedAlgorithmError,
    MalformedEnvelopeError,
    AuthenticationFailedError,
    EncryptionError,
    KeyNotFoundError
)
from ..audit import AuditLogger
from ..masking import Masker, MaskingConfig


class FieldCipher:
    """
    Field-level encryption/decryption using AES-256-GCM.

    Encrypts individual fields with envelope format storage.
    By default, decryption returns masked values for safe logging/display.
    Use decrypt_raw() for full plaintext (audited operation).
    """

    def __init__(
        self,
        keys: KeyProvider,
        audit: Optional[AuditLogger] = None
    ):
        """
        Initialize the field cipher.

        The telemetry client and the token are gone from this class. They
        existed so every cipher carried both and could make a network request
        inside ``encrypt()`` and ``decrypt_raw()`` — once per operation, from a
        library whose promise is that it works without the portal. Counting is
        now a process-local counter increment (``panda.telemetry.count``), and
        the token comes from the credentials ``panda init`` wrote.

        Args:
            keys: Key provider instance
            audit: Optional audit logger
        """
        self._keys = keys
        self._audit = audit or AuditLogger()

    def encrypt(
        self,
        plaintext: str,
        kid: str,
        actor: str = "system",
        field: str = "unknown"
    ) -> Envelope:
        """
        Encrypt a plaintext value.

        Args:
            plaintext: String to encrypt
            kid: Key identifier to use for encryption
            actor: Optional actor identifier for audit log
            field: Optional field name for audit log

        Returns:
            Envelope containing the encrypted data

        Raises:
            KeyNotFoundError: If the key cannot be found
            EncryptionError: If encryption fails
        """
        try:
            # Get the encryption key
            key = self._keys.get_key(kid)
        except KeyNotFoundError as e:
            self._audit.log(actor, field, kid, "encrypt", "key_not_found")
            raise

        try:
            # Generate random 12-byte nonce
            nonce = os.urandom(12)

            # Encrypt using AES-256-GCM
            aesgcm = AESGCM(key)
            ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

            # Create envelope
            envelope = Envelope(
                v=1,
                alg="aes-256-gcm",
                kid=kid,
                nonce=base64.b64encode(nonce).decode("ascii"),
                ciphertext=base64.b64encode(ciphertext_and_tag).decode("ascii")
            )

            self._audit.log(actor, field, kid, "encrypt", "success")

            count("encrypts")

            return envelope

        except Exception as e:
            self._audit.log(actor, field, kid, "encrypt", "encryption_failed")
            raise EncryptionError(f"Encryption failed: {e}") from e

    def decrypt(
        self,
        envelope: Envelope,
        actor: str = "system",
        field: str = "unknown",
        masking_config: Optional[MaskingConfig] = None
    ) -> str:
        """
        Decrypt an envelope and return the masked value.

        Args:
            envelope: Envelope to decrypt
            actor: Optional actor identifier for audit log
            field: Optional field name for audit log
            masking_config: Optional masking configuration

        Returns:
            Masked plaintext string

        Raises:
            EnvelopeVersionError: If envelope version is unsupported
            UnsupportedAlgorithmError: If algorithm is unsupported
            MalformedEnvelopeError: If envelope format is invalid
            AuthenticationFailedError: If authentication fails
            KeyNotFoundError: If the key cannot be found
        """
        # The label goes in rather than being logged here as well: the shared
        # implementation logs every failure, so logging again here wrote two
        # audit entries per masked read — one of them claiming a raw decrypt,
        # which is the entry the whole audit trail exists to make meaningful.
        raw_plaintext = self.decrypt_raw_impl(envelope, actor, field, "decrypt_masked")
        masked = Masker.mask(raw_plaintext, masking_config)

        self._audit.log(actor, field, envelope.kid, "decrypt_masked", "success")
        count("decrypts")

        return masked

    def decrypt_raw(
        self,
        envelope: Envelope,
        actor: str = "system",
        field: str = "unknown"
    ) -> str:
        plaintext = self.decrypt_raw_impl(envelope, actor, field, "decrypt_raw")

        self._audit.log(actor, field, envelope.kid, "decrypt_raw", "success")
        count("decryptsRaw")

        return plaintext

    def decrypt_raw_impl(
        self,
        envelope: Envelope,
        actor: str,
        field: str,
        label: str
    ) -> str:
        """
        Decrypt an envelope and return the full unmasked plaintext.

        This is an audited operation - all calls are logged separately
        from masked decrypt operations.

        Args:
            envelope: Envelope to decrypt
            actor: Optional actor identifier for audit log
            field: Optional field name for audit log

        Returns:
            Full unmasked plaintext string

        Raises:
            EnvelopeVersionError: If envelope version is unsupported
            UnsupportedAlgorithmError: If algorithm is unsupported
            MalformedEnvelopeError: If envelope format is invalid
            AuthenticationFailedError: If authentication fails
            KeyNotFoundError: If the key cannot be found
        """
        # Validate envelope version
        if envelope.v != 1:
            self._audit.log(actor, field, envelope.kid, label, "unsupported_envelope_version")
            raise EnvelopeVersionError(f"Unsupported envelope version: {envelope.v}")

        # Validate algorithm
        if envelope.alg.lower() != "aes-256-gcm":
            self._audit.log(actor, field, envelope.kid, label, "unsupported_algorithm")
            raise UnsupportedAlgorithmError(f"Unsupported algorithm: {envelope.alg}")

        # Get the decryption key
        try:
            key = self._keys.get_key(envelope.kid)
        except KeyNotFoundError as e:
            self._audit.log(actor, field, envelope.kid, label, "key_not_found")
            raise

        # Decode nonce
        try:
            nonce = base64.b64decode(envelope.nonce)
        except Exception as e:
            self._audit.log(actor, field, envelope.kid, label, "malformed_envelope")
            raise MalformedEnvelopeError(f"Invalid nonce encoding: {e}") from e

        if len(nonce) != 12:
            self._audit.log(actor, field, envelope.kid, label, "malformed_envelope")
            raise MalformedEnvelopeError("Invalid nonce length in envelope. Expected 12 bytes.")

        # Decode ciphertext (combined with tag)
        try:
            combined = base64.b64decode(envelope.ciphertext)
        except Exception as e:
            self._audit.log(actor, field, envelope.kid, label, "malformed_envelope")
            raise MalformedEnvelopeError(f"Invalid ciphertext encoding: {e}") from e

        if len(combined) < 16:
            self._audit.log(actor, field, envelope.kid, label, "malformed_envelope")
            raise MalformedEnvelopeError("Invalid ciphertext length. Must include 16-byte auth tag.")

        try:
            # Decrypt using AES-256-GCM
            aesgcm = AESGCM(key)
            plaintext_bytes = aesgcm.decrypt(nonce, combined, None)
            plaintext_str = plaintext_bytes.decode("utf-8")

            # No success entry here. The two public methods log their own,
            # because only they know which one ran.
            return plaintext_str

        except Exception as e:
            self._audit.log(actor, field, envelope.kid, label, "auth_failure")
            raise AuthenticationFailedError("Ciphertext decryption/authentication failed.") from e
