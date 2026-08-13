"""
Tests for FieldCipher class.
"""

import pytest
import base64
from panda.crypto import (
    FieldCipher,
    LocalKeyProvider,
    Envelope,
    KeyNotFoundError,
    AuthenticationFailedError,
    EnvelopeVersionError,
    UnsupportedAlgorithmError
)
from panda.masking import MaskingConfig


class TestFieldCipher:
    """Test field encryption/decryption."""

    @pytest.fixture
    def key(self):
        """Fixture for test key - exactly 32 bytes."""
        return b"this is a 32-byte key for testing!!"

    @pytest.fixture
    def key_provider(self, key):
        """Fixture for key provider."""
        provider = LocalKeyProvider()
        provider.set_key("test-key", key)
        return provider

    @pytest.fixture
    def cipher(self, key_provider):
        """Fixture for field cipher."""
        return FieldCipher(key_provider)

    def test_encrypt_decrypt_basic(self, cipher):
        """Test basic encrypt/decrypt cycle."""
        plaintext = "Hello, World!"
        kid = "test-key"

        # Encrypt
        envelope = cipher.encrypt(plaintext, kid)

        assert isinstance(envelope, Envelope)
        assert envelope.v == 1
        assert envelope.alg == "aes-256-gcm"
        assert envelope.kid == kid
        assert envelope.nonce
        assert envelope.ciphertext

        # Decrypt (masked)
        masked = cipher.decrypt(envelope)
        assert masked == "He************d!"

        # Decrypt raw
        raw = cipher.decrypt_raw(envelope)
        assert raw == plaintext

    def test_encrypt_with_custom_masking(self, cipher):
        """Test decryption with custom masking."""
        plaintext = "3201012501990001"
        kid = "test-key"

        envelope = cipher.encrypt(plaintext, kid)
        masked = cipher.decrypt(
            envelope,
            masking_config=MaskingConfig(
                keep_leading=3,
                keep_trailing=1,
                mask_char="*"
            )
        )

        assert masked == "320************1"

    def test_decrypt_invalid_version(self, cipher):
        """Test decrypting envelope with unsupported version."""
        envelope = Envelope(
            v=2,
            alg="aes-256-gcm",
            kid="test-key",
            nonce="abcd",
            ciphertext="encrypted"
        )

        with pytest.raises(EnvelopeVersionError):
            cipher.decrypt_raw(envelope)

    def test_decrypt_unsupported_algorithm(self, cipher):
        """Test decrypting envelope with unsupported algorithm."""
        envelope = Envelope(
            v=1,
            alg="chacha20-poly1305",
            kid="test-key",
            nonce="abcd",
            ciphertext="encrypted"
        )

        with pytest.raises(UnsupportedAlgorithmError):
            cipher.decrypt_raw(envelope)

    def test_decrypt_nonexistent_key(self, cipher):
        """Test decrypting with a key that doesn't exist."""
        envelope = Envelope(
            v=1,
            alg="aes-256-gcm",
            kid="nonexistent-key",
            nonce="abcd",
            ciphertext="encrypted"
        )

        with pytest.raises(KeyNotFoundError):
            cipher.decrypt_raw(envelope)

    def test_decrypt_tampered_ciphertext(self, cipher):
        """Test that tampering is detected."""
        plaintext = "Hello, World!"
        kid = "test-key"

        # Encrypt
        envelope = cipher.encrypt(plaintext, kid)

        # Tamper with ciphertext
        tampered_ct = envelope.ciphertext + "tamper"
        tampered_env = Envelope(
            v=envelope.v,
            alg=envelope.alg,
            kid=envelope.kid,
            nonce=envelope.nonce,
            ciphertext=tampered_ct
        )

        with pytest.raises(AuthenticationFailedError):
            cipher.decrypt_raw(tampered_env)

    def test_encrypt_empty_string(self, cipher):
        """Test encrypting an empty string."""
        plaintext = ""
        kid = "test-key"

        envelope = cipher.encrypt(plaintext, kid)
        raw = cipher.decrypt_raw(envelope)

        assert raw == plaintext

    def test_encrypt_unicode(self, cipher):
        """Test encrypting Unicode text."""
        plaintext = "Halo, Dunia! 🌍"
        kid = "test-key"

        envelope = cipher.encrypt(plaintext, kid)
        raw = cipher.decrypt_raw(envelope)

        assert raw == plaintext

    def test_decrypt_short_plaintext(self, cipher):
        """Test decrypting a string shorter than mask characters."""
        plaintext = "AB"
        kid = "test-key"

        envelope = cipher.encrypt(plaintext, kid)
        masked = cipher.decrypt(envelope)

        # Should be fully masked
        assert masked == "**"
