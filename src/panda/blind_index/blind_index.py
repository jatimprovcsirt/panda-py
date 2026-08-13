"""
Blind index module for PANDA SDK.

Provides deterministic hashing for searchable encrypted fields.
"""

import hmac
import hashlib
import base64
from typing import Union


class BlindIndexer:
    """
    Deterministic indexing for encrypted fields using HMAC-SHA256.

    Blind indexes enable exact-match searches on encrypted fields
    without storing searchable plaintext or using deterministic encryption.

    The index is computed as: HMAC-SHA256(blind_index_key, normalize(plaintext))

    Security Note: Blind indexes leak equality patterns. An attacker who
    gains database access can determine which records have the same value
    for a field. Use with caution on low-cardinality fields.
    """

    # Normalization modes
    NORMALIZATION_DIGITS = "digits"
    NORMALIZATION_LOWERCASE = "lowercase"
    NORMALIZATION_EMAIL = "email"
    NORMALIZATION_PHONE = "phone"
    NORMALIZATION_NIK = "nik"
    NORMALIZATION_TRIM = "trim"
    NORMALIZATION_NONE = "none"
    NORMALIZATION_RAW = "raw"

    @staticmethod
    def normalize(plaintext: str, normalization: str) -> str:
        """
        Normalize plaintext before generating blind index.

        Normalization must be applied identically on both write and read paths
        to ensure consistent index values.

        Args:
            plaintext: String to normalize
            normalization: Normalization mode

        Returns:
            Normalized string

        Examples:
            >>> BlindIndexer.normalize("  Email@Example.COM  ", "lowercase")
            'email@example.com'

            >>> BlindIndexer.normalize("+62-812-3456-7890", "digits")
            '6281234567890'
        """
        mode = normalization.lower()

        if mode in (BlindIndexer.NORMALIZATION_DIGITS,
                   BlindIndexer.NORMALIZATION_PHONE,
                   BlindIndexer.NORMALIZATION_NIK):
            # Extract only digits
            import re
            return re.sub(r"\D", "", plaintext)

        elif mode in (BlindIndexer.NORMALIZATION_LOWERCASE,
                     BlindIndexer.NORMALIZATION_EMAIL):
            # Lowercase and trim whitespace
            return plaintext.strip().lower()

        elif mode == BlindIndexer.NORMALIZATION_TRIM:
            # Only trim whitespace
            return plaintext.strip()

        elif mode in (BlindIndexer.NORMALIZATION_NONE,
                     BlindIndexer.NORMALIZATION_RAW):
            # No normalization
            return plaintext

        else:
            # Default to no normalization for unknown modes
            return plaintext

    @staticmethod
    def generate(
        plaintext: str,
        key: Union[str, bytes],
        normalization: str = "lowercase"
    ) -> str:
        """
        Generate a blind index for searchable encryption.

        The blind index is a deterministic HMAC-SHA256 hash that can be
        stored in a separate database column for exact-match queries.

        Args:
            plaintext: Value to generate index for
            key: Blind index key (distinct from encryption key!)
            normalization: Normalization mode to apply

        Returns:
            Base64-encoded HMAC-SHA256 hash

        Examples:
            >>> BlindIndexer.generate("user@example.com", "my-blind-index-key", "lowercase")
            'abc123def456...'

            >>> # To search: WHERE blind_index_column = BlindIndexer.generate(query_value, key, "lowercase")
        """
        # Normalize the plaintext
        normalized = BlindIndexer.normalize(plaintext, normalization)

        # Convert key to bytes if needed
        if isinstance(key, str):
            key_bytes = key.encode("utf-8")
        else:
            key_bytes = key

        # Compute HMAC-SHA256
        hmac_obj = hmac.new(key_bytes, normalized.encode("utf-8"), hashlib.sha256)
        digest = hmac_obj.digest()

        # Return base64-encoded digest
        return base64.b64encode(digest).decode("ascii")

    @staticmethod
    def validate_key(key: Union[str, bytes]) -> bool:
        """
        Validate that a blind index key meets security requirements.

        Args:
            key: Key to validate

        Returns:
            True if key is valid, False otherwise
        """
        if isinstance(key, str):
            key_bytes = key.encode("utf-8")
        else:
            key_bytes = key

        # Key should be at least 16 bytes (128 bits)
        return len(key_bytes) >= 16
