"""
Masking module for PANDA SDK.

Provides data masking utilities for safe display of sensitive data.
"""

from typing import Optional
from dataclasses import dataclass


@dataclass
class MaskingConfig:
    """
    Configuration for data masking.

    Attributes:
        keep_leading: Number of leading characters to preserve (default: 2)
        keep_trailing: Number of trailing characters to preserve (default: 2)
        mask_char: Character to use for masking (default: '*')
    """
    keep_leading: int = 2
    keep_trailing: int = 2
    mask_char: str = "*"


class Masker:
    """
    Data masking utility for safe display of sensitive information.

    By default, preserves 2 leading and 2 trailing characters.
    The middle portion is replaced with the mask character.
    """

    @staticmethod
    def mask(plaintext: str, config: Optional[MaskingConfig] = None) -> str:
        """
        Mask a plaintext string according to the specified configuration.

        Args:
            plaintext: String to mask
            config: Optional masking configuration

        Returns:
            Masked string

        Examples:
            >>> Masker.mask("3201012501990001")
            '32************01'

            >>> Masker.mask("user@example.com", MaskingConfig(keep_leading=4, keep_trailing=6))
            'user********@example.com'

            >>> Masker.mask("AB", MaskingConfig(keep_leading=2, keep_trailing=2))
            '**'  # String too short to preserve both ends
        """
        cfg = config or MaskingConfig()

        # Use grapheme clusters for proper Unicode handling
        # For Python, we'll use list() which splits into Unicode code points
        chars = list(plaintext)
        length = len(chars)

        # If string is too short to preserve both ends, mask entirely
        if length <= cfg.keep_leading + cfg.keep_trailing:
            return cfg.mask_char * length

        # Build masked string
        leading = "".join(chars[:cfg.keep_leading])
        trailing = "".join(chars[length - cfg.keep_trailing:])
        mask_length = length - cfg.keep_leading - cfg.keep_trailing
        masked_middle = cfg.mask_char * mask_length

        return leading + masked_middle + trailing
