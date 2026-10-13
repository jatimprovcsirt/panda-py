"""
Security tests for token validation.

Tests verify that PANDA tokens are properly validated according
to the specified format: panda_(demo|live)_[48 or 64 lowercase hex chars]

Pinned in panda-spec/token-format.md, which is the one definition the four
SDKs are checked against.
"""

import pytest

# From the module that defines it, not from panda.cli.commands, which only
# re-exports it. `panda.cli.commands` was where the pattern lived — as a second
# copy, which accepted 48 hex characters where this one accepts 48 or 64.
from panda.crypto.token import TOKEN_PATTERN, validate_token_format


class TestTokenValidation:
    """Test token validation security rules."""

    def test_valid_demo_token_all_lowercase(self):
        """Test valid demo token with all lowercase hex."""
        token = "panda_demo_" + "a" * 48
        assert validate_token_format(token) is True

    def test_invalid_demo_token_all_uppercase(self):
        """Test invalid demo token with uppercase hex (should be lowercase)."""
        token = "panda_demo_" + "A" * 48
        assert validate_token_format(token) is False

    def test_invalid_demo_token_mixed_case(self):
        """Test invalid demo token with mixed case hex (should be lowercase only)."""
        token = "panda_demo_" + "aA1Bb2Cc3" * 4  # 48 chars
        assert validate_token_format(token) is False

    def test_valid_live_token(self):
        """Test valid live token."""
        token = "panda_live_" + "f" * 48
        assert validate_token_format(token) is True

    def test_valid_64_char_token(self):
        """Test a 64-hex-character token is accepted.

        panda-node, panda-php and panda-go have always accepted these; this
        SDK rejected them until the pattern was aligned.
        """
        token = "panda_live_" + "ab12" * 16
        assert len(token) == 75
        assert validate_token_format(token) is True

    def test_invalid_63_and_65_char_tokens(self):
        """Test lengths between and beyond the two allowed ones are rejected."""
        assert validate_token_format("panda_demo_" + "a" * 63) is False
        assert validate_token_format("panda_demo_" + "a" * 65) is False

    def test_valid_token_numeric_only(self):
        """Test valid token with only numeric hex."""
        # 48 hex characters. The previous expression built 52, so the test
        # asserted that an over-long token was valid.
        token = "panda_demo_" + "1234567890" * 4 + "12345678"
        assert validate_token_format(token) is True

    def test_invalid_token_wrong_prefix_bear(self):
        """Test token with wrong prefix 'bear' instead of 'panda'."""
        token = "bear_demo_" + "a" * 48
        assert validate_token_format(token) is False

    def test_invalid_token_wrong_prefix_test(self):
        """Test token with wrong prefix 'test' instead of 'panda'."""
        token = "test_demo_" + "a" * 48
        assert validate_token_format(token) is False

    def test_invalid_token_no_prefix(self):
        """Test token without panda_ prefix."""
        token = "demo_" + "a" * 48
        assert validate_token_format(token) is False

    def test_invalid_token_empty_string(self):
        """Test empty string is rejected."""
        assert validate_token_format("") is False

    def test_trailing_newline_is_rejected(self):
        """A token with a trailing newline is not a token.

        This is the one case where the four SDKs' regex engines disagreed on
        the same pattern. In Python and in PCRE, `$` also matches immediately
        before a newline at the end of the string, so this string matched here
        and in PHP while Node and Go rejected it. A token read from a file or
        pasted out of a heredoc carries a trailing newline routinely, so it was
        not hypothetical: the same bytes were a valid token in two SDKs and not
        in the other two. `\\Z`, and PCRE's `D` modifier, anchor at the end of
        the string and nothing else.
        """
        token = "panda_demo_" + "a" * 48
        assert validate_token_format(token) is True
        assert validate_token_format(token + "\n") is False
        assert validate_token_format(token + "\r") is False
        assert validate_token_format(token + "\r\n") is False
        assert validate_token_format("\n" + token) is False

    def test_the_pattern_is_the_one_the_spec_pins(self):
        """The constant exists so there is one definition, not four."""
        assert TOKEN_PATTERN.startswith("^panda_(demo|live)_")

    def test_invalid_token_none(self):
        """Test None is rejected."""
        # validate_token_format expects a string, None should raise TypeError or return False
        # The implementation uses re.match which requires a string
        try:
            result = validate_token_format(None)
            assert result is False
        except (TypeError, AttributeError):
            # Also acceptable - None cannot be matched against regex
            pass

    def test_invalid_token_too_short_47_chars(self):
        """Test token with 47 hex chars (one too short)."""
        token = "panda_demo_" + "a" * 47
        assert validate_token_format(token) is False

    def test_invalid_token_too_short_1_char(self):
        """Test token with only 1 hex char after prefix."""
        token = "panda_demo_a"
        assert validate_token_format(token) is False

    def test_invalid_token_too_long_49_chars(self):
        """Test token with 49 hex chars (one too long)."""
        token = "panda_demo_" + "a" * 49
        assert validate_token_format(token) is False

    def test_invalid_token_too_long_100_chars(self):
        """Test token with 100 hex chars (way too long)."""
        token = "panda_demo_" + "a" * 100
        assert validate_token_format(token) is False

    def test_invalid_token_non_hex_char_g(self):
        """Test token with 'g' which is not valid hex."""
        token = "panda_demo_" + "g" * 48
        assert validate_token_format(token) is False

    def test_invalid_token_non_hex_char_z(self):
        """Test token with 'z' which is not valid hex."""
        token = "panda_demo_" + "z" * 48
        assert validate_token_format(token) is False

    def test_invalid_token_with_spaces(self):
        """Test token with spaces is rejected."""
        token = "panda_demo_ " + "a" * 48
        assert validate_token_format(token) is False

    def test_invalid_token_with_special_chars(self):
        """Test token with special characters is rejected."""
        token = "panda_demo_" + "!@#$%^&*()" + "a" * 38
        assert validate_token_format(token) is False

    def test_invalid_token_underscore_in_hex(self):
        """Test token with underscore in hex part is rejected."""
        token = "panda_demo_" + "a" * 24 + "_" + "a" * 23
        assert validate_token_format(token) is False

    def test_invalid_token_hyphen_in_hex(self):
        """Test token with hyphen in hex part is rejected."""
        token = "panda_demo_" + "a" * 24 + "-" + "a" * 23
        assert validate_token_format(token) is False

    def test_invalid_token_wrong_type_after_demo(self):
        """Test token with wrong type after prefix (production vs demo)."""
        token = "panda_production_" + "a" * 48
        assert validate_token_format(token) is False

    def test_invalid_token_wrong_type_staging(self):
        """Test token with staging type (not demo or live)."""
        token = "panda_staging_" + "a" * 48
        assert validate_token_format(token) is False

    def test_valid_token_lowercase_type(self):
        """Test valid token with lowercase type."""
        token = "panda_live_" + "a" * 48
        assert validate_token_format(token) is True

    def test_invalid_token_uppercase_prefix(self):
        """Test token with uppercase PANDA prefix."""
        token = "PANDA_DEMO_" + "a" * 48
        assert validate_token_format(token) is False

    def test_invalid_token_mixed_case_prefix(self):
        """Test token with mixed case prefix."""
        token = "Panda_Demo_" + "a" * 48
        assert validate_token_format(token) is False

    def test_valid_token_leading_zero(self):
        """Test valid token with leading zeros in hex."""
        token = "panda_demo_" + "0" * 48
        assert validate_token_format(token) is True

    def test_valid_token_max_hex_value(self):
        """Test valid token with max hex value (f)."""
        token = "panda_live_" + "f" * 48
        assert validate_token_format(token) is True

    def test_invalid_token_with_newline(self):
        """Test token with newline character is rejected."""
        token = "panda_demo_\n" + "a" * 48
        assert validate_token_format(token) is False

    def test_invalid_token_with_tab(self):
        """Test token with tab character is rejected."""
        token = "panda_demo_\t" + "a" * 48
        assert validate_token_format(token) is False

    def test_valid_token_exact_length(self):
        """Test token with exactly 48 hex chars."""
        # The prefix concatenated with 48 hex characters. The previous
        # expression repeated the whole string three times, which produced
        # three prefixes and 81 characters.
        token = "panda_demo_" + "1234567890abcdef" * 3
        assert validate_token_format(token) is True

    def test_invalid_token_with_colon(self):
        """Test token with colon in hex part is rejected."""
        token = "panda_demo_:" + "a" * 47
        assert validate_token_format(token) is False

    def test_invalid_token_with_slash(self):
        """Test token with slash in hex part is rejected."""
        token = "panda_demo_/" + "a" * 47
        assert validate_token_format(token) is False

    def test_valid_token_boundary_case(self):
        """Test token at boundary of valid chars (all 9s)."""
        token = "panda_demo_" + "9" * 48
        assert validate_token_format(token) is True

    def test_invalid_token_boundary_case_g(self):
        """Test token just outside valid hex range (g)."""
        token = "panda_demo_" + "g" * 48
        assert validate_token_format(token) is False


class TestTokenSecurityImplications:
    """Test security implications of token validation."""

    def test_token_format_prevents_injection(self):
        """Test that token format prevents basic injection attempts."""
        # SQL injection attempt
        token = "panda_demo_' OR '1'='1"
        assert validate_token_format(token) is False

        # Path traversal attempt
        token = "panda_demo_../../etc/passwd"
        assert validate_token_format(token) is False

        # XSS attempt
        token = "panda_demo_<script>alert('xss')</script>"
        assert validate_token_format(token) is False

    def test_token_length_limits_memory_usage(self):
        """Test that token length validation prevents excessive memory use."""
        # Very long token should be rejected
        token = "panda_demo_" + "a" * 10000
        assert validate_token_format(token) is False

    def test_token_hex_only_prevents_special_chars(self):
        """Test that hex-only validation prevents special character usage."""
        special_chars = [
            "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "+", "=",
            "[", "]", "{", "}", "|", "\\", ":", ";", '"', "'", "<", ">", ",", ".",
            "?", "/", "~", "`"
        ]

        for char in special_chars:
            token = f"panda_demo_{char}{'a' * 47}"
            assert validate_token_format(token) is False, f"Token with '{char}' should be rejected"

    def test_token_type_restriction(self):
        """Test that only 'demo' and 'live' types are allowed."""
        valid_types = ["demo", "live"]
        invalid_types = ["test", "staging", "prod", "production", "dev", "beta", "alpha"]

        for valid_type in valid_types:
            token = f"panda_{valid_type}_{'a' * 48}"
            assert validate_token_format(token) is True, f"Token type '{valid_type}' should be valid"

        for invalid_type in invalid_types:
            token = f"panda_{invalid_type}_{'a' * 48}"
            assert validate_token_format(token) is False, f"Token type '{invalid_type}' should be invalid"
