"""
Edge case tests for error handling.

Tests verify that the system handles edge cases and errors gracefully
across key providers and CLI operations.
"""

import pytest
import json
import os
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner

from panda.cli.commands import (
    cli,
    PandaCredentials,
    read_credentials,
    validate_token_format,
    PANDA_DIR_NAME
)
from panda.crypto.keys import (
    LocalKeyProvider,
    VaultKeyProvider,
    InfisicalKeyProvider,
    create_key_provider,
    KeyNotFoundError,
    CryptoProviderError
)


class TestCLIErrorHandling:
    """Test CLI command error handling."""

    @pytest.fixture
    def runner(self):
        """Create CLI runner."""
        return CliRunner()

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing."""
        temp_path = Path(tempfile.mkdtemp())
        yield temp_path
        shutil.rmtree(temp_path)

    def test_init_with_corrupted_credentials(self, runner, temp_dir):
        """Test init handles existing corrupted credentials file."""
        panda_dir = temp_dir / PANDA_DIR_NAME
        panda_dir.mkdir()

        # Create corrupted credentials file
        (panda_dir / "credentials").write_text("{invalid json")

        with patch("pathlib.Path.cwd", return_value=temp_dir):
            # Should allow proceeding with --reinit
            result = runner.invoke(
                cli,
                ["init", "--token", "panda_demo_" + "a" * 48, "--reinit"],
                input="1\ntest-key\n"
            )
            # Should succeed despite corrupted file
            assert result.exit_code == 0

    def test_generate_without_init(self, runner, temp_dir):
        """Test generate fails gracefully without initialization."""
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(cli, ["generate", "test-key"])
            assert result.exit_code == 1
            assert "not initialized" in result.output.lower()

    def test_status_without_init(self, runner, temp_dir):
        """Test status shows not initialized message."""
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(cli, ["status"])
            assert result.exit_code == 0
            assert "not initialized" in result.output.lower()

    def test_config_without_init(self, runner, temp_dir):
        """Test config fails without initialization."""
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(cli, ["config"])
            assert result.exit_code == 1 or "not initialized" in result.output.lower()

    def test_deinit_without_init(self, runner, temp_dir):
        """Test deinit handles missing .panda directory gracefully."""
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(cli, ["deinit"])
            assert result.exit_code == 0
            assert "not initialized" in result.output.lower()

    def test_generate_with_empty_kid(self, runner, temp_dir):
        """Test generate handles empty key ID."""
        # Initialize first
        panda_dir = temp_dir / PANDA_DIR_NAME
        panda_dir.mkdir()
        (panda_dir / "credentials").write_text(
            json.dumps({"token": "panda_demo_" + "a" * 48, "provider": "local"})
        )
        (temp_dir / ".env").write_text("")

        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["generate"],
                input="\ntest-key\n"  # Empty kid, then provide one
            )
            # Should work after providing valid kid
            assert "test-key" in result.output

    def test_init_with_very_long_kid(self, runner, temp_dir):
        """Test init handles very long key IDs."""
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", "panda_demo_" + "a" * 48],
                input="1\n" + "a" * 1000 + "\n"  # Very long kid
            )
            # Should handle long kid (may truncate or reject)
            assert result.exit_code == 0


class TestKeyProviderErrorHandling:
    """Test key provider error handling."""

    def test_local_provider_key_not_found(self):
        """Test LocalKeyProvider raises KeyNotFoundError for missing key."""
        provider = LocalKeyProvider()
        with pytest.raises(KeyNotFoundError, match="not found"):
            provider.get_key("nonexistent-key")

    def test_local_provider_invalid_base64(self, monkeypatch):
        """Test LocalKeyProvider handles invalid base64 in env."""
        monkeypatch.setenv("PANDA_KEY_INVALID", "not-valid-base64!!!")
        provider = LocalKeyProvider()
        with pytest.raises(KeyNotFoundError, match="Invalid base64"):
            provider.get_key("invalid")

    def test_local_provider_wrong_key_length(self, monkeypatch):
        """Test LocalKeyProvider validates key length."""
        short_key = "YQ=="  # 1 char base64 (valid base64, but decodes to 1 byte)
        monkeypatch.setenv("PANDA_KEY_SHORT", short_key)
        provider = LocalKeyProvider()
        with pytest.raises(KeyNotFoundError, match="Key must be base64-encoded and decode to exactly 32 bytes"):
            provider.get_key("short")

    @patch("http.client.HTTPConnection")
    def test_vault_provider_connection_error(self, mock_conn):
        """Test VaultKeyProvider handles connection errors."""
        mock_connection = Mock()
        mock_connection.getresponse.side_effect = OSError("Connection refused")
        mock_conn.return_value = mock_connection

        provider = VaultKeyProvider(
            vault_url="http://localhost:8200",
            vault_token="test-token"
        )
        # CryptoProviderError, not KeyNotFoundError. A Vault that cannot be
        # reached is an outage; reporting it as a missing key sends whoever
        # is on call to look for a key that is probably fine. The provider
        # was changed to distinguish the two and this expectation was not.
        with pytest.raises(CryptoProviderError):
            provider.get_key("test-key")

    @patch("http.client.HTTPSConnection")
    def test_infisical_provider_connection_error(self, mock_conn):
        """Test InfisicalKeyProvider handles connection errors."""
        mock_connection = Mock()
        mock_connection.getresponse.side_effect = OSError("Connection refused")
        mock_conn.return_value = mock_connection

        provider = InfisicalKeyProvider(
            site_url="https://app.infisical.com",
            client_id="test",
            client_secret="test",
            project_id="test",
            environment="dev"
        )
        with pytest.raises(CryptoProviderError):
            provider.get_key("test-key")

    @patch("http.client.HTTPSConnection")
    def test_infisical_auth_timeout(self, mock_conn):
        """Test InfisicalKeyProvider handles authentication timeout."""
        mock_connection = Mock()
        mock_connection.getresponse.side_effect = OSError("Timeout")
        mock_conn.return_value = mock_connection

        provider = InfisicalKeyProvider(
            site_url="https://app.infisical.com",
            client_id="test",
            client_secret="test",
            project_id="test",
            environment="dev"
        )
        with pytest.raises(CryptoProviderError, match="connection"):
            provider._ensure_authenticated()

    def test_factory_invalid_driver(self):
        """Test create_key_provider handles unknown driver."""
        with pytest.raises(ValueError, match="Unknown key provider"):
            create_key_provider("unknown", {})

    def test_factory_vault_missing_url(self):
        """Test create_key provider validates Vault config."""
        with pytest.raises(ValueError, match="requires vaultUrl"):
            create_key_provider("vault", {"vaultToken": "token"})

    def test_factory_vault_missing_token(self):
        """Test create_key_provider validates Vault config.

        With a URL and nothing else, the factory defaults to AppRole and
        says so. The expectation here used to be "requires vaultUrl", which
        is not the problem — the URL is the one thing that *was* given.
        """
        with pytest.raises(ValueError, match="requires role_id and secret_id"):
            create_key_provider("vault", {"vaultUrl": "http://localhost:8200"})

    def test_factory_infisical_missing_fields(self):
        """Test create_key_provider validates Infisical config."""
        with pytest.raises(ValueError, match="requires"):
            create_key_provider("infisical", {
                "siteUrl": "https://app.infisical.com",
                # Missing other required fields
            })


class TestCredentialFileEdgeCases:
    """Test edge cases with credential file handling."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing."""
        temp_path = Path(tempfile.mkdtemp())
        yield temp_path
        shutil.rmtree(temp_path)

    def test_read_credentials_partial_file(self, temp_dir):
        """Test reading partial credentials file."""
        panda_dir = temp_dir / PANDA_DIR_NAME
        panda_dir.mkdir()

        # Write incomplete credentials
        (panda_dir / "credentials").write_text('{"token": "test"')

        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = read_credentials()
            assert result is None

    def test_read_credentials_empty_object(self, temp_dir):
        """Test reading empty object from credentials."""
        panda_dir = temp_dir / PANDA_DIR_NAME
        panda_dir.mkdir()

        (panda_dir / "credentials").write_text("{}")

        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = read_credentials()
            # Should return PandaCredentials with default values
            assert isinstance(result, PandaCredentials)

    def test_read_credentials_with_null_values(self, temp_dir):
        """Test reading credentials with null values."""
        panda_dir = temp_dir / PANDA_DIR_NAME
        panda_dir.mkdir()

        (panda_dir / "credentials").write_text(
            '{"token": null, "provider": null, "default_kid": null}'
        )

        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = read_credentials()
            assert result is not None
            assert result.token is None
            assert result.default_kid is None

    def test_read_credentials_unicode_values(self, temp_dir):
        """Test reading credentials with Unicode values."""
        panda_dir = temp_dir / PANDA_DIR_NAME
        panda_dir.mkdir()

        (panda_dir / "credentials").write_text(
            json.dumps({
                "token": "panda_demo_" + "a" * 48,
                "provider": "infisical",
                "unicode_field": "Halo Dunia 🌍"
            })
        )

        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = read_credentials()
            assert result is not None
            # Unicode handling depends on implementation
            # The test verifies it doesn't crash


class TestKeyIDEdgeCases:
    """Test edge cases for key ID handling."""

    def test_key_id_with_special_unicode(self):
        """Test key ID with Unicode characters (should be rejected)."""
        assert not validate_token_format("panda_demo_测试测试测试测试测试测试测试测试测试测试")

    def test_key_id_with_emoji(self):
        """Test key ID with emoji (should be rejected)."""
        assert not validate_token_format("panda_demo_🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑")

    def test_key_id_with_right_to_left(self):
        """Test key ID with RTL characters (should be rejected)."""
        assert not validate_token_format("panda_demo_مرحبااااااااااااااااااااااااااااا")

    def test_key_id_with_whitespace_variations(self):
        """Test various whitespace characters are rejected."""
        assert not validate_token_format("panda_demo_\ta" * 48)  # Tab
        assert not validate_token_format("panda_demo_\na" * 48)  # Newline
        assert not validate_token_format("panda_demo_\ra" * 48)  # Carriage return
        assert not validate_token_format("panda_demo_ a" * 48)  # Space

    def test_key_id_case_sensitivity(self):
        """Test case sensitivity of panda_ prefix."""
        # Uppercase prefix should fail
        assert not validate_token_format("PANDA_DEMO_" + "a" * 48)
        # Mixed case prefix should fail
        assert not validate_token_format("PaNdA_dEmO_" + "a" * 48)
        # Lowercase should pass
        assert validate_token_format("panda_demo_" + "a" * 48)

    def test_key_id_type_case_sensitivity(self):
        """Test case sensitivity of type field (demo/live)."""
        # Uppercase DEMO should fail
        assert not validate_token_format("panda_DEMO_" + "a" * 48)
        # Uppercase LIVE should fail
        assert not validate_token_format("panda_LIVE_" + "a" * 48)
        # Mixed case should fail
        assert not validate_token_format("panda_DeMo_" + "a" * 48)
        # Lowercase should pass
        assert validate_token_format("panda_demo_" + "a" * 48)
        assert validate_token_format("panda_live_" + "a" * 48)


class TestEnvironmentVariableEdgeCases:
    """Test edge cases with environment variable handling."""

    @pytest.mark.skipif(
        os.name == "nt",
        reason="Windows environment variables are case-insensitive, so "
        "PANDA_KEY_test-key and PANDA_KEY_TEST-KEY are the same variable. "
        "The exact-match step cannot be isolated from the normalised one "
        "here, which is what this test exists to distinguish.",
    )
    def test_env_var_priority(self, monkeypatch):
        """Test priority of env var lookups."""
        # bytes, because that is what get_key returns and is annotated to
        # return. Comparing against a str could never hold.
        key = b"a" * 32
        # 32 bytes, not 34. The previous value decoded to 34 and the provider
        # rejected it, so these tests were failing on their own fixture.
        b64_key = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="

        # Set both exact and normalized versions
        monkeypatch.setenv("PANDA_KEY_TEST_KEY", b64_key)
        monkeypatch.setenv("PANDA_KEY_TEST-KEY", "different-value")

        provider = LocalKeyProvider()
        result = provider.get_key("test-key")

        # Exact match should take priority
        assert result == key

    def test_env_var_hyphen_normalization(self, monkeypatch):
        """Test hyphen to underscore normalization."""
        # bytes, because that is what get_key returns and is annotated to
        # return. Comparing against a str could never hold.
        key = b"a" * 32
        # 32 bytes, not 34. The previous value decoded to 34 and the provider
        # rejected it, so these tests were failing on their own fixture.
        b64_key = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="

        # Set with underscore
        monkeypatch.setenv("PANDA_KEY_MY_TEST_KEY", b64_key)

        provider = LocalKeyProvider()
        result = provider.get_key("my-test-key")

        assert result == key

    def test_env_var_dot_normalization(self, monkeypatch):
        """Test dot to underscore normalization."""
        # bytes, because that is what get_key returns and is annotated to
        # return. Comparing against a str could never hold.
        key = b"a" * 32
        # 32 bytes, not 34. The previous value decoded to 34 and the provider
        # rejected it, so these tests were failing on their own fixture.
        b64_key = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="

        # Set with underscore
        monkeypatch.setenv("PANDA_KEY_MY_API_KEY", b64_key)

        provider = LocalKeyProvider()
        result = provider.get_key("my.api.key")

        assert result == key

    def test_env_var_empty_value(self, monkeypatch):
        """Test empty environment variable is handled correctly."""
        monkeypatch.setenv("PANDA_KEY_EMPTY", "")

        provider = LocalKeyProvider()
        with pytest.raises(KeyNotFoundError):
            provider.get_key("empty")

    def test_env_var_whitespace_value(self, monkeypatch):
        """Test whitespace-only environment variable."""
        monkeypatch.setenv("PANDA_KEY_WHITESPACE", "   ")

        provider = LocalKeyProvider()
        # Should treat as empty/invalid
        with pytest.raises(KeyNotFoundError):
            provider.get_key("whitespace")
