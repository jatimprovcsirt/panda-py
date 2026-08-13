"""
Unit tests for PANDA CLI commands.

Tests cover the main CLI interface including command registration
and common utilities.
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
    get_panda_dir,
    credentials_exist,
    read_credentials,
    write_credentials,
    validate_token_format,
    PANDA_DIR_NAME,
    CREDENTIALS_FILE,
    CONFIG_FILE,
    KEYS_FILE
)


class TestCLIBasics:
    """Test basic CLI functionality."""

    def test_cli_group_exists(self):
        """Test that CLI group is properly defined."""
        assert cli is not None
        assert cli.name == "cli"

    def test_cli_version_option(self):
        """Test CLI version option."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_cli_help(self):
        """Test CLI help output."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "PANDA" in result.output
        assert "init" in result.output
        assert "generate" in result.output
        assert "status" in result.output


class TestPandaCredentials:
    """Test PandaCredentials dataclass."""

    def test_credentials_initialization(self):
        """Test default credentials initialization."""
        creds = PandaCredentials()
        assert creds.token is None
        assert creds.provider == "local"
        assert creds.default_kid is None
        assert creds.keys == {}

    def test_credentials_with_values(self):
        """Test credentials with specific values."""
        creds = PandaCredentials(
            token="panda_demo_1234567890abcdef1234567890abcdef1234567890abcdef",
            provider="infisical",
            default_kid="test-key",
            infisical_site_url="https://app.infisical.com",
            infisical_project_id="test-project",
            infisical_environment="dev"
        )
        assert creds.token == "panda_demo_1234567890abcdef1234567890abcdef1234567890abcdef"
        assert creds.provider == "infisical"
        assert creds.default_kid == "test-key"
        assert creds.infisical_site_url == "https://app.infisical.com"

    def test_credentials_keys_initialization(self):
        """Test that keys dict is initialized."""
        creds = PandaCredentials()
        assert creds.keys == {}
        creds.keys["test-key"] = {"created": "2024-01-01T00:00:00Z"}
        assert len(creds.keys) == 1


class TestTokenValidation:
    """Test token validation functionality."""

    def test_valid_demo_token(self):
        """Test validation of valid demo token."""
        token = "panda_demo_" + "a" * 48
        assert validate_token_format(token) is True

    def test_valid_live_token(self):
        """Test validation of valid live token."""
        token = "panda_live_" + "f" * 48
        assert validate_token_format(token) is True

    def test_valid_hex_token(self):
        """Test validation of token with mixed hex."""
        token = "panda_demo_" + "1a2b3c4d5e6f7890" * 3  # 48 hex chars
        assert validate_token_format(token) is True

    def test_invalid_token_no_prefix(self):
        """Test validation fails without panda_ prefix."""
        assert validate_token_format("demo_token") is False

    def test_invalid_token_wrong_prefix(self):
        """Test validation fails with wrong prefix."""
        assert validate_token_format("bear_demo_" + "a" * 48) is False

    def test_invalid_token_too_short(self):
        """Test validation fails with too short hex."""
        token = "panda_demo_" + "a" * 40  # Only 40 chars instead of 48
        assert validate_token_format(token) is False

    def test_invalid_token_too_long(self):
        """Test validation fails with too long hex."""
        token = "panda_demo_" + "a" * 50  # 50 chars instead of 48
        assert validate_token_format(token) is False

    def test_invalid_token_non_hex(self):
        """Test validation fails with non-hex characters."""
        token = "panda_demo_" + "g" * 48  # 'g' is not valid hex
        assert validate_token_format(token) is False

    def test_invalid_token_empty(self):
        """Test validation fails with empty string."""
        assert validate_token_format("") is False

    def test_invalid_token_none(self):
        """Test validation fails with None."""
        # validate_token_format expects a string
        try:
            result = validate_token_format(None)
            assert result is False
        except (TypeError, AttributeError):
            # Also acceptable - None cannot be matched against regex
            pass


class TestPandaDirectory:
    """Test .panda directory management."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_path = Path(tempfile.mkdtemp())
        yield temp_path
        shutil.rmtree(temp_path)

    @pytest.fixture
    def panda_dir(self, temp_dir):
        """Create a .panda directory in temp directory."""
        panda_path = temp_dir / PANDA_DIR_NAME
        panda_path.mkdir()
        (panda_path / CREDENTIALS_FILE).write_text("{}")
        (panda_path / CONFIG_FILE).write_text('{"provider": "local"}')
        (panda_path / KEYS_FILE).write_text('{"keys": []}')
        return panda_path

    def test_get_panda_dir(self, temp_dir):
        """Test get_panda_dir returns correct path."""
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = get_panda_dir()
            assert result == temp_dir / PANDA_DIR_NAME

    def test_credentials_exist_false(self, temp_dir):
        """Test credentials_exist returns False when missing."""
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            assert credentials_exist() is False

    def test_credentials_exist_true(self, panda_dir):
        """Test credentials_exist returns True when present."""
        with patch("pathlib.Path.cwd", return_value=panda_dir.parent):
            assert credentials_exist() is True

    def test_read_credentials_missing(self, temp_dir):
        """Test read_credentials returns None when file missing."""
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            assert read_credentials() is None

    def test_read_credentials_success(self, panda_dir):
        """Test read_credentials returns credentials object."""
        with patch("pathlib.Path.cwd", return_value=panda_dir.parent):
            creds = read_credentials()
            assert creds is not None
            assert isinstance(creds, PandaCredentials)

    def test_read_credentials_invalid_json(self, panda_dir):
        """Test read_credentials handles invalid JSON."""
        (panda_dir / CREDENTIALS_FILE).write_text("{invalid json")
        with patch("pathlib.Path.cwd", return_value=panda_dir.parent):
            assert read_credentials() is None

    def test_write_credentials_creates_directory(self, temp_dir):
        """Test write_credentials creates .panda directory."""
        creds = PandaCredentials(token="test-token", provider="local")
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            write_credentials(creds)
            assert (temp_dir / PANDA_DIR_NAME).exists()
            assert (temp_dir / PANDA_DIR_NAME / CREDENTIALS_FILE).exists()

    def test_write_credentials_file_contents(self, temp_dir):
        """Test write_credentials writes correct JSON."""
        creds = PandaCredentials(
            token="panda_demo_test",
            provider="infisical",
            default_kid="test-key"
        )
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            write_credentials(creds)
            content = (temp_dir / PANDA_DIR_NAME / CREDENTIALS_FILE).read_text()
            data = json.loads(content)
            assert data["token"] == "panda_demo_test"
            assert data["provider"] == "infisical"
            assert data["default_kid"] == "test-key"


class TestStatusCommand:
    """Test status command."""

    def test_status_not_initialized(self):
        """Test status when PANDA not initialized."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["status"])
            assert result.exit_code == 0
            assert "not initialized" in result.output

    def test_status_initialized(self, temp_dir):
        """Test status when PANDA is initialized."""
        creds = PandaCredentials(
            token="panda_demo_test",
            provider="infisical",
            default_kid="test-key",
            infisical_site_url="https://app.infisical.com",
            infisical_project_id="test-project",
            infisical_environment="dev"
        )
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            write_credentials(creds)
            runner = CliRunner()
            result = runner.invoke(cli, ["status"])
            assert result.exit_code == 0
            assert "Provider: infisical" in result.output
            assert "test-key" in result.output


class TestConfigCommand:
    """Test config command."""

    def test_config_not_initialized(self):
        """Test config when PANDA not initialized."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["config"])
            assert result.exit_code == 0
            assert "not initialized" in result.output

    def test_config_shows_details(self, temp_dir):
        """Test config shows configuration details."""
        creds = PandaCredentials(
            token="panda_demo_very_long_token_for_testing",
            provider="vault",
            vault_url="http://localhost:8200",
            vault_mount="secret"
        )
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            write_credentials(creds)
            runner = CliRunner()
            result = runner.invoke(cli, ["config"])
            assert result.exit_code == 0
            assert "Provider: vault" in result.output
            assert "http://localhost:8200" in result.output


class TestDeinitCommand:
    """Test deinit command."""

    def test_deinit_not_initialized(self):
        """Test deinit when PANDA not initialized."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["deinit"])
            assert result.exit_code == 0
            assert "not initialized" in result.output

    def test_deinit_with_force(self, temp_dir):
        """Test deinit with --force flag."""
        creds = PandaCredentials(token="test", provider="local")
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            write_credentials(creds)
            runner = CliRunner()
            result = runner.invoke(cli, ["deinit", "--force"])
            assert result.exit_code == 0
            assert "removed" in result.output.lower()
            assert not (temp_dir / PANDA_DIR_NAME).exists()

    def test_deinit_removes_env_entries(self, temp_dir):
        """Test deinit removes PANDA entries from .env."""
        # Create .env with PANDA entries
        env_file = temp_dir / ".env"
        env_file.write_text("PANDA_KEY_TEST=value\nOTHER_VAR=value\n")

        creds = PandaCredentials(token="test", provider="local")
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            write_credentials(creds)
            runner = CliRunner()
            result = runner.invoke(cli, ["deinit", "--force"])

        assert result.exit_code == 0
        # Check that .env was cleaned
        remaining_content = env_file.read_text()
        assert "PANDA_KEY_TEST" not in remaining_content
        assert "OTHER_VAR" in remaining_content

    def test_deinit_preserves_other_env_vars(self, temp_dir):
        """Test deinit preserves non-PANDA environment variables."""
        env_file = temp_dir / ".env"
        env_file.write_text(
            "PANDA_KEY_TEST=value\n"
            "DATABASE_URL=postgres://localhost\n"
            "API_KEY=secret\n"
        )

        creds = PandaCredentials(token="test", provider="local")
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            write_credentials(creds)
            runner = CliRunner()
            result = runner.invoke(cli, ["deinit", "--force"])

        remaining_content = env_file.read_text()
        assert "DATABASE_URL" in remaining_content
        assert "API_KEY" in remaining_content


class TestCommandFilesConstants:
    """Test command file constants."""

    def test_panda_dir_name(self):
        """Test PANDA_DIR_NAME constant."""
        assert PANDA_DIR_NAME == ".panda"

    def test_credentials_file(self):
        """Test CREDENTIALS_FILE constant."""
        assert CREDENTIALS_FILE == "credentials"

    def test_config_file(self):
        """Test CONFIG_FILE constant."""
        assert CONFIG_FILE == "config.json"

    def test_keys_file(self):
        """Test KEYS_FILE constant."""
        assert KEYS_FILE == "keys.json"
