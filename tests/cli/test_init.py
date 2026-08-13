"""
Unit tests for PANDA init command.

Tests cover the init wizard including token validation,
provider selection, and credential storage.
"""

import pytest
import json
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner

from panda.cli.commands import cli, PandaCredentials, PANDA_DIR_NAME


class TestInitCommand:
    """Test init command functionality."""

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

    def test_init_requires_token_or_prompt(self, runner, temp_dir):
        """Test init prompts for token if not provided."""
        # Use valid token format to avoid validation failure
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(cli, ["init"], input=f"{valid_token}\n1\nmy-key\n")
            assert result.exit_code == 0

    def test_init_with_valid_token(self, runner, temp_dir):
        """Test init with valid token format."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input="1\nmy-key\n"  # Select local, use default key name
            )
            assert result.exit_code == 0
            assert "Token format validated" in result.output

    def test_init_with_invalid_token_continues(self, runner, temp_dir):
        """Test init continues despite invalid token format if confirmed."""
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", "invalid-token"],
                input="y\n1\nmy-key\n"  # Continue anyway, select local
            )
            assert result.exit_code == 0
            # Should continue after warning

    def test_init_with_invalid_token_aborts(self, runner, temp_dir):
        """Test init aborts on invalid token if not confirmed."""
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", "invalid-token"],
                input="n\n"  # Don't continue
            )
            # Should exit without error
            assert result.exit_code == 0

    def test_init_detects_existing_installation(self, runner, temp_dir):
        """Test init detects existing .panda directory."""
        # Create existing .panda directory
        panda_dir = temp_dir / PANDA_DIR_NAME
        panda_dir.mkdir()
        (panda_dir / "credentials").write_text("{}")

        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(cli, ["init", "--token", "test-token"])
            assert result.exit_code == 0
            assert "already initialized" in result.output.lower()

    def test_init_with_reinit_flag(self, runner, temp_dir):
        """Test --reinit flag forces re-initialization."""
        # Create existing .panda directory
        panda_dir = temp_dir / PANDA_DIR_NAME
        panda_dir.mkdir()
        (panda_dir / "credentials").write_text("{}")

        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token, "--reinit"],
                input="1\ntest-key\n"
            )
            assert result.exit_code == 0
            # Should not show "already initialized" message

    def test_init_local_provider_selection(self, runner, temp_dir):
        """Test selecting local provider."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input="1\ntest-key\n"  # Select local (option 1)
            )
            assert result.exit_code == 0
            assert ".env" in result.output

    def test_init_vault_provider_selection(self, runner, temp_dir):
        """Test selecting Vault provider."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input=(
                    "2\n"  # Select Vault (option 2)
                    "http://localhost:8200\n"  # Vault URL
                    "test-token\n"  # Vault token
                    "secret\n"  # Mount path
                    "test-key\n"  # Default key ID
                )
            )
            assert result.exit_code == 0

    def test_init_infisical_provider_selection(self, runner, temp_dir):
        """Test selecting Infisical provider."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input=(
                    "3\n"  # Select Infisical (option 3)
                    "https://app.infisical.com\n"  # Site URL
                    "test-client-id\n"  # Client ID
                    "test-client-secret\n"  # Client Secret
                    "test-project-id\n"  # Project ID
                    "dev\n"  # Environment
                    "300\n"  # Cache TTL
                    "test-key\n"  # Default key ID
                )
            )
            assert result.exit_code == 0
            assert "infisical" in result.output.lower()

    def test_init_creates_panda_directory(self, runner, temp_dir):
        """Test init creates .panda directory."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input="1\ntest-key\n"
            )
            assert result.exit_code == 0
            assert (temp_dir / PANDA_DIR_NAME).exists()

    def test_init_creates_credentials_file(self, runner, temp_dir):
        """Test init creates credentials file."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input="1\ntest-key\n"
            )
            assert result.exit_code == 0
            creds_file = temp_dir / PANDA_DIR_NAME / "credentials"
            assert creds_file.exists()

    def test_init_credentials_contain_token(self, runner, temp_dir):
        """Test credentials file contains token."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input="1\ntest-key\n"
            )
            assert result.exit_code == 0
            creds_file = temp_dir / PANDA_DIR_NAME / "credentials"
            content = creds_file.read_text()
            data = json.loads(content)
            assert data["token"] == valid_token

    def test_init_credentials_contain_provider(self, runner, temp_dir):
        """Test credentials file contains provider type."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input="1\ntest-key\n"
            )
            assert result.exit_code == 0
            creds_file = temp_dir / PANDA_DIR_NAME / "credentials"
            content = creds_file.read_text()
            data = json.loads(content)
            assert "provider" in data

    def test_init_local_provider_creates_env_file(self, runner, temp_dir):
        """Test local provider creates .env file."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input="1\ntest-key\n"
            )
            assert result.exit_code == 0
            env_file = temp_dir / ".env"
            assert env_file.exists()
            content = env_file.read_text()
            assert "PANDA_KEY_TEST_KEY=" in content

    def test_init_local_provider_creates_env_example(self, runner, temp_dir):
        """Test local provider creates .env.example file."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input="1\ntest-key\n"
            )
            assert result.exit_code == 0
            env_example = temp_dir / ".env.example"
            assert env_example.exists()
            content = env_example.read_text()
            assert "PANDA_KEY_TEST_KEY=" in content
            # Example should have empty value
            assert "PANDA_KEY_TEST_KEY=\n" in content

    def test_init_normalizes_key_id(self, runner, temp_dir):
        """Test key ID is normalized for env var names."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input="1\nnik-key\n"  # Key with hyphen
            )
            assert result.exit_code == 0
            env_file = temp_dir / ".env"
            content = env_file.read_text()
            assert "PANDA_KEY_NIK_KEY=" in content

    def test_init_shows_success_message(self, runner, temp_dir):
        """Test init shows success message."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input="1\ntest-key\n"
            )
            assert result.exit_code == 0
            assert "initialized" in result.output.lower()
            assert "local" in result.output.lower()

    def test_init_shows_next_steps(self, runner, temp_dir):
        """Test init shows next steps."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input="1\ntest-key\n"
            )
            assert result.exit_code == 0
            assert "Next steps" in result.output or "next:" in result.output.lower()


class TestInitInfisicalSpecific:
    """Test Infisical-specific init functionality."""

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

    def test_infisical_credentials_stored(self, runner, temp_dir):
        """Test Infisical credentials are stored correctly."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input=(
                    "3\n"
                    "https://app.infisical.com\n"
                    "my-client-id\n"
                    "my-client-secret\n"
                    "proj-123\n"
                    "production\n"
                    "600\n"
                    "api-key\n"
                )
            )
            assert result.exit_code == 0
            creds_file = temp_dir / PANDA_DIR_NAME / "credentials"
            content = creds_file.read_text()
            data = json.loads(content)
            assert data["provider"] == "infisical"
            assert data["infisical_site_url"] == "https://app.infisical.com"
            assert data["infisical_client_id"] == "my-client-id"
            assert data["infisical_client_secret"] == "my-client-secret"
            assert data["infisical_project_id"] == "proj-123"
            assert data["infisical_environment"] == "production"
            assert data["infisical_cache_ttl"] == 600
            assert data["default_kid"] == "api-key"

    def test_infisical_default_values(self, runner, temp_dir):
        """Test Infisical init uses correct default values."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input=(
                    "3\n"  # Select Infisical
                    "\n"  # Default site URL (press Enter)
                    "client-id\n"
                    "client-secret\n"
                    "project-id\n"
                    "\n"  # Default environment (dev)
                    "\n"  # Default cache TTL (300)
                    "key-name\n"
                )
            )
            assert result.exit_code == 0
            creds_file = temp_dir / PANDA_DIR_NAME / "credentials"
            content = creds_file.read_text()
            data = json.loads(content)
            # Check defaults
            assert data["infisical_environment"] == "dev"
            assert data["infisical_cache_ttl"] == 300
            # Site URL might have trailing slash stripped
            assert "app.infisical.com" in data["infisical_site_url"]


class TestInitVaultSpecific:
    """Test Vault-specific init functionality."""

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

    def test_vault_credentials_stored(self, runner, temp_dir):
        """Test Vault credentials are stored correctly."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input=(
                    "2\n"  # Select Vault
                    "http://vault.example.com:8200\n"
                    "s.1234567890abcdef\n"
                    "kv\n"
                    "vault-key\n"
                )
            )
            assert result.exit_code == 0
            creds_file = temp_dir / PANDA_DIR_NAME / "credentials"
            content = creds_file.read_text()
            data = json.loads(content)
            assert data["provider"] == "vault"
            assert data["vault_url"] == "http://vault.example.com:8200"
            assert data["vault_token"] == "s.1234567890abcdef"
            assert data["vault_mount"] == "kv"
            assert data["default_kid"] == "vault-key"

    def test_vault_default_mount_path(self, runner, temp_dir):
        """Test Vault init uses default mount path."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input=(
                    "2\n"  # Select Vault
                    "http://localhost:8200\n"
                    "token\n"
                    "\n"  # Default mount path (secret)
                    "key-id\n"
                )
            )
            assert result.exit_code == 0
            creds_file = temp_dir / PANDA_DIR_NAME / "credentials"
            content = creds_file.read_text()
            data = json.loads(content)
            assert data["vault_mount"] == "secret"
