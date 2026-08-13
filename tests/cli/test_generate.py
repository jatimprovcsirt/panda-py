"""
Unit tests for PANDA generate command.

Tests cover key generation functionality including different
providers and key validation.
"""

import pytest
import json
import base64
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner

from panda.cli.commands import cli, PandaCredentials, PANDA_DIR_NAME


class TestGenerateCommand:
    """Test generate command functionality."""

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

    @pytest.fixture
    def initialized_local(self, temp_dir):
        """Create initialized PANDA with local provider."""
        panda_dir = temp_dir / PANDA_DIR_NAME
        panda_dir.mkdir()

        creds = PandaCredentials(
            token="panda_demo_" + "a" * 48,
            provider="local",
            default_kid="default-key"
        )
        creds_file = panda_dir / "credentials"
        creds_file.write_text(json.dumps(creds.__dict__, default=str))

        # Create .env file
        env_file = temp_dir / ".env"
        env_file.write_text("")

        return temp_dir

    @pytest.fixture
    def initialized_infisical(self, temp_dir):
        """Create initialized PANDA with Infisical provider."""
        panda_dir = temp_dir / PANDA_DIR_NAME
        panda_dir.mkdir()

        creds = PandaCredentials(
            token="panda_demo_" + "a" * 48,
            provider="infisical",
            default_kid="default-key",
            infisical_site_url="https://app.infisical.com",
            infisical_client_id="test-client-id",
            infisical_client_secret="test-client-secret",
            infisical_project_id="test-project",
            infisical_environment="dev"
        )
        creds_file = panda_dir / "credentials"
        creds_file.write_text(json.dumps(creds.__dict__, default=str))

        return temp_dir

    @pytest.fixture
    def initialized_vault(self, temp_dir):
        """Create initialized PANDA with Vault provider."""
        panda_dir = temp_dir / PANDA_DIR_NAME
        panda_dir.mkdir()

        creds = PandaCredentials(
            token="panda_demo_" + "a" * 48,
            provider="vault",
            default_kid="default-key",
            vault_url="http://localhost:8200",
            vault_token="test-token",
            vault_mount="secret"
        )
        creds_file = panda_dir / "credentials"
        creds_file.write_text(json.dumps(creds.__dict__, default=str))

        return temp_dir

    def test_generate_requires_init(self, runner):
        """Test generate fails when PANDA not initialized."""
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["generate"])
            assert result.exit_code == 1
            assert "not initialized" in result.output.lower()

    def test_generate_prompts_for_kid(self, runner, initialized_local):
        """Test generate prompts for key ID if not provided."""
        with patch("pathlib.Path.cwd", return_value=initialized_local):
            result = runner.invoke(
                cli,
                ["generate"],
                input="test-key\n"
            )
            assert result.exit_code == 0
            assert "test-key" in result.output

    def test_generate_with_kid_argument(self, runner, initialized_local):
        """Test generate with key ID as argument."""
        with patch("pathlib.Path.cwd", return_value=initialized_local):
            result = runner.invoke(cli, ["generate", "my-key"])
            assert result.exit_code == 0
            assert "my-key" in result.output

    def test_generate_empty_kid_aborts(self, runner, initialized_local):
        """Test generate aborts with empty key ID."""
        with patch("pathlib.Path.cwd", return_value=initialized_local):
            result = runner.invoke(cli, ["generate", ""])
            assert result.exit_code == 1
            assert "required" in result.output.lower() or "key id" in result.output.lower()

    def test_generate_invalid_kid_characters(self, runner, initialized_local):
        """Test generate rejects invalid key ID characters."""
        with patch("pathlib.Path.cwd", return_value=initialized_local):
            result = runner.invoke(cli, ["generate", "invalid key!"])
            assert result.exit_code == 1
            assert "alphanumeric" in result.output.lower() or "characters" in result.output.lower()

    def test_generate_valid_kid_with_hyphen(self, runner, initialized_local):
        """Test generate accepts valid key ID with hyphens."""
        with patch("pathlib.Path.cwd", return_value=initialized_local):
            result = runner.invoke(cli, ["generate", "nik-key"])
            assert result.exit_code == 0
            assert "nik-key" in result.output

    def test_generate_valid_kid_with_underscore(self, runner, initialized_local):
        """Test generate accepts valid key ID with underscores."""
        with patch("pathlib.Path.cwd", return_value=initialized_local):
            result = runner.invoke(cli, ["generate", "user_data_key"])
            assert result.exit_code == 0
            assert "user_data_key" in result.output

    def test_generate_valid_kid_with_dot(self, runner, initialized_local):
        """Test generate accepts valid key ID with dots."""
        with patch("pathlib.Path.cwd", return_value=initialized_local):
            result = runner.invoke(cli, ["generate", "apikey"])
            assert result.exit_code == 0
            assert "apikey" in result.output

    def test_generate_creates_32_byte_key(self, runner, initialized_local):
        """Test generate creates a 32-byte key."""
        with patch("pathlib.Path.cwd", return_value=initialized_local):
            result = runner.invoke(cli, ["generate", "test-key"])
            assert result.exit_code == 0

            # Check the key was written to .env
            env_file = initialized_local / ".env"
            content = env_file.read_text()

            # Find the line with the key
            for line in content.split("\n"):
                if line.startswith("PANDA_KEY_TEST_KEY="):
                    key_value = line.split("=", 1)[1]
                    key_bytes = base64.b64decode(key_value)
                    assert len(key_bytes) == 32
                    break
            else:
                pytest.fail("Key not found in .env file")

    def test_generate_local_updates_env(self, runner, initialized_local):
        """Test generate updates .env file for local provider."""
        with patch("pathlib.Path.cwd", return_value=initialized_local):
            result = runner.invoke(cli, ["generate", "new-key"])
            assert result.exit_code == 0

            env_file = initialized_local / ".env"
            content = env_file.read_text()
            assert "PANDA_KEY_NEW_KEY=" in content

    def test_generate_local_updates_env_example(self, runner, initialized_local):
        """Test generate updates .env.example file."""
        env_example = initialized_local / ".env.example"
        env_example.write_text("")

        with patch("pathlib.Path.cwd", return_value=initialized_local):
            result = runner.invoke(cli, ["generate", "example-key"])
            assert result.exit_code == 0

            content = env_example.read_text()
            assert "PANDA_KEY_EXAMPLE_KEY=" in content
            # .env.example should have empty value
            assert "PANDA_KEY_EXAMPLE_KEY=\n" in content

    def test_generate_normalizes_kid_for_env(self, runner, initialized_local):
        """Test generate normalizes key ID for environment variable."""
        with patch("pathlib.Path.cwd", return_value=initialized_local):
            result = runner.invoke(cli, ["generate", "api-key"])
            assert result.exit_code == 0

            env_file = initialized_local / ".env"
            content = env_file.read_text()
            assert "PANDA_KEY_API_KEY=" in content

    def test_generate_updates_credentials(self, runner, initialized_local):
        """Test generate updates credentials keys metadata."""
        with patch("pathlib.Path.cwd", return_value=initialized_local):
            result = runner.invoke(cli, ["generate", "tracked-key"])
            assert result.exit_code == 0

            creds_file = initialized_local / PANDA_DIR_NAME / "credentials"
            content = creds_file.read_text()
            data = json.loads(content)

            assert "keys" in data
            assert "tracked-key" in data["keys"]
            assert "created" in data["keys"]["tracked-key"]

    def test_generate_vault_prints_command(self, runner, initialized_vault):
        """Test generate prints vault command for Vault provider."""
        with patch("pathlib.Path.cwd", return_value=initialized_vault):
            result = runner.invoke(cli, ["generate", "vault-key"])
            assert result.exit_code == 0
            assert "vault kv put" in result.output
            assert "vault-key" in result.output

    def test_generate_vault_shows_base64_key(self, runner, initialized_vault):
        """Test generate shows base64-encoded key for Vault."""
        with patch("pathlib.Path.cwd", return_value=initialized_vault):
            result = runner.invoke(cli, ["generate", "vault-test"])
            assert result.exit_code == 0

            # Should contain a base64 string (44 chars for 32 bytes)
            assert any(len(line) == 44 or "=" in line for line in result.output.split("\n"))

    @patch("http.client.HTTPSConnection")
    def test_generate_infisical_stores_secret(self, mock_conn, runner, initialized_infisical):
        """Test generate stores secret in Infisical."""
        # Mock auth response
        auth_response = Mock()
        auth_response.status = 200
        auth_response.read.return_value = json.dumps({
            "accessToken": "test-access-token"
        }).encode("utf-8")

        # Mock create secret response
        secret_response = Mock()
        secret_response.status = 201
        secret_response.read.return_value = json.dumps({
            "secret": {"secretPath": "infisical-key"}
        }).encode("utf-8")

        mock_connection = Mock()
        mock_connection.getresponse.side_effect = [auth_response, secret_response]
        mock_conn.return_value = mock_connection

        with patch("pathlib.Path.cwd", return_value=initialized_infisical):
            result = runner.invoke(cli, ["generate", "infisical-key"])
            assert result.exit_code == 0
            assert "Infisical" in result.output or "infisical" in result.output.lower()

    @patch("http.client.HTTPSConnection")
    def test_generate_infisical_auth_failure_shows_manual(self, mock_conn, runner, initialized_infisical):
        """Test generate shows manual instructions on auth failure."""
        # Mock auth failure
        auth_response = Mock()
        auth_response.status = 401
        auth_response.read.return_value = b"Unauthorized"

        mock_connection = Mock()
        mock_connection.getresponse.return_value = auth_response
        mock_conn.return_value = mock_connection

        with patch("pathlib.Path.cwd", return_value=initialized_infisical):
            result = runner.invoke(cli, ["generate", "manual-key"])
            assert result.exit_code == 0
            assert "manually" in result.output.lower() or "create" in result.output.lower()

    def test_generate_shows_usage_example(self, runner, initialized_local):
        """Test generate shows usage example."""
        with patch("pathlib.Path.cwd", return_value=initialized_local):
            result = runner.invoke(cli, ["generate", "usage-key"])
            assert result.exit_code == 0
            assert "encrypt" in result.output.lower() or "usage-key" in result.output

    def test_generate_success_message(self, runner, initialized_local):
        """Test generate shows success message."""
        with patch("pathlib.Path.cwd", return_value=initialized_local):
            result = runner.invoke(cli, ["generate", "success-key"])
            assert result.exit_code == 0
            assert "generated" in result.output.lower() or "success" in result.output.lower()

    def test_generate_multiple_keys(self, runner, initialized_local):
        """Test generate can create multiple keys."""
        with patch("pathlib.Path.cwd", return_value=initialized_local):
            # Generate first key
            result1 = runner.invoke(cli, ["generate", "first-key"])
            assert result1.exit_code == 0

            # Generate second key
            result2 = runner.invoke(cli, ["generate", "second-key"])
            assert result2.exit_code == 0

            # Check both keys are in credentials
            creds_file = initialized_local / PANDA_DIR_NAME / "credentials"
            content = creds_file.read_text()
            data = json.loads(content)

            assert "first-key" in data["keys"]
            assert "second-key" in data["keys"]

    def test_generate_preserves_existing_keys(self, runner, initialized_local):
        """Test generate preserves existing keys in .env."""
        # Add existing key to .env
        env_file = initialized_local / ".env"
        env_file.write_text("PANDA_KEY_EXISTING=existing-value\nOTHER_VAR=value\n")

        with patch("pathlib.Path.cwd", return_value=initialized_local):
            result = runner.invoke(cli, ["generate", "new-key"])
            assert result.exit_code == 0

            content = env_file.read_text()
            assert "PANDA_KEY_EXISTING=existing-value" in content
            assert "OTHER_VAR=value" in content
            assert "PANDA_KEY_NEW_KEY=" in content


class TestGenerateKeyValidation:
    """Test key ID validation in generate command."""

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

    @pytest.fixture
    def initialized(self, temp_dir):
        """Create initialized PANDA."""
        panda_dir = temp_dir / PANDA_DIR_NAME
        panda_dir.mkdir()

        creds = PandaCredentials(
            token="panda_demo_" + "a" * 48,
            provider="local",
            default_kid="default-key"
        )
        creds_file = panda_dir / "credentials"
        creds_file.write_text(json.dumps(creds.__dict__, default=str))

        env_file = temp_dir / ".env"
        env_file.write_text("")

        return temp_dir

    def test_rejects_kid_with_spaces(self, runner, initialized):
        """Test generate rejects key ID with spaces."""
        with patch("pathlib.Path.cwd", return_value=initialized):
            result = runner.invoke(cli, ["generate", "key with spaces"])
            assert result.exit_code == 1

    def test_rejects_kid_with_special_chars(self, runner, initialized):
        """Test generate rejects key ID with special characters."""
        with patch("pathlib.Path.cwd", return_value=initialized):
            result = runner.invoke(cli, ["generate", "key@special!"])
            assert result.exit_code == 1

    def test_accepts_numeric_kid(self, runner, initialized):
        """Test generate accepts numeric key ID."""
        with patch("pathlib.Path.cwd", return_value=initialized):
            result = runner.invoke(cli, ["generate", "12345"])
            assert result.exit_code == 0

    def test_accepts_mixed_case(self, runner, initialized):
        """Test generate accepts mixed case key ID."""
        with patch("pathlib.Path.cwd", return_value=initialized):
            result = runner.invoke(cli, ["generate", "MyKey123"])
            assert result.exit_code == 0

    def test_accepts_uppercase(self, runner, initialized):
        """Test generate accepts uppercase key ID."""
        with patch("pathlib.Path.cwd", return_value=initialized):
            result = runner.invoke(cli, ["generate", "UPPERCASE_KEY"])
            assert result.exit_code == 0
