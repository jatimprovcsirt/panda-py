"""
Unit tests for PANDA init command.

Tests cover the init wizard including token validation,
provider selection, and credential storage.
"""

import pytest
import json
import os
import shutil
import subprocess
import sys
import tempfile
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
        """Test selecting Vault provider with AppRole (default)."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input=(
                    "2\n"  # Select Vault (option 2)
                    "http://localhost:8200\n"  # Vault URL
                    "\n"  # Default auth method (AppRole)
                    "test-role-id\n"  # Role ID
                    "test-secret-id\n"  # Secret ID
                    "\n"  # Default Token TTL
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
        """Test Vault credentials are stored correctly with AppRole (default)."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input=(
                    "2\n"  # Select Vault
                    "http://vault.example.com:8200\n"
                    "1\n"  # Select AppRole (default)
                    "role-id-123\n"
                    "secret-id-456\n"
                    "\n"  # Default Token TTL
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
            assert data["vault_auth_method"] == "approle"
            assert data["vault_role_id"] == "role-id-123"
            assert data["vault_secret_id"] == "secret-id-456"
            assert data["vault_mount"] == "kv"
            assert data["default_kid"] == "vault-key"

    def test_vault_default_mount_path(self, runner, temp_dir):
        """Test Vault init uses default mount path with AppRole."""
        valid_token = "panda_demo_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli,
                ["init", "--token", valid_token],
                input=(
                    "2\n"  # Select Vault
                    "http://localhost:8200\n"
                    "\n"  # Default auth method (AppRole)
                    "role-123\n"
                    "secret-456\n"
                    "\n"  # Default Token TTL
                    "\n"  # Default mount path (secret)
                    "key-id\n"
                )
            )
            assert result.exit_code == 0
            creds_file = temp_dir / PANDA_DIR_NAME / "credentials"
            content = creds_file.read_text()
            data = json.loads(content)
            assert data["vault_mount"] == "secret"


class TestInitQuickMode:
    """`panda init --quick` — the non-interactive path.

    This SDK had none until now. panda-node, panda-php and panda-go all had
    `--quick`, so the documented one-liner for a CI pipeline or a Dockerfile
    was wrong for exactly one of the four implementations — and the CLI guide
    papered over it by documenting a different command per language.

    Every test here closes stdin (`input=""`). A prompt on this path is a
    hang, not a failure, and a hang would be the wrong outcome in CI.
    """

    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def temp_dir(self):
        temp_path = Path(tempfile.mkdtemp())
        yield temp_path
        shutil.rmtree(temp_path)

    LIVE = "panda_live_" + "a" * 48

    def test_quick_writes_the_kid_it_was_given(self, runner, temp_dir):
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli, ["init", "--quick", "--token", self.LIVE, "--kid", "my-app-key-1"], input=""
            )

        assert result.exit_code == 0, result.output
        creds = json.loads((temp_dir / PANDA_DIR_NAME / "credentials").read_text())
        assert creds["default_kid"] == "my-app-key-1"
        assert "PANDA_KEY_MY_APP_KEY_1=" in (temp_dir / ".env").read_text()

    def test_quick_defaults_the_kid(self, runner, temp_dir):
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(cli, ["init", "--quick", "--token", self.LIVE], input="")

        assert result.exit_code == 0, result.output
        creds = json.loads((temp_dir / PANDA_DIR_NAME / "credentials").read_text())
        assert creds["default_kid"] == "default-key"

    def test_quick_prompts_for_nothing(self, runner, temp_dir):
        """No prompt may appear — the wizard's questions must be skipped."""
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(cli, ["init", "--quick", "--token", self.LIVE], input="")

        assert result.exit_code == 0, result.output
        for prompt in ("Select key provider", "Enter choice", "Default Key ID", "Vault URL"):
            assert prompt not in result.output, f"prompted with: {prompt}"

    def test_quick_without_a_token_fails(self, runner, temp_dir):
        """Fail closed rather than prompting — there is nobody to prompt."""
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(cli, ["init", "--quick"], input="")

        assert result.exit_code == 1
        assert "requires a token" in result.output

    def test_quick_with_a_malformed_token_fails_without_asking(self, runner, temp_dir):
        """The wizard offers "Continue anyway?". This path cannot, and must not hang."""
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(cli, ["init", "--quick", "--token", "nonsense"], input="")

        assert result.exit_code == 1
        assert "Continue anyway?" not in result.output
        assert "token gate failed" in result.output

    def test_quick_produces_no_configuration_when_the_gate_fails(self, runner, temp_dir):
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            runner.invoke(cli, ["init", "--quick", "--token", "nonsense"], input="")

        assert not (temp_dir / PANDA_DIR_NAME).exists()
        assert not (temp_dir / ".env").exists()

    def test_quick_reads_the_token_from_the_environment(self, runner, temp_dir, monkeypatch):
        """So the token need not appear in shell history or the process list."""
        monkeypatch.setenv("PANDA_ACCESS_TOKEN", self.LIVE)
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(cli, ["init", "--quick"], input="")

        assert result.exit_code == 0, result.output
        assert (temp_dir / PANDA_DIR_NAME / "credentials").exists()

    def test_quick_writes_the_same_files_as_the_wizard(self, runner, temp_dir):
        """Both paths share one writer, so a .env does not depend on the command."""
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            runner.invoke(cli, ["init", "--quick", "--token", self.LIVE, "--kid", "k"], input="")

        env = (temp_dir / ".env").read_text()
        assert "PANDA_KEY_K=" in env
        assert "PANDA_DEFAULT_KID=k" in env
        assert (temp_dir / ".env.example").exists()

    def test_quick_skip_key_gen_writes_no_key(self, runner, temp_dir):
        """`--skip-key-gen` exists in panda-php and panda-go; this SDK lacked it."""
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli, ["init", "--quick", "--token", self.LIVE, "--skip-key-gen"], input=""
            )

        assert result.exit_code == 0, result.output
        assert not (temp_dir / ".env").exists()
        # The identifier is still recorded — only the key generation is skipped.
        creds = json.loads((temp_dir / PANDA_DIR_NAME / "credentials").read_text())
        assert creds["default_kid"] == "default-key"


class TestInitSkipKeyGen:
    """`--skip-key-gen` applies to the wizard too, as it does in panda-go."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def temp_dir(self):
        temp_path = Path(tempfile.mkdtemp())
        yield temp_path
        shutil.rmtree(temp_path)

    def test_wizard_skip_key_gen_writes_no_key(self, runner, temp_dir):
        token = "panda_live_" + "a" * 48
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(
                cli, ["init", "--token", token, "--skip-key-gen"], input="1\nmy-key\n"
            )

        assert result.exit_code == 0, result.output
        assert not (temp_dir / ".env").exists()
        creds = json.loads((temp_dir / PANDA_DIR_NAME / "credentials").read_text())
        assert creds["default_kid"] == "my-key"


class TestConsoleEncoding:
    """The CLI must not die on a console that cannot encode its output.

    Almost every message it prints begins with a tick or a warning sign, and on
    a console whose encoding is cp1252, `print` raises UnicodeEncodeError and
    takes the command down with it. `panda init` failed at its first success
    line on a default Windows terminal — the platform these users are most
    likely to be on, running the workflow the documentation opens with.

    Reproduced here by forcing the encoding rather than by mocking, because the
    failure is in the encoding layer and a mock would replace the thing under
    test.
    """

    def test_init_survives_a_cp1252_stdout(self, tmp_path):
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "cp1252"
        env["PANDA_SKIP_ONLINE_VALIDATION"] = "1"
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")

        proc = subprocess.run(
            [
                sys.executable, "-m", "panda.cli.commands", "init",
                "--quick", "--token", "panda_live_" + "a" * 48, "--kid", "enc-check",
            ],
            cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
        )

        assert proc.returncode == 0, proc.stderr
        assert "UnicodeEncodeError" not in proc.stderr
        assert (tmp_path / ".env").exists(), "the command died partway through"


class TestQuickModeProviderSelection:
    """`--provider` on the non-interactive path.

    panda-node had this flag and the other three did not, so `init --quick`
    could only ever configure a local provider here: Vault and Infisical were
    unreachable from a CI pipeline in three of the four SDKs. The flag set is
    pinned in panda-spec/cli-flags.md and checked by verify_interop.js.

    The names of the variables are read from the module's own tuples rather
    than written out again. A test that restates the rule asserts its own copy
    of it — which is how the token pattern's second copy survived a whole
    release here.
    """

    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def temp_dir(self):
        temp_path = Path(tempfile.mkdtemp())
        yield temp_path
        shutil.rmtree(temp_path)

    @pytest.fixture(autouse=True)
    def clear_provider_env(self, monkeypatch):
        """Every provider variable removed, so each test states its own."""
        from panda.cli import commands

        for name in (
            commands._VAULT_REQUIRED_VARS
            + commands._VAULT_APPROLE_VARS
            + commands._INFISICAL_REQUIRED_VARS
        ):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv("PANDA_VAULT_AUTH_METHOD", raising=False)
        monkeypatch.delenv("PANDA_VAULT_TOKEN", raising=False)

    LIVE = "panda_live_" + "a" * 48

    def run(self, runner, temp_dir, argv):
        with patch("pathlib.Path.cwd", return_value=temp_dir):
            return runner.invoke(cli, argv, input="")

    def credentials(self, temp_dir):
        return json.loads((temp_dir / PANDA_DIR_NAME / "credentials").read_text())

    def test_vault_without_its_variables_fails_closed(self, runner, temp_dir, monkeypatch):
        """Fail closed, like the token gate: this path has nobody to ask."""
        result = self.run(
            runner, temp_dir, ["init", "--quick", "--token", self.LIVE, "--provider", "vault"]
        )

        assert result.exit_code == 1
        assert "PANDA_VAULT_URL" in result.output
        assert not (temp_dir / PANDA_DIR_NAME).exists(), "wrote a configuration it could not complete"

    def test_vault_records_an_approle_configuration(self, runner, temp_dir, monkeypatch):
        monkeypatch.setenv("PANDA_VAULT_URL", "https://vault.example:8200")
        monkeypatch.setenv("PANDA_VAULT_ROLE_ID", "role-1")
        monkeypatch.setenv("PANDA_VAULT_SECRET_ID", "secret-1")

        result = self.run(
            runner, temp_dir, ["init", "--quick", "--token", self.LIVE, "--provider", "vault"]
        )

        assert result.exit_code == 0, result.output
        creds = self.credentials(temp_dir)
        assert creds["provider"] == "vault"
        assert creds["vault_url"] == "https://vault.example:8200"
        assert creds["vault_auth_method"] == "approle"
        assert creds["vault_role_id"] == "role-1"
        assert creds["vault_secret_id"] == "secret-1"

    def test_vault_infers_token_authentication(self, runner, temp_dir, monkeypatch):
        """Asked for nothing it has already been told."""
        monkeypatch.setenv("PANDA_VAULT_URL", "https://vault.example:8200")
        monkeypatch.setenv("PANDA_VAULT_TOKEN", "hvs.token")

        result = self.run(
            runner, temp_dir, ["init", "--quick", "--token", self.LIVE, "--provider", "vault"]
        )

        assert result.exit_code == 0, result.output
        creds = self.credentials(temp_dir)
        assert creds["vault_auth_method"] == "token"
        assert creds["vault_token"] == "hvs.token"

    def test_vault_rejects_an_unknown_auth_method(self, runner, temp_dir, monkeypatch):
        monkeypatch.setenv("PANDA_VAULT_URL", "https://vault.example:8200")
        monkeypatch.setenv("PANDA_VAULT_AUTH_METHOD", "kerberos")

        result = self.run(
            runner, temp_dir, ["init", "--quick", "--token", self.LIVE, "--provider", "vault"]
        )

        assert result.exit_code == 1
        assert "kerberos" in result.output

    def test_infisical_names_every_variable_it_is_missing(self, runner, temp_dir):
        from panda.cli import commands

        result = self.run(
            runner, temp_dir, ["init", "--quick", "--token", self.LIVE, "--provider", "infisical"]
        )

        assert result.exit_code == 1
        for name in commands._INFISICAL_REQUIRED_VARS:
            assert name in result.output, f"{name} not named in the refusal"

    def test_infisical_records_its_configuration(self, runner, temp_dir, monkeypatch):
        monkeypatch.setenv("PANDA_INFISICAL_CLIENT_ID", "cid")
        monkeypatch.setenv("PANDA_INFISICAL_CLIENT_SECRET", "csecret")
        monkeypatch.setenv("PANDA_INFISICAL_PROJECT_ID", "pid")

        result = self.run(
            runner, temp_dir, ["init", "--quick", "--token", self.LIVE, "--provider", "infisical"]
        )

        assert result.exit_code == 0, result.output
        creds = self.credentials(temp_dir)
        assert creds["provider"] == "infisical"
        assert creds["infisical_project_id"] == "pid"
        assert creds["infisical_environment"] == "dev", "the safe default was not applied"

    def test_a_non_local_provider_writes_no_local_key(self, runner, temp_dir, monkeypatch):
        """A key written 'for' a secret manager is a second key nothing reads."""
        monkeypatch.setenv("PANDA_VAULT_URL", "https://vault.example:8200")
        monkeypatch.setenv("PANDA_VAULT_TOKEN", "hvs.token")

        self.run(runner, temp_dir, ["init", "--quick", "--token", self.LIVE, "--provider", "vault"])

        env_file = temp_dir / ".env"
        assert not env_file.exists() or "PANDA_KEY_" not in env_file.read_text()

    def test_provider_alone_is_non_interactive(self, runner, temp_dir, monkeypatch):
        """Naming a provider cannot be handed to a wizard, which would ask anyway."""
        monkeypatch.setenv("PANDA_VAULT_URL", "https://vault.example:8200")
        monkeypatch.setenv("PANDA_VAULT_TOKEN", "hvs.token")

        result = self.run(
            runner, temp_dir, ["init", "--token", self.LIVE, "--kid", "k1", "--provider", "vault"]
        )

        assert result.exit_code == 0, result.output
        for prompt in ("Select key provider", "Enter choice", "Vault URL", "Default Key ID"):
            assert prompt not in result.output, f"prompted with: {prompt}"

    def test_provider_local_still_writes_a_key(self, runner, temp_dir):
        result = self.run(
            runner, temp_dir, ["init", "--quick", "--token", self.LIVE, "--kid", "k1",
                               "--provider", "local"]
        )

        assert result.exit_code == 0, result.output
        assert "PANDA_KEY_K1=" in (temp_dir / ".env").read_text()

    def test_no_provider_still_means_local(self, runner, temp_dir):
        """The default is unchanged for every existing caller."""
        result = self.run(runner, temp_dir, ["init", "--quick", "--token", self.LIVE, "--kid", "k1"])

        assert result.exit_code == 0, result.output
        assert self.credentials(temp_dir)["provider"] == "local"
        assert "PANDA_KEY_K1=" in (temp_dir / ".env").read_text()

    def test_generate_overrides_the_recorded_provider(self, runner, temp_dir, monkeypatch):
        self.run(runner, temp_dir, ["init", "--quick", "--token", self.LIVE, "--kid", "k1"])

        with patch("pathlib.Path.cwd", return_value=temp_dir):
            result = runner.invoke(cli, ["generate", "k2", "--provider", "vault"], input="")

        assert result.exit_code == 0, result.output
        assert "vault kv put" in result.output
        assert "PANDA_KEY_K2" not in (temp_dir / ".env").read_text(), "stored locally anyway"
