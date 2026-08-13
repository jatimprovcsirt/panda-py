"""
Unit tests for KeyProvider implementations.

Tests cover LocalKeyProvider, VaultKeyProvider, and InfisicalKeyProvider
including authentication, key retrieval, caching, and error handling.
"""

import pytest
import base64
import time
import json
from unittest.mock import Mock, patch, MagicMock
from urllib.parse import urlparse
import http.client

from panda.crypto.keys import (
    LocalKeyProvider,
    VaultKeyProvider,
    InfisicalKeyProvider,
    create_key_provider,
    KeyNotFoundError,
    CryptoProviderError
)

# Valid 32-byte test key
TEST_KEY_32_BYTES = b"this is a 32-byte key for testing!!"
TEST_KEY_BASE64 = base64.b64encode(TEST_KEY_32_BYTES).decode("ascii")


class TestLocalKeyProvider:
    """Test LocalKeyProvider implementation."""

    def test_initial_keys_are_loaded(self):
        """Test that initial keys are loaded into the provider."""
        key = TEST_KEY_32_BYTES
        provider = LocalKeyProvider(initial_keys={"test-key": key})
        assert provider.get_key("test-key") == key

    def test_set_key_stores_in_memory(self):
        """Test set_key method stores key in memory."""
        provider = LocalKeyProvider()
        key = TEST_KEY_32_BYTES
        provider.set_key("my-key", key)
        assert provider.get_key("my-key") == key

    def test_set_key_validates_length(self):
        """Test that set_key validates key length."""
        provider = LocalKeyProvider()
        with pytest.raises(ValueError, match="Key must be exactly 32 bytes"):
            provider.set_key("short", b"too-short")

    def test_get_key_from_environment_variable(self, monkeypatch):
        """Test retrieving key from environment variable."""
        key = TEST_KEY_BASE64
        monkeypatch.setenv("PANDA_KEY_TEST_KEY", key)
        monkeypatch.delenv("PANDA_KEY_TEST-KEY", raising=False)

        provider = LocalKeyProvider()
        retrieved_key = provider.get_key("test-key")
        assert retrieved_key == base64.b64decode(key)

    def test_get_key_normalized_kid(self, monkeypatch):
        """Test KID normalization (hyphens to underscores)."""
        key = TEST_KEY_BASE64
        monkeypatch.setenv("PANDA_KEY_MY_SPECIAL_KEY", key)

        provider = LocalKeyProvider()
        # Should find normalized version
        retrieved_key = provider.get_key("my-special-key")
        assert retrieved_key == base64.b64decode(key)

    def test_get_key_missing_raises_error(self):
        """Test that missing key raises KeyNotFoundError."""
        provider = LocalKeyProvider()
        with pytest.raises(KeyNotFoundError, match="Encryption key not found"):
            provider.get_key("nonexistent-key")

    def test_get_key_invalid_base64_raises_error(self, monkeypatch):
        """Test that invalid base64 raises KeyNotFoundError."""
        monkeypatch.setenv("PANDA_KEY_BAD_KEY", "not-valid-base64!!!")

        provider = LocalKeyProvider()
        with pytest.raises(KeyNotFoundError, match="Invalid base64 encoding"):
            provider.get_key("bad-key")

    def test_get_key_wrong_length_raises_error(self, monkeypatch):
        """Test that wrong key length raises KeyNotFoundError."""
        short_key = base64.b64encode(b"short").decode("ascii")
        monkeypatch.setenv("PANDA_KEY_SHORT_KEY", short_key)

        provider = LocalKeyProvider()
        with pytest.raises(KeyNotFoundError, match="Invalid key format"):
            provider.get_key("short-key")

    def test_get_key_caches_after_retrieval(self, monkeypatch):
        """Test that keys are cached after retrieval from env."""
        key = TEST_KEY_BASE64
        monkeypatch.setenv("PANDA_KEY_CACHE_TEST", key)

        provider = LocalKeyProvider()
        # First call reads from env
        first_key = provider.get_key("cache-test")
        # Delete env var
        monkeypatch.delenv("PANDA_KEY_CACHE_TEST")
        # Second call should use cache
        second_key = provider.get_key("cache-test")

        assert first_key == second_key


class TestVaultKeyProvider:
    """Test VaultKeyProvider implementation."""

    @pytest.fixture
    def vault_config(self):
        """Fixture for Vault configuration."""
        return {
            "vault_url": "http://localhost:8200",
            "vault_token": "test-token",
            "mount_path": "secret"
        }

    @pytest.fixture
    def vault_provider(self, vault_config):
        """Fixture for Vault provider."""
        return VaultKeyProvider(**vault_config)

    def test_initialization(self, vault_config):
        """Test Vault provider initialization."""
        provider = VaultKeyProvider(**vault_config)
        assert provider.vault_url == "http://localhost:8200"
        assert provider.vault_token == "test-token"
        assert provider.mount_path == "secret"
        assert provider._cache == {}

    def test_url_trailing_slash_removed(self):
        """Test that trailing slash is removed from URL."""
        provider = VaultKeyProvider(
            vault_url="http://localhost:8200/",
            vault_token="test"
        )
        assert provider.vault_url == "http://localhost:8200"

    def test_mount_path_slashes_removed(self):
        """Test that slashes are removed from mount path."""
        provider = VaultKeyProvider(
            vault_url="http://localhost:8200",
            vault_token="test",
            mount_path="/secret/"
        )
        assert provider.mount_path == "secret"

    @patch("http.client.HTTPConnection")
    def test_get_key_success(self, mock_conn, vault_provider):
        """Test successful key retrieval from Vault."""
        # Setup mock response
        mock_response = Mock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "data": {
                "data": {
                    "key": TEST_KEY_BASE64
                }
            }
        }).encode("utf-8")

        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_conn.return_value = mock_connection

        key = vault_provider.get_key("test-key")
        assert len(key) == 32
        assert "test-key" in vault_provider._cache

    @patch("http.client.HTTPConnection")
    def test_get_key_uses_cache(self, mock_conn, vault_provider):
        """Test that cached keys are returned without API call."""
        # Pre-populate cache
        cached_key = TEST_KEY_32_BYTES
        vault_provider._cache["cached-key"] = cached_key

        key = vault_provider.get_key("cached-key")
        assert key == cached_key
        # Verify no HTTP call was made
        mock_conn.assert_not_called()

    @patch("http.client.HTTPConnection")
    def test_get_key_missing_secret(self, mock_conn, vault_provider):
        """Test handling of missing secret in Vault."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "data": {"data": {}}
        }).encode("utf-8")

        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_conn.return_value = mock_connection

        with pytest.raises(KeyNotFoundError, match="not found in Vault response data structure"):
            vault_provider.get_key("missing-key")

    @patch("http.client.HTTPConnection")
    def test_get_key_http_error(self, mock_conn, vault_provider):
        """Test handling of HTTP error response."""
        mock_response = Mock()
        mock_response.status = 404
        mock_response.read.return_value = b"Not found"

        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_conn.return_value = mock_connection

        with pytest.raises(KeyNotFoundError, match="HTTP status code: 404"):
            vault_provider.get_key("test-key")

    @patch("http.client.HTTPConnection")
    def test_get_key_invalid_base64(self, mock_conn, vault_provider):
        """Test handling of invalid base64 in response."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "data": {"data": {"key": "not-valid-base64!!!"}}
        }).encode("utf-8")

        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_conn.return_value = mock_connection

        with pytest.raises(KeyNotFoundError, match="Invalid base64 encoding"):
            vault_provider.get_key("test-key")

    @patch("http.client.HTTPConnection")
    def test_get_key_wrong_key_length(self, mock_conn, vault_provider):
        """Test handling of wrong key length in response."""
        short_key = base64.b64encode(b"short").decode("ascii")
        mock_response = Mock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "data": {"data": {"key": short_key}}
        }).encode("utf-8")

        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_conn.return_value = mock_connection

        with pytest.raises(KeyNotFoundError, match="not a valid 32-byte"):
            vault_provider.get_key("test-key")


class TestInfisicalKeyProvider:
    """Test InfisicalKeyProvider implementation."""

    @pytest.fixture
    def infisical_config(self):
        """Fixture for Infisical configuration."""
        return {
            "site_url": "https://app.infisical.com",
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "project_id": "test-project-id",
            "environment": "dev",
            "cache_ttl": 300
        }

    @pytest.fixture
    def infisical_provider(self, infisical_config):
        """Fixture for Infisical provider."""
        return InfisicalKeyProvider(**infisical_config)

    def test_initialization(self, infisical_config):
        """Test Infisical provider initialization."""
        provider = InfisicalKeyProvider(**infisical_config)
        assert provider.site_url == "https://app.infisical.com"
        assert provider.client_id == "test-client-id"
        assert provider.client_secret == "test-client-secret"
        assert provider.project_id == "test-project-id"
        assert provider.environment == "dev"
        assert provider.cache_ttl == 300
        assert provider._cache == {}
        assert provider._access_token is None

    def test_url_trailing_slash_removed(self):
        """Test that trailing slash is removed from URL."""
        provider = InfisicalKeyProvider(
            site_url="https://app.infisical.com/",
            client_id="test",
            client_secret="test",
            project_id="test",
            environment="dev"
        )
        assert provider.site_url == "https://app.infisical.com"

    @patch("http.client.HTTPSConnection")
    def test_ensure_authenticated(self, mock_conn, infisical_provider):
        """Test successful authentication."""
        # Setup mock response for auth
        mock_response = Mock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "accessToken": "test-access-token"
        }).encode("utf-8")

        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_conn.return_value = mock_connection

        infisical_provider._ensure_authenticated()
        assert infisical_provider._access_token == "test-access-token"
        assert infisical_provider._token_expires > time.time()

    @patch("http.client.HTTPSConnection")
    def test_ensure_authenticated_uses_cached_token(self, mock_conn, infisical_provider):
        """Test that cached token is used if still valid."""
        infisical_provider._access_token = "cached-token"
        infisical_provider._token_expires = time.time() + 600  # 10 minutes from now

        infisical_provider._ensure_authenticated()
        assert infisical_provider._access_token == "cached-token"
        # Verify no HTTP call was made
        mock_conn.assert_not_called()

    @patch("http.client.HTTPSConnection")
    def test_ensure_authentication_failure(self, mock_conn, infisical_provider):
        """Test handling of authentication failure."""
        mock_response = Mock()
        mock_response.status = 401
        mock_response.read.return_value = b"Unauthorized"

        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_conn.return_value = mock_connection

        with pytest.raises(CryptoProviderError, match="authentication failed"):
            infisical_provider._ensure_authenticated()

    @patch("http.client.HTTPSConnection")
    def test_ensure_authentication_missing_token(self, mock_conn, infisical_provider):
        """Test handling of missing access token in response."""
        mock_response = Mock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "notToken": "missing field"
        }).encode("utf-8")

        mock_connection = Mock()
        mock_connection.getresponse.return_value = mock_response
        mock_conn.return_value = mock_connection

        with pytest.raises(CryptoProviderError, match="No access token"):
            infisical_provider._ensure_authenticated()

    @patch("http.client.HTTPSConnection")
    def test_get_key_success(self, mock_conn, infisical_provider):
        """Test successful key retrieval from Infisical."""
        # Setup auth response
        auth_response = Mock()
        auth_response.status = 200
        auth_response.read.return_value = json.dumps({
            "accessToken": "test-access-token"
        }).encode("utf-8")

        # Setup secret retrieval response
        secret_response = Mock()
        secret_response.status = 200
        secret_response.read.return_value = json.dumps({
            "secretValue": TEST_KEY_BASE64
        }).encode("utf-8")

        mock_connection = Mock()
        mock_connection.getresponse.side_effect = [auth_response, secret_response]
        mock_conn.return_value = mock_connection

        key = infisical_provider.get_key("test-key")
        assert len(key) == 32
        assert "test-key" in infisical_provider._cache

    @patch("http.client.HTTPSConnection")
    def test_get_key_uses_cache(self, mock_conn, infisical_provider):
        """Test that cached keys are returned without API call."""
        # Pre-populate cache with unexpired key
        cached_key = TEST_KEY_32_BYTES
        infisical_provider._cache["cached-key"] = (cached_key, time.time() + 300)

        key = infisical_provider.get_key("cached-key")
        assert key == cached_key
        # Verify no HTTP call was made
        mock_conn.assert_not_called()

    @patch("http.client.HTTPSConnection")
    def test_get_key_cache_expiry(self, mock_conn, infisical_provider):
        """Test that expired cache triggers refresh."""
        # Pre-populate cache with expired key
        cached_key = TEST_KEY_32_BYTES
        infisical_provider._cache["expired-key"] = (cached_key, time.time() - 100)

        # Setup auth and secret responses
        auth_response = Mock()
        auth_response.status = 200
        auth_response.read.return_value = json.dumps({
            "accessToken": "test-access-token"
        }).encode("utf-8")

        secret_response = Mock()
        secret_response.status = 200
        different_key = base64.b64encode(b"different 32-byte key for cache test!!").decode("ascii")
        secret_response.read.return_value = json.dumps({
            "secretValue": different_key
        }).encode("utf-8")

        mock_connection = Mock()
        mock_connection.getresponse.side_effect = [auth_response, secret_response]
        mock_conn.return_value = mock_connection

        key = infisical_provider.get_key("expired-key")
        assert key != cached_key  # Should get fresh key

    @patch("http.client.HTTPSConnection")
    def test_get_key_missing_secret(self, mock_conn, infisical_provider):
        """Test handling of missing secret in Infisical."""
        # Setup auth
        auth_response = Mock()
        auth_response.status = 200
        auth_response.read.return_value = json.dumps({
            "accessToken": "test-access-token"
        }).encode("utf-8")

        # Setup secret response with missing secretValue
        secret_response = Mock()
        secret_response.status = 200
        secret_response.read.return_value = json.dumps({
            "notSecretValue": "missing"
        }).encode("utf-8")

        mock_connection = Mock()
        mock_connection.getresponse.side_effect = [auth_response, secret_response]
        mock_conn.return_value = mock_connection

        with pytest.raises(KeyNotFoundError, match="not found in Infisical response"):
            infisical_provider.get_key("missing-key")

    @patch("http.client.HTTPSConnection")
    def test_get_key_http_error(self, mock_conn, infisical_provider):
        """Test handling of HTTP error response."""
        # Setup auth
        auth_response = Mock()
        auth_response.status = 200
        auth_response.read.return_value = json.dumps({
            "accessToken": "test-access-token"
        }).encode("utf-8")

        # Setup error response
        secret_response = Mock()
        secret_response.status = 404
        secret_response.read.return_value = b"Not found"

        mock_connection = Mock()
        mock_connection.getresponse.side_effect = [auth_response, secret_response]
        mock_conn.return_value = mock_connection

        with pytest.raises(KeyNotFoundError, match="HTTP 404"):
            infisical_provider.get_key("test-key")

    @patch("http.client.HTTPSConnection")
    def test_get_key_invalid_base64(self, mock_conn, infisical_provider):
        """Test handling of invalid base64 in response."""
        # Setup auth
        auth_response = Mock()
        auth_response.status = 200
        auth_response.read.return_value = json.dumps({
            "accessToken": "test-access-token"
        }).encode("utf-8")

        # Setup invalid base64 response
        secret_response = Mock()
        secret_response.status = 200
        secret_response.read.return_value = json.dumps({
            "secretValue": "not-valid-base64!!!"
        }).encode("utf-8")

        mock_connection = Mock()
        mock_connection.getresponse.side_effect = [auth_response, secret_response]
        mock_conn.return_value = mock_connection

        with pytest.raises(KeyNotFoundError, match="Invalid base64 encoding"):
            infisical_provider.get_key("test-key")

    @patch("http.client.HTTPSConnection")
    def test_get_key_wrong_key_length(self, mock_conn, infisical_provider):
        """Test handling of wrong key length in response."""
        # Setup auth
        auth_response = Mock()
        auth_response.status = 200
        auth_response.read.return_value = json.dumps({
            "accessToken": "test-access-token"
        }).encode("utf-8")

        # Setup short key response
        short_key = base64.b64encode(b"short").decode("ascii")
        secret_response = Mock()
        secret_response.status = 200
        secret_response.read.return_value = json.dumps({
            "secretValue": short_key
        }).encode("utf-8")

        mock_connection = Mock()
        mock_connection.getresponse.side_effect = [auth_response, secret_response]
        mock_conn.return_value = mock_connection

        with pytest.raises(KeyNotFoundError, match="not a valid 32-byte"):
            infisical_provider.get_key("test-key")

    def test_cache_ttl_default(self):
        """Test default cache TTL is 300 seconds."""
        provider = InfisicalKeyProvider(
            site_url="https://app.infisical.com",
            client_id="test",
            client_secret="test",
            project_id="test",
            environment="dev"
        )
        assert provider.cache_ttl == 300

    def test_cache_ttl_custom(self):
        """Test custom cache TTL."""
        provider = InfisicalKeyProvider(
            site_url="https://app.infisical.com",
            client_id="test",
            client_secret="test",
            project_id="test",
            environment="dev",
            cache_ttl=600
        )
        assert provider.cache_ttl == 600


class TestCreateKeyProvider:
    """Test key provider factory function."""

    def test_create_local_provider(self):
        """Test creating LocalKeyProvider."""
        provider = create_key_provider("local", {})
        assert isinstance(provider, LocalKeyProvider)

    def test_create_local_provider_with_initial_keys(self):
        """Test creating LocalKeyProvider with initial keys."""
        key = b"this is a 32-byte key for testing!!"
        provider = create_key_provider("local", {"initialKeys": {"test": key}})
        assert isinstance(provider, LocalKeyProvider)
        assert provider.get_key("test") == key

    def test_create_vault_provider(self):
        """Test creating VaultKeyProvider."""
        config = {
            "vaultUrl": "http://localhost:8200",
            "vaultToken": "test-token",
            "mountPath": "secret"
        }
        provider = create_key_provider("vault", config)
        assert isinstance(provider, VaultKeyProvider)

    def test_create_vault_provider_missing_config(self):
        """Test Vault provider creation with missing config."""
        with pytest.raises(ValueError, match="requires vaultUrl and vaultToken"):
            create_key_provider("vault", {"vaultUrl": "http://localhost:8200"})

    def test_create_infisical_provider(self):
        """Test creating InfisicalKeyProvider."""
        config = {
            "siteUrl": "https://app.infisical.com",
            "clientId": "test-client",
            "clientSecret": "test-secret",
            "projectId": "test-project",
            "environment": "dev"
        }
        provider = create_key_provider("infisical", config)
        assert isinstance(provider, InfisicalKeyProvider)

    def test_create_infisical_provider_missing_config(self):
        """Test Infisical provider creation with missing config."""
        with pytest.raises(ValueError, match="requires"):
            create_key_provider("infisical", {
                "siteUrl": "https://app.infisical.com",
                "clientId": "test-client"
                # Missing: clientSecret, projectId, environment
            })

    def test_create_unknown_provider(self):
        """Test creating unknown provider type."""
        with pytest.raises(ValueError, match="Unknown key provider driver"):
            create_key_provider("unknown", {})

    def test_create_infisical_with_cache_ttl(self):
        """Test Infisical provider with custom cache TTL."""
        config = {
            "siteUrl": "https://app.infisical.com",
            "clientId": "test-client",
            "clientSecret": "test-secret",
            "projectId": "test-project",
            "environment": "dev",
            "cacheTTL": 600
        }
        provider = create_key_provider("infisical", config)
        assert provider.cache_ttl == 600

    def test_create_vault_with_timeout(self):
        """Test Vault provider with custom timeout."""
        config = {
            "vaultUrl": "http://localhost:8200",
            "vaultToken": "test-token",
            "timeout": 10
        }
        provider = create_key_provider("vault", config)
        assert provider.timeout == 10
