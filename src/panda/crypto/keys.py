"""
Key providers for PANDA SDK.

Implements the KeyProvider interface and various key storage backends.
"""

import os
import base64
from abc import ABC, abstractmethod
from typing import Optional
import http.client
import urllib.parse
import json
import time

from .errors import KeyNotFoundError, CryptoProviderError


class KeyProvider(ABC):
    """
    Abstract base class for key providers.

    All key providers must implement the get_key method to retrieve
    a 32-byte encryption key by key identifier (KID).
    """

    @abstractmethod
    def get_key(self, kid: str) -> bytes:
        """
        Retrieve a 32-byte encryption key by key identifier.

        Args:
            kid: Key identifier

        Returns:
            32-byte key as bytes

        Raises:
            KeyNotFoundError: If the key cannot be found
            CryptoProviderError: If the provider operation fails
        """
        pass


class LocalKeyProvider(KeyProvider):
    """
    Key provider that reads keys from environment variables.

    Keys are read from PANDA_KEY_<KID> environment variables.
    The key value must be a base64-encoded 32-byte key.
    """

    def __init__(self, initial_keys: Optional[dict[str, bytes]] = None):
        """
        Initialize the local key provider.

        Args:
            initial_keys: Optional dictionary of pre-loaded keys
        """
        self._keys: dict[str, bytes] = initial_keys or {}

    def set_key(self, kid: str, key_bytes: bytes) -> None:
        """
        Store a key in memory.

        Args:
            kid: Key identifier
            key_bytes: 32-byte key
        """
        if len(key_bytes) != 32:
            raise ValueError("Key must be exactly 32 bytes")
        self._keys[kid] = key_bytes

    def get_key(self, kid: str) -> bytes:
        """
        Retrieve a key from memory or environment variables.

        Args:
            kid: Key identifier

        Returns:
            32-byte key as bytes

        Raises:
            KeyNotFoundError: If the key cannot be found
        """
        # Check memory cache first
        if kid in self._keys:
            return self._keys[kid]

        # Check environment variables
        # Try exact match first
        env_value = os.environ.get(f"PANDA_KEY_{kid}")

        # Try normalized version (uppercase, underscores for hyphens/special chars)
        if not env_value:
            normalized_kid = kid.replace("-", "_").replace(".", "_").upper()
            env_value = os.environ.get(f"PANDA_KEY_{normalized_kid}")

        if not env_value:
            raise KeyNotFoundError(
                f"Encryption key not found for kid: {kid} "
                f"(expected env variable: PANDA_KEY_{kid})"
            )

        try:
            key_bytes = base64.b64decode(env_value)
        except Exception as e:
            raise KeyNotFoundError(
                f"Invalid base64 encoding for key '{kid}': {e}"
            )

        if len(key_bytes) != 32:
            raise KeyNotFoundError(
                f"Invalid key format for kid: {kid}. "
                f"Key must be base64-encoded and decode to exactly 32 bytes."
            )

        # Cache in memory
        self._keys[kid] = key_bytes
        return key_bytes


class VaultKeyProvider(KeyProvider):
    """
    Key provider that fetches keys from HashiCorp Vault.

    Uses the Vault KV v2 secrets engine to retrieve encryption keys.
    Keys are cached in memory to reduce API calls.
    """

    def __init__(
        self,
        vault_url: str,
        vault_token: str,
        mount_path: str = "secret",
        timeout: int = 5
    ):
        """
        Initialize the Vault key provider.

        Args:
            vault_url: URL of the Vault server (e.g., "http://localhost:8200")
            vault_token: Vault token for authentication
            mount_path: Mount path of the KV v2 secrets engine (default: "secret")
            timeout: HTTP request timeout in seconds (default: 5)
        """
        self.vault_url = vault_url.rstrip("/")
        self.vault_token = vault_token
        self.mount_path = mount_path.strip("/")
        self.timeout = timeout
        self._cache: dict[str, bytes] = {}

        # Check for insecure TLS setting
        self._verify_tls = os.environ.get("PANDA_VAULT_INSECURE") != "1"

    def get_key(self, kid: str) -> bytes:
        """
        Retrieve a key from Vault.

        Args:
            kid: Key identifier (used as the secret path)

        Returns:
            32-byte key as bytes

        Raises:
            KeyNotFoundError: If the key cannot be found
            CryptoProviderError: If the Vault request fails
        """
        # Check cache first
        if kid in self._cache:
            return self._cache[kid]

        # Build Vault KV v2 API URL
        url = f"{self.vault_url}/v1/{self.mount_path}/data/{kid}"

        try:
            # Parse URL for http/https
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ("http", "https"):
                raise CryptoProviderError(f"Unsupported URL scheme: {parsed.scheme}")

            # Create HTTP connection
            conn_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
            conn = conn_class(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), timeout=self.timeout)

            # Send request
            headers = {
                "X-Vault-Token": self.vault_token,
                "Accept": "application/json"
            }
            conn.request("GET", parsed.path, headers=headers)

            # Get response
            response = conn.getresponse()
            body = response.read().decode("utf-8")
            conn.close()

            if response.status != 200:
                raise KeyNotFoundError(
                    f"Could not retrieve key '{kid}' from Vault "
                    f"(HTTP status code: {response.status})"
                )

            # Parse response
            data = json.loads(body)

            # KV v2 response structure: data.data.data.key or data.data.data.value
            key_value = None
            if "data" in data and isinstance(data["data"], dict):
                inner_data = data["data"].get("data", {})
                key_value = inner_data.get("key") or inner_data.get("value")

            if not key_value:
                raise KeyNotFoundError(
                    f"Key '{kid}' not found in Vault response data structure."
                )

            # Decode base64 key
            try:
                key_bytes = base64.b64decode(key_value)
            except Exception as e:
                raise KeyNotFoundError(f"Invalid base64 encoding for key '{kid}': {e}")

            if len(key_bytes) != 32:
                raise KeyNotFoundError(
                    f"Key '{kid}' retrieved from Vault is not a valid 32-byte base64 string."
                )

            # Cache the key
            self._cache[kid] = key_bytes
            return key_bytes

        except KeyNotFoundError:
            raise
        except http.client.HTTPException as e:
            raise CryptoProviderError(f"Vault HTTP error: {e}")
        except (OSError, IOError) as e:
            raise CryptoProviderError(f"Vault connection error: {e}")
        except json.JSONDecodeError as e:
            raise CryptoProviderError(f"Failed to parse Vault response: {e}")


class InfisicalKeyProvider(KeyProvider):
    """
    Key provider that fetches keys from Infisical.

    Uses Universal Auth (Machine Identity credentials) to authenticate
    and retrieve encryption keys. Keys are cached in memory with a
    configurable TTL.
    """

    def __init__(
        self,
        site_url: str,
        client_id: str,
        client_secret: str,
        project_id: str,
        environment: str,
        cache_ttl: int = 300,
        timeout: int = 5
    ):
        """
        Initialize the Infisical key provider.

        Args:
            site_url: Infisical site URL (e.g., "https://app.infisical.com")
            client_id: Machine Identity Client ID
            client_secret: Machine Identity Client Secret
            project_id: Infisical Project ID
            environment: Environment name (e.g., "dev", "prod")
            cache_ttl: Key cache TTL in seconds (default: 300)
            timeout: HTTP request timeout in seconds (default: 5)
        """
        self.site_url = site_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.project_id = project_id
        self.environment = environment
        self.cache_ttl = cache_ttl
        self.timeout = timeout

        self._cache: dict[str, tuple[bytes, float]] = {}  # kid -> (key, expires_at)
        self._access_token: Optional[str] = None
        self._token_expires: float = 0

    def _ensure_authenticated(self) -> None:
        """
        Ensure we have a valid access token for Infisical API.

        Raises:
            CryptoProviderError: If authentication fails
        """
        # Check if we have a valid cached token
        now = time.time()
        if self._access_token and now < self._token_expires:
            return

        # Authenticate using Universal Auth
        auth_url = f"{self.site_url}/api/v1/auth/universal-auth/login"
        payload = {
            "clientId": self.client_id,
            "clientSecret": self.client_secret
        }

        try:
            parsed = urllib.parse.urlparse(auth_url)
            conn_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
            conn = conn_class(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), timeout=self.timeout)

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            conn.request("POST", parsed.path, body=json.dumps(payload), headers=headers)

            response = conn.getresponse()
            body = response.read().decode("utf-8")
            conn.close()

            if response.status != 200:
                raise CryptoProviderError(
                    f"Infisical authentication failed (HTTP {response.status})"
                )

            data = json.loads(body)
            self._access_token = data.get("accessToken")
            if not self._access_token:
                raise CryptoProviderError("No access token in Infisical auth response")

            # Token expires in 9.5 minutes (Infisical tokens are 10 min)
            self._token_expires = now + (9.5 * 60)

        except CryptoProviderError:
            raise
        except (http.client.HTTPException, json.JSONDecodeError) as e:
            raise CryptoProviderError(f"Infisical authentication error: {e}")
        except (OSError, IOError) as e:
            raise CryptoProviderError(f"Infisical connection error: {e}")

    def get_key(self, kid: str) -> bytes:
        """
        Retrieve a key from Infisical.

        Args:
            kid: Key identifier (used as the secret path)

        Returns:
            32-byte key as bytes

        Raises:
            KeyNotFoundError: If the key cannot be found
            CryptoProviderError: If the Infisical request fails
        """
        now = time.time()

        # Check cache first
        if kid in self._cache:
            key_bytes, expires = self._cache[kid]
            if now < expires:
                return key_bytes

        # Ensure we have a valid access token
        self._ensure_authenticated()

        # Fetch secret from Infisical API v3
        params = urllib.parse.urlencode({
            "projectId": self.project_id,
            "environment": self.environment,
            "secretPath": kid
        })
        api_url = f"{self.site_url}/api/v3/secrets/raw?{params}"

        try:
            parsed = urllib.parse.urlparse(api_url)
            conn_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
            conn = conn_class(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), timeout=self.timeout)

            headers = {
                "Authorization": f"Bearer {self._access_token}",
                "Accept": "application/json"
            }
            conn.request("GET", parsed.path + "?" + parsed.query, headers=headers)

            response = conn.getresponse()
            body = response.read().decode("utf-8")
            conn.close()

            if response.status != 200:
                raise KeyNotFoundError(
                    f"Could not retrieve key '{kid}' from Infisical (HTTP {response.status})"
                )

            data = json.loads(body)
            secret_value = data.get("secretValue") or data.get("secret")

            if not secret_value:
                raise KeyNotFoundError(
                    f"Key '{kid}' not found in Infisical response"
                )

            # Decode base64 key
            try:
                key_bytes = base64.b64decode(secret_value)
            except Exception as e:
                raise KeyNotFoundError(f"Invalid base64 encoding for key '{kid}': {e}")

            if len(key_bytes) != 32:
                raise KeyNotFoundError(
                    f"Key '{kid}' is not a valid 32-byte base64 string"
                )

            # Cache the key
            self._cache[kid] = (key_bytes, now + self.cache_ttl)
            return key_bytes

        except KeyNotFoundError:
            raise
        except CryptoProviderError:
            raise
        except (http.client.HTTPException, json.JSONDecodeError) as e:
            raise CryptoProviderError(f"Infisical request error: {e}")
        except (OSError, IOError) as e:
            raise CryptoProviderError(f"Infisical connection error: {e}")


def create_key_provider(
    driver: str,
    config: Optional[dict] = None
) -> KeyProvider:
    """
    Factory function to create KeyProvider instances.

    Args:
        driver: Type of key provider ('local', 'vault', or 'infisical')
        config: Configuration object for the selected provider

    Returns:
        Configured KeyProvider instance

    Raises:
        ValueError: If driver is unknown or config is invalid
    """
    config = config or {}

    if driver == "local":
        return LocalKeyProvider(config.get("initialKeys"))

    elif driver == "vault":
        if not config.get("vaultUrl") or not config.get("vaultToken"):
            raise ValueError("VaultKeyProvider requires vaultUrl and vaultToken")
        return VaultKeyProvider(
            vault_url=config["vaultUrl"],
            vault_token=config["vaultToken"],
            mount_path=config.get("mountPath", "secret"),
            timeout=config.get("timeout", 5)
        )

    elif driver == "infisical":
        required = ["siteUrl", "clientId", "clientSecret", "projectId", "environment"]
        if not all(config.get(k) for k in required):
            raise ValueError(f"InfisicalKeyProvider requires: {', '.join(required)}")
        return InfisicalKeyProvider(
            site_url=config["siteUrl"],
            client_id=config["clientId"],
            client_secret=config["clientSecret"],
            project_id=config["projectId"],
            environment=config["environment"],
            cache_ttl=config.get("cacheTTL", 300),
            timeout=config.get("timeout", 5)
        )

    else:
        raise ValueError(f"Unknown key provider driver: {driver}")
