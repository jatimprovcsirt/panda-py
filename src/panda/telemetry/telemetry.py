"""
Telemetry module for PANDA SDK.

Provides fail-silent telemetry reporting.
"""

import json
import hashlib
import urllib.parse
import http.client
import os
from typing import Optional


class TelemetryClient:
    """
    Fail-silent telemetry reporter for PANDA SDK.

    Telemetry reports one-way key fingerprints and SDK version information.
    Designed to fail silently without blocking core functionality.

    Opt-out via PANDA_TELEMETRY_DISABLED=1 environment variable.
    """

    def __init__(
        self,
        portal_url: Optional[str] = None,
        timeout: int = 2
    ):
        """
        Initialize the telemetry client.

        Args:
            portal_url: Optional custom portal URL
            timeout: HTTP request timeout in seconds
        """
        self._portal_url = portal_url or os.environ.get("PANDA_PORTAL_URL", "https://panda.jatimprovcsirt.go.id")
        self._timeout = timeout
        self._disabled = os.environ.get("PANDA_TELEMETRY_DISABLED") == "1"

    def _is_disabled(self) -> bool:
        """Check if telemetry is disabled."""
        return self._disabled

    def report(self, token: str, key: bytes, sdk_version: str = "0.1.0") -> bool:
        """
        Report telemetry data (fail-silent).

        Args:
            token: Access token
            key: Encryption key bytes (only fingerprint is sent)
            sdk_version: SDK version string

        Returns:
            True if report succeeded, False otherwise (but never raises)
        """
        if self._is_disabled():
            return False

        try:
            # Compute one-way key fingerprint (SHA-256)
            key_fingerprint = hashlib.sha256(key).hexdigest()

            # Build payload (never includes actual key material)
            payload = {
                "token": token,
                "keyFingerprint": key_fingerprint,
                "sdkVersion": sdk_version,
                "language": "python"
            }

            # Send telemetry report
            url = f"{self._portal_url}/api/v1/telemetry"
            parsed = urllib.parse.urlparse(url)

            conn_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
            conn = conn_class(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), timeout=self._timeout)

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }

            try:
                conn.request("POST", parsed.path, body=json.dumps(payload), headers=headers)
                response = conn.getresponse()
                conn.close()

                # Success regardless of response code
                return True

            except Exception:
                conn.close()
                return False

        except Exception:
            # Fail silently - never block core functionality
            return False

    def heartbeat(self, token: str, sdk_version: str = "0.1.0") -> bool:
        """
        Send a heartbeat ping (fail-silent).

        Args:
            token: Access token
            sdk_version: SDK version string

        Returns:
            True if heartbeat succeeded, False otherwise
        """
        if self._is_disabled():
            return False

        try:
            payload = {
                "token": token,
                "sdkVersion": sdk_version,
                "language": "python",
                "type": "heartbeat"
            }

            url = f"{self._portal_url}/api/v1/heartbeat"
            parsed = urllib.parse.urlparse(url)

            conn_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
            conn = conn_class(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), timeout=self._timeout)

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }

            try:
                conn.request("POST", parsed.path, body=json.dumps(payload), headers=headers)
                response = conn.getresponse()
                conn.close()
                return True

            except Exception:
                conn.close()
                return False

        except Exception:
            return False
