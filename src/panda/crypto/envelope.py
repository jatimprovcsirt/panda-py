"""
Envelope module for PANDA SDK.

Defines the Envelope class that represents the encrypted data format.
"""

from typing import Dict, Any
from dataclasses import dataclass
import json


class EnvelopeError(Exception):
    """Base exception for envelope-related errors."""
    pass


class MalformedEnvelopeError(EnvelopeError):
    """Raised when the envelope format is invalid."""
    pass


@dataclass(frozen=True)
class Envelope:
    """
    Represents an encrypted envelope containing ciphertext and metadata.

    The envelope format follows the PANDA specification:
    {
        "v": 1,
        "alg": "aes-256-gcm",
        "kid": "key-identifier",
        "nonce": "<base64 12-byte IV>",
        "ciphertext": "<base64 ciphertext + 16-byte auth tag>"
    }
    """

    v: int
    alg: str
    kid: str
    nonce: str
    ciphertext: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert envelope to a dictionary with deterministic key order."""
        return {
            "v": self.v,
            "alg": self.alg,
            "kid": self.kid,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext
        }

    def to_json(self) -> str:
        """Convert envelope to JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> "Envelope":
        """
        Create an Envelope from a JSON string.

        Args:
            json_str: JSON string representing the envelope

        Returns:
            Envelope instance

        Raises:
            MalformedEnvelopeError: If JSON is invalid or missing required fields
        """
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise MalformedEnvelopeError(f"Invalid JSON envelope format: {e}")

        if not isinstance(data, dict):
            raise MalformedEnvelopeError("Envelope must be a JSON object")

        # Check for required fields
        required_fields = ["v", "alg", "kid", "nonce", "ciphertext"]
        for field in required_fields:
            if field not in data:
                raise MalformedEnvelopeError(f"Missing required envelope field: {field}")

        # Validate field types
        if not isinstance(data["v"], int):
            raise MalformedEnvelopeError("Envelope version ('v') must be an integer")

        return cls(
            v=int(data["v"]),
            alg=str(data["alg"]),
            kid=str(data["kid"]),
            nonce=str(data["nonce"]),
            ciphertext=str(data["ciphertext"])
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Envelope":
        """
        Create an Envelope from a dictionary.

        Args:
            data: Dictionary containing envelope fields

        Returns:
            Envelope instance

        Raises:
            MalformedEnvelopeError: If dictionary is invalid
        """
        required_fields = ["v", "alg", "kid", "nonce", "ciphertext"]
        for field in required_fields:
            if field not in data:
                raise MalformedEnvelopeError(f"Missing required envelope field: {field}")

        if not isinstance(data["v"], int):
            raise MalformedEnvelopeError("Envelope version ('v') must be an integer")

        return cls(
            v=int(data["v"]),
            alg=str(data["alg"]),
            kid=str(data["kid"]),
            nonce=str(data["nonce"]),
            ciphertext=str(data["ciphertext"])
        )
