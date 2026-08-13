"""
Tests for Envelope class.
"""

import pytest
import json
from panda.crypto import Envelope, MalformedEnvelopeError


class TestEnvelope:
    """Test envelope creation and serialization."""

    def test_create_envelope(self):
        """Test creating an envelope from components."""
        envelope = Envelope(
            v=1,
            alg="aes-256-gcm",
            kid="test-key",
            nonce="abcd1234",
            ciphertext="encrypteddata"
        )

        assert envelope.v == 1
        assert envelope.alg == "aes-256-gcm"
        assert envelope.kid == "test-key"
        assert envelope.nonce == "abcd1234"
        assert envelope.ciphertext == "encrypteddata"

    def test_to_dict(self):
        """Test converting envelope to dictionary."""
        envelope = Envelope(
            v=1,
            alg="aes-256-gcm",
            kid="test-key",
            nonce="abcd1234",
            ciphertext="encrypteddata"
        )

        expected = {
            "v": 1,
            "alg": "aes-256-gcm",
            "kid": "test-key",
            "nonce": "abcd1234",
            "ciphertext": "encrypteddata"
        }

        assert envelope.to_dict() == expected

    def test_to_json(self):
        """Test converting envelope to JSON."""
        envelope = Envelope(
            v=1,
            alg="aes-256-gcm",
            kid="test-key",
            nonce="abcd1234",
            ciphertext="encrypteddata"
        )

        json_str = envelope.to_json()
        data = json.loads(json_str)

        assert data["v"] == 1
        assert data["alg"] == "aes-256-gcm"
        assert data["kid"] == "test-key"

    def test_from_json_valid(self):
        """Test parsing envelope from valid JSON."""
        json_str = '{"v": 1, "alg": "aes-256-gcm", "kid": "test-key", "nonce": "abcd", "ciphertext": "encrypted"}'
        envelope = Envelope.from_json(json_str)

        assert envelope.v == 1
        assert envelope.alg == "aes-256-gcm"
        assert envelope.kid == "test-key"

    def test_from_json_invalid_json(self):
        """Test parsing envelope from invalid JSON."""
        with pytest.raises(MalformedEnvelopeError):
            Envelope.from_json("not valid json")

    def test_from_json_missing_field(self):
        """Test parsing envelope with missing required field."""
        json_str = '{"v": 1, "alg": "aes-256-gcm", "kid": "test-key"}'

        with pytest.raises(MalformedEnvelopeError, match="Missing required"):
            Envelope.from_json(json_str)

    def test_from_dict_valid(self):
        """Test parsing envelope from valid dictionary."""
        data = {
            "v": 1,
            "alg": "aes-256-gcm",
            "kid": "test-key",
            "nonce": "abcd",
            "ciphertext": "encrypted"
        }
        envelope = Envelope.from_dict(data)

        assert envelope.v == 1
        assert envelope.kid == "test-key"

    def test_from_dict_missing_field(self):
        """Test parsing envelope dict with missing field."""
        data = {"v": 1, "alg": "aes-256-gcm", "kid": "test-key"}

        with pytest.raises(MalformedEnvelopeError, match="Missing required"):
            Envelope.from_dict(data)
