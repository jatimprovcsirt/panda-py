"""
Audit logging module for PANDA SDK.

Provides structured logging of encryption/decryption events.
"""

import json
import time
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from enum import Enum


class EventType(Enum):
    """Types of audit events."""
    ENCRYPT = "encrypt"
    DECRYPT_MASKED = "decrypt_masked"
    DECRYPT_RAW = "decrypt_raw"
    ROTATE = "rotate"
    SHRED = "shred"


class Outcome(Enum):
    """Possible outcomes of an operation."""
    SUCCESS = "success"
    AUTH_FAILURE = "auth_failure"
    MALFORMED_ENVELOPE = "malformed_envelope"
    KEY_NOT_FOUND = "key_not_found"
    ENCRYPTION_FAILED = "encryption_failed"
    UNSUPPORTED_ENVELOPE_VERSION = "unsupported_envelope_version"
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"


class AuditLogger(ABC):
    """
    Abstract base class for audit loggers.

    Audit loggers record encryption/decryption events for compliance
    and security monitoring. All decrypt_raw() calls (full plaintext
    exposure) are logged distinctly from masked decrypt operations.
    """

    @abstractmethod
    def log(
        self,
        actor: str,
        field: str,
        kid: str,
        event_type: EventType,
        outcome: Outcome,
        **extra
    ) -> None:
        """
        Log an audit event.

        Args:
            actor: Identifier for the entity performing the action
            field: Field name being accessed
            kid: Key identifier used
            event_type: Type of event
            outcome: Outcome of the operation
            **extra: Additional metadata to include in the log
        """
        pass


class ConsoleAuditLogger(AuditLogger):
    """Audit logger that writes to console (stdout/stderr)."""

    def __init__(self, use_stderr: bool = False):
        """
        Initialize the console audit logger.

        Args:
            use_stderr: If True, write to stderr instead of stdout
        """
        import sys
        self._output = sys.stderr if use_stderr else sys.stdout

    def log(
        self,
        actor: str,
        field: str,
        kid: str,
        event_type: EventType,
        outcome: Outcome,
        **extra
    ) -> None:
        """Log an audit event to console."""
        event = {
            "timestamp": time.time(),
            "actor": actor,
            "field": field,
            "kid": kid,
            "eventType": event_type.value if isinstance(event_type, EventType) else event_type,
            "outcome": outcome.value if isinstance(outcome, Outcome) else outcome,
            **extra
        }
        self._output.write(json.dumps(event) + "\n")


class FileAuditLogger(AuditLogger):
    """Audit logger that writes to a file."""

    def __init__(self, file_path: str):
        """
        Initialize the file audit logger.

        Args:
            file_path: Path to the audit log file
        """
        self._file_path = file_path

    def log(
        self,
        actor: str,
        field: str,
        kid: str,
        event_type: EventType,
        outcome: Outcome,
        **extra
    ) -> None:
        """Log an audit event to file."""
        event = {
            "timestamp": time.time(),
            "actor": actor,
            "field": field,
            "kid": kid,
            "eventType": event_type.value if isinstance(event_type, EventType) else event_type,
            "outcome": outcome.value if isinstance(outcome, Outcome) else outcome,
            **extra
        }

        try:
            with open(self._file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except IOError as e:
            # Fail silently to avoid breaking the application
            # In production, you might want to log to stderr or a fallback
            pass


class NullAuditLogger(AuditLogger):
    """
    No-op audit logger that discards all events.

    Use this for development/testing or when audit logging is not required.
    """

    def log(
        self,
        actor: str,
        field: str,
        kid: str,
        event_type: EventType,
        outcome: Outcome,
        **extra
    ) -> None:
        """Discard the log entry."""
        pass
