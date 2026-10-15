"""Telemetry module for PANDA SDK.

Provides fail-silent telemetry reporting, as pinned in
``panda-spec/telemetry-format.md``.

``count`` is what the cipher calls: a dictionary addition on the hot path.
``flush`` and ``report_key`` are the network calls, and they happen on the
window boundary rather than inside an operation — the cipher used to hold a
telemetry client and a token and call out once per encrypt, which is what this
module no longer offers.
"""

from .payload import (
    LANGUAGE,
    PORTAL_BASE_URL,
    TELEMETRY_URL,
    build_key_payload,
    build_usage_payload,
    key_fingerprint,
)
from .telemetry import (
    backend,
    count,
    disabled,
    flush,
    new_encryption_key,
    report_key,
    reset_for_tests,
    sdk_version,
)

__all__ = [
    "LANGUAGE",
    "PORTAL_BASE_URL",
    "TELEMETRY_URL",
    "backend",
    "build_key_payload",
    "build_usage_payload",
    "count",
    "disabled",
    "flush",
    "key_fingerprint",
    "new_encryption_key",
    "report_key",
    "reset_for_tests",
    "sdk_version",
]
