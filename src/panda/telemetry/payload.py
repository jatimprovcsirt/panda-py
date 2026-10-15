"""The telemetry payloads, as pinned in panda-spec/telemetry-format.md.

Separate from the client that sends them, and pure, so the format can be
checked without a portal. ``verify_interop.js`` section 11 gives every SDK the
same counters and asserts they produce the same fields.

It is separate for a second reason, which is the defect it exists to prevent:
the SDK and the portal disagreed about the field names -- the SDK sent
``keyFingerprint``/``sdkVersion``/``language`` and the portal read
``eventType``/``metadata`` -- and nothing noticed, because the endpoint was
never reached. A payload built in one typed place, against a written contract,
is a payload someone can compare against the receiver.
"""

import base64
import hashlib
import json
from typing import Any, Dict

#: What this SDK calls itself in the payload.
LANGUAGE = "python"

#: The one definition every portal endpoint is derived from.
#:
#: ``TelemetryClient`` used to carry its own literal here -- a hostname that
#: does not exist -- while the token gate next door had the right one. Two
#: definitions of one host is how they came apart.
PORTAL_BASE_URL = "https://csirt.jatimprov.go.id/panda/api/v1"

#: Derived, never written out again.
TELEMETRY_URL = f"{PORTAL_BASE_URL}/telemetry"


def build_usage_payload(v: Dict[str, Any]) -> str:
    """Render a usage report.

    Every counter is written, including the ones at zero. Omitting an unmoved
    counter would be indistinguishable, at the receiver, from an older SDK that
    never sent the field -- and an idle installation has to be tellable from an
    out-of-date one.
    """
    counters = v["counters"]
    return json.dumps(
        {
            "eventType": "usage",
            "token": v["token"],
            "sdkVersion": v["sdkVersion"],
            "language": LANGUAGE,
            "windowSeconds": int(v["windowSeconds"]),
            "counters": {
                "encrypts": int(counters["encrypts"]),
                "decrypts": int(counters["decrypts"]),
                "decryptsRaw": int(counters["decryptsRaw"]),
            },
        },
        separators=(",", ":"),
    )


def build_key_payload(token: str, sdk_version: str, key: bytes) -> str:
    """Render a key report, sent once when a key is generated."""
    return json.dumps(
        {
            "eventType": "key",
            "token": token,
            "sdkVersion": sdk_version,
            "language": LANGUAGE,
            "keyFingerprint": key_fingerprint(key),
        },
        separators=(",", ":"),
    )


def key_fingerprint(key: bytes) -> str:
    """``base64(SHA-256(key bytes))`` -- the bytes, not their base64 text.

    Hashing the encoded form is the mistake that survives every round-trip
    test, because the implementation agrees with itself and only disagrees with
    the other three. A vector in ``vectors.json`` hashes a key whose base64
    encoding is itself, so the two readings differ.
    """
    return base64.b64encode(hashlib.sha256(key).digest()).decode("ascii")
