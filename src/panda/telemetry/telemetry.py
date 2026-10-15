"""Ongoing telemetry reporting (FR-14, FR-16).

IMPORTANT: this handles ONGOING telemetry only. It is opt-out via
``PANDA_TELEMETRY_DISABLED=1``, and it always fails silently: a DNS failure, a
timeout, a refused connection or any non-2xx response is swallowed and never
reaches the caller. The init-time token gate (FR-28/FR-29) is a separate
mechanism, mandatory and fail-closed, and this flag does not affect it.

What it does NOT do any more is run inside an operation. It used to be called
from ``encrypt()`` and ``decrypt_raw()`` — once per operation — and the cipher
had to hold a token for it, taken from ``PANDA_PORTAL_TOKEN``, which nothing in
this project has ever set. Counting is now a dictionary addition (see
``count``), and the token comes from the credentials ``panda init`` wrote, at
report time.

The heartbeat call is gone too: it posted to ``/api/v1/heartbeat``, a route the
portal has never had.
"""

import atexit
import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from typing import Dict, Optional

from .counter_store import CounterStore, NAMES, best, total, zeroes
from .payload import TELEMETRY_URL, build_key_payload, build_usage_payload

#: Whichever is reached first, per panda-spec/telemetry-format.md.
FLUSH_INTERVAL_SECONDS = 300
FLUSH_VOLUME = 1000

TIMEOUT_SECONDS = 2

#: Counted this process, not yet merged into the store.
_pending: Dict[str, int] = zeroes()
_store: Optional[CounterStore] = None
_backend = "memory"
_atexit_registered = False
_said_no_token = False


def disabled() -> bool:
    return os.environ.get("PANDA_TELEMETRY_DISABLED") in ("1", "true")


def backend() -> str:
    """Which counter store this host ended up with."""
    _get_store()
    return _backend


# ── the hot path ──────────────────────────────────────────────────────────

def count(name: str) -> None:
    """Record one operation. A dictionary addition and nothing else.

    The first call in a process also registers the exit hook that merges this
    batch into the shared store and reports it if the window has closed. Doing
    it here rather than per operation is the whole point: a lock and a file
    write inside ``encrypt()`` would be the same class of mistake as the HTTP
    call it replaces.
    """
    global _atexit_registered

    if disabled() or name not in NAMES:
        return

    _pending[name] += 1

    if not _atexit_registered:
        _atexit_registered = True
        atexit.register(on_exit)


def on_exit() -> None:
    """Merge this process's batch, then report if the window has closed."""
    if disabled():
        return

    try:
        store = _get_store()
        store.add_many(_pending)
        for name in NAMES:
            _pending[name] = 0

        if _due(store):
            flush()
    except Exception:  # noqa: BLE001 - fail-silent by contract
        pass


# ── reporting ─────────────────────────────────────────────────────────────

def flush() -> bool:
    """Report the accumulated counts. Returns True when the portal acked."""
    if disabled():
        return False

    store = _get_store()
    counters = store.snapshot()
    if total(counters) <= 0:
        return False

    token = access_token()
    if not token:
        _warn_no_token()
        return False

    body = build_usage_payload(
        {
            "token": token,
            "sdkVersion": sdk_version(),
            "windowSeconds": store.window_seconds(),
            "counters": counters,
        }
    )

    if not _post(body):
        # The counters stay where they are, so the next window carries them.
        # That is what keeps a portal outage from quietly discarding the
        # operations that happened during it.
        return False

    store.commit(counters)
    return True


def new_encryption_key() -> bytes:
    """Generate a 32-byte key and report that one exists.

    The one definition of "a key was generated", so the event cannot be
    forgotten at one of the call sites — which is how ``decrypt``, the most
    common read path of all, came to be uncounted. Every key-producing path
    goes through here: init, ``panda generate`` and ``rotate-key``.
    """
    key = secrets.token_bytes(32)

    report_key(key)

    return key


def report_key(key: bytes) -> None:
    """Report a generated key. Sent once per key, and the only carrier of the
    fingerprint."""
    if disabled():
        return

    token = access_token()
    if not token:
        return

    _post(build_key_payload(token, sdk_version(), key))


# ── internals ─────────────────────────────────────────────────────────────

def sdk_version() -> str:
    """The package's own version, not a literal.

    This module used to default to ``"0.1.0"`` in its ``report`` and
    ``heartbeat`` signatures — the same defect as the CLI's ``--version``,
    which ``0.2.2`` fixed by reading the package. A version string is the
    easiest thing in a codebase to leave behind, because nothing depends on it
    until somebody quotes it in a bug report.
    """
    try:
        from panda import __version__

        return __version__
    except Exception:  # noqa: BLE001
        return "unknown"


def access_token() -> Optional[str]:
    """The access token, from where ``panda init`` put it.

    ``PANDA_PORTAL_TOKEN`` is still honoured for an application that would
    rather hold it in the environment, but it is no longer the only source —
    and it was the reason nothing was ever reported, because nothing sets it.
    """
    try:
        from panda.cli.commands import read_credentials

        credentials = read_credentials()
        if credentials is not None and getattr(credentials, "token", None):
            return str(credentials.token)
    except Exception:  # noqa: BLE001 - not initialised, or not a project
        pass

    return os.environ.get("PANDA_PORTAL_TOKEN") or None


def _get_store() -> CounterStore:
    global _store, _backend

    if _store is None:
        store, name = best()
        _store = store
        _backend = name

        if name == "memory":
            # Said out loud rather than degraded in silence. A figure that is
            # quietly low, because workers were recycled before they reported,
            # is worse than one known to be low.
            print(
                "panda: telemetry counters are process-local (no writable "
                ".panda/telemetry-counters.json). Counts will be under-reported "
                "behind a multi-worker server. See panda-spec/telemetry-format.md.",
                file=sys.stderr,
            )

    return _store


def _due(store: CounterStore) -> bool:
    seconds = store.window_seconds()
    if seconds <= 0:
        return False
    if seconds >= FLUSH_INTERVAL_SECONDS:
        return True
    return total(store.snapshot()) >= FLUSH_VOLUME


def _warn_no_token() -> None:
    global _said_no_token

    if _said_no_token:
        return
    _said_no_token = True
    if os.environ.get("PANDA_TELEMETRY_DEBUG") == "1":
        print(
            "panda: telemetry has no access token to report under; run `panda init`.",
            file=sys.stderr,
        )


def _post(body: str) -> bool:
    request = urllib.request.Request(
        TELEMETRY_URL,
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return 200 <= int(response.status) < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False
    except Exception:  # noqa: BLE001 - fail-silent by contract
        return False


def reset_for_tests() -> None:
    """Testing seam: the counters are module state and a test needs a clean one."""
    global _store, _backend, _atexit_registered, _said_no_token

    for name in NAMES:
        _pending[name] = 0
    _store = None
    _backend = "memory"
    _atexit_registered = False
    _said_no_token = False


# Keep json imported for callers that historically imported it from here.
_ = json
