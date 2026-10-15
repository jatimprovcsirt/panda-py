"""Where the operation counters live between requests.

In a single-process runtime they would live in the process. Python behind
gunicorn or uwsgi is not one: the server forks workers, each has its own
memory, and a worker's counts die with it. A counter that lives only in a
worker sees one slice of the traffic and may never report, so quiet
installations — which is the government deployment profile — lose their
counts. The bias falls on exactly the installations most worth counting.

``panda-spec/telemetry-format.md`` names APCu for PHP; Python has no
equivalent built in, so the two back-ends here are:

file    — a lock-protected JSON file in ``.panda/``, shared by every worker
          of one installation. Needs nothing installed.
memory  — process-local, the lossiest, used only when the file cannot be
          written. It **says so** rather than degrading in silence: a
          statistics figure that is quietly low is worse than one that is
          known to be.

**Two tiers, on purpose.** The hot path increments process-local memory: one
dictionary addition, no lock, no I/O. At process exit the accumulated batch is
merged into the shared file in one operation. Writing to a shared file per
operation would put a lock and a write inside ``encrypt()``, which is the
shape of problem this whole change exists to remove.
"""

import json
import os
from typing import Dict, List

try:  # POSIX. Windows has no flock, and the file back-end is skipped there.
    import fcntl
except ImportError:  # pragma: no cover - platform dependent
    fcntl = None  # type: ignore[assignment]

NAMES: List[str] = ["encrypts", "decrypts", "decryptsRaw"]

_FILE_NAME = "telemetry-counters.json"


def zeroes() -> Dict[str, int]:
    return {name: 0 for name in NAMES}


def total(counters: Dict[str, int]) -> int:
    return sum(int(counters.get(name, 0)) for name in NAMES)


def subtract(counters: Dict[str, int], sent: Dict[str, int]) -> Dict[str, int]:
    """Subtract, never below zero.

    Subtracting rather than zeroing keeps anything counted while the report
    was in flight; zeroing would discard it and nothing would report that.
    """
    return {
        name: max(0, int(counters.get(name, 0)) - int(sent.get(name, 0)))
        for name in NAMES
    }


def default_path() -> str:
    """Inside ``.panda``, beside the credentials, because it belongs to the
    same installation — and a path derived from the working directory is the
    one thing that cannot end up somewhere unexpected."""
    return os.path.join(os.getcwd(), ".panda", _FILE_NAME)


class CounterStore:
    """The shared tier. One write per request, not per operation."""

    def add_many(self, counters: Dict[str, int]) -> None:
        raise NotImplementedError

    def snapshot(self) -> Dict[str, int]:
        raise NotImplementedError

    def commit(self, sent: Dict[str, int]) -> None:
        raise NotImplementedError

    def window_seconds(self) -> int:
        raise NotImplementedError


class FileCounterStore(CounterStore):
    def __init__(self, path: str) -> None:
        self._path = path

    @staticmethod
    def usable(path: str) -> bool:
        if fcntl is None:
            return False
        directory = os.path.dirname(path)
        if not os.path.isdir(directory):
            return False
        return os.access(directory, os.W_OK)

    def add_many(self, counters: Dict[str, int]) -> None:
        if total(counters) <= 0:
            return

        def mutate(data: Dict[str, object]) -> Dict[str, object]:
            current = _clean(data.get("counters"))
            for name in NAMES:
                current[name] += int(counters.get(name, 0))
            data["counters"] = current
            if not data.get("window"):
                import time

                data["window"] = int(time.time())
            return data

        self._with_lock(mutate)

    def snapshot(self) -> Dict[str, int]:
        return _clean(self._read().get("counters"))

    def commit(self, sent: Dict[str, int]) -> None:
        def mutate(data: Dict[str, object]) -> Dict[str, object]:
            remaining = subtract(_clean(data.get("counters")), sent)
            data["counters"] = remaining
            if total(remaining) <= 0:
                data["window"] = 0
            return data

        self._with_lock(mutate)

    def window_seconds(self) -> int:
        import time

        data = self._read()
        counters = _clean(data.get("counters"))
        window = int(data.get("window") or 0)
        if total(counters) <= 0 or window == 0:
            return 0
        return max(0, int(time.time()) - window)

    def _read(self) -> Dict[str, object]:
        try:
            with open(self._path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return {"counters": zeroes(), "window": 0}
        if not isinstance(data, dict):
            return {"counters": zeroes(), "window": 0}
        return data

    def _with_lock(self, mutate) -> None:
        """Read, change, write, under one lock.

        The lock is held across the read as well as the write: two workers
        that both read before either writes would each add their batch to the
        same starting value, and one of the two would vanish.
        """
        try:
            handle = open(self._path, "a+", encoding="utf-8")
        except OSError:
            return

        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.seek(0)
            raw = handle.read()
            try:
                data = json.loads(raw) if raw.strip() else {}
            except ValueError:
                data = {}
            if not isinstance(data, dict):
                data = {}
            data.setdefault("counters", zeroes())
            data.setdefault("window", 0)

            data = mutate(data)

            handle.seek(0)
            handle.truncate()
            handle.write(json.dumps(data))
            handle.flush()
            # No fsync. It costs a disk round-trip per request that did any
            # crypto, to protect counts that the spec already says may be lost
            # — the window bounds the loss, and a host crash is outside what
            # this is for. flock is released by close, but explicitly here so
            # the intent is readable.
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            handle.close()


class MemoryCounterStore(CounterStore):
    """The last resort. Process-local, and it says so."""

    def __init__(self) -> None:
        self._counters = zeroes()
        self._window = 0

    def add_many(self, counters: Dict[str, int]) -> None:
        import time

        if total(counters) <= 0:
            return
        for name in NAMES:
            self._counters[name] += int(counters.get(name, 0))
        if self._window == 0:
            self._window = int(time.time())

    def snapshot(self) -> Dict[str, int]:
        return dict(self._counters)

    def commit(self, sent: Dict[str, int]) -> None:
        self._counters = subtract(self._counters, sent)
        if total(self._counters) <= 0:
            self._window = 0

    def window_seconds(self) -> int:
        import time

        if total(self._counters) <= 0 or self._window == 0:
            return 0
        return max(0, int(time.time()) - self._window)


def best() -> "tuple[CounterStore, str]":
    """The best store this host can offer, and its backend name."""
    path = default_path()
    if os.path.isdir(os.path.dirname(path)) and FileCounterStore.usable(path):
        return FileCounterStore(path), "file"
    return MemoryCounterStore(), "memory"


def _clean(counters: object) -> Dict[str, int]:
    out = zeroes()
    if isinstance(counters, dict):
        for name in NAMES:
            try:
                out[name] = max(0, int(counters.get(name, 0)))
            except (TypeError, ValueError):
                out[name] = 0
    return out
