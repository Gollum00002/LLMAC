"""Global event bus: server-side events with long-poll for agents.

Event types emitted:
  * ``proc_exit``     — background process exited (data: proc id, name, rc)
  * ``proc_log``      — v2.4.7: a RUNNING proc produced output on
                        stdout/stderr (data: proc id, name, stream, size).
                        The agent slices the new content with
                        /proc/logs (after=<next> from its previous call).
  * ``approval_pending``  — new approval request (data: approval id, op, agent)
  * ``approval_decided``  — approval resolved (data: id, decision, agent)
  * ``write``         — file written/edited by an agent (data: path, agent)
  * ``note``          — session note stored (data: agent, note)
  * ``message``      — v2.5.0: the human sent a message to an agent's
                        inbox from the GUI chat pane (data: agent, seq,
                        text) — agents long-polling /events see it land
                        in real time.
  * ``agents_changed``— agent keys added/revoked/refreshed

Agents subscribe with ``GET /events?since=<seq>&wait=<seconds>`` — the call
blocks until a new event arrives or the wait elapses, then returns the
events with seq > since. Simple, works through urllib, no SSE needed.
"""
from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone

_MAX_EVENTS = 500


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class EventBus:
    def __init__(self):
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._events: deque = deque(maxlen=_MAX_EVENTS)
        self._next_seq = 1

    def emit(self, type_: str, data: dict | None = None) -> int:
        with self._cond:
            event = {
                "seq": self._next_seq,
                "ts": _now_iso(),
                "type": type_,
                "data": data or {},
            }
            self._next_seq += 1
            self._events.append(event)
            self._cond.notify_all()
            return event["seq"]

    def latest_seq(self) -> int:
        with self._lock:
            return self._next_seq - 1

    def wait(self, since: int, timeout: float = 25.0) -> list:
        """Return events with seq > since, waiting up to `timeout` seconds."""
        import time as _time
        deadline = _time.monotonic() + max(0.0, min(timeout, 120.0))
        with self._cond:
            while True:
                events = [e for e in self._events if e["seq"] > since]
                if events:
                    return events
                remaining = deadline - _time.monotonic()
                if remaining <= 0:
                    return []
                self._cond.wait(remaining)
