"""Approval registry: human-in-the-loop gating for dangerous operations.

Flow:
  1. API handler decides an op needs approval (per settings.approval_policy).
  2. It calls ``create(agent, op, summary, detail)`` and receives an id.
  3. The GUI (which shares this registry object with the server) shows the
     request; the human clicks Approve / Deny.
  4. The blocked request long-polls ``wait(id)`` until a decision arrives
     or its timeout elapses (then it returns "pending" — the agent may
     re-poll with ``approvals wait --id``).
  5. Decisions emit events on the EventBus so waiting agents wake up.
"""
from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timezone

from .constants import APPROVAL_WAIT_MAX

_MAX_DECIDED = 200


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Approval:
    def __init__(self, agent: str, op: str, summary: str, detail: str = "",
                 payload: dict | None = None,
                 expires_in: float | None = None,
                 timeout_action: str | None = None):
        self.id = "apr_" + uuid.uuid4().hex[:12]
        self.agent = agent
        self.op = op
        self.summary = summary
        self.detail = detail
        # Structured, op-specific data. Currently used by "share_root"
        # requests: {"path": ..., "reason": ...}. The GUI consumes it to
        # apply the side effect when (and only when) the human approves.
        self.payload: dict = dict(payload) if payload else {}
        self.created_at = _now()
        self.status = "pending"   # pending|approved|denied|expired-equivalent
        self.decided_at: str | None = None
        self.decided_by: str | None = None
        # v2.4.5 (sudo installs): a pending approval may carry a countdown.
        # `expires_epoch` is time.time()-based for cheap remaining-seconds
        # math in the GUI; `timeout_action` ("approve"|"reject") is baked
        # in at create time from settings["sudo_timeout_action"]. When the
        # deadline passes while still pending, the registry resolves it
        # itself: status approved/denied, decided_by "timeout". The human
        # can still beat the clock — decide() works until the sweep pops
        # the entry.
        self.expires_epoch: float | None = (
            time.time() + expires_in) if expires_in else None
        self.timeout_action: str | None = timeout_action

    def remaining_s(self) -> float | None:
        if self.expires_epoch is None:
            return None
        return max(0.0, self.expires_epoch - time.time())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "agent": self.agent,
            "op": self.op,
            "summary": self.summary,
            "detail": self.detail,
            "payload": self.payload,
            "created_at": self.created_at,
            "status": self.status,
            "decided_at": self.decided_at,
            "decided_by": self.decided_by,
            "expires_in": (round(self.remaining_s(), 1)
                           if self.expires_epoch is not None else None),
            "timeout_action": self.timeout_action,
        }


class ApprovalRegistry:
    def __init__(self, on_event=None):
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._pending: dict = {}      # id -> Approval
        self._decided: list = []      # recent decided approvals (capped)
        self._on_event = on_event    # callback(type, data)

    # -- API side ----------------------------------------------------------

    def create(self, agent: str, op: str, summary: str, detail: str = "",
               payload: dict | None = None,
               expires_in: float | None = None,
               timeout_action: str | None = None) -> str:
        a = Approval(agent, op, summary, detail, payload,
                     expires_in=expires_in, timeout_action=timeout_action)
        with self._cond:
            self._pending[a.id] = a
            self._cond.notify_all()
        self._emit("approval_pending", {
            "id": a.id, "op": a.op, "summary": a.summary, "agent": agent,
            "payload": a.payload,
            "expires_in": (round(a.remaining_s(), 1)
                           if a.expires_epoch is not None else None),
            "timeout_action": a.timeout_action})
        return a.id

    def find_pending(self, op: str, match: dict | None = None) -> Approval | None:
        """Return the first pending approval of `op` whose payload contains
        all the given key/value pairs (for request de-duplication)."""
        with self._lock:
            for a in self._pending.values():
                if a.op != op:
                    continue
                if match and not all(a.payload.get(k) == v
                                     for k, v in match.items()):
                    continue
                return a
        return None

    def wait(self, approval_id: str, timeout: float = 30.0) -> str:
        """Block until decided (returns status) or timeout (returns 'pending').

        v2.4.5: an approval with a countdown auto-resolves AT ITS OWN
        deadline (per its timeout_action) even if `timeout` here is
        longer — the waiter wakes exactly when the countdown ends.
        """
        deadline = time.monotonic() + min(max(timeout, 0.0), APPROVAL_WAIT_MAX)
        with self._cond:
            while True:
                a = self._pending.get(approval_id)
                if a is None:
                    # Already decided — look in decided history.
                    for d in self._decided:
                        if d.id == approval_id:
                            return d.status
                    return "unknown"
                if a.expires_epoch is not None:
                    remaining = a.expires_epoch - time.time()
                    if remaining <= 0:
                        # Countdown elapsed: resolve it per the baked-in
                        # action. Same code path as sweep_expired().
                        self._resolve_expired_locked(a)
                        return a.status
                    deadline = min(deadline, time.monotonic() + remaining)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return "pending"
                self._cond.wait(remaining)

    # -- v2.4.5: countdown sweep -------------------------------------------

    def _resolve_expired_locked(self, a: Approval) -> None:
        """Caller holds the condition lock. Pop + resolve one expired
        pending approval per its timeout_action. The decision is marked
        decided_by='timeout' — auditable, distinguishable from a human.
        """
        self._pending.pop(a.id, None)
        a.status = "approved" if a.timeout_action == "approve" else "denied"
        a.decided_at = _now()
        a.decided_by = "timeout"
        self._decided.append(a)
        if len(self._decided) > _MAX_DECIDED:
            del self._decided[: len(self._decided) - _MAX_DECIDED]
        self._cond.notify_all()
        self._emit("approval_decided", {
            "id": a.id, "op": a.op, "agent": a.agent,
            "decision": a.status, "by": "timeout"})

    def sweep_expired(self) -> int:
        """Resolve every pending approval whose countdown elapsed. Called
        from the GUI poll and from list endpoints so entries resolve even
        if their original waiter vanished (client dropped the socket).
        Returns how many were resolved."""
        n = 0
        now = time.time()
        with self._cond:
            expired = [a for a in self._pending.values()
                       if a.expires_epoch is not None
                       and a.expires_epoch <= now]
            for a in expired:
                self._resolve_expired_locked(a)
                n += 1
        return n

    def status(self, approval_id: str) -> dict | None:
        with self._lock:
            a = self._pending.get(approval_id)
            if a:
                return a.to_dict()
            for d in self._decided:
                if d.id == approval_id:
                    return d.to_dict()
        return None

    def pending(self) -> list:
        with self._lock:
            return [a.to_dict() for a in self._pending.values()]

    def recent_decided(self, n: int = 20) -> list:
        with self._lock:
            return [a.to_dict() for a in self._decided[-n:]]

    # -- GUI side -----------------------------------------------------------

    def decide(self, approval_id: str, approved: bool, by: str = "host") -> str:
        """Approve or deny. Returns the new status, or 'unknown'."""
        with self._cond:
            a = self._pending.pop(approval_id, None)
            if a is None:
                return "unknown"
            a.status = "approved" if approved else "denied"
            a.decided_at = _now()
            a.decided_by = by
            self._decided.append(a)
            if len(self._decided) > _MAX_DECIDED:
                del self._decided[: len(self._decided) - _MAX_DECIDED]
            self._cond.notify_all()
        self._emit("approval_decided", {
            "id": a.id, "op": a.op, "agent": a.agent,
            "decision": a.status, "by": by})
        return a.status

    # -- internal -----------------------------------------------------------

    def _emit(self, type_: str, data: dict) -> None:
        if self._on_event is not None:
            try:
                self._on_event(type_, data)
            except Exception:
                pass
