"""Server-side per-agent session memory.

The harness feature that chat-based agents need most: the host remembers
what the agent has done (reads, writes, edits, execs), so after context
pruning the agent can re-anchor with a single cheap ``session status`` call
instead of re-reading files.

The registry records ops automatically from the API layer. The agent can
add free-form notes ("the plan", "where I left off") which are included in
the digest.

v2.5.0 — the human channel: each agent also has a user->agent INBOX
(the GUI chat pane writes it; `session inbox` reads it between work
units). Notes stay agent->record; inbox messages are the reverse
direction. Both merge into the per-agent transcript the GUI renders.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone

from .constants import (SESSION_INBOX_CAP, SESSION_NOTES_CAP,
                       SESSION_OPS_CAP)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AgentSession:
    def __init__(self, agent: str):
        self.agent = agent
        self.started_at = _now()
        self.last_seen = self.started_at
        self.ops: list = []          # capped log of {ts, op, detail}
        self.notes: list = []        # capped [{ts, text}]
        self.files: dict = {}        # path -> {"reads": n, "writes": n, "last": ts}
        self.execs: list = []        # recent exec summaries (capped 100)
        # v2.5.0 (ASK-001): the user->agent inbox — the human channel.
        # Messages persist for the GUI transcript (capped, drop-oldest);
        # `inbox_seen` is a watermark: the agent's read consumes NEW
        # messages (seq > seen) without erasing the thread history.
        self.inbox: list = []        # capped [{seq, ts, text}]
        self._inbox_seq = 0          # monotonic per-agent message counter
        self.inbox_seen = 0           # highest seq the agent has consumed
        self.last_inbox_ts = None     # persists after consumption (sidebar)

    def record(self, op: str, detail: str = "", path: str = "",
               kind: str = "") -> None:
        self.last_seen = _now()
        if len(self.ops) >= SESSION_OPS_CAP:
            del self.ops[: len(self.ops) - SESSION_OPS_CAP + 1]
        self.ops.append({"ts": self.last_seen, "op": op, "detail": detail[:200]})
        if path:
            entry = self.files.setdefault(
                path, {"reads": 0, "writes": 0, "last": ""})
            field = "reads" if kind == "read" else (
                "writes" if kind in ("write", "edit") else None)
            if field:
                entry[field] += 1
            entry["last"] = self.last_seen
            # Cap the per-file map to avoid unbounded growth.
            if len(self.files) > 2000:
                oldest = sorted(self.files.items(),
                                key=lambda kv: kv[1]["last"])[:500]
                for k, _ in oldest:
                    del self.files[k]

    def record_exec(self, command: str, rc, truncated: bool = False) -> None:
        self.execs.append({
            "ts": _now(), "command": command[:300],
            "rc": rc, "truncated": truncated,
        })
        if len(self.execs) > 100:
            del self.execs[: len(self.execs) - 100]

    def add_note(self, text: str) -> None:
        if len(self.notes) >= SESSION_NOTES_CAP:
            del self.notes[: len(self.notes) - SESSION_NOTES_CAP + 1]
        self.notes.append({"ts": _now(), "text": text[:4000]})

    # ---- v2.5.0 (ASK-001): user->agent inbox --------------------------

    def add_inbox(self, text: str) -> dict:
        """Store one human->agent message; returns the stored dict."""
        self._inbox_seq += 1
        if len(self.inbox) >= SESSION_INBOX_CAP:
            del self.inbox[: len(self.inbox) - SESSION_INBOX_CAP + 1]
        msg = {"seq": self._inbox_seq, "ts": _now(), "text": text[:4000]}
        self.inbox.append(msg)
        self.last_inbox_ts = msg["ts"]
        return msg

    def read_inbox(self, mark: bool = True) -> dict:
        """New (unconsumed) messages: seq > inbox_seen. mark=True consumes
        them for the agent's CLI view; the transcript list is untouched
        (the GUI thread keeps its history). mark=False only peeks — the
        unread banner keeps counting."""
        msgs = [m for m in self.inbox if m["seq"] > self.inbox_seen]
        if mark:
            self.inbox_seen = self._inbox_seq
        return {"messages": msgs,
                "unread": max(0, self._inbox_seq - self.inbox_seen)}

    def unread_count(self) -> int:
        # Counts every un-consumed send, including ones the cap already
        # dropped from the transcript — the next mark absorbs them.
        return max(0, self._inbox_seq - self.inbox_seen)

    def digest(self, all_notes: bool = False) -> dict:
        """A compact, context-cheap summary of the session."""
        top_files = sorted(
            self.files.items(),
            key=lambda kv: (kv[1]["reads"] + kv[1]["writes"]),
            reverse=True,
        )[:20]
        n_execs = len(self.execs)
        failed = [e for e in self.execs if e["rc"] not in (0, None)]
        return {
            "agent": self.agent,
            "started_at": self.started_at,
            "last_seen": self.last_seen,
            "op_count": len(self.ops),
            "files_touched": len(self.files),
            "top_files": [
                {"path": p, **stats} for p, stats in top_files
            ],
            "exec_count": n_execs,
            "exec_failed_count": len(failed),
            "recent_execs": self.execs[-5:],
            "notes": self.notes if all_notes else self.notes[-10:],
            "recent_ops": self.ops[-15:],
            # v2.5.0 (ASK-001): inbox state — the unread banner data.
            "unread": self.unread_count(),
            "last_inbox_ts": self.last_inbox_ts,
        }


class SessionRegistry:
    """Thread-safe collection of per-agent sessions."""

    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: dict = {}

    def get(self, agent: str) -> AgentSession:
        with self._lock:
            s = self._sessions.get(agent)
            if s is None:
                s = AgentSession(agent)
                self._sessions[agent] = s
            return s

    def record(self, agent: str, op: str, detail: str = "", path: str = "",
               kind: str = "") -> None:
        self.get(agent).record(op, detail, path, kind)

    def reset(self, agent: str) -> None:
        with self._lock:
            self._sessions[agent] = AgentSession(agent)

    def note(self, agent: str, text: str) -> None:
        self.get(agent).add_note(text)

    def digest(self, agent: str, all_notes: bool = False) -> dict:
        return self.get(agent).digest(all_notes=all_notes)

    # ---- v2.5.0 (ASK-001/002): the human channel -----------------------

    def inbox(self, agent: str, text: str, events=None) -> dict:
        """Store a user->agent message. The GUI (in-process owner of the
        AppContext) passes ctx.events so live /events pollers see the
        'message' event immediately; the agent gets it on its next
        `session inbox` poll between work units (agent.md convention)."""
        msg = self.get(agent).add_inbox(text)
        if events is not None:
            events.emit("message", {"agent": agent, "seq": msg["seq"],
                                    "text": text[:150]})
        return msg

    def read_inbox(self, agent: str, mark: bool = True) -> dict:
        return self.get(agent).read_inbox(mark=mark)

    def agents_snapshot(self) -> list:
        """Sidebar data for the multi-session GUI (ASK-002): every known
        agent session with live/dormant + unread badge inputs."""
        with self._lock:
            return [{
                "agent": s.agent,
                "started_at": s.started_at,
                "last_seen": s.last_seen,
                "op_count": len(s.ops),
                "note_count": len(s.notes),
                "unread": s.unread_count(),
                "last_inbox_ts": s.last_inbox_ts,
            } for s in self._sessions.values()]

    def thread(self, agent: str, limit: int = 200) -> list:
        """The merged transcript the GUI chat pane renders: agent notes +
        user inbox messages, ts-ordered, newest last."""
        s = self.get(agent)
        items = ([{"kind": "note", **n} for n in s.notes]
                 + [{"kind": "message", **m} for m in s.inbox])
        items.sort(key=lambda x: (x["ts"], x.get("seq", 0)))
        return items[-limit:]
