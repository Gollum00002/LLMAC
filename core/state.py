"""State persistence v2: agents, settings, roots + history + export/import.

Schema v2 state.json::

    {
      "schema_version": 2,
      "roots": ["/abs/..."],
      "host": "127.0.0.1",
      "port": 8765,
      "agents": [
        {"name": "default", "key": "llmac_...", "roots": [],
         "perms": {"read": true, "write": true, "delete": true,
                   "exec": false, "proc": false},
         "expires_at": null, "created_at": "..."}
      ],
      "settings": {
        "tls": true, "allow_exec": false, "approval_policy": "destructive",
        "venvs": []
      },
      "created_at": "...", "updated_at": "..."
    }

``agents[*].roots`` is a list; an EMPTY list means "all shared roots"
(wildcard). Non-empty lists restrict the agent to those roots (which must be
subdirectories of, or equal to, shared roots at enforcement time).

v1 state files ({"key": ...} with no agents) are migrated transparently:
the single key becomes the "default" agent.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import sys
import threading
from datetime import datetime, timezone
from typing import Optional

from .constants import (
    DEFAULT_SHOT_DIR, SCREEN_INPUT_MAX_EVENTS_DEFAULT,
    SCREEN_INPUT_MAX_MINUTES_DEFAULT,
    DEFAULT_HOST, DEFAULT_PERMS, DEFAULT_PORT, EXPORT_FORMAT, EXPORT_VERSION,
    KEY_PREFIX, POLICY_DESTRUCTIVE, STATE_SCHEMA_VERSION, VALID_POLICIES,
    HISTORY_ROTATE_BYTES, HISTORY_KEEP_GENERATIONS,
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def key_fingerprint(key: str) -> str:
    if not key:
        return "<none>"
    if len(key) < 12:
        return key[:2] + "*" * (len(key) - 2)
    return f"{key[:10]}...{key[-4:]}"


def new_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(24)


def make_default_agent(key: str = "", name: str = "default") -> dict:
    """A full-permission, non-expiring agent (the v1 single-key model)."""
    return {
        "name": name,
        "key": key or new_key(),
        "roots": [],                      # [] = all shared roots
        "perms": dict(DEFAULT_PERMS),
        "expires_at": None,
        "created_at": now_iso(),
    }


def normalize_agent(agent: dict) -> dict:
    """Fill in defaults / coerce types for a (possibly partial) agent dict."""
    out = dict(agent)
    out.setdefault("name", "unnamed")
    out.setdefault("key", "")
    roots = out.get("roots")
    out["roots"] = [str(r) for r in roots] if isinstance(roots, list) else []
    perms = out.get("perms") if isinstance(out.get("perms"), dict) else {}
    out["perms"] = {k: bool(perms.get(k, DEFAULT_PERMS[k])) for k in DEFAULT_PERMS}
    out["expires_at"] = out.get("expires_at") or None
    out["created_at"] = out.get("created_at") or now_iso()
    return out


def default_settings() -> dict:
    return {
        "tls": True,
        "allow_exec": False,
        "approval_policy": POLICY_DESTRUCTIVE,
        "venvs": [],
        # v2.7.0 (ASK-016/017): the screen channel — screenshots ON
        # (still approval-gated per shot), observe + input OFF until the
        # host flips them in the GUI Security tab.
        "screen_shots_enabled": True,
        "screen_observe_enabled": False,
        "screen_input_enabled": False,
        "screen_shot_dir": DEFAULT_SHOT_DIR,
        "screen_input_max_minutes": SCREEN_INPUT_MAX_MINUTES_DEFAULT,
        "screen_input_max_events": SCREEN_INPUT_MAX_EVENTS_DEFAULT,
    }


def _migrate_v1(data: dict) -> dict:
    """Upgrade a v1 state dict (or empty) to the v2 schema."""
    old_key = data.get("key") or ""
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "roots": [str(r) for r in (data.get("roots") or [])],
        "host": data.get("host") or DEFAULT_HOST,
        "port": int(data.get("port") or DEFAULT_PORT),
        "agents": [make_default_agent(old_key)],
        "settings": default_settings(),
        "created_at": now_iso(),
    }


class StateStore:
    """Persists v2 state to <data_dir>/state.json (chmod 600 on POSIX)."""

    def __init__(self, data_dir: str):
        self.data_dir = os.path.abspath(data_dir)
        self.state_path = os.path.join(self.data_dir, "state.json")
        self.backup_path = os.path.join(self.data_dir, "state.json.bak")
        self._lock = threading.Lock()
        os.makedirs(self.data_dir, exist_ok=True)
        # The data dir stays 755 (deletable without sudo; the secret lives
        # inside state.json which is 600).
        if os.name == "posix":
            try:
                os.chmod(self.data_dir, 0o755)
            except OSError:
                pass

    def load(self) -> dict:
        """Load state, migrating v1 files. Returns a valid v2 dict always."""
        with self._lock:
            for path in (self.state_path, self.backup_path):
                if not os.path.exists(path):
                    continue
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except (json.JSONDecodeError, OSError):
                    continue
                if not isinstance(data, dict):
                    continue
                if data.get("schema_version", 1) >= 2 and data.get("agents"):
                    state = dict(data)
                    state.setdefault("settings", default_settings())
                    state["agents"] = [normalize_agent(a) for a in state["agents"]]
                    return state
                return _migrate_v1(data)
        return _migrate_v1({})

    def save(self, state: dict) -> None:
        with self._lock:
            os.makedirs(self.data_dir, exist_ok=True)
            state = dict(state)
            state["schema_version"] = STATE_SCHEMA_VERSION
            state["updated_at"] = now_iso()
            state.setdefault("created_at", state["updated_at"])
            if os.path.exists(self.state_path):
                try:
                    os.replace(self.state_path, self.backup_path)
                except OSError:
                    pass
            tmp = self.state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2, ensure_ascii=False)
            if os.name == "posix":
                try:
                    os.chmod(tmp, 0o600)   # the key is inside; protect it
                except OSError:
                    pass
            os.replace(tmp, self.state_path)

    def build_state(self, *, roots: list, host: str, port: int,
                    agents: list, settings: dict) -> dict:
        return {
            "roots": [os.path.abspath(r) for r in roots],
            "host": host,
            "port": int(port),
            "agents": [normalize_agent(a) for a in agents],
            "settings": dict(settings),
        }


class History:
    """Append-only JSONL event log with size-based rotation.

    v2: every agent operation (including exec commands and their exit codes)
    is appended here, giving a full audit trail. Keys appear only as
    fingerprints.
    """

    def __init__(self, data_dir: str):
        self.data_dir = os.path.abspath(data_dir)
        os.makedirs(self.data_dir, exist_ok=True)
        self.path = os.path.join(self.data_dir, "history.jsonl")
        self._lock = threading.Lock()

    def append(self, event: dict) -> None:
        event = dict(event)
        event.setdefault("ts", now_iso())
        with self._lock:
            try:
                self._rotate_if_needed()
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")
            except OSError:
                pass  # best-effort

    def _rotate_if_needed(self) -> None:
        try:
            if os.path.getsize(self.path) < HISTORY_ROTATE_BYTES:
                return
            for gen in range(HISTORY_KEEP_GENERATIONS - 1, 0, -1):
                src = self.path if gen == 1 else f"{self.path}.{gen}"
                dst = f"{self.path}.{gen + 1}"
                if os.path.exists(src):
                    os.replace(src, dst)
            os.replace(self.path, self.path + ".1")
        except OSError:
            pass

    def tail(self, n: int = 50) -> list:
        if not os.path.exists(self.path):
            return []
        events: list = []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return []
        return events[-n:]


# ---------------------------------------------------------------------------
# Export / import (portable session files)
# ---------------------------------------------------------------------------

def export_session(state: dict, dest_path: str, notes: str = "") -> dict:
    import platform as _platform
    export = {
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "exported_at": now_iso(),
        "source": {
            "hostname": socket.gethostname(),
            "platform": _platform.platform(),
            "python": sys.version.split()[0],
        },
        "state": state,
        "notes": notes or "",
    }
    os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
    with open(dest_path, "w", encoding="utf-8") as f:
        json.dump(export, f, indent=2, ensure_ascii=False)
    if os.name == "posix":
        try:
            os.chmod(dest_path, 0o600)     # contains keys in plaintext
        except OSError:
            pass
    return export


def import_session(src_path: str) -> dict:
    with open(src_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or data.get("format") != EXPORT_FORMAT:
        raise ValueError("Not an LLMAC session export.")
    if data.get("version") not in (1, EXPORT_VERSION):
        raise ValueError(f"Unsupported export version: {data.get('version')!r}")
    if not isinstance(data.get("state"), dict):
        raise ValueError("Export is missing its 'state' object.")
    return data


def clamp_policy(value) -> str:
    return value if value in VALID_POLICIES else POLICY_DESTRUCTIVE


def set_permissive_umask() -> None:
    """umask 022 so agent-written files are 644/755 — deletable by the user
    without sudo. Called once at host startup."""
    try:
        os.umask(0o022)
    except OSError:
        pass
