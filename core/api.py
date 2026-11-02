"""LLMAC v2 HTTP API: routing, auth, caps, versioning, approvals, sessions.

Design notes
------------
* One handler class, a route table, per-op methods returning plain dicts.
* Auth: multi-agent keys (constant-time compare, expiry aware) with
  per-IP failure rate limiting.
* Caps: request body size, exec timeout, exec output (head+tail capture),
  read size, search results — all enforced SERVER-side; client-sent values
  are clamped, never trusted.
* Concurrency: a general semaphore caps concurrent regular ops; exec gets
  a stricter semaphore. /events and approval waits never hold semaphores
  while blocking.
* Versioning: every write/edit can carry ``expected_version`` (a cheap
  mtime+size token). Mismatch -> 409 version_conflict, so concurrent human
  edits are never clobbered silently.
"""
from __future__ import annotations

import base64
import errno
import gzip
import hashlib
import io
import json
import math
import os
import re
import secrets
import shutil
import subprocess
import tarfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from .constants import (
    APPROVAL_WAIT_MAX, CLI_PATH, DEFAULT_IGNORES, DELETE_CONFIRM_THRESHOLD,
    EXEC_OUTPUT_CAP, EXEC_HEAD_KEEP, EXEC_TAIL_KEEP, EXEC_TIMEOUT_DEFAULT,
    EXEC_TIMEOUT_MAX, EXEC_TIMEOUT_MIN, GZIP_MIN_BYTES, GRANT_MAX_MINUTES,
    HEX_DEFAULT_BYTES, MAX_HEX_DUMP_BYTES, LLMAC_VERSION,
    HEX_FIND_CTX_AFTER, HEX_FIND_CTX_BEFORE, HEX_FIND_MAX_HITS,
    HEX_FIND_MAX_HITS_CAP, HEX_FIND_PATTERN_MAX,
    MAX_ARCHIVE_BYTES, MAX_ARCHIVE_ENTRIES, MAX_BODY_BYTES,
    MAX_BATCH_OPS, MAX_BATCH_RESPONSE_BYTES, MAX_CONCURRENT_EXEC,
    MAX_CONCURRENT_REQUESTS, MAX_DIFF_BYTES, MAX_READ_BYTES,
    MAX_SEARCH_RESULTS, OP_RING_CAP, OVERVIEW_BUDGET_DEFAULT,
    OVERVIEW_BUDGET_MAX, SESSION_LOG_DEFAULT, SESSION_LOG_MAX,
    OVERVIEW_DEPTH_MAX, OVERVIEW_DOC_HEADS_MAX, OVERVIEW_TREE_ENTRIES,
    POLICY_AUTO, POLICY_DESTRUCTIVE, POLICY_FULLAUTO, POLICY_STRICT,
    STAT_HASH_MAX_BYTES, SUDO_APPROVAL_TIMEOUT_S, SUDO_TIMEOUT_MIN_S,
    SUDO_TIMEOUT_MAX_S,
    DEFAULT_SHOT_DIR, MAX_SHOT_WIDTH, SCREEN_INPUT_MAX_EVENTS_DEFAULT,
    SCREEN_INPUT_MAX_MINUTES_DEFAULT, SHOT_JPG_QUALITY,
)
from .state import now_iso
from .sandbox import ProtectedPathError, Sandbox
from .policy import InstallPolicy
from .edits import EditError, apply_edits_atomic, unified_diff
from . import screen as screen_channel
from .screen import (
    DriveSessions, MODIFIER_KEYSYMS, ScreenError, keysym_valid,
    validate_format, validate_max_width, validate_shot_target,
    validate_text,
)

# ---------------------------------------------------------------------------
# Auth: agent registry + per-IP rate limiting
# ---------------------------------------------------------------------------

_AUTH_WINDOW = 60.0
_AUTH_MAX_FAILURES = 5
# Cloud agents can rotate egress IPs, which defeats per-IP limiting (F30).
# Too many failures from ANYWHERE pauses auth for everyone for a while.
_AUTH_GLOBAL_WINDOW = 300.0
_AUTH_GLOBAL_MAX_FAILURES = 40


class AuthError(Exception):
    def __init__(self, status: int, error: str, message: str):
        super().__init__(message)
        self.status, self.error, self.message = status, error, message


class AuthRegistry:
    """Maps keys -> agent dicts; enforces failure rate limiting per IP."""

    def __init__(self, agents: list):
        self._lock = threading.Lock()
        self._agents = list(agents)
        self._failures: dict = {}   # ip -> [timestamps]
        self._global_failures: list = []   # [timestamps], all IPs (F30)

    def update(self, agents: list) -> None:
        with self._lock:
            self._agents = list(agents)

    def _prune_failures(self, ip: str) -> None:
        now = time.monotonic()
        stamps = [t for t in self._failures.get(ip, []) if now - t < _AUTH_WINDOW]
        if stamps:
            self._failures[ip] = stamps
        else:
            self._failures.pop(ip, None)

    def _rate_limited(self, ip: str) -> bool:
        return len(self._failures.get(ip, [])) >= _AUTH_MAX_FAILURES

    def authenticate(self, token: str, ip: str) -> dict:
        """Return the agent dict or raise AuthError."""
        with self._lock:
            self._prune_failures(ip)
            now = time.monotonic()
            self._global_failures = [
                t for t in self._global_failures
                if now - t < _AUTH_GLOBAL_WINDOW]
            if len(self._global_failures) >= _AUTH_GLOBAL_MAX_FAILURES:
                raise AuthError(429, "rate_limited_global",
                                "Too many failed auth attempts from all "
                                "addresses combined. Authentication is "
                                "paused — wait a few minutes.")
            if self._rate_limited(ip):
                raise AuthError(429, "rate_limited",
                                "Too many failed auth attempts from this "
                                "address. Wait 60 seconds.")
            for agent in self._agents:
                if agent.get("key") and secrets.compare_digest(
                        agent["key"], token):
                    exp = agent.get("expires_at")
                    if exp:
                        try:
                            if datetime.fromisoformat(exp) < datetime.now(timezone.utc):
                                raise AuthError(401, "key_expired",
                                                f"Agent '{agent['name']}' "
                                                "key has expired.")
                        except ValueError:
                            pass
                    return agent
            self._failures.setdefault(ip, []).append(time.monotonic())
            self._global_failures.append(time.monotonic())
        raise AuthError(401, "unauthorized", "Invalid or missing key.")


# ---------------------------------------------------------------------------
# Versioning helper
# ---------------------------------------------------------------------------

def file_version(path: str) -> str:
    try:
        st = os.stat(path)
        return f"{st.st_mtime_ns:x}-{st.st_size:x}"
    except OSError:
        return "0-0"


# NUL / other control bytes decode cleanly as UTF-8 but are binary in
# practice. Without this, zero-filled files came back as "text" with every
# NUL json-escaped into 6 chars — 6x response bloat and NUL soup in the
# agent's context (F28).
_BINARYISH_RE = re.compile(rb"[\x00\x01-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _looks_binary(data: bytes) -> bool:
    return _BINARYISH_RE.search(data) is not None


def _hex_dump(data: bytes, base: int = 0) -> str:
    """v2.4.7: xxd-style rendering for `read hex=true` — 16 bytes per
    row, three columns (offset, hex, printable-ascii). The offset column
    carries the ABSOLUTE file offset so agents can jump straight to
    `read --hex --offset` for any byte they spot."""
    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"{base + i:08x}  {hexpart}  |{asciipart}|")
    return "\n".join(rows) + ("\n" if rows else "")


_HEX_NIBBLES = frozenset("0123456789abcdef")


def _hex_find_pattern(find_hex: str, find_text: str) -> tuple:
    """v2.4.8: build + validate the byte pattern for `read hex=true`
    find_hex/find_text — the GOTO/search primitive for binary blobs.
    Returns (pattern_bytes, kind) with kind in {"hex", "text"}; raises
    OpBlocked(400) on bad input (never on a merely absent pattern —
    the caller already checked that one was given)."""
    if find_hex and find_text:
        raise OpBlocked(400, {"error": "find_conflict",
                              "message": "Give EITHER find_hex OR "
                                         "find_text, not both."})
    if find_hex:
        compact = find_hex.replace(" ", "").replace("\t", "").lower()
        if (not compact or len(compact) % 2 != 0
                or not set(compact) <= _HEX_NIBBLES):
            raise OpBlocked(400, {
                "error": "bad_find_hex",
                "message": "find_hex must be even-length hex bytes, e.g. "
                           "'4d5a' or '4d 5a 90 00' (spaces allowed)."})
        pattern = bytes.fromhex(compact)
        kind = "hex"
    else:
        pattern = find_text.encode("utf-8")
        kind = "text"
    if not pattern:
        raise OpBlocked(400, {"error": "empty_pattern",
                              "message": "The find pattern is empty."})
    if len(pattern) > HEX_FIND_PATTERN_MAX:
        raise OpBlocked(400, {
            "error": "find_pattern_too_long",
            "message": f"Pattern is {len(pattern)} B; the cap is "
                       f"{HEX_FIND_PATTERN_MAX} B. Narrow the pattern."})
    return pattern, kind


_HEX_FIND_CHUNK = 1024 * 1024      # scan chunk size; the last
                                   # (len(pattern)-1) bytes carry over
                                   # so a hit spanning a chunk boundary
                                   # is never missed


def _hex_find_scan(path: str, start: int, pattern: bytes,
                   max_hits: int) -> tuple:
    """Scan a file for `pattern` from absolute byte `start`. Chunked
    (no whole-file loads: DXHRDC.exe-sized blobs stay cheap), returns
    (hits, more): absolute offsets of at most max_hits matches, and
    whether the scan was cut at the hit cap (more may exist past the
    last hit — continue from last_hit+1)."""
    plen = len(pattern)
    hits: list = []
    with open(path, "rb") as f:
        f.seek(max(0, start))
        file_pos = f.tell()
        overlap = b""
        while True:
            chunk = f.read(_HEX_FIND_CHUNK)
            if not chunk:
                break
            buf = overlap + chunk
            base = file_pos - len(overlap)
            i = buf.find(pattern)
            while i >= 0 and len(hits) < max_hits:
                hits.append(base + i)
                i = buf.find(pattern, i + 1)
            file_pos += len(chunk)
            if len(hits) >= max_hits:
                break
            overlap = buf[-(plen - 1):] if plen > 1 else b""
    return hits, len(hits) >= max_hits


# ---------------------------------------------------------------------------
# Bounded exec output capture (head + tail)
# ---------------------------------------------------------------------------

class _BoundedCapture:
    """Collects up to cap bytes keeping head and tail slices.

    v2.3.1: bytearray-backed with amortized compaction. The previous
    bytes-concat per line was quadratic once past the cap — a 3M-line
    command pinned a core for ~30s server-side while the client's HTTP
    timeout reported a transport failure for a command that actually
    completed (F20).
    """

    def __init__(self, cap: int = EXEC_OUTPUT_CAP):
        self.cap = cap
        self.total = 0
        self._lock = threading.Lock()
        self._head = bytearray()
        self._tail = bytearray()

    @property
    def head(self) -> bytes:
        return bytes(self._head)

    @property
    def tail(self) -> bytes:
        return bytes(self._tail)

    def feed(self, chunk: bytes) -> None:
        with self._lock:
            self.total += len(chunk)
            if self.total <= self.cap:
                self._head += chunk
                return
            # Over cap: keep the first EXEC_HEAD_KEEP bytes, then a rolling
            # EXEC_TAIL_KEEP window. The tail compacts only when it has
            # doubled, so the cost per byte is amortized O(1).
            if len(self._head) < EXEC_HEAD_KEEP:
                room = EXEC_HEAD_KEEP - len(self._head)
                self._head += chunk[:room]
                chunk = chunk[room:]
                if not chunk:
                    return
            self._tail += chunk
            if len(self._tail) > 2 * EXEC_TAIL_KEEP:
                del self._tail[: len(self._tail) - EXEC_TAIL_KEEP]

    def text(self) -> str:
        with self._lock:
            if self.total <= self.cap:
                data = bytes(self._head)
            else:
                marker = (f"\n...[{self.total - self.cap} bytes truncated, "
                         f"{self.total} total]...\n").encode()
                data = bytes(self._head) + marker + bytes(self._tail)
        return data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# App context (shared mutable state between server, GUI, headless runner)
# ---------------------------------------------------------------------------

class AppContext:
    def __init__(self, sandbox: Sandbox, agents: list, settings: dict,
                 policy: InstallPolicy, sessions, approvals, events, procs,
                 history, state_store, log_callback=None):
        self.sandbox = sandbox
        self.auth = AuthRegistry(agents)
        self.settings = settings              # mutable dict
        self.policy = policy
        self.sessions = sessions
        self.approvals = approvals
        self.events = events
        self.procs = procs
        self.history = history
        self.state_store = state_store
        self.log_callback = log_callback
        # v2.5.2 (ASK-010): server-side op-log retention — a bounded ring
        # of {seq, ts, agent, level, msg} for the WHOLE host; the SCOPING
        # happens at read time, by authentication (op_log_slice). Backs
        # POST /session/log; the GUI callback keeps its full view.
        self.op_ring: list = []
        self._op_ring_lock = threading.Lock()
        self._op_ring_seq = 0
        # Roots auto-added server-side (policy 'auto_all'). The owner app
        # (GUI poll timer / headless drain thread) drains this list on its
        # own thread and persists the change — the server never writes
        # state.json directly.
        self.share_queue: list = []
        # v2.4.6: sudo password, GUI-set, MEMORY-ONLY. Never persisted to
        # state.json (it deliberately does NOT live in self.settings,
        # which build_state() writes to disk), never returned by any
        # handler, never logged — the ONLY consumer is _run_exec, which
        # pipes it to `sudo -S` stdin after a human approved the command.
        # No API route reads or writes it: setting it through the API
        # would give an agent a password-guessing oracle. Plain attribute
        # assignment is atomic under the GIL, so a GUI write racing a
        # request thread can only pick up the old or the new value.
        self.sudo_password: str | None = None
        # v2.7.0 (ASK-016/017): the screen channel. ctx.screen is the
        # capture service (None on a headless host -> screen_unavailable
        # naming it); ctx.input is the injection backend (X11/XTest,
        # None when unreachable). The drive-session registry and the
        # until-restart session grants are MEMORY-ONLY by design: both
        # die with the process — a restart revokes every screen grant
        # and closes every drive session, no matter what state.json says.
        self.screen = None
        self.input = None
        self.screen_drive = DriveSessions()
        self.screen_session_grants: dict = {}
        # Semaphores
        self._req_sem = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)
        self._exec_sem = threading.BoundedSemaphore(MAX_CONCURRENT_EXEC)

    def acquire(self, timeout: float = 15.0) -> bool:
        return self._req_sem.acquire(timeout=timeout)

    def release(self) -> None:
        try:
            self._req_sem.release()
        except ValueError:
            pass

    def acquire_exec(self) -> bool:
        return self._exec_sem.acquire(timeout=30)

    def release_exec(self) -> None:
        try:
            self._exec_sem.release()
        except ValueError:
            pass

    def op_log(self, level: str, msg: str, agent=None) -> None:
        # v2.5.2 (ASK-009/010): `agent` (dict or name string) rides the
        # log entry — the GUI Log-tab filter and the agent-scoped
        # /session/log view are both built on it.
        name = (agent.get("name") if isinstance(agent, dict)
                else (str(agent) if agent else None))
        with self._op_ring_lock:
            self._op_ring_seq += 1
            self.op_ring.append({
                "seq": self._op_ring_seq, "ts": now_iso(),
                "agent": name, "level": level, "msg": msg})
            if len(self.op_ring) > OP_RING_CAP:
                del self.op_ring[: len(self.op_ring) - OP_RING_CAP]
        cb = self.log_callback
        if cb is not None:
            try:
                cb(("OP", level, msg, name))
            except Exception:
                pass

    def op_log_slice(self, agent: str, after: int = 0,
                     limit: int = SESSION_LOG_DEFAULT) -> tuple:
        """ASK-010: ONLY this agent's ring entries (seq > after, up to
        limit). The caller passes the AUTHENTICATED name — a client
        may never widen its own scope. Returns (entries, next_after);
        entries are copies (callers can mutate freely)."""
        with self._op_ring_lock:
            entries = [dict(e) for e in self.op_ring
                       if e["agent"] == agent and e["seq"] > after]
        if limit > 0:
            entries = entries[:limit]
        return entries, (entries[-1]["seq"] if entries else after)

    def audit(self, **kv) -> None:
        if self.history is not None:
            self.history.append({"type": "op", **kv})


# ---------------------------------------------------------------------------
# Permission / policy helpers
# ---------------------------------------------------------------------------

class OpBlocked(Exception):
    """Raised when an op is rejected by policy/approval. status + body."""

    def __init__(self, status: int, body: dict):
        super().__init__(body.get("error", "blocked"))
        self.status, self.body = status, body


def _os_error_response(e: OSError) -> tuple:
    """Map user-caused OSErrors to clean 4xx JSON instead of raw 500
    'internal' dumps (F5): errno + strerror + filename, no noise."""
    what = e.strerror or str(e)
    fname = getattr(e, "filename", None) or ""
    msg = f"{what}: {fname}" if fname else what
    if e.errno in (errno.EACCES, errno.EPERM):
        return (403, {
            "error": "access_denied",
            "message": msg + " — the OS refused (restrictive file mode?). "
                      "Use exec to 'chmod -R u+w' the tree, then retry.",
        })
    if e.errno == errno.ENOENT:
        return (404, {"error": "not_found", "message": msg})
    return (400, {"error": "os_error", "errno": e.errno, "message": msg})


def _agent_paths(ctx: AppContext, agent: dict) -> list:
    return ctx.sandbox.roots_for(agent.get("roots") or [])


def resolve_for_agent(ctx: AppContext, agent: dict, target: str) -> str:
    """Sandbox-check + agent-scope-check. Raises PermissionError."""
    path = ctx.sandbox.resolve(target)     # global containment (realpath)
    eff = _agent_paths(ctx, agent)
    if not eff:
        raise PermissionError(
            "This agent has no roots in scope (share was removed).")
    real = os.path.realpath(path)
    for r in eff:
        if real == r or real.startswith(r + os.sep):
            return path
    raise PermissionError(
        f"Path '{target}' is not within this agent's allowed roots.")


def need_perm(agent: dict, perm: str) -> None:
    if not agent.get("perms", {}).get(perm):
        raise OpBlocked(403, {
            "error": "permission_denied",
            "message": f"Agent '{agent['name']}' lacks the '{perm}' "
                      f"permission for this operation.",
        })


# ---------------------------------------------------------------------------
# Time-boxed approval grants (Tier 2: approve once, stop re-clicking)
# ---------------------------------------------------------------------------

def _active_grants(ctx: AppContext, agent: dict) -> list:
    """Live grants for this agent (expired/foreign entries filtered out)."""
    now = datetime.now(timezone.utc)
    out = []
    for g in (ctx.settings.get("grants") or []):
        try:
            exp = datetime.fromisoformat(g.get("expires_at"))
        except (TypeError, ValueError):
            continue
        if exp <= now:
            continue
        if g.get("agent") not in (None, agent["name"]):
            continue
        out.append(g)
    return out


def _grant_covers(ctx: AppContext, agent: dict, op: str, path: str) -> bool:
    """True if a live grant covers `op` on `path` (scope prefix match)."""
    if not path:
        return False
    try:
        real = os.path.realpath(path)
    except OSError:
        return False
    for g in _active_grants(ctx, agent):
        if op not in (g.get("ops") or []):
            continue
        scope = g.get("scope") or ""
        if not scope or real == scope or real.startswith(scope + os.sep):
            return True
    return False


def add_grant(ctx: AppContext, agent_name: str, op: str, scope: str,
              minutes: int) -> dict:
    """Create (or extend) a live grant. Called by the GUI on
    approve-with-grant; the caller persists settings afterwards."""
    minutes = max(1, min(int(minutes), GRANT_MAX_MINUTES))
    scope_real = os.path.realpath(scope)
    grants = ctx.settings.setdefault("grants", [])
    now = datetime.now(timezone.utc)
    for g in grants:
        if g.get("agent") != agent_name or g.get("scope") != scope_real:
            continue
        try:
            exp = datetime.fromisoformat(g["expires_at"])
        except (KeyError, TypeError, ValueError):
            continue
        if exp > now:
            # Extend the existing grant for this scope: add the op and
            # push expiry out from now.
            ops = g.setdefault("ops", [])
            if op not in ops:
                ops.append(op)
            g["expires_at"] = (now + timedelta(minutes=minutes)).isoformat(
                timespec="seconds")
            return g
    grant = {
        "id": "gra_" + uuid.uuid4().hex[:12],
        "agent": agent_name,
        "ops": [op],
        "scope": scope_real,
        "created_at": now_iso(),
        "created_by": "host",
        "expires_at": (now + timedelta(minutes=minutes)).isoformat(
            timespec="seconds"),
    }
    # Drop expired entries so the list cannot grow without bound.
    alive = []
    for g in grants:
        try:
            if datetime.fromisoformat(g.get("expires_at")) > now:
                alive.append(g)
        except (TypeError, ValueError):
            continue
    ctx.settings["grants"] = alive + [grant]
    return grant


def maybe_gate(ctx: AppContext, agent: dict, op: str, summary: str,
               detail: str = "", wait: bool = True,
               path: str = "", forced: bool = False,
               expires_in: float | None = None,
               timeout_action: str | None = None) -> None:
    """Create an approval request if policy requires it; block for the
    decision. Raises OpBlocked(403 approval_denied) if denied. A live
    grant covering `op` + `path` short-circuits the whole flow.

    v2.4.5 `forced=True`: gate REGARDLESS of approval_policy — used for
    sudo package installs (the user's rule: those ALWAYS prompt, even
    under auto_all) and with an optional countdown (expires_in seconds;
    on expiry the registry auto-resolves per timeout_action, which was
    baked in from the security-panel setting at create time). Grants
    are deliberately NOT consulted when forced — a sudo install is
    never covered by an earlier blanket approval.
    """
    if not forced:
        policy_mode = ctx.settings.get("approval_policy", POLICY_DESTRUCTIVE)
        if policy_mode in (POLICY_AUTO, POLICY_FULLAUTO):
            return
        if path and _grant_covers(ctx, agent, op, path):
            ctx.op_log("OK", f"GRANT covers {op} on {path} "
                              f"(agent {agent['name']})", agent=agent)
            return
    aid = ctx.approvals.create(agent["name"], op, summary, detail,
                               payload={"path": path} if path else None,
                               expires_in=expires_in,
                               timeout_action=timeout_action)
    ctx.op_log("WARN", f"APPROVAL REQUIRED [{aid}] {op}: {summary}"
                       + (f" (auto-{timeout_action} in "
                          f"{int(expires_in)}s)" if expires_in else ""),
              agent=agent)
    if not wait:
        raise OpBlocked(202, {
            "error": "approval_pending", "approval_id": aid,
            "message": "This operation requires host approval. Poll it "
                       "with approvals wait.",
        })
    status = ctx.approvals.wait(aid, APPROVAL_WAIT_MAX)
    if status == "approved":
        ctx.op_log("OK", f"APPROVAL GRANTED [{aid}] {op}", agent=agent)
        return
    if status == "pending":
        raise OpBlocked(202, {
            "error": "approval_pending", "approval_id": aid,
            "message": "Host has not decided yet. Poll with "
                       "approvals wait --id " + aid,
        })
    raise OpBlocked(403, {
        "error": "approval_denied", "approval_id": aid,
        "message": ("The host denied this operation"
                    + (" (sudo approval timed out — the security panel "
                        "is set to auto-reject)."
                        if forced else ".")),
    })


def _sudo_timeout_s(ctx: AppContext) -> float:
    """Countdown seconds for sudo-install approvals. Default 120; the
    settings key exists so tests can shorten it and hosts can tune it —
    the GUI deliberately exposes only the timeout ACTION, not seconds."""
    try:
        v = float(ctx.settings.get("sudo_timeout_s", SUDO_APPROVAL_TIMEOUT_S))
    except (TypeError, ValueError):
        v = SUDO_APPROVAL_TIMEOUT_S
    return max(SUDO_TIMEOUT_MIN_S, min(v, SUDO_TIMEOUT_MAX_S))


def _sudo_timeout_action(ctx: AppContext) -> str:
    """Security-panel setting: what a sudo approval does when its 2-min
    countdown elapses. 'reject' (fail closed) or 'approve'."""
    return "approve" if ctx.settings.get(
        "sudo_timeout_action", "reject") == "approve" else "reject"


def _policy_gates_write(ctx: AppContext) -> bool:
    return ctx.settings.get("approval_policy") == POLICY_STRICT


def _policy_gates_exec(ctx: AppContext) -> bool:
    return ctx.settings.get("approval_policy") == POLICY_STRICT


def _policy_gates_delete(ctx: AppContext, recursive: bool, count: int) -> bool:
    mode = ctx.settings.get("approval_policy")
    if mode == POLICY_STRICT:
        return True
    if mode == POLICY_DESTRUCTIVE:
        return recursive or count > 5
    return False


_PROTECTED_NAMES = {".git"}


def _check_protected(ctx: AppContext, path: str) -> None:
    """Reject ops on a shared root itself or on any .git directory."""
    real = os.path.realpath(path)
    if real in ctx.sandbox.roots:
        raise OpBlocked(403, {
            "error": "protected_path",
            "message": "Refusing to modify/delete a shared root itself. "
                      "Remove the share from the host GUI instead.",
        })
    for root in ctx.sandbox.roots:
        if real.startswith(root + os.sep):
            rel_parts = os.path.relpath(real, root).split(os.sep)
            if any(p in _PROTECTED_NAMES for p in rel_parts):
                raise OpBlocked(403, {
                    "error": "protected_path",
                    "message": "Refusing to touch .git directories — they "
                              "are the host's undo mechanism.",
                })
            break


def _count_dir(path: str, cap: int = 100000) -> int:
    n = 0
    for _root, _dirs, files in os.walk(path):
        n += len(files)
        if n >= cap:
            break
    return n


# ---------------------------------------------------------------------------
# The request handler
# ---------------------------------------------------------------------------

POST_ROUTES = {}
GET_ROUTES = {}


def route(method: str, path: str):
    def deco(fn):
        if method == "POST":
            POST_ROUTES[path] = fn
        else:
            GET_ROUTES[path] = fn
        return fn
    return deco


class RawResponse:
    """A non-JSON response (archive download). Handlers return this to make
    the dispatcher emit raw bytes with the given content type."""

    def __init__(self, body: bytes, content_type: str = "application/gzip",
                 meta: dict | None = None):
        self.body = body
        self.content_type = content_type
        self.meta = meta or {}


def _stamp_unread(h, headers: dict) -> None:
    """v2.5.1 (ASK-005): the ENFORCED notice — every authenticated
    response carries the acting agent's unread inbox count, so an
    agent cannot run ANY op without the message state appearing in
    its context (the CLI turns this into a loud banner).
    Set by _auth; per-request, never per-connection."""
    name = getattr(h, "_unread_agent", None)
    if not name:
        return
    try:
        headers["X-LLMAC-Unread"] = str(
            h.ctx.sessions.get(name).unread_count())
    except Exception:
        pass


class LLMACRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"      # keep-alive by default (Tier 1)
    ctx: AppContext = None
    server_version = f"LLMAC/{LLMAC_VERSION}"

    # ---- plumbing ---------------------------------------------------------

    def _send_json(self, status: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8"}
        _stamp_unread(self, headers)   # v2.5.1 (ASK-005)
        # Tier 1: gzip large JSON bodies when the client asks for it.
        if ("gzip" in (self.headers.get("Accept-Encoding") or "").lower()
                and len(body) >= GZIP_MIN_BYTES):
            body = gzip.compress(body, 6)
            headers["Content-Encoding"] = "gzip"
            headers["Vary"] = "Accept-Encoding"
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        # Tier 1: no forced "Connection: close" — HTTP/1.1 keep-alive lets
        # agents reuse one TCP+TLS session across many ops.
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_raw(self, status: int, body: bytes, content_type: str,
                  meta: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        # v2.5.1 (ASK-005): the notice rides raw responses too
        # (archive streams, binary transfers). Direct full-name send —
        # the meta loop below adds its own X-LLMAC- prefix.
        _u = {}
        _stamp_unread(self, _u)
        for k, v in _u.items():
            self.send_header(k, v)
        for k, v in (meta or {}).items():
            self.send_header(f"X-LLMAC-{str(k).title()}", str(v))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _auth(self) -> dict:
        # v2.5.1 (ASK-005): stamp state is per-REQUEST — clear first
        # (a keep-alive connection reuses one handler instance).
        self._unread_agent = None
        auth = self.headers.get("Authorization", "")
        token = (auth[7:].strip() if auth.startswith("Bearer ")
                 else auth.strip())
        if not token:
            token = self.headers.get("X-API-Key", "").strip()
        try:
            agent = self.ctx.auth.authenticate(token, self.client_address[0])
        except AuthError as e:
            self._send_json(e.status, {"error": e.error, "message": e.message})
            return None
        # v2.5.1 (ASK-005): stash the acting agent for the response
        # chokepoints — _send_json/_send_raw stamp X-LLMAC-Unread.
        self._unread_agent = agent.get("name")
        return agent

    def log_message(self, fmt, *args):
        msg = (f"[{time.strftime('%H:%M:%S')}] "
               f"{self.address_string()} - {fmt % args}")
        cb = self.ctx.log_callback if self.ctx else None
        if cb is not None:
            try:
                cb(msg)
            except Exception:
                pass

    def _read_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length > MAX_BODY_BYTES:
            # Drain (bounded) so well-behaved clients can finish sending
            # and read our clean 413 instead of hitting a broken pipe.
            remaining = min(length, 256 * 1024 * 1024)
            try:
                while remaining > 0:
                    chunk = self.rfile.read(min(65536, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
            except OSError:
                pass
            raise OpBlocked(413, {
                "error": "body_too_large",
                "message": f"Request body exceeds {MAX_BODY_BYTES} bytes. "
                           "Write files in smaller chunks.",
            })
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise OpBlocked(400, {"error": "bad_request",
                                   "message": f"Invalid JSON: {e}"})
        return payload if isinstance(payload, dict) else {}

    # ---- dispatch -----------------------------------------------------------

    def do_GET(self):
        self._unread_agent = None   # v2.5.1 (ASK-005): per-request
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/health":
            self._send_json(200, {"status": "ok", "server": "llmac",
                                  "version": LLMAC_VERSION})
            return
        agent = self._auth()
        if agent is None:
            return
        if path in GET_ROUTES:
            query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            try:
                resp = GET_ROUTES[path](self, self.ctx, agent, query)
                status = 200
                if isinstance(resp, tuple):
                    resp, status = resp
                if isinstance(resp, RawResponse):
                    self._send_raw(200, resp.body, resp.content_type,
                                   resp.meta)
                else:
                    self._send_json(status, resp)
            except OpBlocked as e:
                self._send_json(e.status, e.body)
            except ProtectedPathError as e:
                self._send_json(403, {"error": "protected_path",
                                      "message": str(e)})
            except PermissionError as e:
                self._send_json(403, {"error": "forbidden", "message": str(e)})
            except OSError as e:
                status, body = _os_error_response(e)
                self._send_json(status, body)
            except Exception as e:
                self._send_json(500, {"error": "internal",
                                      "message": f"{type(e).__name__}: {e}"})
            return
        self._send_json(404, {"error": "not_found", "path": path})

    def do_POST(self):
        self._unread_agent = None   # v2.5.1 (ASK-005): per-request
        path = urlparse(self.path).path
        agent = self._auth()
        if agent is None:
            return
        handler = POST_ROUTES.get(path)
        if handler is None:
            self._send_json(404, {"error": "not_found", "path": path})
            return
        try:
            payload = self._read_body()
        except OpBlocked as e:
            self._send_json(e.status, e.body)
            return
        # Long-polling endpoints must NOT hold the general semaphore while
        # they block — otherwise a handful of waiters starves every other op.
        needs_semaphore = path not in ("/approvals/wait",)
        if needs_semaphore:
            if not self.ctx.acquire():
                self._send_json(503, {
                    "error": "server_busy",
                    "message": "Too many concurrent operations; retry shortly.",
                })
                return
        try:
            resp = handler(self, self.ctx, agent, payload)
            status = 200
            if isinstance(resp, tuple):
                resp, status = resp
            self._send_json(status, resp)
        except OpBlocked as e:
            self._send_json(e.status, e.body)
        except ProtectedPathError as e:
            self._send_json(403, {"error": "protected_path",
                                  "message": str(e)})
        except PermissionError as e:
            self._send_json(403, {"error": "forbidden", "message": str(e)})
        except FileNotFoundError as e:
            self._send_json(404, {"error": "not_found", "message": str(e)})
        except EditError as e:
            self._send_json(400, {"error": "edit_failed", "message": str(e)})
        except OSError as e:
            status, body = _os_error_response(e)
            self._send_json(status, body)
        except Exception as e:
            self._send_json(500, {"error": "internal",
                                  "message": f"{type(e).__name__}: {e}"})
        finally:
            if needs_semaphore:
                self.ctx.release()


# ---------------------------------------------------------------------------
# Handlers: identity / bootstrap / events
# ---------------------------------------------------------------------------

@route("GET", "/info")
def h_info(h, ctx: AppContext, agent: dict, q: dict) -> dict:
    # v2.4.2: prune remembered venvs that no longer exist on disk
    # (e.g. the agent deleted its venv) so /info self-heals without a
    # restart. Remembered entries are always venv ROOTS created via
    # `python -m venv X`, so a pyvenv.cfg at the root is the liveness
    # test. Cheapest possible stat per venv; the set is tiny.
    # v2.4.3: pruning touches ONLY the discovered set — the configured
    # allow-list is human-managed (GUI/settings) and must survive /info
    # even if its directory is (temporarily) missing.
    for v in [v for v in ctx.policy.discovered_venvs
              if not os.path.isfile(os.path.join(v, "pyvenv.cfg"))]:
        ctx.policy.discovered_venvs.discard(v)
    return {
        "server": "llmac",
        "version": LLMAC_VERSION,
        "agent": {
            "name": agent["name"],
            "perms": agent.get("perms", {}),
            "expires_at": agent.get("expires_at"),
        },
        "roots": _agent_paths(ctx, agent),
        "exec_enabled": bool(ctx.settings.get("allow_exec")),
        "approval_policy": ctx.settings.get("approval_policy"),
        # True when the host runs 'auto_all': share requests are granted
        # instantly (agent-driven sandbox expansion).
        "roots_auto_approved":
            ctx.settings.get("approval_policy") == POLICY_FULLAUTO,
        # An agent with zero roots is not stranded: it can ask for a share
        # (human-gated under every policy except 'auto_all').
        "can_request_roots": True,
        "tls": bool(ctx.settings.get("tls")),
        # v2.4.3: "venvs" is now purely the CONFIGURED allow-list
        # (settings / GUI card); agent-created venvs are reported
        # separately so clients — and the GUI — can render the two
        # concepts distinctly instead of one opaque merged set.
        "venvs": sorted(ctx.policy.venvs),
        "venvs_discovered": sorted(ctx.policy.discovered_venvs),
        "procs_running": sum(1 for p in ctx.procs.list() if p["running"]),
    }


@route("GET", "/grants")
def h_grants(h, ctx: AppContext, agent: dict, q: dict) -> dict:
    """Live approval grants for this agent (Tier 2)."""
    return {"grants": _active_grants(ctx, agent)}


@route("GET", "/bootstrap")
@route("POST", "/bootstrap")
def h_bootstrap(h, ctx: AppContext, agent: dict, q: dict) -> dict:
    """Serve the CLI client so an agent can self-install.

    Registered for both GET (what the generated one-liner uses) and POST
    (defensive: some hand-rolled clients pass an empty body, which makes
    urllib switch to POST — accept that too rather than 404).
    """
    try:
        with open(CLI_PATH, "r", encoding="utf-8") as f:
            cli_src = f.read()
    except OSError:
        # 503: the service exists but the client file is missing right now.
        raise OpBlocked(503, {
            "error": "bootstrap_unavailable",
            "message": "cli.py is not present on the host."})
    return {
        "name": "llmac.py",
        "cli_py": cli_src,
        "cli_sha256": hashlib.sha256(cli_src.encode("utf-8")).hexdigest(),
        "version": LLMAC_VERSION,
        "hint": "Write cli_py to a file named llmac.py, then run: "
                "python3 llmac.py connect --host <host> --port <port> "
                "--key <key> --save. The connection block's one-liner "
                "verifies the cert fingerprint and this cli_sha256 "
                "before writing anything.",
    }


@route("GET", "/events")
def h_events(h, ctx: AppContext, agent: dict, q: dict) -> dict:
    since = 0
    wait = 25.0
    try:
        since = int(q.get("since", "0"))
    except ValueError:
        pass
    try:
        wait = float(q.get("wait", "25"))
    except ValueError:
        pass
    events = ctx.events.wait(since, wait)
    return {
        "events": events,
        "last_seq": ctx.events.latest_seq(),
    }


# ---------------------------------------------------------------------------
# Handlers: reads
# ---------------------------------------------------------------------------

@route("POST", "/list")
def h_list(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    target = p.get("path", "")
    if not target:
        entries = [{"name": os.path.basename(r) or r, "path": r,
                    "type": "dir"} for r in _agent_paths(ctx, agent)]
        ctx.sessions.record(agent["name"], "list", "roots", kind="read")
        return {"entries": entries, "path": ""}
    folder = resolve_for_agent(ctx, agent, target)
    if not os.path.isdir(folder):
        raise OpBlocked(400, {"error": "not_a_directory", "path": folder})
    entries = []
    with os.scandir(folder) as it:
        for e in sorted(it, key=lambda x: x.name):
            try:
                entries.append({
                    "name": e.name,
                    "path": os.path.join(folder, e.name),
                    "type": "dir" if e.is_dir() else "file",
                    "size": e.stat().st_size if e.is_file() else None,
                })
            except OSError:
                continue
    ctx.sessions.record(agent["name"], "list", folder, folder, "read")
    return {"entries": entries, "path": folder}


@route("POST", "/tree")
def h_tree(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    from .search import tree as build_tree
    roots = _agent_paths(ctx, agent)
    target = p.get("path", "")
    depth = p.get("depth", 3)
    include_hidden = bool(p.get("all", False))
    if not target:
        out = {"roots": roots, "trees": []}
        for r in roots:
            t = build_tree(r, depth=depth, include_hidden=include_hidden,
                           protected=ctx.sandbox.protected)
            out["trees"].append(t)
            if any(t2.get("truncated") for t2 in out["trees"]):
                break
        out["truncated"] = any(t.get("truncated") for t in out["trees"])
        return out
    path = resolve_for_agent(ctx, agent, target)
    if not os.path.isdir(path):
        raise OpBlocked(400, {"error": "not_a_directory", "path": path})
    return build_tree(path, depth=depth, include_hidden=include_hidden,
                      protected=ctx.sandbox.protected)


@route("POST", "/read")
def h_read(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    target = p.get("path", "")
    if not target:
        raise OpBlocked(400, {"error": "missing_field", "field": "path"})
    path = resolve_for_agent(ctx, agent, target)
    if not os.path.isfile(path):
        raise OpBlocked(404, {"error": "not_found", "path": path,
                              "message": f"No such file: {path}"})
    version = file_version(path)

    if (str(p.get("find_hex", "") or "").strip()
            or str(p.get("find_text", "") or "")) \
            and not p.get("hex"):
        # v2.4.8: find rides the hex reader — hex offsets and rendered
        # context are the whole point; silently ignoring it would be a
        # confusing no-op.
        raise OpBlocked(400, {
            "error": "find_needs_hex",
            "message": "find_hex/find_text ride the hex=true reader "
                       "(absolute hex offsets + context); add hex=true."})

    # v2.4.9 (lesson #11): the Task 28 payload mistake — a bare max_hits
    # in a read op was silently ignored (the field is find_max_hits),
    # and a cap without a scan had nowhere to go. Loud 400s, direct AND
    # batch read ops alike.
    if "max_hits" in p:
        raise OpBlocked(400, {
            "error": "max_hits_unknown_field",
            "message": "read ops cap scans with find_max_hits "
                       "(find_hex/find_text); a bare max_hits would be "
                       "silently ignored."})
    if p.get("find_max_hits") and not (str(p.get("find_hex", "") or
                                            "").strip()
                                       or p.get("find_text")):
        raise OpBlocked(400, {
            "error": "find_max_hits_needs_find",
            "message": "find_max_hits caps a find_hex/find_text scan; "
                       "add a find pattern."})

    from_line = p.get("from_line")
    to_line = p.get("to_line")
    offset = p.get("offset")
    limit = p.get("limit")
    numbered = bool(p.get("numbered", False))
    max_bytes = min(int(p.get("max_bytes") or MAX_READ_BYTES), MAX_READ_BYTES)

    size = os.path.getsize(path)
    with open(path, "rb") as f:
        if p.get("hex"):
            # v2.4.7: server-side hex dump — the RE primitive for binary
            # blobs. Byte slicing via offset/limit (default slice
            # HEX_DEFAULT_BYTES, hard cap MAX_HEX_DUMP_BYTES), rendering
            # happens on the host so the response stays ~4x the bytes
            # instead of the 6x JSON-escaping a raw binary read costs.
            if from_line is not None or to_line is not None:
                raise OpBlocked(400, {
                    "error": "hex_lines_conflict",
                    "message": "hex=true slices BYTES; drop from_line/"
                               "to_line and use offset/limit."})
            find_hex = str(p.get("find_hex", "") or "").strip()
            find_text = str(p.get("find_text", "") or "")
            if find_hex or find_text:
                # v2.4.8: hex FIND — scan for a byte pattern from `offset`
                # (paging: next_offset continues after the last hit) and
                # return each hit with a rendered hex CONTEXT whose
                # rows carry absolute offsets, so `read --hex --offset`
                # is one call away from any byte seen here. The GOTO
                # half of the primitive already existed: --offset.
                if limit is not None:
                    raise OpBlocked(400, {
                        "error": "find_limit_conflict",
                        "message": "find scans for a pattern — drop limit "
                                   "and page with offset (next_offset "
                                   "continues after the last hit); bound "
                                   "the response with find_max_hits."})
                pattern, kind = _hex_find_pattern(find_hex, find_text)
                max_hits = max(1, min(int(p.get("find_max_hits")
                                           or HEX_FIND_MAX_HITS),
                                      HEX_FIND_MAX_HITS_CAP))
                h_offset = max(0, int(offset or 0))
                hits, more = _hex_find_scan(path, h_offset, pattern,
                                            max_hits)
                matches = []
                for hit in hits:
                    ctx_start = max(0, (hit - HEX_FIND_CTX_BEFORE) & ~15)
                    ctx_end = min(size, hit + len(pattern)
                                  + HEX_FIND_CTX_AFTER)
                    f.seek(ctx_start)
                    matches.append({
                        "offset": hit,
                        "context": _hex_dump(
                            f.read(ctx_end - ctx_start), ctx_start)})
                ctx.sessions.record(agent["name"], "read", path, path,
                                    "read")
                return {"path": path, "hex": True,
                        "find": {"kind": kind,
                                 "pattern_hex": pattern.hex(),
                                 "pattern_len": len(pattern),
                                 "scan_from": h_offset},
                        "matches": matches, "match_count": len(matches),
                        "more": more, "version": version, "size": size,
                        "next_offset": (hits[-1] + 1) if (hits and more)
                        else None}
            h_offset = max(0, int(offset or 0))
            f.seek(h_offset)
            want = HEX_DEFAULT_BYTES if limit is None else max(1, int(limit))
            want = min(want, MAX_HEX_DUMP_BYTES)
            h_data = f.read(want)
            h_truncated = size > h_offset + len(h_data)
            ctx.sessions.record(agent["name"], "read", path, path, "read")
            return {"path": path, "content": _hex_dump(h_data, h_offset),
                    "hex": True, "binary": _looks_binary(h_data),
                    "dump_bytes": len(h_data), "truncated": h_truncated,
                    "version": version, "size": size,
                    "next_offset": (h_offset + len(h_data))
                    if h_truncated else None}
        if offset is not None:
            offset = max(0, int(offset))
            f.seek(offset)
            n = max_bytes if limit is None else min(int(limit), max_bytes)
            data = f.read(n)
        else:
            data = f.read(max_bytes)

    truncated = size > (offset or 0) + len(data)
    # Binary-looking content (NUL / control bytes that still decode as
    # UTF-8) is returned as base64 — never as json-escaped text (F28).
    if _looks_binary(data):
        return {"path": path,
                "content_b64": base64.b64encode(data).decode(),
                "binary": True, "truncated": truncated, "version": version,
                "size": size, "next_offset": (offset or 0) + len(data)
                if truncated else None}

    if from_line is not None or to_line is not None:
        # Line-range read (text): decode whole file up to cap then slice.
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise OpBlocked(400, {"error": "binary_file",
                                  "message": "Line-range reads need a text "
                                  "file. Use offset/limit for binary."})
        lines = text.split("\n")
        # A trailing newline creates a phantom empty last element — drop it.
        if lines and lines[-1] == "":
            lines.pop()
        s = max(1, int(from_line or 1))
        e = min(len(lines), int(to_line or len(lines)))
        if s > len(lines) or e < s:
            raise OpBlocked(400, {"error": "range_invalid",
                                  "message": f"lines {s}-{e} invalid for "
                                  f"{len(lines)} lines."})
        sel = lines[s - 1:e]
        if numbered:
            out_text = "\n".join(
                f"{i:>6}\t{ln}" for i, ln in zip(range(s, e + 1), sel))
        else:
            out_text = "\n".join(sel)
        return {
            "path": path, "content": out_text, "binary": False,
            "lines": [s, e], "total_lines": len(lines),
            "version": version,
        }

    try:
        text = data.decode("utf-8")
        if numbered:
            lines = text.split("\n")
            text = "\n".join(f"{i:>6}\t{ln}"
                             for i, ln in enumerate(lines, start=1))
        ctx.sessions.record(agent["name"], "read", path, path, "read")
        return {"path": path, "content": text, "binary": False,
                "truncated": truncated, "version": version,
                "size": size, "next_offset": (offset or 0) + len(data)
                if truncated else None}
    except UnicodeDecodeError:
        return {"path": path,
                "content_b64": base64.b64encode(data).decode(),
                "binary": True, "truncated": truncated, "version": version,
                "size": size, "next_offset": (offset or 0) + len(data)
                if truncated else None}


@route("POST", "/stat")
def h_stat(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    path = resolve_for_agent(ctx, agent, p.get("path", ""))
    st = os.stat(path)
    out = {
        "path": path, "size": st.st_size, "mtime": st.st_mtime,
        "is_dir": os.path.isdir(path), "is_file": os.path.isfile(path),
        "version": file_version(path),
    }
    # B3: opt-in sha256 so agents verify transfers WITHOUT exec
    # (sha256sum) — works even on exec=off hosts. Files above the cap
    # skip hashing rather than stalling the request on a multi-GB read.
    if p.get("hash") and out["is_file"]:
        if st.st_size <= STAT_HASH_MAX_BYTES:
            digest = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    digest.update(chunk)
            out["sha256"] = digest.hexdigest()
        else:
            out["sha256_skipped"] = (
                f"file exceeds {STAT_HASH_MAX_BYTES} bytes; hash it via "
                "exec sha256sum instead")
    return out


# ---------------------------------------------------------------------------
# Handlers: search
# ---------------------------------------------------------------------------

@route("POST", "/search")
def h_search(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    from . import search as searchmod
    query = p.get("query", "")
    name_pattern = p.get("name", "") or p.get("glob", "")
    path = p.get("path", "")
    roots = _agent_paths(ctx, agent)
    if path:
        base = resolve_for_agent(ctx, agent, path)
        if os.path.isfile(base):
            # v2.4.9 (Task 29 live finding): search a single file —
            # content grep or name match on its basename. This used to
            # 400 not_a_directory with a subjectless message.
            bases = [base]
        elif os.path.isdir(base):
            bases = [base]
        else:
            raise OpBlocked(404, {"error": "not_found", "path": base,
                                  "message": f"No such file or "
                                             f"directory: {base}"})
    else:
        bases = roots
    if not bases:
        raise OpBlocked(403, {"error": "no_roots",
                              "message": "No shared directories are in "
                              "scope for a path-less search. Share a "
                              "directory first or pass a --path inside "
                              "one."})
    regex = bool(p.get("regex", False))
    max_results = int(p.get("max_results", 50))
    context = int(p.get("context", 0))
    include_hidden = bool(p.get("all", False))

    results = {"matches": [], "truncated": False, "files_scanned": 0}
    for base in bases:
        if query:
            res = searchmod.content_search(
                base, query, regex=regex, glob=name_pattern or None,
                max_results=max_results, context=context,
                include_hidden=include_hidden,
                protected=ctx.sandbox.protected)
        elif name_pattern:
            res = searchmod.name_search(
                base, name_pattern, max_results=max_results,
                include_hidden=include_hidden,
                protected=ctx.sandbox.protected)
        else:
            raise OpBlocked(400, {"error": "missing_field",
                                  "field": "query or name/glob is required"})
        if "error" in res:
            raise OpBlocked(400, res)
        results["matches"].extend(res.get("matches", []))
        results["files_scanned"] += res.get("files_scanned", 0)
        results["truncated"] = results["truncated"] or res.get("truncated", False)
        if len(results["matches"]) >= MAX_SEARCH_RESULTS:
            results["matches"] = results["matches"][:MAX_SEARCH_RESULTS]
            results["truncated"] = True
            break
    ctx.sessions.record(agent["name"], "search",
                        f"q={query or name_pattern!r} "
                        f"({len(results['matches'])} hits)", kind="read")
    return results


# ---------------------------------------------------------------------------
# Handlers: overview + diff (v2.4.1 Tier B — context-economy composites)
# ---------------------------------------------------------------------------

_OVERVIEW_DOC_NAMES = ("README.md", "readme.md", "README", "agent.md",
                       "AGENT.md")


@route("POST", "/overview")
def h_overview(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    """B1: the orientation context pack — ONE call instead of the
    measured 5-call / 6.6K-token fresh-agent boot (F-B4). Returns the
    info core, a depth-capped tree with sizes, heads of README*/agent.md
    found in the target, and a session-digest pointer — trimmed to a
    byte budget so a naive agent can never blow its context here."""
    roots = _agent_paths(ctx, agent)
    if not roots:
        raise OpBlocked(403, {"error": "no_roots",
                              "message": "No shared directories are in "
                                         "scope for this agent."})
    target = p.get("path", "") or roots[0]
    path = resolve_for_agent(ctx, agent, target)
    if not os.path.isdir(path):
        raise OpBlocked(400, {"error": "not_a_directory", "path": path})
    try:
        depth = max(1, min(int(p.get("depth", 2)), OVERVIEW_DEPTH_MAX))
    except (TypeError, ValueError):
        depth = 2
    try:
        doc_heads = max(0, min(int(p.get("doc_heads", 40)),
                               OVERVIEW_DOC_HEADS_MAX))
    except (TypeError, ValueError):
        doc_heads = 40
    try:
        budget = max(500, min(int(p.get("budget", OVERVIEW_BUDGET_DEFAULT)),
                               OVERVIEW_BUDGET_MAX))
    except (TypeError, ValueError):
        budget = OVERVIEW_BUDGET_DEFAULT

    info = {
        "version": LLMAC_VERSION,
        "policy": ctx.settings.get("approval_policy", POLICY_AUTO),
        "exec_enabled": bool(ctx.settings.get("allow_exec")),
        "roots": roots,
    }

    # Depth-capped tree with sizes (bounded well below the budget).
    from .search import tree as build_tree
    tree = build_tree(path, depth=depth, max_entries=OVERVIEW_TREE_ENTRIES,
                      include_hidden=False,
                      protected=ctx.sandbox.protected)
    trimmed = {"tree_truncated": bool(tree.get("truncated"))}

    # Heads of onboarding docs sitting at the top of the target.
    docs = []
    if doc_heads:
        wanted = list(_OVERVIEW_DOC_NAMES)
        for e in tree.get("entries", []):
            if len(docs) >= 2:
                break
            if e.get("type") == "file" and e.get("name") in wanted \
                    and e.get("depth") == 1 \
                    and (e.get("size") or 0) <= MAX_READ_BYTES:
                try:
                    with open(e["path"], "r", encoding="utf-8") as f:
                        head = "".join(f.readline() for _ in range(doc_heads))
                except (OSError, UnicodeDecodeError):
                    continue
                docs.append({"path": e["path"], "lines": head.count("\n"),
                             "head": head})
                wanted.remove(e["name"])

    # Session pointer: enough to know recovery is possible, not the payload.
    sd = ctx.sessions.digest(agent["name"])
    session = {"op_count": sd.get("op_count", 0),
               "files_touched": sd.get("files_touched", 0),
               "exec_count": sd.get("exec_count", 0),
               "notes": len(sd.get("notes", [])),
               "hint": "full detail: POST /session/status"}

    resp = {"path": path, "info": info, "tree": tree,
            "docs": docs, "session": session, "trimmed": trimmed}

    # ---- byte-budget trim ladder (docs heads -> tree tail -> docs -> all) --
    def _size():
        return len(json.dumps(resp, ensure_ascii=False))
    if _size() > budget:
        resp["docs"] = [{**d, "head": d["head"][:min(100, budget // 8)]}
                        for d in resp["docs"]]
        resp["trimmed"]["docs"] = True
    if _size() > budget and resp["tree"].get("entries"):
        keep = max(4, len(resp["tree"]["entries"]) // 2)
        while keep > 4 and _size() > budget:
            keep = max(4, keep // 2)
        resp["tree"]["entries"] = resp["tree"]["entries"][:keep]
        resp["tree"]["truncated"] = True
        resp["trimmed"]["tree"] = True
    if _size() > budget:
        resp["docs"] = []
        resp["trimmed"]["docs_dropped"] = True
    if _size() > budget and resp["tree"].get("entries"):
        resp["tree"]["entries"] = []
        resp["tree"]["truncated"] = True
        resp["trimmed"]["tree_dropped"] = True
    resp["bytes"] = _size()
    resp["budget"] = budget
    ctx.sessions.record(agent["name"], "overview", path, kind="read")
    ctx.audit(agent=agent["name"], op="overview", path=path)
    return resp


@route("POST", "/diff")
def h_diff(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    """B2: server-side unified diff. The constant agent loop is "did my
    change land / what drifted" — re-reading whole files for that costs
    ~100% of the file; the diff is typically 1-2% (measured >= 10x on
    gui.py-scale cases). Two modes: two host paths, or a host path vs
    proposed inline content (a write dry-run). Sandbox + protected-path
    checks identical to read."""
    need_perm(agent, "read")
    a = p.get("a", "")
    if not a:
        raise OpBlocked(400, {"error": "missing_field", "field": "a"})
    a_path = resolve_for_agent(ctx, agent, a)
    if not os.path.isfile(a_path):
        raise OpBlocked(404, {"error": "not_found", "path": a_path,
                              "message": f"No such file: {a_path}"})
    try:
        with open(a_path, "rb") as f:
            a_raw = f.read(MAX_READ_BYTES + 1)
    except OSError as e:
        status, body = _os_error_response(e)
        raise OpBlocked(status, body)
    if len(a_raw) > MAX_READ_BYTES:
        raise OpBlocked(413, {"error": "file_too_large",
                              "message": "Diff supports files up to "
                                         f"{MAX_READ_BYTES} bytes."})
    if _looks_binary(a_raw):
        raise OpBlocked(400, {"error": "binary_file",
                              "message": "Diff needs text files; use stat "
                                         "--hash to compare binaries."})
    try:
        a_text = a_raw.decode("utf-8")
    except UnicodeDecodeError:
        raise OpBlocked(400, {"error": "binary_file",
                              "message": "Diff needs UTF-8 text files."})

    inline = p.get("inline", "")
    if p.get("inline_b64"):
        try:
            inline_raw = base64.b64decode(p["inline_b64"])
        except (ValueError, TypeError) as e:
            raise OpBlocked(400, {"error": "bad_request",
                                  "message": f"inline_b64 invalid: {e}"})
        if _looks_binary(inline_raw):
            raise OpBlocked(400, {"error": "binary_file",
                                  "message": "Diff needs text content; use "
                                             "stat --hash for binaries."})
        try:
            inline = inline_raw.decode("utf-8")
        except UnicodeDecodeError:
            raise OpBlocked(400, {"error": "binary_file",
                                  "message": "Diff needs UTF-8 text "
                                             "content."})
    if inline:
        b_path, b_text = "(inline proposal)", inline
    else:
        b = p.get("b", "")
        if not b:
            raise OpBlocked(400, {"error": "missing_field",
                                  "field": "b or inline is required"})
        b_path = resolve_for_agent(ctx, agent, b)
        if not os.path.isfile(b_path):
            raise OpBlocked(404, {"error": "not_found", "path": b_path,
                                  "message": f"No such file: {b_path}"})
        try:
            with open(b_path, "rb") as f:
                b_raw = f.read(MAX_READ_BYTES + 1)
        except OSError as e:
            status, body = _os_error_response(e)
            raise OpBlocked(status, body)
        if len(b_raw) > MAX_READ_BYTES:
            raise OpBlocked(413, {"error": "file_too_large",
                                  "message": "Diff supports files up to "
                                             f"{MAX_READ_BYTES} bytes."})
        if _looks_binary(b_raw):
            raise OpBlocked(400, {"error": "binary_file",
                                  "message": "Diff needs text files; use "
                                         "stat --hash to compare binaries."})
        try:
            b_text = b_raw.decode("utf-8")
        except UnicodeDecodeError:
            raise OpBlocked(400, {"error": "binary_file",
                                  "message": "Diff needs UTF-8 text files."})

    text = unified_diff(a_text, b_text, path=os.path.basename(a_path))
    diff_truncated = False
    if len(text) > MAX_DIFF_BYTES:
        head = text[:int(MAX_DIFF_BYTES * 0.8)].rsplit("\n", 1)[0] + "\n"
        tail = "\n" + text[-int(MAX_DIFF_BYTES * 0.15):]
        text = head + "...[diff truncated at 200KB]...\n" + tail
        diff_truncated = True
    added = sum(1 for ln in text.splitlines()
                if ln.startswith("+") and not ln.startswith("+++"))
    removed = sum(1 for ln in text.splitlines()
                  if ln.startswith("-") and not ln.startswith("---"))
    ctx.sessions.record(agent["name"], "diff",
                        f"{a_path} vs {b_path}", a_path, "read")
    ctx.audit(agent=agent["name"], op="diff", a=a_path, b=b_path)
    return {"a": a_path, "b": b_path, "diff": text, "added": added,
            "removed": removed, "truncated": diff_truncated,
            "same": added == 0 and removed == 0}


# ---------------------------------------------------------------------------
# Handlers: writes / edits
# ---------------------------------------------------------------------------

def _atomic_write(path: str, data: bytes) -> None:
    """Write bytes to path atomically, preserving the mode of an existing
    file (so executables stay executable, private files stay private)."""
    mode = None
    try:
        mode = os.stat(path).st_mode & 0o7777
    except OSError:
        pass
    tmp = os.path.join(os.path.dirname(path) or ".",
                       f".llmac_tmp_{uuid.uuid4().hex[:12]}")
    with open(tmp, "wb") as f:
        f.write(data)
    if mode is not None:
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
    os.replace(tmp, path)


@route("POST", "/write")
def h_write(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    need_perm(agent, "write")
    target = p.get("path", "")
    if not target:
        raise OpBlocked(400, {"error": "missing_field", "field": "path"})
    path = resolve_for_agent(ctx, agent, target)
    _check_protected(ctx, path)

    content = p.get("content", "")
    if p.get("content_b64"):
        try:
            data = base64.b64decode(p["content_b64"])
        except (ValueError, TypeError) as e:
            raise OpBlocked(400, {"error": "bad_request",
                                  "message": f"content_b64 is not valid "
                                  f"base64: {e}"})
    else:
        data = content.encode("utf-8")

    expected = p.get("expected_version")
    if expected:
        current = file_version(path) if os.path.exists(path) else "0-0"
        if current != expected:
            raise OpBlocked(409, {
                "error": "version_conflict",
                "message": "File changed since you last read it. Re-read "
                          "and retry with the new version token.",
                "current_version": current,
            })

    if _policy_gates_write(ctx):
        maybe_gate(ctx, agent, "write",
                   f"{os.path.getsize(path) if os.path.exists(path) else 0}B -> "
                   f"{len(data)}B {path}", str(p.get("note", "")), path=path)

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    _atomic_write(path, data)
    version = file_version(path)
    ctx.sessions.record(agent["name"], "write", path, path, "write")
    ctx.events.emit("write", {"path": path, "agent": agent["name"],
                              "bytes": len(data)})
    ctx.audit(agent=agent["name"], op="write", path=path, bytes=len(data))
    ctx.op_log("OK", f"WRITE {path} ({len(data)} B) by {agent['name']}",
              agent=agent)
    return {"path": path, "bytes": len(data), "version": version}


@route("POST", "/edit")
def h_edit(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    need_perm(agent, "write")
    target = p.get("path", "")
    if not target:
        raise OpBlocked(400, {"error": "missing_field", "field": "path"})
    path = resolve_for_agent(ctx, agent, target)
    _check_protected(ctx, path)
    if not os.path.isfile(path):
        raise OpBlocked(404, {"error": "not_found", "path": path,
                              "message": f"No such file: {path}"})
    if os.path.getsize(path) > 8 * 1024 * 1024:
        raise OpBlocked(413, {"error": "file_too_large",
                              "message": "Edit supports files up to 8 MB."})
    ops = p.get("ops") or []
    if not ops:
        raise OpBlocked(400, {"error": "missing_field", "field": "ops"})

    expected = p.get("expected_version")
    current = file_version(path)
    if expected and expected != current:
        raise OpBlocked(409, {
            "error": "version_conflict",
            "message": "File changed since you last read it.",
            "current_version": current,
        })

    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    if _policy_gates_write(ctx):
        maybe_gate(ctx, agent, "edit", f"edit {path}",
                   f"{len(ops)} op(s)", path=path)

    new_text, changes, diff = apply_edits_atomic(text, ops)
    _atomic_write(path, new_text.encode("utf-8"))
    version = file_version(path)
    ctx.sessions.record(agent["name"], "edit", path, path, "write")
    ctx.events.emit("write", {"path": path, "agent": agent["name"],
                              "edit": True})
    ctx.audit(agent=agent["name"], op="edit", path=path, changes=changes)
    ctx.op_log("OK", f"EDIT {path} ({changes} change(s)) by {agent['name']}",
              agent=agent)
    return {"path": path, "changes": changes, "diff": diff,
            "version": version, "bytes": os.path.getsize(path)}


# ---------------------------------------------------------------------------
# Handlers: filesystem structure
# ---------------------------------------------------------------------------

@route("POST", "/mkdir")
def h_mkdir(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    need_perm(agent, "write")
    path = resolve_for_agent(ctx, agent, p.get("path", ""))
    _check_protected(ctx, path)
    if _policy_gates_write(ctx):
        maybe_gate(ctx, agent, "mkdir", path, path=path)
    os.makedirs(path, exist_ok=True)
    ctx.sessions.record(agent["name"], "mkdir", path, path, "write")
    ctx.audit(agent=agent["name"], op="mkdir", path=path)
    return {"path": path, "created": True}


@route("POST", "/delete")
def h_delete(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    need_perm(agent, "delete")
    path = resolve_for_agent(ctx, agent, p.get("path", ""))
    _check_protected(ctx, path)
    if not os.path.exists(path):
        raise OpBlocked(404, {"error": "not_found", "path": path})

    is_dir = os.path.isdir(path)
    count = _count_dir(path) if is_dir else 1

    # Large recursive deletes need explicit client confirmation ...
    if is_dir and count > DELETE_CONFIRM_THRESHOLD and not p.get("confirm"):
        raise OpBlocked(409, {
            "error": "confirm_required",
            "message": f"'{path}' contains {count} files. Pass "
                       f"confirm=true to delete it.",
            "file_count": count,
        })
    # ... and host approval per policy.
    if _policy_gates_delete(ctx, is_dir, count):
        maybe_gate(ctx, agent, "delete",
                   f"{path} ({count} file(s))",
                   f"recursive={is_dir} count={count}", path=path)

    if is_dir:
        shutil.rmtree(path)
    else:
        os.remove(path)
    ctx.sessions.record(agent["name"], "delete", path, path, "write")
    ctx.events.emit("delete", {"path": path, "agent": agent["name"]})
    ctx.audit(agent=agent["name"], op="delete", path=path, files=count)
    ctx.op_log("OK", f"DELETE {path} ({count} file(s)) by {agent['name']}",
              agent=agent)
    return {"path": path, "deleted": True, "file_count": count}


@route("POST", "/move")
def h_move(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    need_perm(agent, "write")
    src = p.get("src", "")
    dest = p.get("dest", "")
    if not src or not dest:
        raise OpBlocked(400, {"error": "missing_field",
                              "field": "src and dest required"})
    src_abs = resolve_for_agent(ctx, agent, src)
    dest_abs = resolve_for_agent(ctx, agent, dest)
    _check_protected(ctx, src_abs)
    _check_protected(ctx, dest_abs)
    if not os.path.exists(src_abs):
        raise OpBlocked(404, {"error": "src_not_found", "src": src_abs})
    if os.path.isdir(dest_abs):
        dest_final = os.path.join(dest_abs, os.path.basename(src_abs))
        _check_protected(ctx, dest_final)
    else:
        os.makedirs(os.path.dirname(dest_abs) or ".", exist_ok=True)
        dest_final = dest_abs
    if os.path.exists(dest_final) and not p.get("overwrite"):
        raise OpBlocked(409, {"error": "dest_exists", "dest": dest_final,
                              "message": "Pass overwrite=true to replace."})
    if _policy_gates_write(ctx):
        maybe_gate(ctx, agent, "move", f"{src_abs} -> {dest_final}",
                   path=dest_final)
    shutil.move(src_abs, dest_final)
    ctx.sessions.record(agent["name"], "move", f"{src_abs} -> {dest_final}",
                        src_abs, "write")
    ctx.audit(agent=agent["name"], op="move", src=src_abs, dest=dest_final)
    return {"src": src_abs, "dest": dest_final, "moved": True}


@route("POST", "/copy")
def h_copy(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    need_perm(agent, "write")
    src = p.get("src", "")
    dest = p.get("dest", "")
    if not src or not dest:
        raise OpBlocked(400, {"error": "missing_field",
                              "field": "src and dest required"})
    src_abs = resolve_for_agent(ctx, agent, src)
    dest_abs = resolve_for_agent(ctx, agent, dest)
    _check_protected(ctx, src_abs)
    _check_protected(ctx, dest_abs)
    if not os.path.exists(src_abs):
        raise OpBlocked(404, {"error": "src_not_found", "src": src_abs})
    if os.path.isdir(dest_abs):
        dest_final = os.path.join(dest_abs, os.path.basename(src_abs))
        _check_protected(ctx, dest_final)
    else:
        os.makedirs(os.path.dirname(dest_abs) or ".", exist_ok=True)
        dest_final = dest_abs
    if os.path.exists(dest_final) and not p.get("overwrite"):
        raise OpBlocked(409, {"error": "dest_exists", "dest": dest_final,
                              "message": "Pass overwrite=true to replace."})
    if _policy_gates_write(ctx):
        maybe_gate(ctx, agent, "copy", f"{src_abs} -> {dest_final}",
                   path=dest_final)
    if os.path.isdir(src_abs):
        # symlinks=True: copy links AS LINKS. Following them materialized the
        # link target's entire tree inside the sandbox (a link to /etc became
        # a readable /etc copy that the realpath defenses then never saw,
        # F14). Links-as-links are inert: reading through them is blocked.
        shutil.copytree(src_abs, dest_final, dirs_exist_ok=True,
                        symlinks=True)
    else:
        shutil.copy2(src_abs, dest_final)
    ctx.sessions.record(agent["name"], "copy", f"{src_abs} -> {dest_final}",
                        dest_final, "write")
    ctx.audit(agent=agent["name"], op="copy", src=src_abs, dest=dest_final)
    return {"src": src_abs, "dest": dest_final, "copied": True}


# ---------------------------------------------------------------------------
# Handlers: exec + processes
# ---------------------------------------------------------------------------

def _exec_allowed(ctx: AppContext, agent: dict) -> None:
    if not ctx.settings.get("allow_exec"):
        raise OpBlocked(403, {
            "error": "exec_disabled",
            "message": "Raw shell execution is disabled on this host. "
                       "Use the structured tools (read/write/edit/search/"
                       "proc) instead.",
        })
    need_perm(agent, "exec")


def _exec_cwd(ctx: AppContext, agent: dict, p: dict, what: str = "Exec") -> str:
    """Resolve + validate the working dir for an exec-ish op. Raises
    OpBlocked(403 no_roots / 404 cwd_not_found). Shared by /exec, /proc
    and batch-exec so the semantics never drift apart."""
    cwd = p.get("cwd", "") or (ctx.sandbox.roots[0]
                                if ctx.sandbox.roots else "")
    if not cwd:
        raise OpBlocked(403, {
            "error": "no_roots",
            "message": f"{what} needs at least one shared directory to "
                       "anchor its working directory. Ask the host to "
                       "share one (roots request)."})
    cwd = resolve_for_agent(ctx, agent, cwd)
    if not os.path.isdir(cwd):
        raise OpBlocked(404, {"error": "cwd_not_found", "cwd": cwd})
    return cwd


def _exec_timeout(p: dict) -> int:
    try:
        timeout = int(p.get("timeout", EXEC_TIMEOUT_DEFAULT))
    except (TypeError, ValueError):
        timeout = EXEC_TIMEOUT_DEFAULT
    return max(EXEC_TIMEOUT_MIN, min(timeout, EXEC_TIMEOUT_MAX))


def _exec_save_path(ctx: AppContext, agent: dict, p: dict,
                    field: str = "save") -> str | None:
    """v2.4.4 (--save): resolve + validate the optional file an exec's
    stdout streams into, FULL and uncapped. Validated BEFORE anything
    runs — a bad target never starts the command (and in a batch,
    refuses the whole batch atomically). This is the RE workflow
    primitive: run `objdump -d target` straight into a file inside the
    sandbox, then grep/ranged-read the artifact, without shell
    redirects or quoting in the command string.
    v2.4.8: `field` also serves save_stderr — the optional second
    target that receives stderr the same way (stdout and stderr stay
    separate files; a shared target would interleave the two pipes
    into garbage, so the caller rejects it)."""
    save = str(p.get(field, "") or "").strip()
    if not save:
        return None
    try:
        path = resolve_for_agent(ctx, agent, save)
    except PermissionError as e:
        raise OpBlocked(403, {"error": "save_outside_sandbox",
                              "message": str(e)})
    _check_protected(ctx, path)
    parent = os.path.dirname(path) or "."
    if not os.path.isdir(parent):
        flag = "--save-stderr" if field == "save_stderr" else "--save"
        raise OpBlocked(400, {
            "error": "save_dir_missing",
            "message": f"Directory '{parent}' does not exist — create it "
                       f"first (mkdir), then re-run with {flag}."})
    return path


def _preflight_exec(ctx: AppContext, agent: dict, command: str,
                    cwd: str) -> dict | None:
    """Sandbox + policy verdict for a command. Returns the rejection dict
    (rejected=True — a RESULT, not an error), None when it may run, or
    (v2.4.5) a SUDO MARKER {needs_sudo_approval: True, ...} when the
    command is a distro package install via sudo — allowed, but ONLY
    after the forced approval flow. Pure check + audit/log: no side
    effects, so a batch can pre-flight EVERY exec op before executing
    anything (B4 atomicity)."""
    err = ctx.sandbox.check_exec_command(command, cwd)
    if err is not None:
        ctx.op_log("REJECTED", f"EXEC REJECTED (sandbox): {command!r}",
                   agent=agent)
        ctx.audit(agent=agent["name"], op="exec_rejected", command=command,
                  rule="path_outside_sandbox")
        return {"rejected": True, "rule": "path_outside_sandbox",
                "warning": err, "stdout": "", "stderr": err,
                "returncode": -1, "command": command}
    verdict = ctx.policy.pre_exec(command, cwd)
    if verdict is not None:
        if verdict.get("needs_sudo_approval"):
            # NOT a rejection: a sudo package change (v2.4.6: install OR
            # removal) that must pass the forced-approval gate first.
            # The audit trail records the attempt; the gate outcome is
            # recorded by maybe_gate.
            verb = verdict.get("sudo_verb") or "install"
            ctx.op_log("WARN", f"EXEC SUDO-{verb.upper()} "
                                f"(approval required): {command!r}",
                       agent=agent)
            ctx.audit(agent=agent["name"], op=f"sudo_{verb}_requested",
                      command=command[:500])
            return {"needs_sudo_approval": True, "sudo_verb": verb,
                    "command": command}
        ctx.op_log("REJECTED", f"EXEC REJECTED rule={verdict['rule']} "
                               f"cmd={command!r}", agent=agent)
        ctx.audit(agent=agent["name"], op="exec_rejected", command=command,
                  rule=verdict["rule"])
        return {"rejected": True, "rule": verdict["rule"],
                "warning": verdict["warning"], "stdout": "",
                "stderr": verdict["warning"], "returncode": -1,
                "command": command}
    return None


def _run_exec(ctx: AppContext, agent: dict, command: str, cwd: str,
              timeout: int, save: str | None = None,
              save_err: str | None = None,
              sudo_password: str | None = None) -> dict:
    """Run one pre-flight-approved command: Popen + bounded capture +
    session/audit records. Raises OpBlocked(503 exec_busy). Shared by
    /exec and batch-exec (B4). With save= (v2.4.4 --save) stdout goes
    FULL and uncapped to that file instead of the response — the agent
    then uses read/search/diff on the artifact. With save_err=
    (v2.4.8 --save-stderr) stderr gets the SAME treatment; each stream
    pipes straight into its own file, so the artifacts are byte-exact
    and no pipe needs a drain thread. The two targets must differ
    (enforced by the callers).
    v2.4.6 sudo_password: only ever set on the APPROVED sudo package
    path (forced approval survived). When present, the command is run
    as `sudo -S -p '' <rest>` with the password piped on stdin — no
    TTY needed, and the password never appears in argv (ps-safe), in
    the audit record, in the response, or on disk. The session/audit/
    op_log records keep the ORIGINAL command string."""
    from .server import EXEC_SHELL
    ctx.op_log("OP", f"EXEC running: {command!r}"
                      + (f"  save={save}" if save else "")
                      + (f"  save_stderr={save_err}" if save_err else "")
                      + ("  (sudo -S, stored password)" if sudo_password
                         else ""), agent=agent)
    if not ctx.acquire_exec():
        raise OpBlocked(503, {
            "error": "exec_busy",
            "message": "Too many concurrent exec commands; retry."})
    stdout_cap = _BoundedCapture()
    stderr_cap = _BoundedCapture()
    timed_out = False
    fh = None
    fh_err = None
    try:
        if save:
            try:
                fh = open(save, "wb")
            except OSError as e:
                raise OpBlocked(400, {
                    "error": "save_open_failed",
                    "message": f"Cannot open '{save}' for writing: {e}"})
        if save_err:
            try:
                fh_err = open(save_err, "wb")
            except OSError as e:
                raise OpBlocked(400, {
                    "error": "save_open_failed",
                    "message": f"Cannot open '{save_err}' for writing: {e}"})
        # v2.4.6: on the approved sudo path, swap `sudo <rest>` for
        # `sudo -S -p '' <rest>` so the password can arrive on stdin.
        # The caller validated the ORIGINAL shape; this transform is a
        # server-side constant injection ("-S -p ''") — it cannot turn
        # a package change into anything else.
        run_command = command
        if sudo_password:
            head, sep, rest = command.partition(" ")
            if head == "sudo" and sep:
                run_command = "sudo -S -p '' " + rest
        argv = [EXEC_SHELL, "-c", run_command] if EXEC_SHELL else run_command
        popen_kwargs = dict(cwd=cwd,
                            stdout=fh if fh else subprocess.PIPE,
                            stderr=fh_err if fh_err else subprocess.PIPE,
                            stdin=subprocess.PIPE if sudo_password
                            else subprocess.DEVNULL)
        if os.name == "posix":
            popen_kwargs["start_new_session"] = True
        proc = subprocess.Popen(argv, **popen_kwargs)
        if sudo_password:
            # Feed the password, then close stdin so sudo -S gets EOF
            # after the line. Small write: pipe buffer swallows it even
            # before sudo reads; no deadlock. Errors here (process died
            # instantly) are fine — sudo's own failure surfaces in rc.
            try:
                proc.stdin.write((sudo_password + "\n").encode())
                proc.stdin.close()
            except (OSError, ValueError):
                pass

        def pump(pipe, cap):
            # Binary 64KB reads instead of per-LINE text iteration: with
            # the old pump a 3M-line command spent ~30s re-slicing the
            # rolling tail (F20).
            try:
                while True:
                    chunk = pipe.read(65536)
                    if not chunk:
                        break
                    cap.feed(chunk)
            except (OSError, ValueError):
                pass

        if fh is None:
            t_out = threading.Thread(target=pump,
                                     args=(proc.stdout, stdout_cap),
                                     daemon=True)
            t_out.start()
        if fh_err is None:
            t_err = threading.Thread(target=pump,
                                     args=(proc.stderr, stderr_cap),
                                     daemon=True)
            t_err.start()
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                if os.name == "posix":
                    import signal as _sig
                    os.killpg(os.getpgid(proc.pid), _sig.SIGKILL)
                else:
                    proc.kill()
            except OSError:
                pass
            rc = proc.wait(timeout=10)
        if fh is None:
            t_out.join(timeout=2)
        if fh_err is None:
            t_err.join(timeout=2)
        if timed_out and fh_err is not None:
            # v2.4.8: the timeout note lands IN the stderr artifact —
            # both pipes are drained (or never existed) by now, so
            # there is no interleaving with the pump threads.
            try:
                fh_err.write(
                    f"\n[command timed out after {timeout}s]".encode())
            except OSError:
                pass
    finally:
        if fh is not None:
            try:
                fh.flush()
                fh.close()
            except OSError:
                pass
        if fh_err is not None:
            try:
                fh_err.flush()
                fh_err.close()
            except OSError:
                pass
        ctx.release_exec()

    stdout = stdout_cap.text()
    stderr = stderr_cap.text()
    saved_bytes = 0
    if save and os.path.exists(save):
        try:
            saved_bytes = os.path.getsize(save)
        except OSError:
            saved_bytes = 0
    saved_stderr_bytes = 0
    if save_err and os.path.exists(save_err):
        try:
            saved_stderr_bytes = os.path.getsize(save_err)
        except OSError:
            saved_stderr_bytes = 0
    if timed_out and fh_err is None:
        stderr += f"\n[command timed out after {timeout}s]"
    level = "OK" if rc == 0 and not timed_out else "WARN"
    ctx.op_log(level, f"EXEC done rc={rc}  cmd={command!r}", agent=agent)
    ctx.sessions.record(agent["name"], "exec", command[:200], kind="exec")
    ctx.sessions.get(agent["name"]).record_exec(command, rc, timed_out)
    ctx.audit(agent=agent["name"], op="exec", command=command[:500], rc=rc,
              timed_out=timed_out, save=save or "",
              save_stderr=save_err or "")
    out = {
        "stdout": stdout, "stderr": stderr, "returncode": rc,
        "command": command, "cwd": cwd, "timed_out": timed_out,
        "truncated": ((fh is None
                       and stdout_cap.total > EXEC_OUTPUT_CAP)
                      or (fh_err is None
                          and stderr_cap.total > EXEC_OUTPUT_CAP)),
    }
    if save:
        out["stdout"] = ""          # the full stream is in the file
        out["saved_path"] = save
        out["saved_bytes"] = saved_bytes
    if save_err:
        out["stderr"] = ""          # v2.4.8: same contract for stderr
        out["saved_stderr_path"] = save_err
        out["saved_stderr_bytes"] = saved_stderr_bytes
    return out


@route("POST", "/exec")
def h_exec(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    _exec_allowed(ctx, agent)
    command = p.get("command", "")
    if not command:
        raise OpBlocked(400, {"error": "missing_field", "field": "command"})
    cwd = _exec_cwd(ctx, agent, p)
    timeout = _exec_timeout(p)
    save = _exec_save_path(ctx, agent, p)   # v2.4.4: before preflight —
    # a bad save target must refuse the command without running it.
    save_err = _exec_save_path(ctx, agent, p, field="save_stderr")
    # v2.4.8: stderr artifact — same rule; both targets must differ or
    # the two streams would interleave into one garbage file.
    if save and save_err and save == save_err:
        raise OpBlocked(400, {"error": "save_same_path",
                              "message": "save and save_stderr must be two "
                                         "different files."})

    ctx.op_log("OP", f"EXEC cwd={cwd} by {agent['name']}  cmd={command!r}",
              agent=agent)

    preflight = _preflight_exec(ctx, agent, command, cwd)
    if preflight is not None:
        if preflight.get("rejected"):
            # A rejected command is a RESULT (HTTP 200, rejected=true),
            # not a transport error — agents must see the rule that
            # blocked it.
            return preflight
        if preflight.get("needs_sudo_approval"):
            # v2.4.5: forced gate — ALWAYS prompts (even auto_all),
            # 2-minute countdown, auto-approve/reject per the security
            # panel setting. This replaces the normal strict-policy gate
            # for this command: one approval, with the countdown.
            # v2.4.6: removals share the flow (the op label carries the
            # verb); the GUI-set sudo password (if any) is piped to
            # `sudo -S` at run time — the agent never sees it.
            verb = preflight.get("sudo_verb") or "install"
            op = "sudo_install" if verb == "install" else "sudo_remove"
            maybe_gate(ctx, agent, op, command[:120], command,
                       forced=True,
                       expires_in=_sudo_timeout_s(ctx),
                       timeout_action=_sudo_timeout_action(ctx))
            ctx.audit(agent=agent["name"], op=f"{op}_approved",
                      command=command[:500])
            return _run_exec(ctx, agent, command, cwd, timeout,
                             save=save, save_err=save_err,
                             sudo_password=ctx.sudo_password or None)

    if ctx.settings.get("approval_policy") == POLICY_STRICT:
        maybe_gate(ctx, agent, "exec", command[:200], command, path=cwd)

    return _run_exec(ctx, agent, command, cwd, timeout, save=save,
                     save_err=save_err)


@route("POST", "/proc/start")
def h_proc_start(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    _exec_allowed(ctx, agent)
    need_perm(agent, "proc")
    command = p.get("command", "")
    if not command:
        raise OpBlocked(400, {"error": "missing_field", "field": "command"})
    cwd = _exec_cwd(ctx, agent, p, what="Background processes")
    ctx.op_log("OP", f"PROC START cwd={cwd} by {agent['name']} "
                     f"cmd={command!r}", agent=agent)
    ctx.audit(agent=agent["name"], op="proc_start", command=command[:500])
    return ctx.procs.start(command, cwd, name=p.get("name", ""),
                           sandbox=ctx.sandbox, policy=ctx.policy)


@route("POST", "/proc/list")
def h_proc_list(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    need_perm(agent, "proc")
    return {"procs": ctx.procs.list()}


@route("POST", "/proc/logs")
def h_proc_logs(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    need_perm(agent, "proc")
    pid = p.get("id", "")
    after = int(p.get("after", 0))
    # v2.4.7: streams advance at different rates; `proc logs --follow`
    # needs independent cursors. Single `after` still applies to both
    # (backward compatible).
    after_out = int(p.get("after_stdout", after))
    after_err = int(p.get("after_stderr", after))
    stream = p.get("stream", "both")
    return ctx.procs.logs(pid, stream, after_out, after_err)


@route("POST", "/proc/stop")
def h_proc_stop(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    need_perm(agent, "proc")
    pid = p.get("id", "")
    force = bool(p.get("force", False))
    ctx.audit(agent=agent["name"], op="proc_stop", id=pid, force=force)
    return ctx.procs.stop(pid, force)


# ---------------------------------------------------------------------------
# Handlers: session memory + approvals
# ---------------------------------------------------------------------------

@route("POST", "/session/status")
def h_session_status(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    # v2.4.4: all_notes=True returns the FULL notes log (up to the 100
    # cap) instead of the last 10 — used by `llmac session export`.
    return ctx.sessions.digest(agent["name"],
                               all_notes=bool(p.get("all_notes")))


@route("POST", "/session/note")
def h_session_note(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    text = p.get("text", "")
    if not text:
        raise OpBlocked(400, {"error": "missing_field", "field": "text"})
    ctx.sessions.record(agent["name"], "note", text[:150])
    ctx.sessions.note(agent["name"], text)
    ctx.events.emit("note", {"agent": agent["name"]})
    return {"stored": True, "notes": len(ctx.sessions.get(agent["name"]).notes)}


@route("POST", "/session/reset")
def h_session_reset(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    ctx.sessions.reset(agent["name"])
    return {"reset": True}


@route("POST", "/session/inbox")
def h_session_inbox(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    """v2.5.0 (ASK-001): the authenticated agent reads its user->agent
    inbox — the messages the human sent from the GUI chat pane while the
    agent was working. Default consumes the new messages (the unread
    banner clears); peek=True only looks. The transcript itself stays on
    the server for the GUI thread."""
    if p.get("text"):
        # The note route is the agent->record direction; a text here is
        # almost certainly a client mixing the two up (lesson #11).
        raise OpBlocked(400, {"error": "text_belongs_to_note",
                              "message": "Use POST /session/note for agent "
                                         "notes; /session/inbox only reads "
                                         "the user->agent inbox."})
    peek = p.get("peek", False)
    if not isinstance(peek, bool):
        raise OpBlocked(400, {"error": "bad_field", "field": "peek",
                              "message": "peek must be a boolean."})
    out = ctx.sessions.read_inbox(agent["name"], mark=not peek)
    ctx.sessions.record(agent["name"], "inbox",
                        ("peek" if peek else "read")
                        + f" {len(out['messages'])} message(s)")
    return out


@route("POST", "/session/log")
def h_session_log(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    """v2.5.2 (ASK-010): the agent-scoped op-log view — the acting
    agent's OWN entries from the server's bounded op ring. Scoping is
    by AUTHENTICATION alone: an explicit "agent" key in the payload
    is a clean 400 (a client may never widen its own scope), and the
    operator GUI keeps the full in-process view. after = seq cursor
    from a previous fetch's next_after; limit is clamped
    server-side."""
    if "agent" in p:
        raise OpBlocked(400, {
            "error": "agent_scoping_is_automatic",
            "message": "The log view is scoped to the authenticated "
                       "agent by construction; remove the 'agent' "
                       "field.",
        })
    try:
        after = int(p.get("after", 0))
    except (TypeError, ValueError):
        after = -1
    try:
        limit = int(p.get("limit", SESSION_LOG_DEFAULT))
    except (TypeError, ValueError):
        limit = 0
    if after < 0:
        raise OpBlocked(400, {
            "error": "bad_field", "field": "after",
            "message": "after must be an integer seq cursor >= 0."})
    if not (1 <= limit <= SESSION_LOG_MAX):
        raise OpBlocked(400, {
            "error": "bad_field", "field": "limit",
            "message": f"limit must be an integer 1..{SESSION_LOG_MAX}."})
    entries, nxt = ctx.op_log_slice(agent["name"], after, limit)
    return {"agent": agent["name"], "entries": entries,
            "next_after": nxt, "count": len(entries)}


@route("POST", "/approvals/list")
def h_approvals_list(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    ctx.approvals.sweep_expired()   # v2.4.5: resolve elapsed countdowns
    return {
        "pending": ctx.approvals.pending(),
        "recent_decided": ctx.approvals.recent_decided(),
    }


@route("POST", "/approvals/wait")
def h_approvals_wait(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    aid = p.get("id", "")
    timeout = float(p.get("timeout", 30))
    status = ctx.approvals.wait(aid, timeout)
    # NOTE: ApprovalRegistry.status() already returns the dict form.
    a = ctx.approvals.status(aid)
    return {"id": aid, "status": status, "approval": a}


# ---------------------------------------------------------------------------
# Handlers: share requests (agent-initiated directory sharing)
# ---------------------------------------------------------------------------

_MAX_PENDING_SHARES = 20


@route("POST", "/roots/request")
def h_roots_request(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    """An agent asks to have a host directory shared with it.

    Under every policy except 'auto_all' this is the one operation that
    stays gated by the human even under 'auto': expanding the sandbox is a
    pure trust decision that only the host can make — if 'auto' granted
    shares too, an agent could silently give itself the whole disk. The
    request lands in the GUI approval queue; on approve, the GUI adds the
    path to the shared roots (see gui.py).

    Under 'auto_all' ('Auto - no restrictions') the host has explicitly
    delegated that decision: the share is granted instantly, loudly
    logged, and queued for the owner app to persist.
    """
    raw_path = str(p.get("path", "")).strip()
    reason = str(p.get("reason", ""))[:500]
    if not raw_path:
        raise OpBlocked(400, {"error": "missing_field", "field": "path"})
    if not os.path.isabs(raw_path):
        raise OpBlocked(400, {"error": "bad_request",
                              "message": "Path must be absolute on the host."})
    real = os.path.realpath(raw_path)
    if not os.path.isdir(real):
        raise OpBlocked(400, {"error": "bad_request",
                              "message": f"Not an existing directory on "
                                         f"the host: {real}"})
    if real in ctx.sandbox.roots:
        return {"status": "already_shared", "path": real}
    # 'Auto - no restrictions': grant immediately.
    if (ctx.settings.get("approval_policy", POLICY_DESTRUCTIVE)
            == POLICY_FULLAUTO):
        return _auto_approve_share(ctx, agent, real, reason)
    # De-duplicate: don't stack identical pending requests.
    existing = ctx.approvals.find_pending("share_root", {"path": real})
    if existing is not None:
        return ({"error": "approval_pending", "approval_id": existing.id,
                 "path": real,
                 "message": "A request for this directory is already "
                            "pending host approval. Poll with approvals "
                            f"wait --id {existing.id}."}, 202)
    if len(ctx.approvals.pending()) >= _MAX_PENDING_SHARES:
        return ({"error": "too_many_pending",
                 "message": "Too many pending requests; wait for decisions "
                            "first."}, 429)
    aid = ctx.approvals.create(
        agent["name"], "share_root", f"Share directory {real}",
        detail=f"reason: {reason or '(none given)'}",
        payload={"path": real, "requested_path": raw_path,
                 "reason": reason})
    ctx.op_log("WARN", f"SHARE REQUEST [{aid}] {real} "
                        f"(agent {agent['name']})", agent=agent)
    return ({"error": "approval_pending", "approval_id": aid,
             "path": real,
             "message": "Requested. The host must approve it in the GUI. "
                        f"Poll with approvals wait --id {aid}."}, 202)


def _auto_approve_share(ctx: AppContext, agent: dict, real: str,
                        reason: str) -> dict:
    """Grant a share request instantly (approval_policy == 'auto_all').

    The server expands the sandbox itself and queues the change for the
    owner app (GUI poll timer / headless drain thread persists it on their
    own thread — the server never writes state.json directly). Emits an
    event and a loud audit line. A scoped agent also gains the share in
    its own scope list, so the request actually helps the requester.
    """
    ctx.sandbox = Sandbox(list(ctx.sandbox.roots) + [real],
                          protected=ctx.sandbox.protected)
    scope = agent.get("roots")
    if scope and real not in scope:
        scope.append(real)   # live dict: GUI + auth registry see it
    ctx.share_queue.append(real)
    ctx.events.emit("roots_changed",
                    {"path": real, "agent": agent["name"], "auto": True})
    ctx.op_log("WARN", f"SHARE AUTO-APPROVED (policy=auto_all) {real} "
                        f"(agent {agent['name']})", agent=agent)
    ctx.audit(agent=agent["name"], op="share_auto_approved",
              path=real, reason=reason or "")
    return {"status": "approved", "path": real, "auto": True,
            "message": "Auto-approved: the host runs the 'Auto - no "
                       "restrictions' policy, so this directory is now "
                       "shared and in scope."}


# ---------------------------------------------------------------------------
# Handlers: the screen channel (v2.7.0 — ASK-016/017, V270-PLAN.md)
# ---------------------------------------------------------------------------

# Approval classes with the until-restart session-grant option (the GUI
# card adds "Approve for this session" for exactly these).
_SCREEN_OPS = ("screen_shot", "screen_observe", "screen_input")
# Screen/input ops are NOT batchable in v1: approvals + the GUI-main-
# thread capture bridge do not belong inside a batch — loud refusal.
_NOT_BATCHABLE_OPS = ("screen_list", "screen_shot", "screen_observe",
                      "input_mouse", "input_key", "input_text")
_MOUSE_ACTIONS = ("move", "click", "doubleclick", "drag", "scroll")
_MOUSE_BUTTONS = ("left", "middle", "right")


def _screen_gate(ctx: AppContext, agent: dict, op: str, summary: str,
                 detail: str = "") -> None:
    """Screen-class approvals are FORCED: they prompt under EVERY policy
    (auto_all included — a screenshot, an OCR read or input injection
    is a privacy decision only the human makes, the sudo-install
    precedent) but honor the until-restart SESSION grant — an in-memory
    set on AppContext that dies with the process. The persisted
    time-boxed path-scoped grants are deliberately NOT consulted:
    screen ops have no path scope, and a disk-persisted screen grant
    would survive restarts, which the plan forbids."""
    if agent["name"] in (ctx.screen_session_grants.get(op) or ()):
        ctx.op_log("OK", f"SESSION GRANT covers {op} "
                          f"(agent {agent['name']})", agent=agent)
        return
    aid = ctx.approvals.create(agent["name"], op, summary, detail)
    ctx.op_log("WARN", f"APPROVAL REQUIRED [{aid}] {op}: {summary}",
               agent=agent)
    status = ctx.approvals.wait(aid, APPROVAL_WAIT_MAX)
    if status == "approved":
        ctx.op_log("OK", f"APPROVAL GRANTED [{aid}] {op}", agent=agent)
        return
    if status == "pending":
        raise OpBlocked(202, {
            "error": "approval_pending", "approval_id": aid,
            "message": "Host has not decided yet. Poll with "
                       "approvals wait --id " + aid})
    raise OpBlocked(403, {
        "error": "approval_denied", "approval_id": aid,
        "message": "The host denied this operation."})


def _screen_service_or_refuse(ctx: AppContext):
    """The capture service must exist (a headless host refuses
    cleanly, naming the reason)."""
    if ctx.screen is None:
        raise OpBlocked(403, {
            "error": "screen_unavailable",
            "message": "No screen service on this host — the GUI owns "
                       "capture (Qt main thread). Run screen ops against "
                       "the GUI host, not a headless one."})
    return ctx.screen


def _shot_dir(ctx: AppContext) -> str:
    """The evidence dir from settings, shared-roots-checked, created."""
    out_dir = str(ctx.settings.get("screen_shot_dir", DEFAULT_SHOT_DIR)
                  or DEFAULT_SHOT_DIR)
    real = os.path.realpath(out_dir)
    if not ctx.sandbox.is_path_allowed(real):
        raise OpBlocked(403, {
            "error": "screen_dir_not_shared",
            "message": "The screen_shot_dir setting points outside the "
                       f"shared roots ({out_dir}) — change it in the GUI "
                       "Security tab (Screen access) or share that tree."})
    try:
        os.makedirs(real, exist_ok=True)
    except OSError as e:
        raise OpBlocked(400, {
            "error": "screen_dir_unwritable",
            "message": f"Cannot create the shot dir {real}: {e}"}) from None
    return real


def _shot_targets(ctx: AppContext, p: dict) -> tuple:
    """Shared /screen/shot + /screen/observe param contract: service,
    screen list, MANDATORY target resolution. Returns (screens,
    targets)."""
    service = _screen_service_or_refuse(ctx)
    try:
        screens = service.list_screens()
    except ScreenError as e:
        raise OpBlocked(e.status, {"error": e.error,
                                   "message": e.message}) from None
    try:
        targets = validate_shot_target(p.get("target"), screens)
    except ScreenError as e:
        raise OpBlocked(400, {"error": e.error,
                              "message": e.message,
                              **e.extra}) from None
    return screens, targets


@route("POST", "/screen/list")
def h_screen_list(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    """v2.7.0 (ASK-016): monitor enumeration — metadata ONLY (index,
    name, geometry in global virtual-desktop coords, primary, scale).
    Zero pixels move, so there is deliberately NO approval."""
    service = _screen_service_or_refuse(ctx)
    try:
        screens = service.list_screens()
    except ScreenError as e:
        raise OpBlocked(e.status, {"error": e.error,
                                   "message": e.message}) from None
    ctx.sessions.record(agent["name"], "screen_list",
                        f"{len(screens)} screen(s)", kind="read")
    return {"screens": screens}


@route("POST", "/screen/shot")
def h_screen_shot(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    """v2.7.0 (ASK-016): per-screen capture. target is explicit and
    MANDATORY (index | 'primary' | 'all'); format png|jpg (jpg quality
    85); optional max-width downscale (aspect kept). Files land in the
    evidence dir with deterministic names; the response carries
    {path, screen, geometry, format, width, height, bytes, sha256} per
    file plus the screens[] snapshot. Approval class screen_shot — per
    shot by default, session-grant-able; every shot op-logged."""
    if not ctx.settings.get("screen_shots_enabled", True):
        raise OpBlocked(403, {
            "error": "screen_shots_disabled",
            "message": "Screenshots are switched off — flip "
                       "screen_shots_enabled in the GUI Security tab "
                       "(Screen access)."})
    screens, targets = _shot_targets(ctx, p)
    try:
        fmt = validate_format(p.get("format"))
        max_width = validate_max_width(p.get("max_width"),
                                       cap=MAX_SHOT_WIDTH)
    except ScreenError as e:
        raise OpBlocked(400, {"error": e.error,
                              "message": e.message}) from None
    out_dir = _shot_dir(ctx)
    summary = (f"screenshot target={p.get('target')!r} format={fmt}"
               + (f" max-width={max_width}" if max_width else ""))
    _screen_gate(ctx, agent, "screen_shot", summary,
                 detail=f"files land in {out_dir}")
    try:
        files = ctx.screen.capture(targets, fmt, SHOT_JPG_QUALITY,
                                   max_width, out_dir, None)
    except ScreenError as e:
        raise OpBlocked(e.status, {"error": e.error,
                                   "message": e.message}) from None
    ctx.op_log("WARN", f"SCREEN SHOT target={p.get('target')!r} "
                       f"files={len(files)} dir={out_dir}", agent=agent)
    ctx.audit(agent=agent["name"], op="screen_shot",
              target=str(p.get("target")), files=len(files))
    ctx.sessions.record(agent["name"], "screen_shot",
                        f"{len(files)} file(s) -> {out_dir}", kind="read")
    return {"files": files, "screens": screens}


@route("POST", "/screen/observe")
def h_screen_observe(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    """v2.7.0 (ASK-017 part A): capture + READ. Full-resolution shot on
    the Item-1 rails, OCR words with confidence and boxes in GLOBAL
    coordinates (the same space input ops target) plus a per-screen
    plain-text digest, plus the X window list (XWayland clients on this
    host; Wayland-native windows are documented as out of that tree).
    Own approval class (screen_observe), OFF until the host flips
    screen_observe_enabled. max_width is REFUSED here — OCR truth needs
    full resolution, and loud contracts beat silent ignores (lesson
    #11)."""
    if not ctx.settings.get("screen_observe_enabled", False):
        raise OpBlocked(403, {
            "error": "screen_observe_disabled",
            "message": "Screen observe is OFF by default — flip "
                       "screen_observe_enabled in the GUI Security tab "
                       "(Screen access) to let agents read the screen."})
    if p.get("max_width") is not None:
        raise OpBlocked(400, {
            "error": "observe_max_width_unsupported",
            "message": "observe refuses max_width: OCR truth needs the "
                       "full-resolution capture (max_width is a "
                       "screen.shot parameter; silently ignoring it "
                       "here would corrupt the word coordinates)."})
    screens, targets = _shot_targets(ctx, p)
    try:
        fmt = validate_format(p.get("format"))
    except ScreenError as e:
        raise OpBlocked(400, {"error": e.error,
                              "message": e.message}) from None
    out_dir = _shot_dir(ctx)
    _screen_gate(ctx, agent, "screen_observe",
                 f"screen observe target={p.get('target')!r} — OCR text "
                 f"with positions + window list",
                 detail=f"shot lands in {out_dir}")
    try:
        files = ctx.screen.capture(targets, fmt, SHOT_JPG_QUALITY, None,
                                   out_dir, None)
    except ScreenError as e:
        raise OpBlocked(e.status, {"error": e.error,
                                   "message": e.message}) from None
    by_index = {s.get("index"): s for s in screens}
    observe = []
    for f in files:
        scr = by_index.get(f.get("screen"), targets[0])
        try:
            words, text = screen_channel.ocr_words(f["path"], scr)
        except ScreenError as e:
            raise OpBlocked(e.status, {"error": e.error,
                                       "message": e.message}) from None
        observe.append({"screen": f.get("screen"), "words": words,
                        "text": text})
    windows: list = []
    windows_error = None
    try:
        windows = screen_channel.window_list()
    except ScreenError as e:
        windows_error = f"{e.error}: {e.message}"
    n_words = sum(len(o["words"]) for o in observe)
    ctx.op_log("WARN", f"SCREEN OBSERVE target={p.get('target')!r} "
                       f"words={n_words} windows={len(windows)}",
               agent=agent)
    ctx.audit(agent=agent["name"], op="screen_observe",
              target=str(p.get("target")), files=len(files))
    ctx.sessions.record(agent["name"], "screen_observe",
                        f"{len(files)} screen(s) observed, {n_words} "
                        f"word(s)", kind="read")
    out = {"files": files, "screens": screens, "observe": observe,
           "windows": windows}
    if windows_error:
        out["windows_error"] = windows_error
    return out


# -- input injection (ASK-017 part B — the safety floor IS the design) --

def _input_floor(ctx: AppContext) -> None:
    """The two OFF-by-default gates: the setting, then the backend."""
    if not ctx.settings.get("screen_input_enabled", False):
        raise OpBlocked(403, {
            "error": "screen_input_disabled",
            "message": "Input injection is OFF by default — flip "
                       "screen_input_enabled in the GUI Security tab "
                       "(Screen access). Until then no input op runs, "
                       "under any policy, with any grant."})
    if ctx.input is None:
        raise OpBlocked(403, {
            "error": "screen_unavailable",
            "message": "No input backend on this host — X11/XTest is "
                       "unreachable (native Wayland without XWayland, or "
                       "a headless host). v1 reach: XWayland clients "
                       "only; the libei/portal route is future work."})


def _drive_gate(ctx: AppContext, agent: dict, summary: str) -> dict:
    """Bounded drive mode. The FIRST input op needs the screen_input
    approval (forced, session-grant-able) and OPENS the session; every
    op re-authorizes against the caps BEFORE injecting. A violation
    closes the session and refuses with drive_cap_exceeded naming the
    cap it hit."""
    sess, reason = ctx.screen_drive.authorize(agent["name"])
    if reason == "no_session":
        _screen_gate(ctx, agent, "screen_input", summary)
        max_events = int(ctx.settings.get(
            "screen_input_max_events", SCREEN_INPUT_MAX_EVENTS_DEFAULT))
        max_minutes = float(ctx.settings.get(
            "screen_input_max_minutes", SCREEN_INPUT_MAX_MINUTES_DEFAULT))
        ctx.screen_drive.open(agent["name"], max_events, max_minutes)
        ctx.op_log("WARN", f"DRIVE SESSION OPEN {agent['name']} — "
                           f"{max_events} events / {max_minutes} min",
                   agent=agent)
        ctx.events.emit("drive_session", {
            "agent": agent["name"], "state": "open",
            "max_events": max_events, "max_minutes": max_minutes})
        sess, reason = ctx.screen_drive.authorize(agent["name"])
    if reason in ("events", "time"):
        cap = ("screen_input_max_events" if reason == "events"
               else "screen_input_max_minutes")
        which = "event cap" if reason == "events" else "time cap"
        # A violation also DROPS the until-restart session grant for
        # this agent: exceeding the bound costs the approval coverage,
        # so the caps are a real bound, not a soft bump — the next input
        # op needs a fresh human approval no matter what was granted.
        granted = ctx.screen_session_grants.get("screen_input")
        if granted:
            granted.discard(agent["name"])
        ctx.op_log("WARN", f"DRIVE CAP EXCEEDED ({reason}) — session "
                           f"closed for {agent['name']}, session grant "
                           f"dropped", agent=agent)
        ctx.events.emit("drive_session", {
            "agent": agent["name"], "state": "closed", "reason": reason})
        raise OpBlocked(403, {
            "error": "drive_cap_exceeded",
            "message": f"The drive session's {which} ({cap}) was "
                       f"exceeded — the session is CLOSED and the "
                       f"until-restart grant with it; the next input op "
                       f"needs a fresh approval."})
    return sess


def _drive_response(ctx: AppContext, agent: dict, sess: dict) -> dict:
    n = ctx.screen_drive.count(agent["name"])
    return {"ok": True, "drive": {
        "agent": agent["name"], "events_used": n,
        "events_cap": sess.get("max_events"),
        "expires_in_s": max(0, round(sess.get("expires", 0.0)
                                     - time.monotonic()))}}


def _mouse_coords(p: dict, action: str) -> dict:
    """Per-action numeric coordinate contract. Missing -> 400
    input_coords_required naming the field; non-numeric ->
    input_coords_invalid."""
    need = (("from_x", "from_y", "to_x", "to_y") if action == "drag"
            else ("x", "y", "dx", "dy") if action == "scroll"
            else ("x", "y"))
    vals = {}
    for f in need:
        v = p.get(f)
        if v is None or isinstance(v, bool):
            raise OpBlocked(400, {
                "error": "input_coords_required", "field": f,
                "message": f"field '{f}' is required for action "
                           f"'{action}'."})
        if not isinstance(v, (int, float)) or not math.isfinite(v):
            raise OpBlocked(400, {
                "error": "input_coords_invalid", "field": f,
                "message": f"field '{f}' must be a finite number (got "
                           f"{v!r})."})
        vals[f] = v
    return vals


def _own_window_check(ctx: AppContext, points: list) -> None:
    """The own-window refusal: resolve the window at EVERY target point
    FIRST; a hit on the tool's own window kills the op before any
    approval, session or injection — the self-approval loop dies by
    construction (and on a Wayland host it is platform-dead too: the
    GUI is a native Wayland window, out of XWayland's reach)."""
    for (px, py) in points:
        wid = ctx.input.window_at(px, py)
        if wid is not None and wid in ctx.input.own_window_ids:
            raise OpBlocked(403, {
                "error": "own_window_refusal",
                "message": f"Input at ({px}, {py}) would land on "
                           f"LLMAC's own window — the tool never drives "
                           f"its own UI. Pick coordinates outside the "
                           f"host GUI."})


@route("POST", "/input/mouse")
def h_input_mouse(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    """v2.7.0 (ASK-017 part B): mouse injection — move | click |
    doubleclick | drag | scroll, button left|middle|right, coordinates
    in the SAME global space screen.list/observe speak. Every event
    op-logged at WARN; bounded drive mode; OFF until enabled."""
    _input_floor(ctx)
    action = p.get("action")
    if not action:
        raise OpBlocked(400, {
            "error": "input_action_required",
            "message": "action is mandatory: move | click | doubleclick "
                       "| drag | scroll."})
    if action not in _MOUSE_ACTIONS:
        raise OpBlocked(400, {
            "error": "input_action_invalid",
            "message": f"unknown mouse action {action!r} — use move | "
                       f"click | doubleclick | drag | scroll."})
    button = p.get("button", "left")
    if button not in _MOUSE_BUTTONS:
        raise OpBlocked(400, {
            "error": "input_button_invalid",
            "message": f"unknown mouse button {button!r} — use left | "
                       f"middle | right."})
    vals = _mouse_coords(p, action)
    points = ([(vals["from_x"], vals["from_y"]),
               (vals["to_x"], vals["to_y"])] if action == "drag"
              else [(vals["x"], vals["y"])])
    _own_window_check(ctx, points)
    coords_desc = (f"({vals['from_x']},{vals['from_y']})->"
                   f"({vals['to_x']},{vals['to_y']})"
                   if action == "drag"
                   else f"({vals['x']},{vals['y']})"
                   + (f" d=({vals['dx']},{vals['dy']})"
                      if action == "scroll" else ""))
    sess = _drive_gate(ctx, agent,
                       f"inject input: mouse {action} {button} "
                       f"{coords_desc} — opens a bounded drive session")
    b = ctx.input
    try:
        if action == "move":
            b.mouse_move(vals["x"], vals["y"])
        elif action == "click":
            b.mouse_click(button, vals["x"], vals["y"])
        elif action == "doubleclick":
            b.mouse_doubleclick(button, vals["x"], vals["y"])
        elif action == "drag":
            b.mouse_drag(button, vals["from_x"], vals["from_y"],
                         vals["to_x"], vals["to_y"])
        else:
            b.mouse_scroll(vals["x"], vals["y"], vals["dx"], vals["dy"])
    except ScreenError as e:
        raise OpBlocked(e.status, {"error": e.error,
                                   "message": e.message}) from None
    resp = _drive_response(ctx, agent, sess)
    ctx.op_log("WARN", f"INPUT mouse {action} {button} {coords_desc} "
                       f"agent={agent['name']} "
                       f"drive={resp['drive']['events_used']}"
                       f"/{resp['drive']['events_cap']}", agent=agent)
    ctx.audit(agent=agent["name"], op="input_mouse", action=action,
              button=button)
    ctx.sessions.record(agent["name"], "input_mouse",
                        f"{action} {button}", kind="write")
    return resp


@route("POST", "/input/key")
def h_input_key(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    """v2.7.0 (ASK-017 part B): a key press — X11 keysym name (Return,
    F5, a, ...) + optional modifiers (ctrl/shift/alt/meta, X11 mapping
    table pinned by test). Own-window check via the FOCUSED window."""
    _input_floor(ctx)
    keysym = p.get("keysym")
    if not keysym or not isinstance(keysym, str):
        raise OpBlocked(400, {
            "error": "input_keysym_required",
            "message": "keysym is mandatory — an X11 keysym name like "
                       "'Return', 'F5' or 'a' (see 'screen observe' "
                       "output / agent.md tip 20)."})
    if not keysym_valid(keysym):
        raise OpBlocked(400, {
            "error": "input_keysym_unknown",
            "message": f"unknown keysym {keysym!r} — use a printable "
                       f"ASCII character or a canonical name (Return, "
                       f"Tab, space, Escape, BackSpace, Delete, Home, "
                       f"End, Prior, Next, Left, Right, Up, Down, "
                       f"Insert, F1..F12)."})
    modifiers = p.get("modifiers", [])
    if not isinstance(modifiers, list):
        modifiers = []
    bad_mod = next((m for m in modifiers
                    if m not in MODIFIER_KEYSYMS), None)
    if bad_mod is not None:
        raise OpBlocked(400, {
            "error": "input_modifier_invalid",
            "message": f"unknown modifier {bad_mod!r} — use ctrl | "
                       f"shift | alt | meta."})
    wid = ctx.input.focused_window()
    if wid is not None and wid in ctx.input.own_window_ids:
        raise OpBlocked(403, {
            "error": "own_window_refusal",
            "message": "The FOCUSED window is LLMAC's own — the tool "
                       "never drives its own UI. Focus a different "
                       "window first."})
    sess = _drive_gate(ctx, agent,
                       f"inject input: key {keysym}"
                       + (f" + {'+'.join(modifiers)}"
                          if modifiers else "")
                       + " — opens a bounded drive session")
    try:
        ctx.input.key(keysym, list(modifiers))
    except ScreenError as e:
        raise OpBlocked(e.status, {"error": e.error,
                                   "message": e.message}) from None
    resp = _drive_response(ctx, agent, sess)
    ctx.op_log("WARN", f"INPUT key {keysym} mods={modifiers} "
                       f"agent={agent['name']} "
                       f"drive={resp['drive']['events_used']}"
                       f"/{resp['drive']['events_cap']}", agent=agent)
    ctx.audit(agent=agent["name"], op="input_key", keysym=keysym,
              modifiers=",".join(modifiers))
    ctx.sessions.record(agent["name"], "input_key",
                        f"{keysym} {modifiers}", kind="write")
    return resp


@route("POST", "/input/text")
def h_input_text(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    """v2.7.0 (ASK-017 part B): type text — keysym-mappable characters
    only; the FIRST unmappable character is named in the refusal
    (input_text_unsupported). No mojibake ever reaches the keyboard."""
    _input_floor(ctx)
    try:
        text = validate_text(p.get("text"))
    except ScreenError as e:
        raise OpBlocked(400, {"error": e.error, "message": e.message,
                              **e.extra}) from None
    wid = ctx.input.focused_window()
    if wid is not None and wid in ctx.input.own_window_ids:
        raise OpBlocked(403, {
            "error": "own_window_refusal",
            "message": "The FOCUSED window is LLMAC's own — the tool "
                       "never drives its own UI. Focus a different "
                       "window first."})
    sess = _drive_gate(ctx, agent,
                       f"inject input: type {len(text)} chars "
                           f"({text[:40]!r}) — opens a bounded drive "
                           f"session")
    try:
        ctx.input.type_text(text)
    except ScreenError as e:
        raise OpBlocked(e.status, {"error": e.error,
                                   "message": e.message}) from None
    resp = _drive_response(ctx, agent, sess)
    ctx.op_log("WARN", f"INPUT text {text[:80]!r} agent={agent['name']} "
                       f"drive={resp['drive']['events_used']}"
                       f"/{resp['drive']['events_cap']}", agent=agent)
    ctx.audit(agent=agent["name"], op="input_text", chars=len(text))
    ctx.sessions.record(agent["name"], "input_text",
                        f"{len(text)} char(s)", kind="write")
    return resp


# ---------------------------------------------------------------------------
# Handlers: batch (Tier 1 — one round trip, many ops)
# ---------------------------------------------------------------------------

_BATCH_WRITE_OPS = ("mkdir", "write", "edit")


@route("POST", "/batch")
def h_batch(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    """Execute a list of ops in one request/response cycle.

    Read/nav ops are always batchable; mkdir/write are batchable only when
    the approval policy would not gate them individually (under `strict`
    each write needs its own human decision, so batch refuses them).
    Deletes/moves/copies are never batchable on purpose.

    v2.4.7 (the long-deferred diff-in-edit item, done right): `edit` ops
    are batchable too — each result carries the surgical diff, so a
    multi-file change costs ONE round trip and still proves itself.
    Strict policy refuses batched edits, same principle as writes.

    v2.4.1 (B4): `exec` ops are batchable. EVERY exec op is pre-flighted
    (cwd + sandbox analyzer + install policy) BEFORE anything in the
    batch runs — one bad command refuses the whole batch with zero
    side effects. Ops then execute in order, so an exec sees the files
    the preceding writes left behind; a non-zero rc or timeout is a
    normal per-op RESULT, not a batch abort. Strict policy refuses
    batched exec outright, same principle as writes.
    """
    ops = p.get("ops")
    if not isinstance(ops, list) or not ops:
        raise OpBlocked(400, {"error": "missing_field",
                              "field": "ops (a non-empty JSON array)"})
    if len(ops) > MAX_BATCH_OPS:
        return ({"error": "batch_too_large",
                 "message": f"Batch supports at most {MAX_BATCH_OPS} ops; "
                            f"got {len(ops)}."}, 400)
    has_write = any(isinstance(o, dict) and o.get("op") in _BATCH_WRITE_OPS
                    for o in ops)
    if has_write and _policy_gates_write(ctx):
        return ({"error": "batch_policy",
                 "message": "Approval policy is 'strict': write/edit ops "
                            "must run individually so each gets host "
                            "approval."},
                400)
    has_exec = any(isinstance(o, dict) and o.get("op") == "exec"
                   for o in ops)
    if has_exec:
        _exec_allowed(ctx, agent)      # 403 exec_disabled / permission
        if _policy_gates_exec(ctx):
            return ({"error": "batch_policy",
                     "message": "Approval policy is 'strict': exec ops "
                                "must run individually so each gets host "
                                "approval."}, 400)

    handlers = {"read": h_read, "stat": h_stat, "list": h_list,
                "tree": h_tree, "search": h_search, "mkdir": h_mkdir,
                "write": h_write, "edit": h_edit}

    # ---- B4 pre-flight: validate EVERY exec op before anything runs -----
    exec_plan: dict = {}  # index -> (cmd, cwd, timeout, save, save_err, sudo_verb)
    for i, o in enumerate(ops):
        if not (isinstance(o, dict) and o.get("op") == "exec"):
            continue
        command = str(o.get("command", ""))
        if not command:
            return ({"error": "exec_preflight", "index": i,
                     "message": "exec op is missing 'command' — the WHOLE "
                                "batch was refused and NOTHING executed."},
                    400)
        try:
            cwd = _exec_cwd(ctx, agent, o, what="Batch exec")
            save = _exec_save_path(ctx, agent, o)   # v2.4.4, same rule:
            # a bad --save target refuses the WHOLE batch atomically.
            save_err = _exec_save_path(ctx, agent, o,
                                       field="save_stderr")  # v2.4.8
        except OpBlocked as e:
            body = dict(e.body)
            body.update({"error": "exec_preflight", "index": i,
                         "cause": e.body.get("error"),
                         "message": f"{e.body.get('error')}: "
                                    f"{e.body.get('message', '')} — the "
                                    "WHOLE batch was refused and NOTHING "
                                    "executed."})
            return (body, e.status)
        if save and save_err and save == save_err:
            return ({"error": "exec_preflight", "index": i,
                     "cause": "save_same_path",
                     "message": "save and save_stderr must be two "
                                "different files — the WHOLE batch was "
                                "refused and NOTHING executed."}, 400)
        rejection = _preflight_exec(ctx, agent, command, cwd)
        if rejection is not None and rejection.get("rejected"):
            return ({"error": "exec_preflight", "index": i,
                     "rule": rejection.get("rule"),
                     "warning": rejection.get("warning", ""),
                     "message": "This command would be rejected — the "
                                "WHOLE batch was refused and NOTHING "
                                "executed. Fix the command and resend."},
                    400)
        # v2.4.5: a sudo marker is ALLOWED at pre-flight; the forced
        # approval runs per-op at execution time (a batch request
        # may block up to the countdown per sudo op — by design).
        # v2.4.6: the verb rides along so removals get the right op
        # label in the Approvals tab.
        sudo_verb = None
        if rejection and rejection.get("needs_sudo_approval"):
            sudo_verb = rejection.get("sudo_verb") or "install"
        exec_plan[i] = (command, cwd, _exec_timeout(o), save, save_err,
                        sudo_verb)

    results: list = []
    total = 0
    truncated = False
    for i, o in enumerate(ops):
        if not isinstance(o, dict):
            results.append({"index": i, "error": "bad_op",
                            "message": "Each op must be a JSON object."})
            continue
        op_name = str(o.get("op", ""))
        if op_name in _NOT_BATCHABLE_OPS:
            results.append({"index": i, "op": op_name,
                            "error": "not_batchable",
                            "message": f"{op_name} is not batchable in "
                                       "v1 — screen/input ops carry "
                                       "approvals and a GUI-main-thread "
                                       "capture bridge; run them "
                                       "directly."})
            continue
        if op_name == "exec":
            command, cwd, timeout, save, save_err, sudo_verb = exec_plan[i]
            if sudo_verb:
                # v2.4.5: forced approval at run time (blocks this batch
                # request up to the countdown). Denied/timeout-rejected
                # is a per-op RESULT, not a batch abort.
                # v2.4.6: op label carries install vs remove.
                op = ("sudo_install" if sudo_verb == "install"
                      else "sudo_remove")
                try:
                    maybe_gate(ctx, agent, op, command[:120],
                               command, forced=True,
                               expires_in=_sudo_timeout_s(ctx),
                               timeout_action=_sudo_timeout_action(ctx))
                except OpBlocked as e:
                    results.append({"index": i, "op": op_name,
                                    **e.body})
                    continue
            try:
                resp = _run_exec(ctx, agent, command, cwd, timeout,
                                 save=save, save_err=save_err,
                                 sudo_password=ctx.sudo_password or None)
            except OpBlocked as e:        # e.g. exec_busy mid-batch
                results.append({"index": i, "op": op_name, **e.body})
                continue
            except Exception as e:        # per-op failures stay isolated
                results.append({"index": i, "op": op_name,
                                "error": "internal",
                                "message": f"{type(e).__name__}: {e}"})
                continue
            total += len(json.dumps(resp, ensure_ascii=False))
            if total > MAX_BATCH_RESPONSE_BYTES:
                results.append({"index": i, "op": op_name,
                                "error": "batch_response_cap",
                                "message": "Aggregate batch response exceeds "
                                           f"{MAX_BATCH_RESPONSE_BYTES} "
                                           "bytes; remaining ops skipped."})
                truncated = True
                break
            results.append({"index": i, "op": op_name, "ok": resp})
            continue
        handler = handlers.get(op_name)
        if handler is None:
            results.append({"index": i, "error": "unknown_op", "op": op_name,
                            "message": "Batchable ops: read, stat, list, "
                                       "tree, search, mkdir, write, "
                                       "edit, exec."})
            continue
        try:
            resp = handler(h, ctx, agent, o)
        except OpBlocked as e:
            results.append({"index": i, "op": op_name, **e.body})
            continue
        except ProtectedPathError as e:
            results.append({"index": i, "op": op_name,
                            "error": "protected_path",
                            "message": str(e)})
            continue
        except PermissionError as e:
            results.append({"index": i, "op": op_name,
                            "error": "forbidden",
                            "message": str(e)})
            continue
        except Exception as e:            # per-op failures stay isolated
            results.append({"index": i, "op": op_name, "error": "internal",
                            "message": f"{type(e).__name__}: {e}"})
            continue
        if "error" in resp:
            results.append({"index": i, "op": op_name,
                            "error": resp.get("error"),
                            "message": resp.get("message", "")})
            continue
        total += len(json.dumps(resp, ensure_ascii=False))
        if total > MAX_BATCH_RESPONSE_BYTES:
            results.append({"index": i, "error": "batch_response_cap",
                            "message": "Aggregate batch response exceeds "
                                       f"{MAX_BATCH_RESPONSE_BYTES} bytes; "
                                       "remaining ops skipped."})
            truncated = True
            break
        results.append({"index": i, "op": op_name, "ok": resp})
    ctx.sessions.record(agent["name"], "batch",
                        f"{len(ops)} ops ({len(results)} results)",
                        kind="read")
    ctx.audit(agent=agent["name"], op="batch", n=len(ops),
              execs=len(exec_plan))
    ctx.op_log("OP", f"BATCH {len(ops)} ops by {agent['name']}"
               + (f" ({len(exec_plan)} exec)" if exec_plan else ""),
              agent=agent)
    return {"results": results, "truncated": truncated}


# ---------------------------------------------------------------------------
# Handlers: archives (Tier 1 — whole-tree transfer in one hop)
# ---------------------------------------------------------------------------

# Never archived, even with all=1 (host undo history / VCS internals).
_ARCHIVE_ALWAYS_SKIP = {".git"}


@route("GET", "/archive")
def h_archive_get(h, ctx: AppContext, agent: dict, q: dict):
    """Stream a directory as a tar.gz archive (RawResponse).

    v2.3.1: over-cap directories are REFUSED with a clean error instead of
    silently truncating into a valid-looking tar (F29) — an agent syncing a
    large tree must never believe it got everything. The server's own data
    dir is never included (F21).
    """
    raw_path = q.get("path", "")
    include_all = str(q.get("all", "0")).lower() in ("1", "true", "yes")
    if not raw_path:
        return ({"error": "missing_field", "field": "path"}, 400)
    base = resolve_for_agent(ctx, agent, raw_path)
    if not os.path.isdir(base):
        return ({"error": "not_a_directory", "path": base,
                 "message": f"Not a directory: {base}"}, 404)

    prot = list(ctx.sandbox.protected)
    buf = io.BytesIO()
    n_entries = 0
    n_bytes = 0
    n_hidden_skipped = 0
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for root, dirs, files in os.walk(base):
            if not include_all:
                n_hidden_skipped += sum(1 for d in dirs if d.startswith("."))
                n_hidden_skipped += sum(1 for f in files if f.startswith("."))
            dirs[:] = sorted(
                d for d in dirs
                if (include_all or not d.startswith("."))
                and d not in _ARCHIVE_ALWAYS_SKIP
                and (include_all or d not in DEFAULT_IGNORES)
                and not any(os.path.join(root, d) == p
                            or os.path.join(root, d).startswith(p + os.sep)
                            for p in prot))
            files[:] = sorted(
                f for f in files
                if include_all or not f.startswith("."))
            for fname in files:
                full = os.path.join(root, fname)
                if os.path.islink(full):
                    continue        # never archive symlinks
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                if (n_entries >= MAX_ARCHIVE_ENTRIES
                        or n_bytes + st.st_size > MAX_ARCHIVE_BYTES):
                    return ({"error": "archive_too_large", "path": base,
                             "message": f"Directory exceeds the archive "
                                        f"caps ({MAX_ARCHIVE_ENTRIES} "
                                        f"entries / {MAX_ARCHIVE_BYTES} "
                                        "bytes). Refusing to send a "
                                        "truncated archive — archive "
                                        "subdirectories separately."},
                            400)
                n_entries += 1
                n_bytes += st.st_size
                try:
                    tf.add(full, arcname=os.path.relpath(full, base),
                           recursive=False)
                except OSError:
                    continue
    data = buf.getvalue()
    ctx.sessions.record(agent["name"], "archive",
                        f"GET {base} ({n_entries} files)", kind="read")
    ctx.audit(agent=agent["name"], op="archive_get", path=base,
              entries=n_entries, bytes=len(data))
    ctx.op_log("OP", f"ARCHIVE GET {base} ({n_entries} files) "
                     f"by {agent['name']}", agent=agent)
    return RawResponse(data, "application/gzip",
                        {"entries": n_entries,
                         "hidden_skipped": n_hidden_skipped})


@route("POST", "/archive")
def h_archive_put(h, ctx: AppContext, agent: dict, p: dict) -> dict:
    """Extract a tar.gz archive under a path inside the shared roots.

    Hardened: member names must be relative and sandbox-contained, only
    regular files/directories are allowed (no symlinks/devices), .git
    paths are refused, caps on entries/bytes, and existing files are not
    clobbered unless overwrite=true.
    """
    need_perm(agent, "write")
    raw_path = p.get("path", "")
    data = base64.b64decode(p["archive_b64"]) if p.get("archive_b64") else b""
    overwrite = bool(p.get("overwrite", False))
    if not raw_path:
        raise OpBlocked(400, {"error": "missing_field", "field": "path"})
    if not data:
        raise OpBlocked(400, {"error": "missing_field",
                              "field": "archive_b64 (the tar.gz payload, "
                                       "base64)"})
    dest = resolve_for_agent(ctx, agent, raw_path)
    os.makedirs(dest, exist_ok=True)
    if _policy_gates_write(ctx):
        maybe_gate(ctx, agent, "archive_put",
                   f"extract {len(data)}B -> {dest}", path=dest)

    def _validate_member(name: str) -> str | None:
        norm = name.replace("\\", "/")
        parts = [seg for seg in norm.split("/") if seg not in ("", ".")]
        if name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", norm) \
                or ".." in parts:
            return "absolute paths and '..' are not allowed"
        if any(part in _ARCHIVE_ALWAYS_SKIP for part in parts):
            return "refusing to extract into .git paths"
        return None

    # Pass 1: validate every member before touching the filesystem.
    entries = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf:
            problem = _validate_member(m.name)
            if problem:
                return ({"error": "archive_bad_member", "member": m.name,
                         "message": problem}, 400)
            if not m.isfile() and not m.isdir():
                return ({"error": "archive_bad_member", "member": m.name,
                         "message": "only regular files and directories are "
                                    "allowed (no links/devices)"}, 400)
            if m.isfile():
                entries += 1
                if entries > MAX_ARCHIVE_ENTRIES:
                    return ({"error": "archive_too_large",
                              "message": f"more than {MAX_ARCHIVE_ENTRIES} "
                                         "members"}, 400)
            target = os.path.join(dest, m.name)
            real = os.path.realpath(target)
            if not (real == dest or real.startswith(dest + os.sep)):
                return ({"error": "archive_bad_member", "member": m.name,
                         "message": "member escapes the destination"}, 400)
            _check_protected(ctx, target)
            if not overwrite and os.path.exists(target):
                return ({"error": "dest_exists", "path": target,
                         "message": "Pass overwrite=true to replace "
                                    "existing files."}, 409)

    # Pass 2: extract (tarfile's 'data' filter re-validates names/links).
    written = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf:
            tf.extract(m, dest, filter="data")
            if m.isfile():
                written += 1
    ctx.sessions.record(agent["name"], "archive",
                        f"PUT {dest} ({written} files)", dest, "write")
    ctx.events.emit("write", {"path": dest, "agent": agent["name"],
                              "archive": True})
    ctx.audit(agent=agent["name"], op="archive_put", path=dest,
              files=written, bytes=len(data))
    ctx.op_log("OK", f"ARCHIVE PUT {dest} ({written} files) "
                     f"by {agent['name']}", agent=agent)
    return {"path": dest, "files": written, "bytes": len(data)}
