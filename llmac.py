#!/usr/bin/env python3
"""
LLMAC CLI v2 — the agent-side adapter (single file, stdlib only).

This is what an LLM/AI runs inside its sandbox to work on the host's
shared directories. It talks to the LLMAC host over HTTPS (self-signed,
fingerprint-pinned) or plain HTTP (localhost only).

Connection state
----------------
First use (or when the human pastes a connection block):

    python3 llmac.py connect --host H --port P --key K [--fp SHA256:...] --save

After that every command reads the saved connection:

    python3 llmac.py info
    python3 llmac.py ls
    python3 llmac.py read --path /shared/file.py
    python3 llmac.py edit --path /shared/file.py --replace "old" --with "new"
    python3 llmac.py search --query "def main" --glob "*.py"

Connections live in ~/.llmac/connections.json (key stored in plaintext —
the sandbox is the agent's own space). Env vars LLMAC_HOST / LLMAC_PORT /
LLMAC_KEY (legacy LDB_* also honored) override flags.

Commands
--------
  connect / disconnect       manage saved connections
  info                      identity, roots, exec, policy
  ls                        list a directory (or roots)
  tree                      depth-capped tree (ignores node_modules etc.)
  read                      whole file, line range, or byte range
  write                     whole-file write (stdin / --content / --file)
  edit                      surgical edits (replace/lines/insert/append/del)
  search                    content grep / filename glob
  stat, mkdir, rm, mv, cp   filesystem
  download / upload         binary-safe transfers
  batch                    many ops in one round trip (v2.3)
  archive --get/--put      whole-tree tar.gz transfers (v2.3)
  exec                      raw shell (only if host enables it)
  proc start/list/logs/stop background processes
  session status/note/reset server-side session memory (context recovery)
  ledger lint              rule 6 as code — flags asks sitting past
                           satisfied flip gates (v2.6.0, local)
  screen list              monitors: index, geometry, primary, scale
  screen shot --target     per-screen capture: 2 | primary | all
  screen observe --target OCR text with positions + window list
  input mouse/key/text     bounded drive-mode injection (v2.7.0)
  approvals list/wait       approval queue (if host gates your ops)
  grants                    your live approval grants (v2.3)
  events                    long-poll host events
  health                    connectivity check

Exit codes: 0 ok · 1 op error · 2 usage/rejected · 3 connection problem
"""
from __future__ import annotations

import argparse
import ast
import base64
import gzip
import hashlib
import http.client
import json
import os
import re
import select
import socket
import ssl
import sys
import threading
import time
import urllib.request
import urllib.error
from urllib.parse import quote

try:
    # Repo checkout: single source of truth (core.constants is stdlib-only,
    # so importing it from the standalone release file is not possible
    # elsewhere, but guarded here it keeps --version honest forever).
    from core.constants import LLMAC_VERSION as VERSION
except ImportError:
    VERSION = "2.8.1"   # standalone release-file fallback — keep in sync
CONNECTIONS_FILE = os.path.join(
    os.path.expanduser("~"), ".llmac", "connections.json")
DEFAULT_CONN = "default"
DEFAULT_PORT = 8765


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------

class Conns:
    @staticmethod
    def _load() -> dict:
        try:
            with open(CONNECTIONS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _save(data: dict) -> None:
        d = os.path.dirname(CONNECTIONS_FILE)
        os.makedirs(d, exist_ok=True)
        tmp = CONNECTIONS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, CONNECTIONS_FILE)
        try:
            os.chmod(CONNECTIONS_FILE, 0o600)
        except OSError:
            pass

    @staticmethod
    def save(name: str, host: str, port: int, key: str, tls: bool,
             fp: str = "") -> None:
        data = Conns._load()
        data[name] = {"host": host, "port": port, "key": key,
                      "tls": tls, "fp": fp, "saved_at": _now()}
        Conns._save(data)

    @staticmethod
    def get(name: str) -> dict | None:
        return Conns._load().get(name)

    @staticmethod
    def delete(name: str) -> bool:
        data = Conns._load()
        if name not in data:
            return False
        del data[name]
        Conns._save(data)
        return True

    @staticmethod
    def list() -> dict:
        return Conns._load()


def _now() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="seconds")


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

class Client:
    def __init__(self, host: str, port: int, key: str, tls: bool = True,
                 fp: str = "", tap: bool = False):
        self.scheme = "https" if tls else "http"
        self.base = f"{self.scheme}://{host}:{port}"
        self.key = key
        self.fp = fp
        self._ctx = None
        if tls:
            self._ctx = ssl._create_unverified_context()
        # v2.3: keep-alive connection reused across requests, plus a
        # transport-retry window (set from --retry) to survive host
        # restarts without burning round trips.
        self._conn = None
        self.retry_seconds = 0.0
        # v2.8 (--tap): a daemon thread watches the idle keep-alive
        # socket for SERVER-INITIATED bytes. A compliant host only
        # writes in response to a request, so anything readable while
        # no request is outstanding is unsolicited push — recorded,
        # alerted, and the connection is dropped before it desyncs.
        self.tap = bool(tap)
        self._inflight = False
        self._tap_lock = threading.Lock()
        self._tap_stop_evt = None
        self._tap_thread = None
        if self.tap:
            self._tap_start()

    # ---- fingerprint (TOFU) -------------------------------------------

    def server_fingerprint(self, timeout: float = 10.0) -> str | None:
        """Fetch the server cert fingerprint (works even before auth)."""
        if self.scheme != "https" or self._ctx is None:
            return None
        host = self.base.split("//", 1)[1].rsplit(":", 1)[0]
        port = self.base.rsplit(":", 1)[1]
        try:
            import socket as _socket
            import hashlib
            with _socket.create_connection((host, int(port)), timeout=timeout) as sock:
                with self._ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    der = tls_sock.getpeercert(binary_form=True)
            return "SHA256:" + hashlib.sha256(der).hexdigest()
        except (OSError, ValueError):
            return None

    # ---- tap: unsolicited-data monitor (v2.8, --tap) --------------------

    def _tap_start(self) -> None:
        self._tap_stop_evt = threading.Event()
        self._tap_thread = threading.Thread(
            target=self._tap_watch, daemon=True, name="llmac-tap")
        self._tap_thread.start()

    def _tap_stop(self) -> None:
        """Stop the monitor (used by tests; normal exits drop the
        daemon thread without ceremony)."""
        if self._tap_stop_evt is not None:
            self._tap_stop_evt.set()
        if self._tap_thread is not None:
            self._tap_thread.join(timeout=2.0)
            self._tap_thread = None

    def _tap_watch(self) -> None:
        """Watch the IDLE keep-alive connection. Never sends, never
        consumes (MSG_PEEK only). Clean idle EOF is normal keep-alive
        expiry: the connection is dropped quietly and the next request
        reopens. Any readable byte with no request outstanding is
        recorded as an unsolicited-data event and the connection is
        closed so nothing desyncs."""
        stop = self._tap_stop_evt
        while not stop.wait(0.25):
            conn = self._conn
            if conn is None:
                continue
            try:
                with self._tap_lock:
                    if self._inflight or self._conn is not conn:
                        continue          # busy or swapped — not ours
                    sock = getattr(conn, "sock", None)
                    if sock is None:
                        continue          # not connected yet
                    n = self._tap_readable_bytes(sock)
                    if n is None:
                        continue          # quiet
                    if n > 0:
                        self._tap_record(n)
                    # n == 0 (clean EOF) or a recorded push: drop the
                    # connection either way so the stream never desyncs.
                    try:
                        conn.close()
                    except Exception:
                        pass
                    if self._conn is conn:
                        self._conn = None
            except (OSError, ValueError):
                continue

    def _tap_readable_bytes(self, sock) -> "int | None":
        """Server-initiated bytes waiting on an IDLE socket, without
        consuming any. None = quiet; 0 = clean EOF; n > 0 = push.
        TLS sockets are checked in BOTH buffers: records already
        decrypted into OpenSSL's buffer (pending()) and kernel-pending
        bytes (select + MSG_PEEK)."""
        pending = getattr(sock, "pending", None)
        if callable(pending):
            try:
                if pending() > 0:
                    return pending()
            except (OSError, ValueError):
                return None
        try:
            ready, _, _ = select.select([sock], [], [], 0)
            if not ready:
                return None
            old = sock.gettimeout()
            sock.settimeout(0)
            try:
                peek = sock.recv(1, socket.MSG_PEEK)
            finally:
                sock.settimeout(old)
            return 0 if peek == b"" else 1
        except (OSError, ValueError):
            return None

    def _tap_record(self, n: int) -> None:
        detail = (f"{n}+ byte(s) server-initiated on the idle "
                  f"connection to {self.base}")
        _TAP["events"].append({"time": time.strftime("%H:%M:%S"),
                               "detail": detail})
        try:
            sys.stderr.write(
                f"\n[TAP] {detail}\n[TAP] The host sent data with no "
                f"request outstanding — treat results with suspicion.\n")
            sys.stderr.flush()
        except (OSError, ValueError):
            pass

    # ---- core request ---------------------------------------------------

    def _open_connection(self, timeout: float = 30.0):
        """One TCP(+TLS) session, reused across requests (keep-alive)."""
        host = self.base.split("//", 1)[1].rsplit(":", 1)[0]
        port = int(self.base.rsplit(":", 1)[1])
        if self.scheme == "https":
            return http.client.HTTPSConnection(
                host, port, context=self._ctx, timeout=timeout)
        return http.client.HTTPConnection(host, port, timeout=timeout)

    def _enforce_inbox_notice(self, resp, path: str) -> None:
        """v2.5.1 (ASK-005) + v2.7.3: the ENFORCED notice. The server
        stamps X-LLMAC-Unread on every authenticated response; this
        records it in the process-wide _INBOX state. v2.7.3: nothing
        is printed HERE any more (a stderr banner emitted mid-request,
        BEFORE the result, was the part agents scrolled past) — the
        command wrapper (_call_with_inbox_notice) appends the notice
        to the operation's own result, on stdout, after the last byte
        of it, and _pjson folds it into JSON results as a field.
        The inbox read itself is exempt. rc is NEVER touched (tip 17:
        the rc reports the transport)."""
        n = None
        try:
            n = int(resp.getheader("X-LLMAC-Unread"))
        except (TypeError, ValueError):
            n = None
        self.last_unread = n
        if path.startswith("/session/inbox"):
            _INBOX["unread"] = 0        # reading it IS the acknowledgement
        elif n is not None:
            _INBOX["unread"] = max(0, n)

    def _attempt(self, method: str, path: str, body, headers: dict,
                 raw: bool = False, timeout: float = 30.0) -> tuple:
        """One request attempt. Returns (result, status), or (None, 0) on
        a transport-level failure (the caller decides whether to retry)."""
        try:
            if self._conn is None:
                self._conn = self._open_connection(timeout)
            conn = self._conn          # local: tap may swap self._conn
            with self._tap_lock:
                self._inflight = True   # v2.8: tap must not peek now
            try:
                conn.request(method, path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
            finally:
                with self._tap_lock:
                    self._inflight = False
            self._enforce_inbox_notice(resp, path)   # v2.5.1 (ASK-005)
            if raw:
                return data, resp.status
            if "gzip" in (resp.getheader("Content-Encoding") or "").lower():
                data = gzip.decompress(data)
            try:
                return json.loads(data.decode("utf-8") or "{}"), resp.status
            except json.JSONDecodeError:
                return {"error": "bad_response",
                        "message": data[:512].decode("utf-8",
                                                     errors="replace")}, resp.status
        except (http.client.HTTPException, OSError):
            # Drop the (possibly stale) connection; the loop reopens.
            try:
                if self._conn is not None:
                    self._conn.close()
            except Exception:
                pass
            self._conn = None
            return None, 0

    def _request(self, method: str, path: str, payload: dict | None = None,
                 timeout: float = 130.0, raw: bool = False) -> tuple:
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.key}",
            "Accept-Encoding": "gzip",   # compressed responses (v2.3)
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }
        deadline = time.monotonic() + max(0.0, self.retry_seconds)
        stale_retry = True    # one free retry when a REUSED socket died
        mid_session = False   # v2.4.4: did a live connection die on us?
        while True:
            reused = self._conn is not None
            result, status = self._attempt(
                method, path, body if payload is not None else None,
                headers, raw=raw, timeout=timeout)
            if result is not None:
                return result, status
            if reused:
                # The transport WORKED before in this process — this is a
                # mid-session death (server restart?), not a bad address.
                mid_session = True
            if reused and stale_retry:
                stale_retry = False   # server closed our keep-alive socket
                continue
            if self.retry_seconds <= 0 or time.monotonic() >= deadline:
                # v2.4.4 UX: distinguish "server restarted under me" from
                # "wrong address/down" — the remedy differs (wait vs fix
                # flags). All 26+ call sites print .message, so the hint
                # lives here, in ONE place.
                if mid_session:
                    msg = (f"Cannot reach {self.base}: the connection died "
                           "mid-session — the server was most likely "
                           "RESTARTED (GUI restart?) or is restarting. "
                           "If the GUI was just restarted, wait a few "
                           "seconds and re-run the SAME command; or pass "
                           "--retry N to wait automatically. exec commands "
                           "are never auto-retried (they may be running "
                           "server-side — check before re-sending).")
                else:
                    msg = (f"Cannot reach {self.base}: connection refused or "
                           "broken — the server is down, the host/port is "
                           "wrong, or TLS/plain mismatch (try adding or "
                           "removing --plain).")
                return {"error": "connection_failed", "message": msg,
                        "mid_session": mid_session}, 0
            time.sleep(1.0)

    # ---- endpoint helpers --------------------------------------------------

    def get(self, path: str, timeout: float = 130.0) -> tuple:
        return self._request("GET", path, None, timeout)

    def post(self, path: str, payload: dict | None = None,
             timeout: float = 130.0) -> tuple:
        return self._request("POST", path, payload or {}, timeout)

    def get_raw(self, path: str, timeout: float = 130.0) -> tuple:
        """Fetch a raw (non-JSON) endpoint: returns (bytes, status)."""
        return self._request("GET", path, None, timeout, raw=True)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

# ---- v2.7.3: the inbox notice rides EVERY operation's result ----------------
#
# Agents routinely skipped the v2.5.1 stderr banner: it printed in the
# middle of the request, before the result, on the stream tool
# wrappers collapse or drop. The notice now travels WITH the result:
#   * plain output  -> a trailer on stdout, after the last byte of the
#                      operation's own output (last thing read);
#   * JSON output   -> a top-level "inbox_notice" field inside the JSON
#                      document itself (stdout stays parseable).
# Either way the text states the count: "N message(s) waiting to be
# addressed in Inbox". Exempt: the inbox read itself.

_INBOX = {"unread": 0, "injected": False}

# v2.8: tap events recorded this process (see --tap). Surfaced after
# each command by _call_with_inbox_notice and folded into JSON results
# by _with_tap — mirroring the inbox notice: the alert describes the
# CHANNEL, never the op, so rc stays untouched.
_TAP = {"events": []}


def _inbox_text(n: int) -> str:
    noun = "message" if n == 1 else "messages"
    return f"{n} {noun} waiting to be addressed in Inbox"


def _inbox_howto() -> str:
    return ("Stop the current work unit and run `python3 llmac.py session "
            "inbox` (read + clear; `--peek` looks without clearing), "
            "answer with `session note --text \"...\"`, then continue.")


def _inbox_field(n: int) -> dict:
    return {"unread": n, "message": f"{_inbox_text(n)}. {_inbox_howto()}"}


def _with_inbox(obj):
    """Return obj with the inbox notice folded in when messages are
    unread and obj is a JSON object (copy — the caller's dict is not
    mutated). A no-op otherwise."""
    n = _INBOX["unread"]
    if n and isinstance(obj, dict) and "inbox_notice" not in obj:
        _INBOX["injected"] = True
        out = dict(obj)
        out["inbox_notice"] = _inbox_field(n)
        return out
    return obj


def _call_with_inbox_notice(func, args) -> int:
    """Run one subcommand; afterwards, if the server reported unread
    inbox messages and the notice has not already been folded into a
    JSON result, append it to stdout. rc is passed through untouched,
    success or failure (the notice describes the inbox, not the op)."""
    if func is cmd_run:        # run calls us per sub-command; no double
        return func(args)
    _INBOX["unread"] = 0
    _INBOX["injected"] = False
    _TAP["events"] = []
    rc = func(args)
    n = _INBOX["unread"]
    if n and not _INBOX["injected"]:
        try:
            sys.stdout.flush()
            bar = "-" * 62
            print(f"\n{bar}\n[INBOX] {_inbox_text(n)}.\n"
                  f"{_inbox_howto()}\n{bar}")
            sys.stdout.flush()
        except (BrokenPipeError, ValueError):
            pass
    if _TAP["events"]:
        # v2.8: loud, AFTER the result (same placement rule as the
        # inbox notice). rc untouched — the alert is about the channel.
        try:
            sys.stdout.flush()
            bar = "!" * 62
            evs = _TAP["events"]
            print(f"\n{bar}\n[TAP] {len(evs)} unsolicited-data "
                  f"event(s) this run — the host sent bytes with no "
                  f"request outstanding:")
            for e in evs:
                print(f"  {e['time']}  {e['detail']}")
            print("Treat all results with suspicion; report this to the "
                  f"operator.\n{bar}")
            sys.stdout.flush()
        except (BrokenPipeError, ValueError):
            pass
    return rc


def _with_tap(obj):
    """Fold tap alerts into JSON results (copy, like _with_inbox)."""
    if _TAP["events"] and isinstance(obj, dict) and "tap_alerts" not in obj:
        out = dict(obj)
        out["tap_alerts"] = list(_TAP["events"])
        return out
    return obj


def _pjson(obj, indent=2):
    print(json.dumps(_with_tap(_with_inbox(obj)), indent=indent,
                     ensure_ascii=False))


def _err(msg: str, code: int = 1):
    print(f"ERROR: {msg}", file=sys.stderr)
    return code


_ERR_FIELD_ORDER = ("message", "path", "field", "expected", "detail",
                    "rule")


def _fmt_err_fields(d: dict) -> str:
    """v2.4.9 (lesson #11 family): render EVERY scalar context field
    the server sent. Payloads like {"error": "not_a_directory",
    "path": p} used to print as 'not_a_directory: ' — the subject was
    dropped on the floor by the hand-rolled `error: message` printers."""
    bits = [str(d.get("error", "error"))]
    for k in _ERR_FIELD_ORDER:
        v = d.get(k)
        if v:
            bits.append(str(v) if k == "message" else f"{k}: {v}")
    for k, v in sorted(d.items()):
        if k in ("error", "index", "op") + _ERR_FIELD_ORDER \
                or isinstance(v, bool) \
                or not isinstance(v, (str, int, float)):
            continue
        bits.append(f"{k}: {v}")
    return ": ".join(bits)


def _err_from_resp(resp: dict, code: int = 1):
    return _err(_fmt_err_fields(resp), code)


def _human_size(n):
    if n is None:
        return ""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} B"


def _print_op_resp(resp, status, ok_keys=("ok", "created", "deleted", "moved",
                                          "copied", "stored", "reset")):
    """Compact one-line confirmation, or JSON on --verbose."""
    if status >= 400 or "error" in resp:
        return _err_from_resp(resp)
    if "--verbose" in sys.argv:
        _pjson(resp)
        return 0
    for k in ok_keys:
        if k in resp:
            bits = [k]
            if "path" in resp:
                bits.append(resp["path"])
            if "bytes" in resp:
                bits.append(_human_size(resp["bytes"]))
            if "changes" in resp:
                bits.append(f"{resp['changes']} change(s)")
            print("  ".join(str(b) for b in bits))
            return 0
    _pjson(resp)
    return 0


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------

_CLIENT_CACHE: dict = {}   # (host, port, key, fp, tls) -> Client (A2)


def _client_from_args(args) -> Client:
    conn_name = getattr(args, "conn", None) or os.environ.get(
        "LLMAC_CONN", DEFAULT_CONN)
    saved = Conns.get(conn_name) or {}

    host = (getattr(args, "host", None)
            or os.environ.get("LLMAC_HOST") or os.environ.get("LDB_HOST")
            or saved.get("host"))
    port = (getattr(args, "port", None)
            or int(os.environ.get("LLMAC_PORT") or os.environ.get("LDB_PORT") or 0)
            or saved.get("port") or DEFAULT_PORT)
    key = (getattr(args, "key", None)
           or os.environ.get("LLMAC_KEY") or os.environ.get("LDB_KEY")
           or saved.get("key") or "")
    fp = (getattr(args, "fp", None) or saved.get("fp") or "")
    tls = saved.get("tls", True)
    if getattr(args, "plain", False):
        tls = False
    if not host:
        host = "127.0.0.1"
    # A2: reuse ONE TLS session across all commands in this process
    # (llmac run) — a fresh one-shot CLI invocation pays ~439 ms fixed
    # overhead per command, 3.6x the request itself (bench 2026-10-25).
    tap = bool(getattr(args, "tap", False))
    ck = (host, int(port), key, fp, bool(tls), tap)
    client = _CLIENT_CACHE.get(ck)
    if client is None:
        client = Client(host, int(port), key, tls=bool(tls), fp=fp, tap=tap)
        # TOFU pinning: if we have a pinned fingerprint, verify.
        if client.scheme == "https" and fp and not getattr(args, "no_verify",
                                                           False):
            live = client.server_fingerprint()
            # Fail CLOSED (F2): a failed probe used to silently skip
            # verification, permanently unpinned.
            if live is None:
                print("ERROR: could not probe the server certificate to "
                      "verify the pinned fingerprint — refusing to "
                      "continue.\nRetry in a moment, or use --no-verify in "
                      "an emergency.", file=sys.stderr)
                sys.exit(3)
            if live != fp:
                print(f"ERROR: certificate fingerprint mismatch!\n"
                      f"  pinned: {fp}\n  live:   {live}\n"
                      f"Refusing to continue (possible MITM). Use --no-verify "
                      f"only if you know why.", file=sys.stderr)
                sys.exit(3)
        _CLIENT_CACHE[ck] = client
    client.retry_seconds = float(getattr(args, "retry", 0) or 0)
    return client


def _require_key(client: Client) -> int:
    if not client.key:
        return _err("no key: pass --key, set LLMAC_KEY, or run "
                    "'llmac connect --host H --port P --key K --save'", 2)
    return 0


# ---- connect ------------------------------------------------------------

def cmd_connect(args) -> int:
    host = args.host
    port = args.port or DEFAULT_PORT
    key = args.key
    if not host or not key:
        return _err("connect requires --host and --key", 2)
    tls = not getattr(args, "plain", False)
    no_verify = getattr(args, "no_verify", False)
    client = Client(host, port, key, tls=tls)
    fp_arg = getattr(args, "fp", "") or ""
    live = client.server_fingerprint() if tls else None
    if tls and fp_arg:
        # An explicitly pinned fp must be VERIFIED before anything else
        # (F1): connect used to succeed + save wrong pins silently.
        if live is None:
            return _err("TLS probe failed — cannot verify the pinned "
                        "fingerprint. Refusing to connect (use --no-verify "
                        "in an emergency).", 3)
        if live != fp_arg and not no_verify:
            print(f"ERROR: certificate fingerprint mismatch!\n"
                  f"  pinned: {fp_arg}\n  live:   {live}\n"
                  f"Refusing to continue (possible MITM). Use --no-verify "
                  f"only if you know why.", file=sys.stderr)
            return 3
    elif tls and not fp_arg:
        if live:
            print(f"Server certificate (TOFU pinned): {live}")
        else:
            print("WARNING: could not fetch the server certificate "
                  "fingerprint.", file=sys.stderr)
    # Verify by calling /info
    resp, status = client.get("/info")
    if status == 0:
        return _err(f"cannot reach host: {resp.get('message', 'connection failed')}", 3)
    if status >= 400 or "error" in resp:
        return _err("host refused connection: "
                    + _fmt_err_fields(resp), 3)
    if args.save:
        if tls and not (fp_arg or live):
            # F2: refuse to persist an unpinned TLS connection.
            return _err("no certificate fingerprint available — refusing "
                        "to save an unpinned connection. Retry, or pass "
                        "--no-verify to override.", 3)
        Conns.save(args.name, host, port, key, tls, fp_arg or (live or ""))
        print(f"Connection '{args.name}' saved to {CONNECTIONS_FILE}")
    agent = resp.get("agent", {}).get("name", "?")
    roots = resp.get("roots", [])
    print(f"Connected. agent={agent}  roots={len(roots)}  "
          f"exec={'on' if resp.get('exec_enabled') else 'off'}  "
          f"policy={resp.get('approval_policy')}")
    return 0


def cmd_disconnect(args) -> int:
    if not Conns.delete(args.name):
        return _err(f"no such connection: {args.name}", 2)
    print(f"Connection '{args.name}' removed.")
    return 0


def cmd_conns(args) -> int:
    data = Conns.list()
    if not data:
        print("(no saved connections)")
        return 0
    for name, c in data.items():
        scheme = "https" if c.get("tls", True) else "http"
        print(f"{name:<16} {scheme}://{c.get('host')}:{c.get('port')}  "
              f"saved {c.get('saved_at', '')}")
    return 0


# ---- identity ------------------------------------------------------------

def cmd_info(args) -> int:
    c = _client_from_args(args)
    rc = _require_key(c)
    if rc:
        return rc
    resp, status = c.get("/info")
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    _pjson(resp)
    return 0 if status < 400 else 1


def cmd_health(args) -> int:
    c = _client_from_args(args)
    resp, status = c.get("/health", timeout=10)
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    _pjson(resp)
    return 0


# ---- navigation ------------------------------------------------------------

def cmd_ls(args) -> int:
    c = _client_from_args(args)
    resp, status = c.post("/list", {"path": args.path or ""})
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    if "error" in resp:
        return _err_from_resp(resp)
    entries = resp.get("entries", [])
    if not entries:
        print("(empty)")
        return 0
    name_w = min(max(len(e["name"]) for e in entries) + 2, 48)
    for e in entries:
        size = e.get("size")
        size_s = _human_size(size).rjust(9) if isinstance(size, int) else " " * 9
        print(f"{e['name'][:name_w]:<{name_w}} [{e['type'][:4]:<4}] "
              f"{size_s}  {e['path']}")
    return 0


def cmd_tree(args) -> int:
    c = _client_from_args(args)
    resp, status = c.post("/tree", {"path": args.path or "",
                                    "depth": args.depth,
                                    "all": args.all})
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    if "error" in resp:
        return _err_from_resp(resp)
    trees = resp.get("trees") or [resp]
    count = 0
    for t in trees:
        root = t.get("root", "")
        if root:
            print(root)
        for e in t.get("entries", []):
            indent = "  " * e["depth"]
            marker = "/" if e["type"] == "dir" else ""
            size = (f"  {_human_size(e['size'])}"
                    if e.get("size") is not None else "")
            print(f"{indent}{e['name']}{marker}{size}")
            count += 1
    if resp.get("truncated"):
        print(f"... (truncated — narrow --path or reduce --depth)")
    return 0


# ---- read/write/edit ------------------------------------------------------------

def cmd_read(args) -> int:
    # v2.4.8 post-release guard: --find-hex/--find-text ride the hex
    # reader. The server 400s find_needs_hex; the CLI must refuse just
    # as loudly BEFORE any request — silently dropping the flags made
    # the client fall back to a plain (binary!) read, and an agent
    # could believe the scan had run.
    if ((getattr(args, "find_hex", None) or getattr(args, "find_text", None))
            and not getattr(args, "hex_flag", False)):
        return _err("find_needs_hex: --find-hex/--find-text ride the hex "
                    "reader (absolute offsets + context); add --hex", 2)
    if getattr(args, "max_hits", None) and not (
            getattr(args, "find_hex", None) or getattr(args, "find_text", None)):
        # v2.4.9 (lesson #11): the cap was sent only inside the hex+find
        # branch and silently ignored otherwise — refuse BEFORE any
        # request, mirroring find_needs_hex.
        return _err("find_max_hits_needs_find: --max-hits caps a "
                    "--find-hex/--find-text scan; add a find pattern", 2)
    c = _client_from_args(args)
    payload = {"path": args.path, "numbered": args.numbered}
    if args.lines:
        try:
            s, e = args.lines.split("-", 1)
            payload["from_line"], payload["to_line"] = int(s), int(e)
        except ValueError:
            return _err("--lines takes START-END (e.g. 10-50)", 2)
    if args.offset is not None:
        payload["offset"] = args.offset
    if args.limit is not None:
        payload["limit"] = args.limit
    if args.max_bytes:
        payload["max_bytes"] = args.max_bytes
    if getattr(args, "hex_flag", False):
        payload["hex"] = True
        # v2.4.8: the find (GOTO/search) primitive — bytes or literal
        # text, paged from --offset, hits carry rendered hex context.
        if getattr(args, "find_hex", None):
            payload["find_hex"] = args.find_hex
        if getattr(args, "find_text", None):
            payload["find_text"] = args.find_text
        if getattr(args, "max_hits", None):
            payload["find_max_hits"] = args.max_hits
    resp, status = c.post("/read", payload)
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    if "error" in resp:
        return _err_from_resp(resp)
    if resp.get("find"):
        # v2.4.8: find mode — one line of summary, then each hit with
        # its rendered hex context (absolute offsets). Honors --to like
        # the plain hex dump does.
        fd = resp["find"]
        hits = resp.get("matches", [])
        lines = [f"{resp.get('match_count', len(hits))} hit(s) for "
                 f"{fd.get('kind')} '{fd.get('pattern_hex', '')}' "
                 f"({fd.get('pattern_len', 0)} B) in {resp.get('path')}, "
                 f"scanned from offset {fd.get('scan_from', 0)}"]
        for i, m in enumerate(hits, 1):
            lines.append(f"== hit {i} @ 0x{m.get('offset', 0):08x} "
                         f"({m.get('offset', 0)}) ==")
            lines.append((m.get("context") or "").rstrip("\n"))
        text = "\n".join(lines)
        out = args.to if args.to else None
        if out and out != "-":
            os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
            with open(out, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"wrote {len(text)} chars -> {out}")
        else:
            try:
                sys.stdout.write(text + "\n")
            except BrokenPipeError:
                pass
        if resp.get("more") and resp.get("next_offset"):
            print(f"[hit cap reached — more may exist; continue with "
                  f"--find-{fd.get('kind')} '{fd.get('pattern_hex', '')}' "
                  f"--offset {resp['next_offset']}]", file=sys.stderr)
        return 0
    if resp.get("hex"):
        # v2.4.7: server-rendered hex dump — plain text, honors --to.
        text = resp.get("content", "")
        out = args.to if args.to else None
        if out and out != "-":
            os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
            with open(out, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"wrote {len(text)} chars -> {out}")
        else:
            try:
                sys.stdout.write(text)
            except BrokenPipeError:
                pass
        if resp.get("truncated"):
            nxt = resp.get("next_offset")
            hint = (f" (continue with --hex --offset {nxt})" if nxt else "")
            print(f"[truncated{hint}]", file=sys.stderr)
        return 0
    if resp.get("binary"):
        data = base64.b64decode(resp["content_b64"])
        out = args.to if args.to else None
        if out:
            os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
            with open(out, "wb") as f:
                f.write(data)
            print(f"wrote {len(data)} B -> {out}")
        else:
            try:
                sys.stdout.buffer.write(data)
            except BrokenPipeError:
                pass
    else:
        out = args.to if args.to else None
        if out == "-":          # explicit '-' means stdout (W6: used to
            out = None          # create a file literally named '-')
        text = (f"version: {resp['version']}\n" if args.verbose else "") + \
               resp.get("content", "")
        if out:
            os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
            with open(out, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"wrote {len(text)} chars -> {out}")
        else:
            # A4 smart truncation: an unwitting whole-file read of a large
            # text file costs ~24.5K tokens (measured on gui.py) — more
            # than an entire orientation boot. Guard the agent's context:
            # head 200 + tail 50 + an omission marker on stderr, unless
            # a range was requested, --to/--raw/--numbered was given, or
            # the file is small.
            ranged = bool(args.lines or getattr(args, "offset", None) is not None
                          or getattr(args, "limit", None) is not None
                          or getattr(args, "max_bytes", None))
            lines = text.split("\n")
            smart = (not ranged and not getattr(args, "raw", False)
                     and not args.numbered and len(text) > 32768
                     and len(lines) > 251)
            if smart:
                omitted = len(lines) - 250
                sys.stdout.write("\n".join(lines[:200]) + "\n")
                print(f"[smart-truncated: {omitted} lines omitted "
                      f"(file: {len(lines)} lines, {len(text)} chars). "
                      f"Use --lines A-B for a range, --raw for the full "
                      f"text, or --to to save it.", file=sys.stderr)
                sys.stdout.write("\n".join(lines[-50:]))
            else:
                # Byte-exact display (F8): never append a newline the file
                # does not have — agents diffing displayed output were misled.
                try:
                    sys.stdout.write(text)
                except BrokenPipeError:
                    pass
    if resp.get("truncated"):
        nxt = resp.get("next_offset")
        hint = (f" (continue with --offset {nxt})" if nxt else "")
        print(f"[truncated{hint}]", file=sys.stderr)
    return 0


def cmd_write(args) -> int:
    if args.content is not None and args.file:
        # v2.4.9 (lesson #11): the file source silently won and the
        # --content bytes vanished.
        return _err("content_file_conflict: --content and --file are "
                    "two sources for one write; give one", 2)
    c = _client_from_args(args)
    payload = {"path": args.path}
    if args.expected_version:
        payload["expected_version"] = args.expected_version
    if args.file:
        with open(args.file, "rb") as f:
            data = f.read()
        try:
            payload["content"] = data.decode("utf-8")
        except UnicodeDecodeError:
            payload["content_b64"] = base64.b64encode(data).decode()
    elif args.content is not None:
        payload["content"] = args.content
    else:
        data = sys.stdin.buffer.read()
        try:
            payload["content"] = data.decode("utf-8")
        except UnicodeDecodeError:
            payload["content_b64"] = base64.b64encode(data).decode()
    resp, status = c.post("/write", payload)
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    if status == 409:
        return _err_from_resp(resp)
    return _print_op_resp(resp, status)


def cmd_edit(args) -> int:
    # v2.4.9 flag-drop guards (lesson #11): occurrence/regex only
    # modify --replace, and --content only feeds --lines/--insert*/
    # --append — every other combination silently dropped them.
    if (args.occurrence != "first" or args.regex) and args.replace is None:
        return _err("modifier_needs_replace: --occurrence/--regex "
                    "modify --replace; add --replace", 2)
    if args.content is not None and not (args.lines is not None
                                         or args.insert_before is not None
                                         or args.insert_after is not None
                                         or args.append):
        return _err("unused_content: --content feeds "
                    "--lines/--insert-*/--append only (with "
                    "--replace/--delete-lines it would be silently "
                    "ignored)", 2)
    c = _client_from_args(args)
    ops = []
    if args.replace is not None:
        if args.with_ is None:
            return _err("--replace requires --with", 2)
        op = {"op": "replace", "find": args.replace, "replace": args.with_,
              "occurrence": args.occurrence}
        if args.regex:
            op["regex"] = True
        ops.append(op)
    if args.lines is not None:
        try:
            s, e = args.lines.split("-", 1)
        except ValueError:
            return _err("--lines takes START-END", 2)
        ops.append({"op": "lines", "start": int(s), "end": int(e),
                    "content": args.content or ""})
    if args.insert_after is not None:
        ops.append({"op": "insert", "after_line": args.insert_after,
                    "content": args.content or ""})
    if args.insert_before is not None:
        ops.append({"op": "insert", "before_line": args.insert_before,
                    "content": args.content or ""})
    if args.append:
        ops.append({"op": "append", "content": args.content or ""})
    if args.delete_lines is not None:
        try:
            s, e = args.delete_lines.split("-", 1)
        except ValueError:
            return _err("--delete-lines takes START-END", 2)
        ops.append({"op": "delete_lines", "start": int(s), "end": int(e)})
    if not ops:
        return _err("no edit op given (see --replace/--lines/--insert-*/"
                    "--append/--delete-lines)", 2)
    payload = {"path": args.path, "ops": ops}
    if args.expected_version:
        payload["expected_version"] = args.expected_version
    resp, status = c.post("/edit", payload)
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    if "error" in resp:
        return _err_from_resp(resp)
    print(f"edited {resp.get('path')} — {resp.get('changes')} change(s), "
          f"new version {resp.get('version')}")
    print(resp.get("diff", ""))
    return 0


# ---- search ------------------------------------------------------------

def cmd_search(args) -> int:
    # v2.4.9 flag-drop guards (lesson #11): context lines and regex
    # ride the CONTENT search — with only --name they were silently
    # dropped by the server's name_search branch; --name/--glob are
    # aliases and the server kept only the first.
    if args.context and not args.query:
        return _err("context_needs_query: --context lines ride the "
                    "content search; add --query", 2)
    if args.regex and not args.query:
        return _err("regex_needs_query: --regex modifies --query; "
                    "add --query", 2)
    if args.name and args.glob:
        return _err("name_glob_conflict: --name and --glob are "
                    "aliases for the same field; give one", 2)
    c = _client_from_args(args)
    payload = {"path": args.path or "", "max_results": args.max_results,
               "context": args.context, "all": args.all}
    if args.query:
        payload["query"] = args.query
        payload["regex"] = bool(args.regex)
    if args.name:
        payload["name"] = args.name
    if args.glob:
        payload["glob"] = args.glob
    resp, status = c.post("/search", payload)
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    if "error" in resp:
        return _err_from_resp(resp)
    matches = resp.get("matches", [])
    if not matches:
        print("(no matches)")
        return 0
    for m in matches:
        if "line" in m:
            print(f"{m['path']}:{m['line']}: {m['text']}")
            for cx in m.get("context", []):
                print(f"    {cx['line']:>5}| {cx['text']}")
        else:
            print(f"{m['path']}  ({_human_size(m.get('size'))})")
    if resp.get("truncated"):
        print(f"... (truncated at {args.max_results} — narrow the query)",
              file=sys.stderr)
    return 0


# ---- fs ------------------------------------------------------------

def _simple_post(args, path, payload, ok_key):
    c = _client_from_args(args)
    resp, status = c.post(path, payload)
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    return _print_op_resp(resp, status)


def cmd_stat(args) -> int:
    payload = {"path": args.path}
    if getattr(args, "hash_flag", False):
        payload["hash"] = True
    return _simple_post(args, "/stat", payload, "ok")


def cmd_mkdir(args) -> int:
    return _simple_post(args, "/mkdir", {"path": args.path}, "created")


def cmd_rm(args) -> int:
    payload = {"path": args.path}
    if args.confirm:
        payload["confirm"] = True
    return _simple_post(args, "/delete", payload, "deleted")


def cmd_mv(args) -> int:
    return _simple_post(args, "/move",
                        {"src": args.src, "dest": args.dest,
                         "overwrite": args.overwrite}, "moved")


def cmd_cp(args) -> int:
    return _simple_post(args, "/copy",
                        {"src": args.src, "dest": args.dest,
                         "overwrite": args.overwrite}, "copied")


def cmd_download(args) -> int:
    """Download a remote file to a local path (binary-safe)."""
    args.to = args.to or "-"
    return cmd_read(args)


def cmd_upload(args) -> int:
    if not args.file:
        return _err("upload requires --file", 2)
    args.content = None
    return cmd_write(args)


# ---- batch / archive / grants (v2.3) --------------------------------------

def cmd_batch(args) -> int:
    if getattr(args, "ops", None) and getattr(args, "ops_file", None):
        # v2.4.9 (lesson #11): --file silently won and --ops vanished.
        return _err("ops_file_conflict: --ops and --file are two "
                    "sources for one batch; give one", 2)
    c = _client_from_args(args)
    if getattr(args, "ops_file", None):
        try:
            with open(args.ops_file, "r", encoding="utf-8") as f:
                ops = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            return _err(f"cannot read ops file: {e}", 2)
    elif getattr(args, "ops", None):
        try:
            ops = json.loads(args.ops)
        except json.JSONDecodeError as e:
            return _err(f"--ops is not valid JSON: {e}", 2)
    else:
        try:
            ops = json.load(sys.stdin)
        except json.JSONDecodeError as e:
            return _err(f"stdin is not valid JSON: {e}", 2)
    if not isinstance(ops, list):
        return _err("ops must be a JSON array", 2)
    resp, status = c.post("/batch", {"ops": ops})
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    if "error" in resp:
        return _err_from_resp(resp)
    if getattr(args, "json_out", False):
        _pjson(resp)
        return 0
    for r in resp.get("results", []):
        i = r.get("index", "?")
        op = r.get("op", "?")
        if "ok" in r:
            ok = r["ok"]
            if ok.get("path"):
                note = ok["path"]
            elif op == "list":
                note = f"{len(ok.get('entries', []))} entries"
            elif op == "search":
                note = f"{len(ok.get('matches', []))} hits"
            else:
                note = ""
            if op == "read":
                if ok.get("find"):
                    note = (f"{note} (find: {ok.get('match_count')} "
                            f"hit(s))")
                elif ok.get("hex"):
                    note = (f"{note} (hex dump, {ok.get('dump_bytes')} B "
                            f"of {ok.get('size')})")
                elif ok.get("binary"):
                    note = (f"{note} (binary, {ok.get('size')} B; use "
                            f"read --to for bytes)")
                else:
                    prev = (ok.get("content") or "").replace(
                        "\n", "\\n")
                    note = f"{note} | {prev[:120]}"
            elif op == "exec":
                # B4: exec in batch — surface rc (and a stdout preview)
                # the way plain `exec` does, so agents don't re-run.
                note = f"rc={ok.get('returncode')}"
                if ok.get("timed_out"):
                    note += " TIMED OUT"
                prev = (ok.get("stdout") or "").replace("\n", "\\n")
                if prev:
                    note += f" | {prev[:80]}"
            elif op == "stat" and ok.get("sha256"):
                note = f"{note} sha256={ok['sha256'][:16]}..."
            print(f"[{i}] {op}: ok {note}".rstrip())
            # v2.4.7: batched edits carry their surgical diff — print it
            # by default (an edit without its diff forces a re-read;
            # --no-diffs suppresses for close-to-the-wire batches).
            if op == "edit" and not getattr(args, "no_diffs", False):
                diff = ok.get("diff") or ""
                if diff:
                    print(diff.rstrip("\n"))
        else:
            print(f"[{i}] {op}: {_fmt_err_fields(r)}")
    if resp.get("truncated"):
        print("[batch truncated]", file=sys.stderr)
    return 0


# ---- run / deploy (v2.4 agent-efficiency tier) -------------------------------

def cmd_run(args) -> int:
    """A2: execute many CLI commands in ONE process over ONE TLS session.
    Each one-shot invocation pays ~439 ms fixed overhead (interpreter +
    TCP/TLS handshake) vs ~166 ms for the request itself; `run` amortizes
    that across N commands. Input: JSON array of arg-vectors, from
    --file or stdin. Stops at the first failure unless --keep-going."""
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                vectors = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            return _err(f"cannot read commands file: {e}", 2)
    else:
        try:
            vectors = json.load(sys.stdin)
        except json.JSONDecodeError as e:
            return _err(f"stdin is not a JSON array: {e}", 2)
    if not isinstance(vectors, list) or not vectors:
        return _err("run input must be a non-empty JSON array of "
                    "arg-vectors, e.g. [[\"read\", \"--path\", \"/a\"]]", 2)
    for v in vectors:
        if not isinstance(v, list) or not v or not all(isinstance(x, str)
                                                       for x in v):
            return _err(f"each command must be an array of strings, got: "
                        f"{json.dumps(v)[:80]}", 2)
        if v[0] in ("run", "deploy"):
            return _err(f"'{v[0]}' inside run is not allowed (recursion / "
                        "atomicity)", 2)
    parser = build_parser()
    done, first_fail = 0, None
    # The sub-parsers do not know the TOP-LEVEL connection flags this
    # process was started with (--host/--port/--key/--plain/...); without
    # this propagation each sub-command would silently fall back to the
    # saved default connection instead of the host the run was aimed at
    # (caught by the v2.4 test suite; the live smoke masked it because
    # the saved default happened to be the intended host).
    _CONN_FIELDS = ("host", "port", "key", "fp", "plain", "retry", "conn",
                    "no_verify")
    for i, vec in enumerate(vectors):
        print(f"=== [{i + 1}/{len(vectors)}] llmac {' '.join(vec)} ===",
              file=sys.stderr)
        try:
            sub_args = parser.parse_args(vec)
            for field in _CONN_FIELDS:
                if getattr(sub_args, field, None) in (None, False, ""):
                    setattr(sub_args, field, getattr(args, field, None))
            if getattr(args, "tap", False):
                sub_args.tap = True   # v2.8: --tap rides into run's subs
            rc = _call_with_inbox_notice(sub_args.func, sub_args)
        except SystemExit as e:            # argparse usage errors (exit 2)
            rc = int(e.code or 2)
        done += 1
        if rc != 0:
            print(f"=== [{i + 1}/{len(vectors)}] FAILED rc={rc} ===",
                  file=sys.stderr)
            if first_fail is None:
                first_fail = rc
            if not args.keep_going:
                break
    tail = (f", stopped at #{done}" if first_fail is not None
            and not args.keep_going else "")
    print(f"run: {done}/{len(vectors)} commands, "
          f"{'all ok' if first_fail is None else f'first failure rc={first_fail}'}"
          f"{tail}", file=sys.stderr)
    return first_fail or 0


_DEPLOY_CHUNK_OPS = 64        # server batch cap
_DEPLOY_CHUNK_BYTES = 4 * 1024 * 1024   # stay well under the 17 MB body cap


def _deploy_chunks(ops: list) -> list:
    """Greedy packing: max 64 ops AND ~4 MB JSON per batch call."""
    chunks, cur, cur_bytes = [], [], 0
    for op in ops:
        n = len(json.dumps(op))
        if cur and (len(cur) >= _DEPLOY_CHUNK_OPS
                    or cur_bytes + n > _DEPLOY_CHUNK_BYTES):
            chunks.append(cur)
            cur, cur_bytes = [], 0
        cur.append(op)
        cur_bytes += n
    if cur:
        chunks.append(cur)
    return chunks


def cmd_deploy(args) -> int:
    """A1: upload N local files + verify their sha256 on the host, in ONE
    invocation. v2.4.1: the hash rides in the SAME batch as the writes
    (stat --hash, B3) — one call on new servers, no exec needed at all;
    old servers transparently fall back to one sha256sum exec. Naive
    deploy loops cost 26 calls / ~15.7 s for 12 files (measured)."""
    pairs = []
    if args.manifest:
        try:
            with open(args.manifest, "r", encoding="utf-8") as f:
                m = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            return _err(f"cannot read manifest: {e}", 2)
        if not isinstance(m, dict) or not isinstance(m.get("files"), list):
            return _err('manifest must be {"files": [{"local": .., '
                        '"remote": ..}, ..]}', 2)
        for item in m["files"]:
            if not isinstance(item, dict) or not item.get("local") \
                    or not item.get("remote"):
                return _err("manifest entries need 'local' and 'remote'", 2)
            pairs.append((item["local"], item["remote"]))
    for p in (args.pairs or []):
        if "=" not in p:
            return _err(f"--pairs entries must be LOCAL=REMOTE, got: {p}", 2)
        l, r = p.split("=", 1)
        pairs.append((l, r))
    if not pairs:
        return _err("deploy requires --pairs LOCAL=REMOTE (repeatable) "
                    "or --manifest FILE", 2)
    import hashlib
    ops, hashes, total = [], [], 0
    for l, r in pairs:
        if not os.path.isfile(l):
            return _err(f"local file not found: {l}", 2)
        if not r.startswith("/"):
            return _err(f"remote path must be absolute: {r}", 2)
        try:
            with open(l, "rb") as f:
                data = f.read()
        except OSError as e:
            return _err(f"cannot read {l}: {e}", 2)
        try:
            ops.append({"op": "write", "path": r, "content":
                        data.decode("utf-8")})
        except UnicodeDecodeError:
            ops.append({"op": "write", "path": r,
                        "content_b64": base64.b64encode(data).decode()})
        hashes.append((r, hashlib.sha256(data).hexdigest(), len(data)))
        total += len(data)
    chunks = _deploy_chunks(ops)
    if args.dry_run:
        print(f"would deploy {len(ops)} files ({total} B) in "
              f"{len(chunks)} batch call(s):")
        for r, h, n in hashes:
            print(f"  {n:>9} B  {r}")
        return 0
    # v2.4.1 (B3+B4): each write is followed in the SAME batch by a
    # stat{hash:true} op — ops run in order, so the hash covers exactly
    # what just landed. ONE call on v2.4.1+ servers, zero exec. Old
    # servers return plain stats (no sha256 key) -> exec fallback below.
    stat_ops = [{"op": "stat", "path": r, "hash": True}
                for r, _, _ in hashes]
    combined = []
    for w, s in zip(ops, stat_ops):
        combined.append(w)
        combined.append(s)
    chunks = _deploy_chunks(combined)
    c = _client_from_args(args)
    failed = []
    stats_out: list = []          # index-aligned with hashes; None on error
    ci = 0
    for chunk in chunks:
        resp, status = c.post("/batch", {"ops": chunk}, timeout=300.0)
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        if "error" in resp:
            return _err("batch refused: " + _fmt_err_fields(resp))
        for r in resp.get("results", []):
            if "ok" in r and r.get("op") == "stat":
                stats_out.append(r["ok"])
            elif "ok" in r:
                pass                      # write results: counted below
            else:
                if r.get("op") == "stat":
                    stats_out.append(None)
                    print(f"[{ci}] stat: {_fmt_err_fields(r)}",
                          file=sys.stderr)
                else:
                    failed.append(r.get("path")
                                  or f"op[{r.get('index', '?')}]")
                    print(f"[{ci}] {r.get('op') or 'op'}: "
                          f"{_fmt_err_fields(r)}",
                          file=sys.stderr)
            ci += 1
    if failed:
        return _err(f"deploy failed for {len(failed)} file(s); nothing "
                    "verified", 1)
    if args.no_verify:
        print(f"deployed {len(ops)} files ({total} B) in {len(chunks)} "
              f"batch call(s) — verification skipped (--no-verify)")
        return 0
    remote = {}
    exec_fallback = False
    if stats_out and all(s and "sha256" in s for s in stats_out):
        # v2.4.1 server: hashes arrived with the writes — no exec needed.
        for (r, h, n), s in zip(hashes, stats_out):
            remote[r] = s["sha256"]
    else:
        # Old server (<2.4.1, stat without hash) or an oversize file:
        # one exec verifies everything (literal paths, no metachars).
        exec_fallback = True
        c.retry_seconds = 0.0
        resp, status = c.post("/exec",
                              {"command": "sha256sum " + " ".join(
                                  r for r, _, _ in hashes),
                               "cwd": "", "timeout": max(30,
                                                         len(hashes) * 5)},
                              timeout=300.0)
        if status == 0 or resp.get("rejected") or "error" in resp:
            print("WARNING: could not verify (server predates stat --hash "
                  "AND the verification exec is disabled/rejected) — "
                  "files ARE deployed; re-verify manually.",
                  file=sys.stderr)
            return 0
        for line in resp.get("stdout", "").splitlines():
            parts = line.split("  ", 1)
            if len(parts) == 2:
                remote[parts[1]] = parts[0].strip()
    mism = [r for r, h, _ in hashes if remote.get(r) != h]
    for r, h, n in hashes:
        mark = "MISMATCH" if r in mism else "ok"
        print(f"  {mark:>8}  {n:>9} B  {r}")
    # v2.4.2: surface the transport cost so deploys are self-verifying
    # in output ("1 batch call(s), no exec" on v2.4.1+ servers).
    print(f"deploy: {len(hashes) - len(mism)}/{len(hashes)} verified"
          + (f", {len(mism)} MISMATCH" if mism else "")
          + f" ({len(chunks)} batch call(s), "
          + ("exec fallback)" if exec_fallback else "no exec)"))
    return 1 if mism else 0


def _hash_local_file(path: str) -> str:
    import hashlib
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cmd_verify(args) -> int:
    """B3 client: compare a local file with a remote path by sha256 —
    works even when the host runs with exec disabled (stat --hash)."""
    if not os.path.isfile(args.local):
        return _err(f"local file not found: {args.local}", 2)
    local_hash = _hash_local_file(args.local)
    c = _client_from_args(args)
    resp, status = c.post("/stat", {"path": args.remote, "hash": True})
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    if "error" in resp:
        return _err_from_resp(resp, 1)
    remote_hash = resp.get("sha256")
    if not remote_hash and resp.get("sha256_skipped"):
        print(f"NOTE: {resp['sha256_skipped']}", file=sys.stderr)
    if not remote_hash:
        # Old server (<2.4.1) or oversize file: exec sha256sum fallback.
        c.retry_seconds = 0.0
        r2, st2 = c.post("/exec",
                         {"command": f"sha256sum {args.remote}",
                          "cwd": "", "timeout": 120}, timeout=150.0)
        if st2 == 0 or r2.get("rejected") or "error" in r2:
            return _err("cannot verify: server predates stat --hash and "
                        "exec is unavailable", 1)
        out = r2.get("stdout", "").split()
        remote_hash = out[0] if out else None
    if remote_hash == local_hash:
        print(f"verify: MATCH  {args.local} == {args.remote}")
        print(f"  sha256 {local_hash}")
        return 0
    print("verify: MISMATCH")
    print(f"  local  {local_hash}  {args.local}")
    print(f"  remote {remote_hash}  {args.remote}")
    return 1


# ---- audit (v2.7.2, reworked v2.8) ----------------------------------------

# The anti-hesitation primitive. A hash proves the bytes are the published
# ones; it cannot say what the bytes DO. `audit` closes that gap
# mechanically and OFFLINE: it hashes this file (or --file), optionally
# binds it to the connection block's Client-SHA256, then reads the source
# with ast.parse - and nothing else - to print a factual report: imports,
# red-flag calls, write sites, egress modules. It never executes the
# audited code, never writes, and never touches the network.
_AUDIT_RED_CALLS = frozenset({"eval", "exec", "compile", "__import__"})
_AUDIT_RED_OS = frozenset({"system", "popen"})
_AUDIT_RED_IMPORTS = frozenset({"pickle", "marshal", "ctypes", "subprocess"})
_AUDIT_EGRESS = frozenset({"http", "urllib", "socket", "ssl"})


def _audit_report(src: str, label: str) -> str:
    """Purely static (ast.parse) facts about a python source string."""
    lines = [f"--- static audit: {label} ---"]
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        lines.append(f"  SYNTAX ERROR: {e} — NOT valid python source")
        return "\n".join(lines)
    mods, red_calls, red_imports, write_sites = set(), [], [], []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                root = a.name.split(".")[0]
                mods.add(root)
                if root in _AUDIT_RED_IMPORTS:
                    red_imports.append(f"L{node.lineno}: import {a.name}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            mods.add(root)
            if root in _AUDIT_RED_IMPORTS:
                red_imports.append(f"L{node.lineno}: from {node.module}")
        elif isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name) and f.id in _AUDIT_RED_CALLS:
                red_calls.append(f"L{node.lineno}: {f.id}()")
            elif (isinstance(f, ast.Attribute)
                  and isinstance(f.value, ast.Name)
                  and f.value.id == "os" and f.attr in _AUDIT_RED_OS):
                red_calls.append(f"L{node.lineno}: os.{f.attr}()")
            elif (isinstance(f, ast.Name) and f.id == "open"
                  and len(node.args) >= 2
                  and isinstance(node.args[1], ast.Constant)
                  and isinstance(node.args[1].value, str)
                  and any(c in node.args[1].value for c in "wax+")):
                tgt = node.args[0]
                tgt_s = (tgt.value if isinstance(tgt, ast.Constant)
                         else "<expr>")
                write_sites.append(
                    f"L{node.lineno}: open({tgt_s!r}, "
                    f"{node.args[1].value!r})")
    std_names = getattr(sys, "stdlib_module_names", None)
    core = sorted(m for m in mods if m != "__future__")
    nonstd = ([m for m in core if m not in std_names]
              if std_names is not None else [])
    lines.append(f"  imports ({len(core)}): {' '.join(core)}")
    lines.append("  non-stdlib imports: "
                 + (", ".join(nonstd) if nonstd else "(none)"))
    lines.append("  red-flag calls (eval/exec/compile/__import__/"
                 "os.system/os.popen): "
                 + ((f"{len(red_calls)}\n    "
                     + "\n    ".join(red_calls)) if red_calls
                    else "(none)"))
    lines.append("  red-flag imports (pickle/marshal/ctypes/subprocess): "
                 + ((f"{len(red_imports)}\n    "
                     + "\n    ".join(red_imports)) if red_imports
                    else "(none)"))
    lines.append("  write sites (open with w/a/x/+ mode): "
                 + ((f"{len(write_sites)}\n    "
                     + "\n    ".join(write_sites)) if write_sites
                    else "(none)"))
    egress = sorted(m for m in core if m in _AUDIT_EGRESS)
    lines.append("  egress modules: "
                 + (", ".join(egress) if egress else "(none)"))
    return "\n".join(lines)


def cmd_audit(args) -> int:
    """Offline audit of the client file itself (v2.8).

    Hashes the file's exact bytes, optionally checks them against the
    SHA-256 in the connection block (--expect-sha256), and prints a static
    ast.parse report. It contacts nothing, writes nothing and never
    executes the audited source. The report is produced even when the hash
    check fails, because that is exactly when an auditor wants to read the
    code."""
    target = getattr(args, "file", None) or os.path.abspath(__file__)
    try:
        with open(target, "rb") as f:
            raw = f.read()
    except OSError as e:
        return _err(f"cannot read {target}: {e}", 2)
    got = hashlib.sha256(raw).hexdigest()
    print(f"audit: file={target}")
    print(f"file   : sha256={got}  size={len(raw)} bytes")

    rc = 0
    want = (getattr(args, "expect_sha256", None) or "").strip().lower()
    if want:
        ok = want == got
        print(f"expect : {want[:16]}... -> {'MATCH' if ok else 'MISMATCH'}")
        if not ok:
            print("ERROR: file does not match the Client-SHA256 in the "
                  "connection block. Do not use this file; re-download it "
                  "from the GitHub release.", file=sys.stderr)
            rc = 1
    else:
        print("expect : (not requested - pass --expect-sha256 to bind the "
              "block's Client-SHA256)")

    try:
        src = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        print(f"ERROR: not valid UTF-8 source: {e}", file=sys.stderr)
        return 1
    print(_audit_report(src, os.path.basename(target)))
    print("audit: COMPLETE - executed nothing; wrote nothing; "
          "contacted nothing")
    return rc


def cmd_orient(args) -> int:
    """B1 client: the one-call orientation pack — info core, depth-capped
    tree, README/agent.md heads, session pointer; budget-trimmed on the
    SERVER, so a naive agent cannot blow its context (measured: replaces
    the 5-call / 6.6K-token fresh-agent boot)."""
    c = _client_from_args(args)
    payload = {}
    if args.path:
        payload["path"] = args.path
    if args.depth:
        payload["depth"] = args.depth
    if args.doc_heads is not None:
        payload["doc_heads"] = args.doc_heads
    if args.budget:
        payload["budget"] = args.budget
    resp, status = c.post("/overview", payload)
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    if "error" in resp:
        return _err_from_resp(resp)
    if "--verbose" in sys.argv:
        _pjson(resp)
        return 0
    info = resp.get("info", {})
    print(f"llmac {info.get('version')}  policy={info.get('policy')}  "
          f"exec={'on' if info.get('exec_enabled') else 'off'}")
    print(f"roots: {', '.join(info.get('roots', []))}")
    for d in resp.get("docs", []):
        print(f"--- {d.get('path')} (head {d.get('lines')} lines) ---")
        print(d.get("head", "").rstrip())
    tree = resp.get("tree", {})
    print("--- tree " + "-" * 42)
    for e in tree.get("entries", []):
        pad = "  " * (e.get("depth") or 1)
        size = "" if e.get("type") == "dir" \
            else f"  {_human_size(e.get('size'))}"
        print(f"{pad}{e.get('name')}{size}")
    if tree.get("truncated"):
        print("  ... (tree truncated — use ls / tree for more)")
    s = resp.get("session", {})
    print(f"--- session: {s.get('op_count')} ops, {s.get('files_touched')} "
          f"files, {s.get('exec_count')} execs, {s.get('notes')} notes "
          f"({s.get('hint')})")
    tr = resp.get("trimmed", {})
    trimmed_notes = [k for k, v in tr.items() if v and k != "tree_truncated"]
    if trimmed_notes:
        print(f"--- trimmed to fit budget ({resp.get('budget')} B): "
              f"{', '.join(sorted(trimmed_notes))}", file=sys.stderr)
    return 0


def cmd_diff(args) -> int:
    """B2 client: server-side unified diff — path vs path, or path vs a
    local proposal file (a write dry-run). Diff bytes are typically 1-2%
    of the files compared (>= 10x context saving on real cases)."""
    if args.inline_file and args.b:
        # v2.4.9 (lesson #11): the inline file silently won and --b
        # vanished.
        return _err("diff_targets_conflict: --b and --inline-file are "
                    "two comparison targets; give one", 2)
    c = _client_from_args(args)
    payload = {"a": args.a}
    if args.inline_file:
        try:
            with open(args.inline_file, "r", encoding="utf-8") as f:
                payload["inline"] = f.read()
        except (OSError, UnicodeDecodeError) as e:
            return _err(f"cannot read {args.inline_file}: {e}", 2)
    elif args.b:
        payload["b"] = args.b
    else:
        return _err("diff needs --b REMOTE_PATH or --inline-file LOCAL_FILE",
                    2)
    resp, status = c.post("/diff", payload)
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    if "error" in resp:
        return _err_from_resp(resp)
    if resp.get("same"):
        print(f"identical: {resp.get('a')} == {resp.get('b')}")
        return 0
    sys.stdout.write(resp.get("diff", ""))
    print(f"[diff: +{resp.get('added')} -{resp.get('removed')}"
          + (" (truncated at 200KB)" if resp.get("truncated") else "") + "]",
          file=sys.stderr)
    return 0


def cmd_archive(args) -> int:
    c = _client_from_args(args)
    if not args.path:
        return _err("archive requires --path", 2)
    if args.get:
        if not args.to:
            return _err("archive --get requires --to (local .tgz file)", 2)
        q = f"/archive?path={quote(args.path, safe='')}"
        if args.all:
            q += "&all=1"
        data, status = c.get_raw(q, timeout=300.0)
        if status == 0:
            return _err("connection failed", 3)
        if status != 200:
            try:
                err = json.loads(data.decode("utf-8"))
                return _err(_fmt_err_fields(err))
            except Exception:
                return _err(f"archive download failed (HTTP {status})", 1)
        out_dir = os.path.dirname(os.path.abspath(args.to))
        os.makedirs(out_dir, exist_ok=True)
        with open(args.to, "wb") as f:
            f.write(data)
        print(f"downloaded {len(data)} B -> {args.to}")
        if not args.all:
            print("[note] dotfiles/ignored entries are skipped by default; "
                  "pass --all to include them (.git never).", file=sys.stderr)
        return 0
    if args.put:
        if not args.file:
            return _err("archive --put requires --file (local .tgz)", 2)
        try:
            with open(args.file, "rb") as f:
                blob = f.read()
        except OSError as e:
            return _err(f"cannot read {args.file}: {e}", 2)
        payload = {"path": args.path,
                   "archive_b64": base64.b64encode(blob).decode(),
                   "overwrite": bool(args.overwrite)}
        resp, status = c.post("/archive", payload, timeout=300.0)
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        return _print_op_resp(resp, status)
    return _err("use --get or --put", 2)


def cmd_grants(args) -> int:
    c = _client_from_args(args)
    resp, status = c.get("/grants")
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    if "error" in resp:
        return _err_from_resp(resp)
    grants = resp.get("grants", [])
    if not grants:
        print("(no active grants)")
        return 0
    for g in grants:
        ops = ",".join(g.get("ops", []))
        print(f"{g.get('id')}  [{ops}] under {g.get('scope')}")
        print(f"    agent={g.get('agent')}  expires={g.get('expires_at')}")
    return 0


# ---- exec / proc ------------------------------------------------------------

_EXEC_VAR_RE = re.compile(r"\$[A-Za-z_]\w*")


def _exec_lint(cmd: str) -> list:
    """A3: pre-flight hazards the SERVER cannot save you from. Command
    substitution happens in the agent's LOCAL shell before llmac ever
    receives the string, so '$(find ...)' silently produced wrong-but-
    plausible results in real agent sessions; '$VAR' is rejected by the
    host analyzer but costs a round trip and confuses beginners."""
    hazards = []
    if "$(" in cmd or "`" in cmd:
        hazards.append(
            "command substitution '$( ... )' or backticks — your LOCAL "
            "shell evaluates these BEFORE llmac receives the command, so "
            "the host sees substituted text you did not intend. Spell "
            "paths out literally; compute locally and paste the result, "
            "or loop repeated llmac calls / use 'llmac run'.")
    m = _EXEC_VAR_RE.search(cmd)
    if m:
        hazards.append(
            f"shell variable {m.group(0)} — the host analyzer rejects "
            "variables because it cannot see their values; use literal "
            "paths instead.")
    return hazards


def cmd_exec(args) -> int:
    # A3: fail fast, before any network round trip, on the known traps.
    if not getattr(args, "i_know", False):
        hazards = _exec_lint(args.command)
        if hazards:
            print("=" * 70, file=sys.stderr)
            print("COMMAND PRE-FLIGHT LINT — fix before sending:",
                  file=sys.stderr)
            for h in hazards:
                print(f"  - {h}", file=sys.stderr)
            print("If you really meant this, re-run with --i-know.",
                  file=sys.stderr)
            print("=" * 70, file=sys.stderr)
            return 2
    c = _client_from_args(args)
    # Never auto-retry exec: a transport failure mid-command must not
    # silently re-run a side-effecting command (F20).
    c.retry_seconds = 0.0
    timeout = max(1, int(args.timeout or 300))
    # Couple the HTTP timeout to the exec timeout (+ margin) so the client
    # stops reporting 'transport failed' at 30s while the command runs on.
    resp, status = c.post("/exec",
                          {"command": args.command, "cwd": args.cwd or "",
                           "timeout": timeout,
                           "save": getattr(args, "save", "") or "",
                           "save_stderr": getattr(args, "save_stderr", "")
                           or ""},
                          timeout=timeout + 30)
    if status == 0:
        print("ERROR: the transport failed before the result arrived — the "
              "command may still be RUNNING or COMPLETED server-side. Do "
              "NOT blindly retry side-effecting commands; check `events` or "
              "re-read the affected paths first.", file=sys.stderr)
        return 3
    if getattr(args, "json_out", False):
        # Machine-readable result for scripted use (F3/F6).
        print(json.dumps(_with_inbox({"returncode": resp.get("returncode"),
                          "stdout": resp.get("stdout", ""),
                          "stderr": resp.get("stderr", ""),
                          "timed_out": resp.get("timed_out", False),
                          "truncated": resp.get("truncated", False),
                          "rejected": bool(resp.get("rejected")),
                          "rule": resp.get("rule"),
                          "saved_path": resp.get("saved_path"),
                          "saved_bytes": resp.get("saved_bytes"),
                          "saved_stderr_path": resp.get("saved_stderr_path"),
                          "saved_stderr_bytes": resp.get(
                              "saved_stderr_bytes"),
                          "error": resp.get("error")}),
                         ensure_ascii=False))
        return 0 if ("error" not in resp
                     and not resp.get("rejected")) else 1
    if resp.get("rejected"):
        print("=" * 70, file=sys.stderr)
        print(f"COMMAND REJECTED [{resp.get('rule')}]:", file=sys.stderr)
        print(resp.get("warning", ""), file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        return 2
    if "error" in resp:
        # Server-level refusals (cwd outside the sandbox, exec_busy, ...)
        # exit 2, consistent with analyzer rejections (F19).
        return _err_from_resp(resp, 2)
    if resp.get("stdout"):
        try:
            sys.stdout.write(resp["stdout"])
        except BrokenPipeError:
            pass
    if resp.get("stderr"):
        sys.stderr.write(resp["stderr"])
    if resp.get("timed_out"):
        print("[timed out]", file=sys.stderr)
    if resp.get("saved_path"):
        # v2.4.4 --save: stdout went to the file (full, uncapped) — say
        # where and how big, so the agent can read/search it next.
        print(f"[saved {resp.get('saved_bytes', 0)} B -> "
              f"{resp['saved_path']}\n tip: llmac read/search/diff that "
              f"file instead of re-running the command]", file=sys.stderr)
    if resp.get("saved_stderr_path"):
        # v2.4.8 --save-stderr: same contract for the stderr artifact.
        print(f"[saved stderr {resp.get('saved_stderr_bytes', 0)} B -> "
              f"{resp['saved_stderr_path']}]", file=sys.stderr)
    # A3: the remote exit code is part of the result — plain mode always
    # surfaces it on stderr so scripted agents do not re-run completed
    # commands or mistake failures for transport problems.
    if not getattr(args, "json_out", False):
        if resp.get("timed_out"):
            print("[rc=timeout]", file=sys.stderr)
        else:
            print(f"[rc={resp.get('returncode')}]", file=sys.stderr)
    if args.verbose:
        print(f"\n[exit_code={resp.get('returncode')} cwd={resp.get('cwd')}]",
              file=sys.stderr)
    rc = resp.get("returncode", 1)
    return rc if rc is not None else 1


def _print_log_slice(resp, quiet=False) -> int:
    """Print one /proc/logs slice (stdout->stdout, stderr->stderr) and
    warn when the slice had to resync (v2.4.7: window rolled past lines
    the agent never saw). Returns lines printed."""
    n = 0
    for line in resp.get("stdout", []):
        print(line)
        n += 1
    for line in resp.get("stderr", []):
        print(line, file=sys.stderr)
        n += 1
    for stream in ("stdout", "stderr"):
        if resp.get(f"{stream}_resynced"):
            print(f"[{stream} resynced: {resp.get(stream + '_skipped')} "
                  f"earlier line(s) rolled out of the readable window "
                  "— slice the artifact or re-run with a shorter poll "
                  "interval]", file=sys.stderr)
    return n


def _proc_logs_follow(c, args) -> int:
    """v2.4.7: `proc logs --follow` — tail -f for procs. Long-polls
    /events and re-slices /proc/logs only when THIS proc emitted a
    proc_log event (output landed) or proc_exit; --max-idle N stops the
    follow after N seconds without new output (bounded RE waits).
    Exits cleanly when the proc finishes or on Ctrl-C."""
    pid = args.id
    after_out = args.after or 0
    after_err = args.after or 0
    header_shown = False
    last_out = time.time()
    # Prime the event cursor so we only react to events from now on.
    resp, status = c.get("/events?since=0&wait=0.1", timeout=5)
    since = (resp or {}).get("last_seq", 0) if status else 0
    while True:
        resp, status = c.post("/proc/logs", {
            "id": pid, "after_stdout": after_out,
            "after_stderr": after_err, "stream": args.stream or "both"})
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        if "error" in resp:
            return _err_from_resp(resp)
        if not header_shown and not args.quiet:
            print(f"[{resp['id']}] running={resp['running']} "
                  f"rc={resp.get('returncode')}  (following — Ctrl-C "
                  "to stop)")
            header_shown = True
        printed = _print_log_slice(resp, quiet=args.quiet)
        if printed:
            last_out = time.time()
        after_out = resp.get("stdout_next", after_out)
        after_err = resp.get("stderr_next", after_err)
        if not resp.get("running"):
            if not args.quiet:
                print(f"[{resp['id']}] exited rc={resp.get('returncode')}")
            return 0
        if args.max_idle and time.time() - last_out >= args.max_idle:
            if not args.quiet:
                print(f"[{pid}] no new output for {args.max_idle}s — "
                      "stopping follow")
            return 0
        wait_s = 25.0
        ev, ev_status = c.get(f"/events?since={since}&wait={wait_s}",
                              timeout=wait_s + 30)
        if ev_status == 0:
            time.sleep(1.0)          # transport hiccup: backoff, re-slice
            continue
        for e in (ev or {}).get("events", []):
            d = e.get("data") or {}
            if e.get("type") in ("proc_log", "proc_exit") \
                    and d.get("id") == pid:
                break                # wake: re-slice at loop top
        since = (ev or {}).get("last_seq", since)


def cmd_proc(args) -> int:
    c = _client_from_args(args)
    if args.proc_cmd == "start":
        if not args.command:
            return _err("proc start requires --command", 2)
        resp, status = c.post("/proc/start", {
            "command": args.command, "cwd": args.cwd or "",
            "name": args.name or ""})
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        if "error" in resp:
            return _err_from_resp(resp)
        p = resp["proc"]
        print(f"started {p['id']}  ({p['name']})  {p['command']}")
        print(f"tail logs:  llmac proc logs --id {p['id']} [--follow]")
        return 0
    elif args.proc_cmd == "list":
        resp, status = c.post("/proc/list", {})
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        for p in resp.get("procs", []):
            state = "RUNNING" if p["running"] else f"exit {p['returncode']}"
            reatt = " (reattached)" if p.get("reattached") else ""
            print(f"{p['id']:<16} {state:<10} {p['name']:<16} "
                  f"{p['command'][:60]}{reatt}")
        return 0
    elif args.proc_cmd == "logs":
        if getattr(args, "max_idle", None) and not getattr(args, "follow", False):
            # v2.4.9 (lesson #11): --max-idle was consumed only inside
            # the follow loop — without --follow it silently vanished
            # (its own help text already said "requires --follow").
            return _err("max_idle_needs_follow: --max-idle bounds a "
                        "--follow wait; add --follow", 2)
        if not args.id:
            return _err("proc logs requires --id", 2)
        if getattr(args, "follow", False):
            try:
                return _proc_logs_follow(c, args)
            except KeyboardInterrupt:
                print(file=sys.stderr)
                return 0
        resp, status = c.post("/proc/logs", {
            "id": args.id, "after": args.after or 0,
            "stream": args.stream or "both"})
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        if "error" in resp:
            return _err_from_resp(resp)
        if not args.quiet:
            print(f"[{resp['id']}] running={resp['running']} "
                  f"rc={resp.get('returncode')}")
        _print_log_slice(resp, quiet=args.quiet)
        return 0
    elif args.proc_cmd == "stop":
        if not args.id:
            return _err("proc stop requires --id", 2)
        resp, status = c.post("/proc/stop", {"id": args.id,
                                             "force": args.force})
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        if "error" in resp:
            return _err_from_resp(resp)
        print(f"stopped {resp.get('id')}  rc={resp.get('returncode')}")
        return 0
    return _err(f"unknown proc subcommand: {args.proc_cmd}", 2)


# ---- session / approvals / events ------------------------------------------------------------

def cmd_session(args) -> int:
    if getattr(args, "text", None) and args.session_cmd != "note":
        # v2.4.9 (lesson #11): --text was read only in the note branch.
        return _err("text_needs_note: --text belongs to 'session note'", 2)
    c = _client_from_args(args)
    if args.session_cmd == "status":
        resp, status = c.post("/session/status", {})
    elif args.session_cmd == "note":
        if not args.text:
            return _err("session note requires --text", 2)
        resp, status = c.post("/session/note", {"text": args.text})
    elif args.session_cmd == "reset":
        resp, status = c.post("/session/reset", {})
    elif args.session_cmd == "inbox":
        # v2.5.0 (ASK-001): read the user->agent inbox — the human
        # channel. Default consumes new messages (the GUI unread banner
        # clears); --peek only looks. Poll between work units (agent.md).
        resp, status = c.post("/session/inbox",
                              {"peek": bool(getattr(args, "peek", False))})
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        if "error" in resp:
            return _err_from_resp(resp)
        msgs = resp.get("messages", [])
        print(f"--- inbox: {len(msgs)} message(s)")
        for m in msgs:
            print(f"[{m.get('seq')}] {m.get('ts')}  {m.get('text')}")
        print(f"--- unread: {resp.get('unread')} message(s)")
        return 0
    elif args.session_cmd == "log":
        # v2.5.2 (ASK-010): the agent-scoped op-log view. The server
        # returns ONLY this agent's entries — scoping is by
        # authentication, so there is no --agent flag and an 'agent'
        # key in the payload is rejected server-side. --after is the
        # next_after cursor from a previous fetch.
        after = int(getattr(args, "after", 0) or 0)
        limit = int(getattr(args, "limit", 200) or 200)
        resp, status = c.post("/session/log",
                              {"after": after, "limit": limit})
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        if "error" in resp:
            return _err_from_resp(resp)
        entries = resp.get("entries", [])
        print(f"--- log: {len(entries)} entries "
              f"(agent {resp.get('agent')})")
        for e in entries:
            print(f"[{e.get('ts')}] {e.get('level')}  {e.get('msg')}")
        print(f"--- next_after: {resp.get('next_after')}")
        return 0
    elif args.session_cmd == "export":
        # v2.4.4: dump the FULL notes log (up to the 100-note cap) to a
        # local file (or stdout) as JSON — hand-off artifact for the next
        # session/agent, no context tokens spent re-reading the digest.
        resp, status = c.post("/session/status", {"all_notes": True})
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        if "error" in resp:
            return _err_from_resp(resp)
        notes = resp.get("notes", [])
        out = {"agent": resp.get("agent"),
               "started_at": resp.get("started_at"),
               "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
               "note_count": len(notes), "notes": notes}
        out_path = getattr(args, "out", None)
        # v2.7.3: only the stdout copy carries the inbox notice — the
        # exported FILE is a hand-off artifact and stays byte-clean.
        payload = json.dumps(out if out_path else _with_inbox(out),
                             indent=2, ensure_ascii=False)
        if out_path:
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(payload + "\n")
            print(f"exported {len(notes)} note(s) -> {out_path}")
        else:
            print(payload)
        return 0
    else:
        return _err(f"unknown session subcommand: {args.session_cmd}", 2)
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    _pjson(resp)
    return 0 if "error" not in resp else 1


def _screen_target_payload(args) -> dict:
    """--target passthrough: numeric strings become ints (the server
    accepts both, ints are the native form)."""
    t = (args.target or "").strip()
    return {"target": int(t) if t.lstrip("-").isdigit() else t}


def cmd_screen(args) -> int:
    """v2.7.0 (ASK-016/017): the screen channel — list monitors, take
    per-screen shots, observe (OCR text with positions + window
    list)."""
    if args.screen_cmd == "list":
        c = _client_from_args(args)
        resp, status = c.post("/screen/list", {})
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        if "error" in resp:
            return _err_from_resp(resp)
        screens = resp.get("screens", [])
        print(f"--- screens: {len(screens)}")
        for s in screens:
            star = "*" if s.get("primary") else " "
            print(f"{star} [{s.get('index')}] {s.get('name')}  "
                  f"{s.get('width')}x{s.get('height')} at "
                  f"({s.get('x')},{s.get('y')})  scale {s.get('scale')}"
                  + ("  (unavailable)" if not s.get("available", True)
                     else ""))
        print("--- coordinates are GLOBAL (the space input ops target)")
        return 0

    if args.screen_cmd == "shot":
        # rc-2 pre-request guards (the find_needs_hex pattern): a bad
        # call never leaves the machine.
        if not (args.target or "").strip():
            return _err("shot_target_required: --target is mandatory "
                        "(a screen index, 'primary' or 'all')", 2)
        fmt = (args.format or "png").strip().lower()
        if fmt not in ("png", "jpg"):
            return _err(f"shot_format_invalid: --format must be png or "
                        f"jpg (got {args.format!r})", 2)
        mw = None
        if args.max_width is not None:
            try:
                mw = int(args.max_width)
            except (TypeError, ValueError):
                return _err(f"max_width_invalid: --max-width must be "
                            f"an integer 1..20000 (got "
                            f"{args.max_width!r})", 2)
            if not (1 <= mw <= 20000):
                return _err("max_width_invalid: --max-width must be an "
                            "integer 1..20000", 2)
        payload = _screen_target_payload(args)
        payload["format"] = fmt
        if mw is not None:
            payload["max_width"] = mw
        c = _client_from_args(args)
        # approvals can block; outlive them
        resp, status = c.post("/screen/shot", payload, timeout=180)
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        if "error" in resp:
            return _err_from_resp(resp)
        files = resp.get("files", [])
        print(f"--- shot {len(files)} file(s)")
        for f in files:
            print(f"[{f.get('screen')}] {f.get('path')}  "
                  f"{f.get('width')}x{f.get('height')} {f.get('format')}  "
                  f"{f.get('bytes')} B  sha256 {f.get('sha256')}")
        return 0

    if args.screen_cmd == "observe":
        if not (args.target or "").strip():
            return _err("shot_target_required: --target is mandatory "
                        "for observe too (a screen index, 'primary' or "
                        "'all')", 2)
        if args.max_width is not None:
            return _err("observe_max_width_unsupported: observe refuses "
                        "max_width — OCR truth needs full resolution", 2)
        payload = _screen_target_payload(args)
        c = _client_from_args(args)
        resp, status = c.post("/screen/observe", payload, timeout=300)
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        if "error" in resp:
            return _err_from_resp(resp)
        for f in resp.get("files", []):
            print(f"--- shot: {f.get('path')} ({f.get('width')}"
                  f"x{f.get('height')}, sha256 {f.get('sha256')})")
        for o in resp.get("observe", []):
            words = o.get("words", [])
            print(f"--- screen [{o.get('screen')}] text: "
                  f"{o.get('text', '')[:400]}")
            print(f"--- screen [{o.get('screen')}] {len(words)} word(s) "
                  f"with global-coord boxes")
        windows = resp.get("windows", [])
        if resp.get("windows_error"):
            print(f"--- windows unavailable: {resp['windows_error']}")
        else:
            print(f"--- windows: {len(windows)} (X tree: XWayland "
                  f"clients only on a Wayland host)")
            for w in windows[:30]:
                mark = ">" if w.get("focused") else " "
                print(f"{mark} [{w.get('id')}] {w.get('title', '')!r} "
                      f"at ({w.get('x')},{w.get('y')}) "
                      f"{w.get('width')}x{w.get('height')}"
                      + ("" if w.get("visible", True) else "  (hidden)"))
        return 0
    return _err(f"unknown screen subcommand: {args.screen_cmd}", 2)


def cmd_input(args) -> int:
    """v2.7.0 (ASK-017 part B): bounded drive-mode input injection.
    rc-2 pre-request guards first; the safety floor (own-window
    refusal, caps, banner disarm) is enforced SERVER-side."""
    verb = args.input_cmd
    if verb == "mouse":
        if not args.action:
            return _err("input_action_required: --action is mandatory "
                        "(move|click|doubleclick|drag|scroll)", 2)
        if args.action not in ("move", "click", "doubleclick", "drag",
                               "scroll"):
            return _err(f"input_action_invalid: unknown action "
                        f"{args.action!r} — use move|click|doubleclick|"
                        f"drag|scroll", 2)
        if args.button and args.button not in ("left", "middle",
                                               "right"):
            return _err(f"input_button_invalid: unknown button "
                        f"{args.button!r} — use left|middle|right", 2)
        payload = {"action": args.action}
        if args.button:
            payload["button"] = args.button
        if args.action == "drag":
            payload.update(from_x=args.from_x, from_y=args.from_y,
                           to_x=args.to_x, to_y=args.to_y)
        elif args.action == "scroll":
            payload.update(x=args.x, y=args.y, dx=args.dx, dy=args.dy)
        else:
            payload.update(x=args.x, y=args.y)
    elif verb == "key":
        if not args.keysym:
            return _err("input_keysym_required: --keysym is mandatory "
                        "(an X11 keysym name: Return, F5, a, ...)", 2)
        if args.action:
            return _err("action_needs_mouse: --action belongs to "
                        "'input mouse'", 2)
        payload = {"keysym": args.keysym}
        if args.modifiers:
            mods = [m.strip().lower() for m in args.modifiers.split(",")
                    if m.strip()]
            bad = next((m for m in mods if m not in
                        ("ctrl", "shift", "alt", "meta")), None)
            if bad is not None:
                return _err(f"input_modifier_invalid: unknown modifier "
                            f"{bad!r} — use ctrl|shift|alt|meta", 2)
            payload["modifiers"] = mods
    else:    # text
        if not args.text:
            return _err("input_text_required: --text is mandatory "
                        "(printable ASCII only; special keys go through "
                        "'input key --keysym')", 2)
        if args.action:
            return _err("action_needs_mouse: --action belongs to "
                        "'input mouse'", 2)
        payload = {"text": args.text}
    c = _client_from_args(args)
    # the approval (first op) can block; outlive it
    resp, status = c.post(f"/input/{verb}", payload, timeout=180)
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    if "error" in resp:
        return _err_from_resp(resp)
    d = resp.get("drive", {})
    print(f"--- injected; drive session: {d.get('events_used')}"
          f"/{d.get('events_cap')} events, expires in "
          f"{d.get('expires_in_s')}s (click the banner to disarm)")
    return 0


def cmd_ledger(args) -> int:
    """v2.6.0 (ASK-015): rule 6 as code — fully local, no connection.
    Flags asks whose own text records a SATISFIED flip gate while the
    status is not shipped. Never mutates the ledger (rule 2): a flag
    is work for the same ops run, not a decision the tool makes."""
    if args.ledger_cmd != "lint":
        return _err(f"unknown ledger command: {args.ledger_cmd}", 2)
    if not args.path:
        return _err("ledger lint needs --path (an ASKS.md-format ledger "
                    "file — usually your sandbox mirror)", 2)
    if not os.path.isfile(args.path):
        return _err(f"ledger_file_not_found: {args.path}", 2)
    flags, total = ledger_lint(args.path, getattr(args, "state", None))
    if args.json:
        print(json.dumps({"path": args.path, "entries": total,
                          "flags": flags}, indent=1))
        return 1 if flags else 0
    n = len(flags)
    print(f"LEDGER LINT — {args.path}: {total} entries, "
          f"{n} flag{'s' if n != 1 else ''}")
    for fl in flags:
        runs = fl.get("consecutive_runs")
        print(f"\n  [STALE-FLIP] {fl['id']} ({fl['status']}) — "
              f"{fl['title']}  (line {fl['line']})")
        for kind, ln in fl["signals"]:
            print(f"      {kind}: {ln}")
        if runs is not None:
            print(f"      flagged for {runs} consecutive lint "
                  f"run{'s' if runs != 1 else ''}")
        print("      rule 6: flip it to shipped in the SAME ops run; "
              "never re-ask the user.")
    if not n:
        print("  clean — no ask sits past a satisfied flip gate.")
    return 1 if flags else 0


_LEDGER_STATUS_WORDS = ("open", "queued", "building", "shipped",
                        "deferred-by-user", "withdrawn-by-user",
                        "wontfix")
# Rule 2: only the user sets these — the linter never argues with them.
_LEDGER_EXEMPT = ("shipped", "deferred-by-user", "withdrawn-by-user",
                  "wontfix")
# Tier-2 satisfaction signals — the ASK-012 detector. Case-insensitive;
# each regex is a phrase that, in a NON-shipped entry's body, records
# a satisfied flip gate (the user asserted or demonstrated it).
_LEDGER_SIGNALS = (
    re.compile(r"flip(?:ped)?\s+captured", re.I),
    re.compile(r"gate\s+(?:was|is|has\s+been)\s+satisfied", re.I),
    re.compile(r"already\s+done", re.I),
    re.compile(r"looks\s+good", re.I),
    re.compile(r"pasted\s+the\s+(?:gui\s+)?transcript", re.I),
    re.compile(r"eyeball\w*\s+(?:happened|was\s+done|is\s+done)", re.I),
    re.compile(r"confirmed\s+at\s+one\s+point", re.I),
)


def _ledger_parse_entries(text: str) -> list:
    """Parse an ASKS.md-format ledger: `### ASK-NNN — title` headers
    open entries; the next `## `/`### ` boundary closes the previous
    one. Status comes off the `- status:` line (first word)."""
    entries = []
    cur = None
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^### (ASK-\d+)\s*[—-]\s*(.*)$", line)
        if m:
            cur = {"id": m.group(1), "title": m.group(2).strip(),
                   "lineno": i, "lines": []}
            entries.append(cur)
            continue
        if cur is None:
            continue
        if line.startswith("## ") or line.startswith("### "):
            cur = None
            continue
        cur["lines"].append(line)
    for e in entries:
        e["body"] = "\n".join(e["lines"])
        e["status"] = "open"
        for ln in e["lines"]:
            sm = re.match(r"^-\s*status:\s*(\S+)", ln)
            if sm:
                word = sm.group(1).rstrip(".|,;")
                if word in _LEDGER_STATUS_WORDS:
                    e["status"] = word
                break
    return entries


def ledger_lint(path: str, state_path: str = None) -> tuple:
    """Rule 6 as code: flag any ask whose own text records a SATISFIED
    flip gate while its status is not shipped. Tier 1 = an explicit
    `- gate-evidence:` field; tier 2 = the signal regexes, scanned
    with the entry's own status / flip-gate / gate-evidence lines
    skipped (descriptions never count as evidence). --state escalates
    across consecutive runs — the across-session-boundary class."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    entries = _ledger_parse_entries(text)
    flags = []
    for e in entries:
        if e["status"] in _LEDGER_EXEMPT:
            continue
        signals = []
        m = re.search(r"^-\s*gate-evidence:\s*\S.*$", e["body"], re.M)
        if m:
            signals.append(("gate-evidence", m.group(0).strip()))
        for ln in e["lines"]:
            if re.match(r"^-\s*(status|flip gate|gate-evidence):", ln):
                continue
            for rx in _LEDGER_SIGNALS:
                if rx.search(ln):
                    signals.append((rx.pattern, ln.strip()))
                    break
        if signals:
            flags.append({"id": e["id"], "status": e["status"],
                          "title": e["title"], "line": e["lineno"],
                          "signals": signals})
    if state_path:
        st = {}
        try:
            with open(state_path, encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                st = loaded
        except (OSError, ValueError):
            st = {}
        now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        out = {}
        for fl in flags:
            prev = st.get(fl["id"]) or {}
            runs = int(prev.get("runs", 0)) + 1
            fl["consecutive_runs"] = runs
            out[fl["id"]] = {"runs": runs,
                             "first_flag": prev.get("first_flag", now),
                             "status": fl["status"],
                             "title": fl["title"]}
        try:
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=1)
        except OSError:
            pass   # the state is best-effort; the flags still report
    return flags, len(entries)


def cmd_approvals(args) -> int:
    c = _client_from_args(args)
    if args.approvals_cmd == "list":
        resp, status = c.post("/approvals/list", {})
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        pend = resp.get("pending", [])
        if not pend:
            print("(no pending approvals)")
        for a in pend:
            print(f"{a['id']}  [{a['op']}] {a['summary']}  "
                  f"(agent {a['agent']}, since {a['created_at']})")
        return 0
    elif args.approvals_cmd == "wait":
        if not args.id:
            return _err("approvals wait requires --id", 2)
        resp, status = c.post("/approvals/wait", {
            "id": args.id, "timeout": args.timeout}, timeout=args.timeout + 30)
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        print(f"{resp.get('id')}: {resp.get('status')}")
        a = resp.get("approval") or {}
        if a.get("status") in ("approved", "denied"):
            print(f"  {a['op']}: {a['summary']} — {a['status']} by "
                  f"{a.get('decided_by')}")
            return 0 if a["status"] == "approved" else 1
        return 0
    return _err(f"unknown approvals subcommand: {args.approvals_cmd}", 2)


def cmd_roots(args) -> int:
    """`roots request --path ... --reason ...` — ask the human to share a
    host directory. Works even when the agent currently has zero roots
    (that is the whole point: the request is how the scope grows)."""
    c = _client_from_args(args)
    if args.roots_cmd != "request":
        return _err(f"unknown roots subcommand: {args.roots_cmd}", 2)
    if not args.path:
        return _err("roots request requires --path (absolute host path)", 2)
    resp, status = c.post("/roots/request",
                          {"path": args.path,
                           "reason": args.reason or ""})
    if status == 0:
        return _err(resp.get("message", "connection failed"), 3)
    if status == 200 and resp.get("status") == "already_shared":
        print(f"already shared: {resp.get('path')}")
        return 0
    if status == 200 and resp.get("status") == "approved":
        print(f"auto-approved: {resp.get('path')} is now shared and in "
              "scope (host policy 'Auto - no restrictions').")
        return 0
    if status == 202:
        aid = resp.get("approval_id", "?")
        print(f"share request submitted: {resp.get('path')}")
        print(f"approval id: {aid}")
        print("The human host must approve it in the LLMAC window "
              "(Approvals tab). Root sharing is a scope expansion — it "
              "stays human-gated under every policy except 'Auto - no "
              "restrictions'.")
        print(f"poll: llmac.py approvals wait --id {aid}")
        return 0
    return _err(_fmt_err_fields(resp))


def cmd_events(args) -> int:
    c = _client_from_args(args)
    since = args.since or 0
    while True:
        resp, status = c.get(f"/events?since={since}&wait={args.wait}",
                             timeout=args.wait + 30)
        if status == 0:
            return _err(resp.get("message", "connection failed"), 3)
        if "error" in resp:
            return _err_from_resp(resp)
        for ev in resp.get("events", []):
            print(f"[{ev['seq']}] {ev['ts']} {ev['type']} "
                  f"{json.dumps(ev.get('data', {}), ensure_ascii=False)}")
        since = resp.get("last_seq", since)
        if not args.follow:
            break
    return 0


# ---- probe (v2.8) ---------------------------------------------------------
#
# The REQUIRED pre-connection step in the connection block. Contract,
# verifiable OFFLINE before running it (llmac.py audit + the block's
# Client-SHA256 pin — the same trust chain as the download itself):
#   * opens ONE socket to the host and completes the TLS handshake;
#   * verifies the pinned fingerprint (the pinning connect uses);
#   * writes ZERO application bytes — no request, no key, no auth;
#   * passively listens for --wait seconds, then closes.
# A compliant LLMAC host sends nothing until it has a complete request,
# so ANY application bytes in the window are an unsolicited push and
# the verdict is FAIL. Clean EOF (host closed the idle connection) and
# a silent timeout are both PASS.


def probe_host(host: str, port: int, fingerprint: str = "",
               wait: float = 10.0, timeout: float = 10.0,
               tls: bool = True) -> dict:
    """Run the passive probe. Returns a verdict dict; network trouble
    is a FAIL with a reason, never an exception."""
    out = {"host": host, "port": port, "tls": tls, "wait": wait,
           "fingerprint": "", "bytes_received": 0, "preview": "",
           "elapsed": None, "verdict": "FAIL", "reason": ""}
    try:
        raw = socket.create_connection((host, int(port)), timeout=timeout)
    except OSError as e:
        out["reason"] = f"unreachable: {e}"
        return out
    s = None
    try:
        if tls:
            ctx = ssl._create_unverified_context()
            s = ctx.wrap_socket(raw, server_hostname=host)
            der = s.getpeercert(binary_form=True)
            live = "SHA256:" + hashlib.sha256(der).hexdigest()
            out["fingerprint"] = live
            if fingerprint and fingerprint != live:
                out["reason"] = (f"fingerprint mismatch — pinned "
                                 f"{fingerprint}, live {live} "
                                 f"(possible MITM)")
                return out
        else:
            s = raw
        s.settimeout(max(0.1, float(wait)))
        t0 = time.monotonic()
        try:
            data = s.recv(4096)
        except socket.timeout:
            out["elapsed"] = round(time.monotonic() - t0, 2)
            out["verdict"] = "PASS"
            out["reason"] = (f"silent for the full {wait:.0f}s window — "
                             f"no unsolicited bytes (TLS handshake "
                             f"aside)")
            return out
        out["elapsed"] = round(time.monotonic() - t0, 2)
        if data == b"":
            out["verdict"] = "PASS"
            out["reason"] = ("host closed the idle connection cleanly — "
                             "no unsolicited bytes")
        else:
            out["bytes_received"] = len(data)
            out["preview"] = data[:64].hex()
            out["reason"] = (f"UNSOLICITED DATA: {len(data)} byte(s) "
                             f"pushed with no request sent")
        return out
    except (OSError, ValueError) as e:
        out["reason"] = f"transport error: {e}"
        return out
    finally:
        # wrap_socket() adopts raw's fd, so closing the SSLSocket is
        # what actually releases it; raw.close() is then a safe no-op
        # (or closes the never-wrapped plain socket).
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
        try:
            raw.close()
        except OSError:
            pass


def cmd_probe(args) -> int:
    res = probe_host(args.host, args.port, fingerprint=(args.fp or ""),
                     wait=args.wait, tls=(not args.plain))
    if getattr(args, "json", False):
        _pjson(res)
    else:
        bar = "=" * 62
        print(bar)
        print(f"PROBE — {res['host']}:{res['port']} "
              f"({'TLS' if res['tls'] else 'plain TCP'})")
        if res["fingerprint"]:
            print(f"  cert:     {res['fingerprint']}")
        print(f"  verdict:  {res['verdict']}")
        print(f"  reason:   {res['reason']}")
        if res["bytes_received"]:
            print(f"  first bytes (hex): {res['preview']}")
        print(bar)
    return 0 if res["verdict"] == "PASS" else 1


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="llmac.py",
        description="LLMAC v2 CLI — agent-side adapter for the LLM "
                    "Machine Access Connector host.",
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--conn", default=None,
                   help=f"Saved connection name (default: {DEFAULT_CONN}).")
    p.add_argument("--host", default=None,
                   help="Host address (env LLMAC_HOST; or from saved conn).")
    p.add_argument("--port", type=int, default=None,
                   help="Port (env LLMAC_PORT; or from saved conn).")
    p.add_argument("--key", default=None,
                   help="Access key (env LLMAC_KEY; or from saved conn).")
    p.add_argument("--plain", action="store_true",
                   help="Use plain HTTP (localhost/testing only).")
    p.add_argument("--fp", default=None,
                   help="Expected TLS cert fingerprint (SHA256:...).")
    p.add_argument("--no-verify", action="store_true",
                   help="Skip fingerprint verification (emergency only).")
    p.add_argument("--verbose", action="store_true",
                   help="Verbose output for some commands.")
    p.add_argument("--retry", type=int, default=0,
                   help="Keep retrying transport failures for N seconds "
                        "(survives host restarts).")
    p.add_argument("--tap", action="store_true",
                   help="v2.8: watch the connection while commands run "
                        "and alert on server data with no request "
                        "outstanding (unsolicited push).")
    p.add_argument("--version", action="version",
                  version=f"llmac {VERSION}")

    sub = p.add_subparsers(dest="cmd", required=True)

    def simple(name, help_, func, extra=None):
        sp = sub.add_parser(name, help=help_)
        if extra:
            for flag, kw in extra:
                sp.add_argument(flag, **kw)
        sp.set_defaults(func=func)
        return sp

    # connection management
    # --plain / --fp are ALSO accepted after the subcommand via SUPPRESS
    # defaults (argparse subparsers otherwise clobber top-level values).
    sp = simple("connect", "Connect to a host and optionally save it.",
                cmd_connect)
    sp.add_argument("--host", required=True)
    sp.add_argument("--port", type=int, default=DEFAULT_PORT)
    sp.add_argument("--key", required=True)
    sp.add_argument("--fp", default=argparse.SUPPRESS,
                    help="Expected TLS cert fingerprint.")
    sp.add_argument("--plain", action="store_true", default=argparse.SUPPRESS,
                    help="Use plain HTTP.")
    sp.add_argument("--no-verify", action="store_true",
                    default=argparse.SUPPRESS,
                    help="Skip fingerprint verification (emergency only).")
    sp.add_argument("--name", default=DEFAULT_CONN,
                    help="Connection name to save as.")
    sp.add_argument("--save", action="store_true",
                    help="Persist this connection for later use.")

    simple("disconnect", "Remove a saved connection.", cmd_disconnect,
           [("--name", {"default": DEFAULT_CONN})])
    simple("conns", "List saved connections.", cmd_conns)

    # Offline audit of the client file (v2.8): hash + static report, no
    # network, no writes, nothing executed.
    sp = sub.add_parser(
        "audit",
        help="Offline: hash this client file and print a STATIC audit "
             "(ast.parse). Contacts nothing, writes nothing, executes "
             "nothing.")
    sp.add_argument("--file", default=None,
                    help="File to audit (default: this llmac.py).")
    sp.add_argument("--expect-sha256", default=None, dest="expect_sha256",
                    help="Exit non-zero unless the file's SHA-256 equals "
                         "this (the block's Client-SHA256 line).")
    sp.set_defaults(func=cmd_audit)

    # Pre-connection probe (v2.8): REQUIRED step 3 of the connection
    # block, before connect. One socket: TLS handshake + fingerprint
    # check, then it LISTENS. Sends no request and no key — ever.
    sp = sub.add_parser(
        "probe",
        help="Pre-connection check (REQUIRED): handshake + verify the "
             "pinned fingerprint, then listen for --wait seconds. "
             "Sends NOTHING (no request, no key). A compliant host is "
             "silent; any bytes received = unsolicited push = FAIL.")
    sp.add_argument("--host", required=True)
    sp.add_argument("--port", type=int, default=DEFAULT_PORT)
    sp.add_argument("--fp", default="",
                    help="Expected TLS cert fingerprint (SHA256:..., the "
                         "block's Cert line).")
    sp.add_argument("--wait", type=float, default=10.0,
                    help="Seconds to listen (default 10).")
    sp.add_argument("--plain", action="store_true",
                    help="Plain TCP, no TLS (no fingerprint check).")
    sp.add_argument("--json", action="store_true",
                    help="Machine-readable result.")
    sp.set_defaults(func=cmd_probe)

    # identity
    simple("info", "Show host info (agent, roots, exec, policy).", cmd_info)
    simple("health", "Unauthenticated health check.", cmd_health)

    # navigation
    simple("ls", "List a directory (or the shared roots).", cmd_ls,
           [("--path", {"default": ""})])
    sp = simple("tree", "Depth-capped tree of a directory.", cmd_tree,
                [("--path", {"default": ""}),
                 ("--depth", {"type": int, "default": 3}),
                 ("--all", {"action": "store_true",
                            "help": "Include hidden files."})])

    # read / write / edit
    sp = sub.add_parser("read", help="Read a file (whole, line range, or byte range).")
    sp.add_argument("--path", required=True)
    sp.add_argument("--lines", default=None,
                    help="Line range START-END (e.g. 10-50).")
    sp.add_argument("--offset", type=int, default=None,
                    help="Byte offset (binary-safe).")
    sp.add_argument("--limit", type=int, default=None,
                    help="Max bytes to read.")
    sp.add_argument("--max-bytes", type=int, default=None, dest="max_bytes")
    sp.add_argument("--hex", action="store_true", dest="hex_flag",
                    help="v2.4.7: server-rendered xxd-style hex dump "
                         "(offset/hex/ascii columns); byte slicing via "
                         "--offset/--limit, default 512 B per slice, "
                         "hard cap 4096 B — the RE primitive for binary "
                         "blobs, no exec needed. v2.4.8: pair with "
                         "--find-hex/--find-text to SCAN for a pattern "
                         "(hits carry hex context; page with --offset).")
    sp.add_argument("--find-hex", default=None, dest="find_hex",
                    help="v2.4.8: with --hex — scan for this hex byte "
                         "pattern (e.g. '4d5a' or '4d 5a 90 00'). Prints "
                         "each hit's offset + hex context; --offset "
                         "starts the scan, next_offset continues it.")
    sp.add_argument("--find-text", default=None, dest="find_text",
                    help="v2.4.8: with --hex — scan for this literal "
                         "text (UTF-8 bytes), e.g. a signature or string "
                         "inside a binary.")
    sp.add_argument("--max-hits", type=int, default=None, dest="max_hits",
                    help="v2.4.8: with a find — cap hits per call "
                         "(default 25, server cap 100); 'more' + a "
                         "continuation hint appear when the cap cuts "
                         "the scan short.")
    sp.add_argument("--numbered", action="store_true",
                    help="Prefix line numbers.")
    sp.add_argument("--raw", action="store_true",
                    help="Byte-exact full text; disables smart truncation "
                         "of large files (A4).")
    sp.add_argument("--to", default=None,
                    help="Write to a local file instead of stdout ('-' = stdout).")
    sp.set_defaults(func=cmd_read)

    sp = sub.add_parser("write", help="Write a file (stdin/--content/--file).")
    sp.add_argument("--path", required=True)
    sp.add_argument("--content", default=None)
    sp.add_argument("--file", default=None, dest="file",
                    help="Upload this local file (binary-safe).")
    sp.add_argument("--expected-version", default=None, dest="expected_version",
                    help="Version token from your last read (conflict guard).")
    sp.set_defaults(func=cmd_write)

    sp = sub.add_parser("edit", help="Surgical edit (returns a diff).")
    sp.add_argument("--path", required=True)
    sp.add_argument("--replace", default=None,
                    help="Find text (or regex with --regex).")
    sp.add_argument("--with", default=None, dest="with_",
                    help="Replacement text.")
    sp.add_argument("--occurrence", default="first",
                    help="first | all | Nth occurrence.")
    sp.add_argument("--regex", action="store_true")
    sp.add_argument("--lines", default=None,
                    help="Replace line range START-END (needs --content).")
    sp.add_argument("--insert-before", type=int, default=None,
                    dest="insert_before",
                    help="Insert --content before this line.")
    sp.add_argument("--insert-after", type=int, default=None,
                    dest="insert_after",
                    help="Insert --content after this line.")
    sp.add_argument("--append", action="store_true",
                    help="Append --content at end.")
    sp.add_argument("--delete-lines", default=None, dest="delete_lines",
                    help="Delete line range START-END.")
    sp.add_argument("--content", default=None,
                    help="Content for --lines/--insert*/--append.")
    sp.add_argument("--expected-version", default=None, dest="expected_version")
    sp.set_defaults(func=cmd_edit)

    sp = sub.add_parser("search", help="Content grep / filename glob.")
    sp.add_argument("--query", default=None,
                    help="Content query (literal, or regex with --regex).")
    sp.add_argument("--regex", action="store_true")
    sp.add_argument("--name", default=None,
                    help="Filename glob (e.g. *.py).")
    sp.add_argument("--glob", default=None, dest="glob",
                    help="Alias of --name, also filters content search.")
    sp.add_argument("--path", default="")
    sp.add_argument("--context", type=int, default=0,
                    help="Context lines around hits (0-3).")
    sp.add_argument("--max-results", type=int, default=50, dest="max_results")
    sp.add_argument("--all", action="store_true",
                    help="Include hidden files/dirs.")
    sp.set_defaults(func=cmd_search)

    # fs
    sp = sub.add_parser("stat",
                        help="File/directory metadata + version token "
                             "(--hash adds sha256, no exec needed).")
    sp.add_argument("--path", required=True)
    sp.add_argument("--hash", action="store_true", dest="hash_flag",
                    help="Include the file's sha256 (files <= 64 MB).")
    sp.set_defaults(func=cmd_stat)
    simple("mkdir", "Create a directory.", cmd_mkdir,
           [("--path", {"required": True})])
    sp = simple("rm", "Delete a file or directory.", cmd_rm,
                [("--path", {"required": True}),
                 ("--confirm", {"action": "store_true",
                                "help": "Confirm large recursive deletes."})])
    sp = simple("mv", "Move/rename inside the sandbox.", cmd_mv,
                [("--src", {"required": True}), ("--dest", {"required": True}),
                 ("--overwrite", {"action": "store_true"})])
    sp = simple("cp", "Copy (recursive) inside the sandbox.", cmd_cp,
                [("--src", {"required": True}), ("--dest", {"required": True}),
                 ("--overwrite", {"action": "store_true"})])
    sp = simple("download", "Download a remote file locally (binary-safe).",
                cmd_download,
                [("--path", {"required": True}),
                 ("--lines", {"default": None,
                              "help": "Line range START-END (text files)."}),
                 ("--offset", {"type": int, "default": None,
                               "help": "Byte offset (binary-safe)."}),
                 ("--limit", {"type": int, "default": None,
                              "help": "Max bytes to read."}),
                 ("--to", {"default": None}),
                 ("--max-bytes", {"type": int, "default": 50 * 1024 * 1024,
                                   "dest": "max_bytes"}),
                 ("--numbered", {"action": "store_true"}),
                 ("--verbose", {"action": "store_true",
                                  "default": argparse.SUPPRESS})])
    sp = simple("upload", "Upload a local file to the host.", cmd_upload,
                [("--path", {"required": True,
                              "help": "Remote destination path."}),
                 ("--file", {"required": True,
                              "help": "Local source file."}),
                 ("--expected-version", {"default": None,
                                           "dest": "expected_version"}),
                 ("--verbose", {"action": "store_true",
                                  "default": argparse.SUPPRESS})])

    # exec / proc
    sp = sub.add_parser("exec", help="Run a shell command on the host "
                                     "(if the host allows it).")
    sp.add_argument("--command", required=True,
                    help="Shell command. Distro package installs may use "
                         "sudo (e.g. 'sudo pacman -S <pkg>') — those "
                         "ALWAYS trigger a host approval with a 2-minute "
                         "countdown, under every approval policy.")
    sp.add_argument("--cwd", default="")
    sp.add_argument("--timeout", type=int, default=300)
    sp.add_argument("--save", default="",
                    help="Stream the command's FULL stdout (uncapped) to "
                         "this host-side file inside the sandbox — no "
                         "shell redirect needed. stderr still returns "
                         "inline. Then read/search/diff the artifact.")
    sp.add_argument("--save-stderr", default="", dest="save_stderr",
                    help="v2.4.8: also stream the command's FULL stderr "
                         "(uncapped) to this SECOND host-side file "
                         "(must differ from --save). Both artifacts "
                         "are byte-exact; response streams go empty.")
    sp.add_argument("--json", action="store_true", dest="json_out",
                    help="Print one machine-readable JSON result object.")
    sp.add_argument("--i-know", action="store_true", dest="i_know",
                    help="Skip the pre-flight lint for local-shell "
                         "substitution hazards (A3).")
    sp.add_argument("--verbose", action="store_true")
    sp.set_defaults(func=cmd_exec)

    sp = sub.add_parser("proc", help="Background processes.")
    sp.add_argument("proc_cmd", choices=["start", "list", "logs", "stop"])
    sp.add_argument("--command", default=None)
    sp.add_argument("--cwd", default="")
    sp.add_argument("--name", default=None)
    sp.add_argument("--id", default=None)
    sp.add_argument("--after", type=int, default=0)
    sp.add_argument("--stream", default="both",
                    choices=["stdout", "stderr", "both"])
    sp.add_argument("--follow", action="store_true",
                    help="v2.4.7: tail -f — long-poll events and print "
                         "new output as it lands; exits when the proc "
                         "exits (or after --max-idle seconds quiet).")
    sp.add_argument("--max-idle", type=int, default=None, dest="max_idle",
                    help="Stop following after N seconds without new "
                         "output (requires --follow).")
    sp.add_argument("--force", action="store_true")
    sp.add_argument("--quiet", action="store_true")
    sp.set_defaults(func=cmd_proc)

    # session / approvals / events
    sp = sub.add_parser("session", help="Server-side session memory.")
    sp.add_argument("session_cmd", choices=["status", "note", "reset",
                                             "export", "inbox", "log"])
    sp.add_argument("--text", default=None,
                    help="Note text (for 'note').")
    sp.add_argument("--peek", action="store_true",
                    help="v2.5.0: 'session inbox' without consuming "
                         "messages — the unread banner keeps counting.")
    sp.add_argument("--out", default=None,
                    help="Local output file for 'export' (default: stdout).")
    sp.add_argument("--after", type=int, default=0,
                    help="v2.5.2: 'session log' seq cursor (next_after "
                         "from the previous fetch; default 0).")
    sp.add_argument("--limit", type=int, default=200,
                    help="v2.5.2: 'session log' max entries (server "
                         "hard-caps at 1000).")
    sp.set_defaults(func=cmd_session)

    sp = sub.add_parser("screen",
                        help="The screen channel (v2.7.0): list, shot, "
                             "observe.")
    sp.add_argument("screen_cmd", choices=["list", "shot", "observe"])
    sp.add_argument("--target", default=None,
                    help="Screen index | 'primary' | 'all' (MANDATORY "
                         "for shot and observe).")
    sp.add_argument("--format", default=None,
                    help="png (default) or jpg.")
    sp.add_argument("--max-width", default=None, dest="max_width",
                    help="Optional downscale width, aspect kept "
                         "(shot only; observe refuses it).")
    sp.set_defaults(func=cmd_screen)

    sp = sub.add_parser("input",
                        help="Input injection (v2.7.0) — bounded drive "
                             "mode; off until the host enables it.")
    sp.add_argument("input_cmd", choices=["mouse", "key", "text"])
    sp.add_argument("--action", default=None,
                    help="mouse: move|click|doubleclick|drag|scroll")
    sp.add_argument("--button", default=None,
                    help="mouse: left|middle|right (default left)")
    sp.add_argument("--x", type=float, default=None)
    sp.add_argument("--y", type=float, default=None)
    sp.add_argument("--from-x", type=float, default=None, dest="from_x")
    sp.add_argument("--from-y", type=float, default=None, dest="from_y")
    sp.add_argument("--to-x", type=float, default=None, dest="to_x")
    sp.add_argument("--to-y", type=float, default=None, dest="to_y")
    sp.add_argument("--dx", type=float, default=None)
    sp.add_argument("--dy", type=float, default=None)
    sp.add_argument("--keysym", default=None,
                    help="key: X11 keysym name (Return, F5, a, ...)")
    sp.add_argument("--modifiers", default=None,
                    help="key: comma list ctrl,shift,alt,meta")
    sp.add_argument("--text", default=None,
                    help="text: printable ASCII string to type")
    sp.set_defaults(func=cmd_input)

    sp = sub.add_parser("ledger",
                        help="Ledger tools — rule 6 as code (v2.6.0).")
    sp.add_argument("ledger_cmd", choices=["lint"])
    sp.add_argument("--path", default=None,
                    help="Path to an ASKS.md-format ledger file "
                         "(usually your sandbox mirror).")
    sp.add_argument("--json", action="store_true",
                    help="Machine-readable output.")
    sp.add_argument("--state", default=None,
                    help="Optional state file — escalates flags across "
                         "consecutive lint runs (the session-boundary "
                         "class).")
    sp.set_defaults(func=cmd_ledger)

    sp = sub.add_parser("roots", help="Ask the host to share a directory "
                                      "(human approves in the GUI).")
    sp.add_argument("roots_cmd", choices=["request"])
    sp.add_argument("--path", required=True,
                    help="Absolute directory path on the host.")
    sp.add_argument("--reason", default="",
                    help="Why you need it (shown to the human).")
    sp.set_defaults(func=cmd_roots)

    sp = sub.add_parser("approvals", help="Approval queue.")
    sp.add_argument("approvals_cmd", choices=["list", "wait"])
    sp.add_argument("--id", default=None)
    sp.add_argument("--timeout", type=int, default=30)
    sp.set_defaults(func=cmd_approvals)

    # batch / archive / grants (v2.3)
    sp = sub.add_parser("batch", help="Run many ops in one round trip.")
    sp.add_argument("--ops", default=None,
                    help="JSON array of ops, inline.")
    sp.add_argument("--file", default=None, dest="ops_file",
                    help="File containing the ops JSON array.")
    sp.add_argument("--json", action="store_true", dest="json_out",
                    help="Print the raw batch response as JSON.")
    sp.add_argument("--no-diffs", action="store_true", dest="no_diffs",
                    help="v2.4.7: suppress the per-op diffs of batched "
                         "edit results (printed by default).")
    sp.set_defaults(func=cmd_batch)

    sp = sub.add_parser("archive",
                        help="Get/put whole-tree tar.gz archives.")
    mode = sp.add_mutually_exclusive_group(required=True)
    mode.add_argument("--get", action="store_true",
                      help="Download a remote directory as tar.gz.")
    mode.add_argument("--put", action="store_true",
                      help="Extract a local tar.gz into a remote directory.")
    sp.add_argument("--path", required=True,
                    help="Remote directory (get: source; put: destination).")
    sp.add_argument("--to", default=None,
                    help="Local .tgz file to write (--get).")
    sp.add_argument("--file", default=None,
                    help="Local .tgz file to upload (--put).")
    sp.add_argument("--all", action="store_true",
                    help="Include hidden/ignored files (never .git).")
    sp.add_argument("--overwrite", action="store_true",
                    help="Replace existing files on --put.")
    sp.set_defaults(func=cmd_archive)

    simple("grants", "List your live approval grants.", cmd_grants)

    # agent-efficiency tier (v2.4)
    sp = sub.add_parser("deploy",
                        help="Upload N local files + verify sha256 on the "
                             "host, in ONE invocation (batch + one exec).")
    sp.add_argument("--pairs", action="append", metavar="LOCAL=REMOTE",
                    help="Local file path and absolute remote path; "
                         "repeatable.")
    sp.add_argument("--manifest", default=None,
                    help='JSON: {"files": [{"local": .., "remote": ..}]}')
    sp.add_argument("--dry-run", action="store_true", dest="dry_run",
                    help="Show the plan without sending anything.")
    sp.add_argument("--no-verify", action="store_true", dest="no_verify",
                    help="Skip the sha256 verification pass.")
    sp.set_defaults(func=cmd_deploy)

    sp = sub.add_parser("run",
                        help="Execute many CLI commands in ONE process / "
                             "ONE TLS session (JSON array of arg-vectors).")
    sp.add_argument("--file", default=None,
                    help="Commands file (JSON array of arg-vectors); "
                         "default: stdin.")
    sp.add_argument("--keep-going", action="store_true", dest="keep_going",
                    help="Do not stop at the first failing command.")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("verify",
                        help="Compare a local file with a remote path by "
                             "sha256 — works even when host exec is off.")
    sp.add_argument("--local", required=True,
                    help="Local file to hash.")
    sp.add_argument("--remote", required=True,
                    help="Remote absolute path to hash.")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("orient",
                        help="One-call orientation pack: info + tree + "
                             "doc heads + session pointer (budget-"
                             "trimmed server-side).")
    sp.add_argument("--path", default="",
                    help="Directory to orient in (default: first root).")
    sp.add_argument("--depth", type=int, default=0,
                    help="Tree depth 1-4 (default 2).")
    sp.add_argument("--doc-heads", type=int, default=None, dest="doc_heads",
                    help="Lines per README/agent.md head (default 40, "
                         "0 disables).")
    sp.add_argument("--budget", type=int, default=0,
                    help="Response byte budget (default 4000).")
    sp.set_defaults(func=cmd_orient)

    sp = sub.add_parser("diff",
                        help="Server-side unified diff: --a vs --b, or --a "
                             "vs --inline-file (a write dry-run).")
    sp.add_argument("--a", required=True, help="First host path.")
    sp.add_argument("--b", default=None,
                    help="Second host path.")
    sp.add_argument("--inline-file", default=None, dest="inline_file",
                    help="LOCAL file with proposed new content.")
    sp.set_defaults(func=cmd_diff)

    sp = sub.add_parser("events", help="Long-poll host events.")
    sp.add_argument("--since", type=int, default=0)
    sp.add_argument("--wait", type=int, default=25)
    sp.add_argument("--follow", action="store_true")
    sp.set_defaults(func=cmd_events)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return _call_with_inbox_notice(args.func, args)


if __name__ == "__main__":
    raise SystemExit(main())
