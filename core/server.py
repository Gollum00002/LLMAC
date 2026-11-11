"""HTTP server plumbing, headless runner, and the agent connection prompt.

The host builds one :class:`~core.api.AppContext` shared by the HTTP
server, the GUI (or headless runner), the approvals registry and the
process manager. TLS is enabled by wrapping the listening socket with an
auto-generated self-signed certificate (see tlsutil) — agents verify the
certificate fingerprint out-of-band (it is embedded in the connection
prompt), SSH-style trust-on-first-use.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import ssl
import sys
import threading
import time
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from typing import Optional

from .api import LLMACRequestHandler, AppContext
from .approvals import ApprovalRegistry
from .constants import (
    CLI_PATH, CLIENT_DOWNLOAD_URL, CLIENT_REPO_URL, DEFAULT_HOST,
    DEFAULT_PORT, EXPOSED_HOST, LLMAC_VERSION,
    POLICY_AUTO, POLICY_DESTRUCTIVE, POLICY_STRICT,
)
from .events import EventBus
from .policy import InstallPolicy
from .procs import ProcessManager
from .sandbox import Sandbox
from .sessions import SessionRegistry
from .state import (
    History, StateStore, clamp_policy, key_fingerprint, make_default_agent,
    new_key, normalize_agent, set_permissive_umask,
)

# Public-IP echo services for the GUI display.
_PUBLIC_IP_SERVICES = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://ipinfo.io/ip",
    "https://4.icanhazip.com",
)
_PUBLIC_IP_TIMEOUT = 6


def detect_shell() -> Optional[str]:
    for candidate in ("/bin/bash", "/usr/bin/bash"):
        if os.path.exists(candidate):
            return candidate
    if shutil.which("bash"):
        return "bash"
    return None


EXEC_SHELL = detect_shell()


def fetch_public_ip() -> Optional[str]:
    """Best-effort public IPv4 lookup (GUI display only)."""
    last_err = ""
    for url in _PUBLIC_IP_SERVICES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "llmac/2"})
            with urllib.request.urlopen(req, timeout=_PUBLIC_IP_TIMEOUT) as r:
                ip = r.read().decode("ascii", errors="replace").strip()
            if ip and len(ip) <= 64 and "\n" not in ip and " " not in ip:
                return ip
        except (urllib.error.URLError, urllib.error.HTTPError, OSError,
                TimeoutError) as e:
            last_err = f"{url}: {e}"
            continue
    return None


# ---------------------------------------------------------------------------
# Context construction
# ---------------------------------------------------------------------------

def build_context(state_store: StateStore, roots: list, agents: list,
                  settings: dict, history: History,
                  log_callback=None) -> AppContext:
    """Assemble the shared AppContext (used by GUI and headless alike)."""
    # The server's own data dir is a protected tree: it holds agent keys,
    # the TLS private key and the audit log, and must never be readable
    # through the API even when it sits inside a shared root (F21/F22).
    sandbox = Sandbox(roots, protected=[state_store.data_dir])
    policy = InstallPolicy(settings.get("venvs") or [])
    events = EventBus()
    approvals = ApprovalRegistry(on_event=lambda t, d: events.emit(t, d))
    procs = ProcessManager(
        EXEC_SHELL,
        on_event=lambda t, d: events.emit(t, d),
        data_dir=state_store.data_dir,   # v2.4.5: restart-surviving procs
    )
    sessions = SessionRegistry()
    return AppContext(
        sandbox=sandbox, agents=agents, settings=settings, policy=policy,
        sessions=sessions, approvals=approvals, events=events, procs=procs,
        history=history, state_store=state_store, log_callback=log_callback,
    )


def make_server(host: str, port: int, ctx: AppContext,
                cert_file: Optional[str] = None,
                key_file: Optional[str] = None):
    """Create (and optionally TLS-wrap) the threaded HTTP server."""

    class _Handler(LLMACRequestHandler):
        pass

    _Handler.ctx = ctx
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.daemon_threads = True

    if cert_file and key_file:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


# ---------------------------------------------------------------------------
# Connection prompt (GUI "Copy Prompt" — what the human pastes to the agent)
# ---------------------------------------------------------------------------
# v2.8: the host does NOT serve code. The agent downloads the one-file
# client (llmac.py) from the public GitHub release and checks it against
# the SHA-256 in this block. The host only hashes its own local copy of
# llmac.py so the block can say what the release asset must hash to.

def _client_sha256() -> str:
    """SHA-256 (hex) of the local llmac.py, over its exact bytes (the same
    value `sha256sum llmac.py` prints; no newline normalisation).

    Returns '' when the file cannot be read; the block then tells the
    agent to take the hash from the GitHub release page instead."""
    try:
        with open(CLI_PATH, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return ""


def _client_url() -> str:
    """Where the agent downloads llmac.py. LLMAC_CLIENT_URL overrides the
    default (forks, mirrors, tests); the SHA-256 pin applies either way."""
    return os.environ.get("LLMAC_CLIENT_URL") or CLIENT_DOWNLOAD_URL


# Download one-liner. Design constraints:
#   * single line, single quotes only — it is embedded in a double-quoted
#     `python3 -c "..."` shell string and must paste safely into bash/zsh
#     and survive being relayed by chat agents (no $, backtick, double
#     quote or ! characters);
#   * stdlib only, nothing from the LLMAC host is fetched or executed;
#   * fail closed: any hash mismatch exits non-zero BEFORE llmac.py is
#     written, and nothing is ever executed by the one-liner itself.
_TOK_URL = "@@URL@@"
_TOK_SHA = "@@SHA@@"
_DOWNLOAD_ONE_LINER = (
    "import urllib.request,hashlib,sys;"
    f"U='{_TOK_URL}';W='{_TOK_SHA}';"
    "d=urllib.request.urlopen(U,timeout=30).read();"
    "g=hashlib.sha256(d).hexdigest();"
    "g==W or sys.exit('ABORT: sha256 mismatch (%s vs %s) - not written'"
    "%(g,W));"
    "open('llmac.py','wb').write(d);"
    "print('llmac.py verified: sha256 OK (%s) - written'%g[:16])"
)


def build_prompt_text(*, key: str, host: str, port: int, roots: list,
                      fingerprint: str = "", tls: bool = True,
                      agent_name: str = "default",
                      client_sha256: "Optional[str]" = None) -> str:
    """A compact, paste-ready connection block for chat-based agents.

    v2.8: the block points the agent at the public GitHub release for the
    client (one stdlib-only file), states the SHA-256 that file must have,
    and gives a fail-closed download one-liner, an offline audit
    command, and — REQUIRED, before connect — the passive `probe`: one
    socket, handshake + fingerprint check, then it listens. It sends no
    request and no key; a compliant host sends nothing unsolicited. The
    host serves nothing: no code and no payload endpoint."""
    sha = (client_sha256 if client_sha256 is not None
           else _client_sha256())
    url = _client_url()
    sep = "=" * 60
    lines = [
        "LLMAC v2 — Agent Connection",
        sep,
        f"Host:  {host}",
        f"Port:  {port}",
        f"TLS:   {'yes' if tls else 'no'}",
        f"Key:   {key}",
    ]
    if fingerprint:
        lines.append(f"Cert:  {fingerprint}")
    sha_shown = sha or "(unavailable - use the hash on the GitHub release page)"
    lines += [
        f"Client-Source:  {CLIENT_REPO_URL}",
        f"Client-File:    {url}",
        f"Client-SHA256:  {sha_shown}",
    ]
    if roots:
        lines.append("")
        lines.append("Shared directories:")
        for r in roots:
            lines.append(f"  - {r}")

    connect_cmd = (f"python3 llmac.py connect --host {host} --port {port} "
                   f"--key {key}")
    if fingerprint:
        connect_cmd += f" --fp {fingerprint}"
    connect_cmd += " --save"
    audit_cmd = "python3 llmac.py audit"
    if sha:
        audit_cmd += f" --expect-sha256 {sha}"
    probe_cmd = (f"python3 llmac.py probe --host {host} --port {port} "
                 f"--wait 10")
    if fingerprint:
        probe_cmd += f" --fp {fingerprint}"

    lines += ["", "1. Get the client. This host does NOT serve code: it is one",
              "   stdlib-only file, published on GitHub (MIT). Read the source",
              f"   first if you like: {CLIENT_REPO_URL}"]
    if sha:
        one = (_DOWNLOAD_ONE_LINER.replace(_TOK_URL, url)
               .replace(_TOK_SHA, sha))
        lines += ["   Download + verify (aborts without writing on any",
                  "   hash mismatch; executes nothing):",
                  f'     python3 -c "{one}"']
    else:
        lines += [f"   Download {url}",
                  "   and compare its SHA-256 with the one on the release page."]
    lines += [
        "2. Audit it (offline, optional): hashes the file and prints a static",
        "   ast.parse report (imports, risky calls, write sites, egress).",
        "   Executes nothing, writes nothing, contacts nothing:",
        f"     {audit_cmd}",
        "3. Probe the HOST (REQUIRED — do this before connecting). One",
        "   socket: TLS handshake + pinned-fingerprint check, then it",
        "   LISTENS for 10 seconds. It sends NO request and NO key; a",
        "   compliant host sends nothing unsolicited, so the verdict must",
        "   be PASS. Any bytes received means the host pushes data —",
        "   do not connect:",
        f"     {probe_cmd}",
        "4. Connect only after the probe passes:",
        f"     {connect_cmd}",
        "Then verify:  python3 llmac.py info",
        "Look around in ONE call:  python3 llmac.py orient --path <root>",
        "If a shared root contains agent.md, read it for full docs.",
        "Tips: installs only inside a venv; search/tree + ranged reads",
        "instead of whole-file reads; deploy/run/verify/diff batch many",
        "ops into one call; read --hex dumps binary slices; proc logs",
        "--follow streams a running proc's output; 'session status'",
        "recovers context.",
        "Work warily: add --tap before any command (python3 llmac.py",
        "--tap info) to alert if the host ever sends data with no",
        "request outstanding.",
        "Missing a directory? 'roots request --path <abs> --reason <why>'",
        "asks the host to share it (they approve it in their window).",
        sep,
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Headless mode
# ---------------------------------------------------------------------------

def run_headless(roots: list, key: str, host: Optional[str], port: Optional[int],
                 data_dir: str, *, expose: bool = False, allow_exec: bool = False,
                 policy: Optional[str] = None, tls: Optional[bool] = None) -> int:
    set_permissive_umask()
    state_store = StateStore(data_dir)
    history = History(data_dir)
    persisted = state_store.load()

    merged_roots = [r for r in (roots or persisted.get("roots") or [])
                    if os.path.isdir(r)]
    agents = persisted.get("agents") or [make_default_agent()]
    settings = dict(persisted.get("settings") or {})
    merged_host = host if host is not None else (
        persisted.get("host") or DEFAULT_HOST)
    merged_port = int(port if port is not None else
                      (persisted.get("port") or DEFAULT_PORT))
    if expose:
        merged_host = EXPOSED_HOST
    if allow_exec:
        settings["allow_exec"] = True
        # Enabling exec on the CLI implies the default agent may use it
        # (matches the GUI's toggle behaviour).
        agents[0] = dict(agents[0])
        agents[0]["perms"] = dict(agents[0].get("perms") or {})
        agents[0]["perms"]["exec"] = True
        agents[0]["perms"]["proc"] = True
    # Headless hosts have no human watching an approval queue — default to
    # auto unless the operator explicitly asks for a policy.
    settings["approval_policy"] = clamp_policy(
        policy or settings.get("approval_policy") or POLICY_AUTO)
    if key:
        agents[0] = dict(agents[0])
        agents[0]["key"] = key

    if not merged_roots:
        print("ERROR: no shared directories (pass --dir, or have persisted "
              "state).", file=sys.stderr)
        return 2

    # TLS: default ON when we can provision a cert.
    from . import tlsutil
    use_tls = tls if tls is not None else bool(settings.get("tls", True))
    cert = keyf = None
    if use_tls:
        cert, keyf = tlsutil.ensure_cert(data_dir)
        if cert is None:
            print("WARNING: openssl unavailable or cert generation failed — "
                  "falling back to plain HTTP. Do NOT expose this server.",
                  file=sys.stderr)
            use_tls = False
    fingerprint = tlsutil.cert_fingerprint(cert) if cert else ""

    ctx = build_context(state_store, merged_roots, agents, settings, history)

    try:
        srv = make_server(merged_host, merged_port, ctx, cert, keyf)
    except OSError as e:
        print(f"ERROR: cannot bind {merged_host}:{merged_port}: {e}",
              file=sys.stderr)
        return 2
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()

    # 'auto_all' shares are granted server-side and queued; without a GUI
    # to drain the queue nothing persists them across restarts — so the
    # headless runner drains it on its own daemon thread.
    def _drain_auto_shares(stop_evt):
        while not stop_evt.wait(2.0):
            try:
                if not ctx.share_queue:
                    continue
                new = []
                while ctx.share_queue:
                    new.append(ctx.share_queue.pop(0))
                for p in new:
                    if p not in merged_roots:
                        merged_roots.append(p)
                        print(f"[auto_all] shared {p} (agent-initiated)")
                state_store.save(state_store.build_state(
                    roots=merged_roots, host=merged_host, port=merged_port,
                    agents=agents, settings=settings))
                history.append({"type": "share_auto_approved",
                                "paths": new})
            except Exception:
                pass

    _share_stop = threading.Event()
    threading.Thread(target=_drain_auto_shares, args=(_share_stop,),
                     daemon=True).start()

    state_store.save(state_store.build_state(
        roots=merged_roots, host=merged_host, port=merged_port,
        agents=agents, settings=settings))
    history.append({
        "type": "launch", "mode": "headless", "host": merged_host,
        "port": merged_port, "roots_n": len(merged_roots),
        "key_fp": key_fingerprint(agents[0]["key"]),
    })

    scheme = "https" if use_tls else "http"
    print("=" * 64)
    print(f"LLMAC v{LLMAC_VERSION} — Headless Host")
    print("=" * 64)
    print(f"Data dir:     {data_dir}")
    print(f"Shared dirs:")
    for r in merged_roots:
        print(f"  - {r}")
    print(f"Listening:    {scheme}://{merged_host}:{merged_port}")
    if fingerprint:
        print(f"Cert SHA256:  {fingerprint}")
    print(f"Exec:         {'ENABLED' if settings.get('allow_exec') else 'disabled'}")
    print(f"Approvals:    {settings['approval_policy']}")
    for a in agents:
        print(f"Agent:        {a['name']}  key={a['key']}")
    print()
    print("Press Ctrl+C to stop.")
    print("=" * 64)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        # v2.4.5: running procs are DETACHED — they survive this shutdown
        # and re-attach on the next start. Do NOT kill them here; a
        # 40-minute analysis run must not die because the host restarted.
        n = ctx.procs.stop_all()
        if n:
            print(f"{n} background process(es) left RUNNING (detached; "
                  "they re-attach on the next start — stop them via the "
                  "GUI Procs tab or `llmac proc stop` if unwanted).")
        srv.shutdown()
        srv.server_close()
        history.append({"type": "close", "mode": "headless",
                        "host": merged_host, "port": merged_port})
        return 0
