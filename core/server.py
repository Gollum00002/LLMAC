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
    CLI_PATH, DEFAULT_HOST, DEFAULT_PORT, EXPOSED_HOST, LLMAC_VERSION,
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
# Connection prompt (GUI "Copy Prompt" — the agent bootstrap incantation)
# ---------------------------------------------------------------------------

def _cli_payload_sha256() -> str:
    """SHA-256 (hex) of the cli.py the host serves via /bootstrap.

    Returns '' when the file cannot be read; the connection block then
    shows the placeholder "(unavailable)" — and the bootstrap one-liner
    still fails closed, because it refuses a missing cli_sha256 in the
    response regardless."""
    try:
        with open(CLI_PATH, "r", encoding="utf-8") as f:
            return hashlib.sha256(f.read().encode("utf-8")).hexdigest()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Self-verifying bootstrap one-liner templates (v2.7.1)
# ---------------------------------------------------------------------------
# Design constraints:
#   * single line, single quotes only — they are embedded in a
#     double-quoted `python3 -c "..."` shell string and must paste
#     safely into bash/zsh and survive being relayed by chat agents;
#   * no $, backtick, double quote, or ! chars;
#   * substitution uses @@TOKEN@@ + str.replace — the payload contains
#     dict braces and %-format calls, so str.format/percent interpolation
#     of the TEMPLATE would be unsafe here;
#   * every failure path exits non-zero via sys.exit('ABORT: ...')
#     BEFORE llmac.py is written — fail closed, write nothing.
_TOK_HOST = "@@HOST@@"
_TOK_PORT = "@@PORT@@"
_TOK_KEY = "@@KEY@@"
_TOK_FP = "@@FP@@"

# Shared tail: fetch, verify payload hash, write, report. Aborts cover
# a missing cli_sha256 (old or hostile host) and a hash mismatch
# (tampered payload). The key travels only in the Authorization header
# (never as positional data — see the v2.1.0 post-mortem below).
_BOOT_TAIL = (
    "c.request('GET','/bootstrap',"
    "headers={'Authorization':'Bearer '+K});"
    "r=c.getresponse();d=json.loads(r.read());"
    "src=d['cli_py'];want=d.get('cli_sha256','');"
    "got=hashlib.sha256(src.encode()).hexdigest();"
    "sys.exit('ABORT: payload hash missing from bootstrap response "
    "- refusing to write or run') if not want else None;"
    "sys.exit('ABORT: payload hash mismatch (%s != %s) - possible "
    "tampering, refusing to write or run'%(got,want)) if got!=want else None;"
    "open('llmac.py','w').write(src);"
    "print('llmac.py verified: payload sha256 OK (%s) - written'"
    "%got[:16])"
)


def _py_bootstrap_tls(fphex: str) -> str:
    """HTTPS bootstrap with in-handshake certificate pinning.

    The pinned-connection subclass checks sha256(peer DER cert) BEFORE
    any HTTP bytes are sent; on mismatch the connection is abandoned
    with nothing ever transmitted. This replaces the old blind
    ssl._create_unverified_context() fetch: the unverified context now
    only stands in for the missing CA chain — the actual verification
    is the explicit fingerprint pin, enforced in connect()."""
    return (
        "import http.client,ssl,hashlib,json,sys;"
        f"H='{_TOK_HOST}';P={_TOK_PORT};K='{_TOK_KEY}';F='{_TOK_FP}';"
        "C=type('C',(http.client.HTTPSConnection,),"
        "{'connect':lambda self:(http.client.HTTPSConnection.connect(self),"
        "hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()==F "
        "or sys.exit('ABORT: cert fingerprint mismatch (possible MITM) "
        "- refusing to continue'))});"
        "c=C(H,P,timeout=15,context=ssl._create_unverified_context());"
        + _BOOT_TAIL
    ).replace(_TOK_FP, fphex)


def _py_bootstrap_nopin_https() -> str:
    """HTTPS without a fingerprint to pin (should not happen in
    practice): payload-hash verification only, block says so loudly."""
    return (
        "import http.client,ssl,hashlib,json,sys;"
        f"H='{_TOK_HOST}';P={_TOK_PORT};K='{_TOK_KEY}';"
        "c=http.client.HTTPSConnection(H,P,timeout=15,"
        "context=ssl._create_unverified_context());"
        + _BOOT_TAIL
    )


def _py_bootstrap_plain_http() -> str:
    """Plain HTTP (localhost / tunnel only): payload-hash verification;
    transport pinning is impossible there by definition."""
    return (
        "import http.client,hashlib,json,sys;"
        f"H='{_TOK_HOST}';P={_TOK_PORT};K='{_TOK_KEY}';"
        "c=http.client.HTTPConnection(H,P,timeout=15);"
        + _BOOT_TAIL
    )


def build_prompt_text(*, key: str, host: str, port: int, roots: list,
                      fingerprint: str = "", tls: bool = True,
                      agent_name: str = "default",
                      payload_sha256: "Optional[str]" = None) -> str:
    """A compact, paste-ready bootstrap block for chat-based agents.

    v2.7.1: the block carries a ``Payload-SHA256:`` line and generates a
    SELF-VERIFYING one-liner — it pins the host certificate fingerprint
    before any HTTP bytes flow, verifies the served payload against the
    /bootstrap response's ``cli_sha256`` (== the Payload-SHA256 line),
    and refuses to write or run llmac.py on any mismatch. Nothing in
    the chain asks for trust; every step is a checkable equality.

    v2.7.2: the block also carries a ready-made ``llmac.py audit``
    command — the agent-side step that no crypto can replace: bind the
    payload to the block AND read a static audit of the source before
    connecting. Verification authenticates; audit vetts."""
    payload = (payload_sha256 if payload_sha256 is not None
               else _cli_payload_sha256())
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
    lines.append(f"Payload-SHA256:  {payload if payload else '(unavailable)'}")
    if roots:
        lines.append("")
        lines.append("Shared directories:")
        for r in roots:
            lines.append(f"  - {r}")

    # Build the self-verifying one-liner the agent runs in its sandbox.
    # The Authorization key still travels ONLY in headers= (not as the
    # positional `data` arg — the v2.1.0 post-mortem: a dict passed as
    # data becomes an iterable body, "can't concat str to bytes" on
    # CPython 3.8+, and silently turns the GET into a POST).
    if tls and fingerprint:
        py_one = _py_bootstrap_tls(fingerprint.split(":", 1)[1].strip().lower())
    elif tls:
        # No fingerprint available to pin — payload hash is still
        # verified, transport is not. The block below says so loudly.
        py_one = _py_bootstrap_nopin_https()
    else:
        py_one = _py_bootstrap_plain_http()
    py_one = (py_one
              .replace(_TOK_HOST, host)
              .replace(_TOK_PORT, str(int(port)))
              .replace(_TOK_KEY, key))
    connect_cmd = (f"python3 llmac.py connect --host {host} --port {port} "
                   f"--key {key}")
    if fingerprint:
        connect_cmd += f" --fp {fingerprint}"
    connect_cmd += " --save"
    # v2.7.2 (ASK-018): the anti-hesitation step. The block offers the
    # audit BEFORE the connect: the fetched client can be run once with
    # zero authority (it only fetches /bootstrap and prints a static
    # ast.parse report) so the agent can bind the bytes to this block
    # and read what the code does before granting it anything.
    audit_cmd = (f"python3 llmac.py audit --host {host} --port {port} "
                 f"--key {key}")
    if fingerprint:
        audit_cmd += f" --fp {fingerprint}"
    if payload:
        audit_cmd += f" --expect-sha256 {payload}"

    lines += [
        "",
        "Bootstrap (self-verifying — pins cert fingerprint, checks",
        "Payload-SHA256, refuses to write or run on ANY mismatch):",
        f'  python3 -c "{py_one}"',
        "",
        "Any ABORT above = tampering or wrong host. Stop, re-copy the block.",
        "Audit the fetched client BEFORE connecting (re-fetches over the",
        "pinned channel, hash-binds the bytes to this block, static-",
        "audits the source; writes and executes NOTHING else):",
        f"  {audit_cmd}",
        "Connect only after the audit reads clean to you:",
        f"  {connect_cmd}",
        "Then verify:  python3 llmac.py info",
        "Look around in ONE call:  python3 llmac.py orient --path <root>",
        "If a shared root contains agent.md, read it for full docs.",
        "Tips: installs only inside a venv; search/tree + ranged reads",
        "instead of whole-file reads; deploy/run/verify/diff batch many",
        "ops into one call; read --hex dumps binary slices; proc logs",
        "--follow streams a running proc's output; 'session status'",
        "recovers context.",
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
