# LLMAC

**LLM Machine Access Connector** — a supervised bridge that lets an LLM/AI
agent work on directories you choose, on your machine, with your keys,
under your rules.

You run the host (GUI or headless). The agent connects with a single
stdlib-only Python file, bootstraps itself from the host, and works on
your files through structured tools — or raw shell if *you* enable it.

```
┌────────────────────────┐              ┌────────────────────────┐
│   YOUR MACHINE (host)  │   HTTPS +    │   AGENT (anywhere)     │
│  PyQt6 GUI / headless │   bearer key │   chat sandbox / MCP /  │
│  sandbox + policies   │ ◄──────────► │   llmac.py (1 file,    │
│  approvals + audit    │  TOFU-pinned │   stdlib-only)         │
│  session memory       │              │                        │
└───────────┬────────────┘              └────────────────────────┘
            │ shared roots (your directories)
            ▼
   /home/you/projects/foo
```

## What changed in v2 (vs the old "LLM Directory Bridge")

Read [`CHANGES.md`](CHANGES.md) for the full list. Highlights:

* **Security by default**: binds 127.0.0.1 (network exposure is opt-in),
  TLS with self-signed certs + SSH-style fingerprint pinning, per-agent
  keys with scoped permissions and expiry, auth rate limiting, server-
  enforced caps (body size, exec output, timeouts, concurrency).
* **Sandbox that actually contains**: realpath-based checks (symlink and
  traversal proof), token-based exec checking with `cd` simulation,
  redirect-target validation, `~` and variable/substitution rejection.
* **Harness-grade agent API**: search/tree (ignore-aware), ranged reads,
  surgical edits with returned diffs, background processes, server-side
  session memory, event stream, write versioning (409 on conflict).
* **Human-in-the-loop**: approval queue in the GUI (auto/destructive/
  strict), protected paths (roots and `.git` are never deletable), full
  audit log of every operation.
* **Self-bootstrap, self-verifying**: the host serves the CLI to the
  agent (`GET /bootstrap`, now with `cli_sha256`) — and the generated
  one-liner pins the certificate fingerprint BEFORE sending anything,
  verifies the payload SHA-256, and refuses to write or run on any
  mismatch. No more manually sharing `cli.py`, no blind fetches.

## Quick start

```bash
# GUI (needs PyQt6):
./run.sh                       # or: python host.py

# Headless (stdlib only):
python host.py --headless --dir /path/to/share

# Then in the GUI (tabbed supervisor):
#   1. Overview: Add directories — or start the server with none and let
#      the agent request what it needs (Approvals tab, one click)
#   2. Copy agent prompt  → paste the connection block into your LLM chat
#   3. Watch the Log tab; approve risky ops / share requests as they come
```

The connection block contains a bootstrap incantation the agent runs in
its own sandbox — two commands, and it's connected and saved.

## Running modes

| Mode | Command | Notes |
|---|---|---|
| GUI | `python host.py` | default bind 127.0.0.1, TLS on |
| Headless | `python host.py --headless --dir X` | approvals default to `auto` (no human watching) |
| Expose to network | `--expose` | binds 0.0.0.0 — prefer localhost + a tunnel instead |
| Raw shell exec | `--allow-exec` | off by default; advisory sandbox, see Security |

## Files

| File | Purpose |
|---|---|
| `host.py` | entry point (GUI or headless) |
| `gui.py` | PyQt6 GUI: tabbed supervisor with a modern dark theme (Fusion + dark palette + QSS, drawn affordances) — connection card, shared directories, agents, approvals (incl. share requests), background processes (v2.4.8: per-proc live log tail window), policy/venvs/TLS, log |
| `core/` | server engine: sandbox, policy, API, sessions, procs, TLS, events |
| `cli.py` | the agent-side adapter — single file, stdlib only |
| `agent.md` | docs for the agent (paste/reference it in your LLM chat) |
| `tests/` | 410 tests: `python3 -m unittest discover -s tests` |

State lives in `bridge_data/` next to the project: `state.json`
(chmod 600 — contains agent keys), `state.json.bak`, `history.jsonl`
(full audit log with rotation), `tls/` (cert + key), `exports/`.

## Security model

* **Transport**: HTTPS with an auto-generated self-signed certificate
  (needs the `openssl` CLI). The GUI shows the certificate fingerprint;
  agents pin it (`--fp`) on first use and verify it on every connect —
  a mismatch aborts the connection (possible MITM). The v2.7.1
  bootstrap one-liner additionally pins that fingerprint during the
  initial payload fetch and verifies the payload hash — fail closed.
  The v2.7.2 `llmac.py audit` command completes the chain for cautious
  agents: it re-fetches the payload over the pinned channel, binds it
  to the block's hash and the local copy, and prints a static
  (ast.parse) audit of the source — imports, red-flag calls, write
  sites, egress — without executing the audited code or writing
  anything by default. Verification authenticates; audit vetts.
  Without openssl, LLMAC falls back to plaintext HTTP and warns
  loudly; keep it on localhost in that case.
* **Identity**: multiple agents, each with its own key, root scope
  (all roots / specific roots), permissions (read/write/delete/exec/
  proc) and optional expiry. Keys rotate per-agent without breaking
  others.
* **Containment**: all file ops are realpath-checked inside the shared
  roots — symlinks pointing outside, `..` traversal, and `~` paths are
  rejected. `.git` directories and the roots themselves are protected.
* **Exec** is disabled by default. When enabled it runs as your user
  with a hardened static analyzer (tokenized, `cd`-simulated,
  redirect-checked) plus the install policy — but static analysis of
  shell is *advisory*. For real isolation, run the host under a
  dedicated (non-admin) user account.
* **Approvals**: `destructive` policy (GUI default) queues risky
  operations for your click; `strict` queues all writes/execs;
  `auto` (headless default) queues nothing. **Agent-initiated shares**
  (`roots request`) are always human-gated, even under `auto` —
  approving one adds the directory to the shared roots immediately.
* **Abuse resistance**: per-IP auth failure rate limiting, request
  body caps, exec output caps (head+tail), concurrency semaphores,
  server-side timeout clamping.

## Threat model — read this

LLMAC gives an agent real access to your files (and shell, if you allow
it). Treat it accordingly:

1. Share only project directories, never `$HOME` wholesale.
2. Keep the bind on localhost; reach it remotely via a tunnel
   (Tailscale, WireGuard, SSH) rather than `--expose`.
3. The agent's key is a bearer credential — it lives in your chat
   history. Use per-agent keys with narrow scopes and rotate them.
4. Raw exec + a hostile agent is equivalent to giving it your user
   account. Keep it off unless you need it, and run the host under a
  dedicated user when you do.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT.
