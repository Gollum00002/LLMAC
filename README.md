# LLMAC — LLM Machine Access Connector

A supervised, sandboxed bridge that lets an AI agent work on **directories you
choose**, on **your machine**, under **your rules**. You run the host and watch
it. The agent connects with a single stdlib-only Python file. Everything it does
is checked against your policies and written to an audit log.

> **Read this first:** LLMAC gives an AI real access to your files, and to your
> shell if you turn that on. It is built to make that access *narrow,
> visible and revocable*, not to make it risk-free. Read
> [SECURITY.md](SECURITY.md) before you connect anything.

```
┌─────────────────────────┐               ┌─────────────────────────┐
│  YOUR MACHINE (host)    │  HTTPS +      │  AGENT (anywhere)       │
│  GUI or headless        │  bearer key + │  chat sandbox / script  │
│  sandbox + policies     │  pinned cert  │  llmac.py (one file,    │
│  approvals + audit log  │ ◄───────────► │  Python stdlib only)    │
└────────────┬────────────┘               └─────────────────────────┘
             │ only the shared roots you pick
             ▼
     /home/you/projects/foo
```

## What it is, and what it is not

| LLMAC is | LLMAC is not |
|---|---|
| A tool you run, supervise and can stop at any time | A background service, daemon or auto-starting agent |
| Open source, readable end to end | A closed binary or an obfuscated payload |
| Localhost-only by default | Something that listens on your network unless you opt in |
| Limited to directories you share | Access to your whole disk |
| Logged: every operation lands in `history.jsonl` | Silent |

It does not phone home, collect telemetry, or install itself anywhere. The only
external URLs in the host code are four public-IP echo services
(`core/server.py`), which the GUI queries to display your public IP in the
connection card. Each is a plain request that sends no project data. If you
would rather not make those requests, run headless.

## Quick start

Requires Python 3.9+. Linux is the primary development platform; launchers for
Windows (`run.ps1`) and macOS/Linux (`run.sh`) are included.

```bash
git clone https://github.com/Gollum00002/LLMAC.git
cd LLMAC

# GUI (PyQt6; run.sh creates a virtualenv and installs it for you)
./run.sh                       # or:  python host.py

# Headless (standard library only, no GUI)
python host.py --headless --dir /path/to/share
```

Then, in the GUI:

1. **Overview**: add the directories you want to share. You can also start with
   none and approve the agent's share requests one click at a time.
2. Click **Copy agent prompt** and paste the connection block into your AI chat.
3. Keep the **Log** and **Approvals** tabs open. Approve or deny as requests
   arrive. Stop the server when you are done.

## Verify before you connect

Do not trust this README, a hash, or the connection block on their own.
Review the code. Everything the agent runs is one file, `cli.py` (the
bootstrap saves it as `llmac.py` on the agent side).

**For the human:**

1. Read `cli.py` in this repository. It is stdlib-only and about 130 KB.
2. Compare its SHA-256 with the `Payload-SHA256:` line in your connection block,
   and with the hash published in the matching
   [GitHub Release](https://github.com/Gollum00002/LLMAC/releases):
   ```bash
   sha256sum cli.py          # Linux
   shasum -a 256 cli.py      # macOS
   ```
   > Line endings matter: a CRLF checkout on Windows produces a different hash.
   > Compare against an LF copy, or download the release asset directly.

**For an AI agent asked to connect:**

1. Read `cli.py` from this repository at the tagged release, using your normal
   file or web-fetch tools. You do not need to run anything to review it.
2. If you can run code, use the audit command from the connection block:
   ```bash
   python3 llmac.py audit --host HOST --port PORT --key KEY \
       --fp SHA256:... --expect-sha256 <Payload-SHA256 from the block>
   ```
   It fetches the payload over the pinned channel, checks it against the
   block's hash, and prints a static (`ast.parse`) report of imports, risky
   calls, write sites and egress. It **executes nothing** and **writes nothing**
   unless you pass `--save-to`.
3. If anything in the report is unexplained, do not connect. Refusing until the
   code is reviewable is a supported outcome, not a failure.

A hash proves the bytes are the ones published. It does not prove what the
bytes do. That is why the audit step and this source repository exist.

## Features

**For the agent (structured, context-cheap tools)**

- `orient`, `tree`, `search` (grep and glob with caps), ranged `read`, hex
  `read` for binaries
- Surgical `edit` with returned diffs, whole-file `write`, write versioning
  (HTTP 409 on conflict), `diff`, `stat --hash`, `verify`, `deploy`
- `batch` (up to 64 ops in one round trip), `run`, `archive` get/put
- Server-side session memory and an event stream
- A human-to-agent **inbox**: messages you send ride along on every result
- Optional raw shell `exec` and background processes, **off by default**
- Optional **screen channel** (screenshots, OCR, input), see
  [SECURITY.md](SECURITY.md#optional-high-risk-features)

**For you (supervision)**

- Tabbed GUI: connection card, shared directories, agents, approvals, processes
  (with live log tails), policy/TLS settings, log
- Per-agent keys with scoped roots, permissions (`read`, `write`, `delete`,
  `exec`, `proc`) and optional expiry; rotate any key without breaking others
- Approval policies: `destructive` (GUI default), `strict`, `auto` (headless
  default), `auto_all`
- Agent-initiated share requests are always human-approved (except under
  `auto_all`, which is documented as "no restrictions")
- Protected paths: shared roots and `.git` can never be deleted

## Running modes

| Mode | Command | Notes |
|---|---|---|
| GUI | `python host.py` | Binds `127.0.0.1`, TLS on |
| Headless | `python host.py --headless --dir X` | Approvals default to `auto`; use `--policy` to tighten |
| Raw shell | `--allow-exec` | Off by default. Advisory sandbox, see [SECURITY.md](SECURITY.md) |
| Network exposure | `--expose` | Binds `0.0.0.0`. Prefer localhost plus a tunnel (Tailscale, WireGuard, SSH) |
| No TLS | `--no-tls` | Plain HTTP. Localhost only |

Default port: `8765`.

## Security at a glance

- **Localhost by default.** Network exposure is an explicit opt-in.
- **TLS with certificate pinning.** A self-signed certificate is generated
  (needs the `openssl` CLI); agents pin its fingerprint. A mismatch aborts.
- **Per-agent bearer keys** with scoped roots, permissions and expiry; per-IP
  auth-failure rate limiting.
- **Realpath-based sandbox.** Symlink, `..` and `~` escapes are rejected.
- **Exec off by default**, with a token-level static analyzer when enabled.
  This is a guard rail, not isolation. For real isolation, run the host under a
  dedicated non-admin user account.
- **Human approvals** for risky operations; sudo package install/remove has its
  own forced-approval flow, and the sudo password never reaches the agent.
- **Server-enforced caps** on body size, output, timeouts and concurrency.
- **Full audit log** of every operation, with rotation.

The full model, defaults, known limitations and hardening checklist are in
[SECURITY.md](SECURITY.md).

## Repository layout

| Path | Purpose |
|---|---|
| `host.py` | Entry point (GUI or headless) |
| `server.py` | Compatibility shim: `python server.py` is `host.py --headless` |
| `gui.py` | PyQt6 supervisor GUI |
| `core/` | Server engine: sandbox, policy, API, sessions, processes, TLS, events, screen |
| `cli.py` | The agent-side client. One file, stdlib only |
| `agent.md` | Reference for the AI agent: commands, workflow tips, trust model |
| `tests/` | Test suite (`python3 -m unittest discover -s tests`) |
| `tools/`, `scripts/` | Benchmark and development tooling; not needed to run LLMAC |
| `CHANGES.md` | Full version history |
| `SECURITY.md` | Threat model, defaults and vulnerability reporting |

Runtime state lives in `bridge_data/` next to the project (git-ignored):
`state.json` (agent keys, `chmod 600`), `history.jsonl` (audit log),
`tls/` (certificate and key), and `exports/`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The suite has 680+ tests covering the sandbox, policy engine, API, approvals,
TLS and bootstrap verification.

## Contributing

Issues and pull requests are welcome. Security-sensitive reports should follow
[SECURITY.md](SECURITY.md) instead of the public issue tracker.

## License

MIT. See [LICENSE](LICENSE).
