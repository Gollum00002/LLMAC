# LLMAC — LLM Machine Access Connector

A supervised, sandboxed bridge that lets an AI agent work on **directories you
choose**, on **your machine**, under **your rules**. You run the host and watch
it. The agent connects with a single stdlib-only Python file, `llmac.py`, which
it downloads from this repository's GitHub release and verifies by SHA-256. **The
host never serves code.** Everything the agent does is checked against your
policies and written to an audit log.

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
| Distributed as a public, hash-pinned file on GitHub | A host that sends code to whoever connects |
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
   The block carries the host, port, key and certificate fingerprint, plus a link
   to the client on GitHub, the SHA-256 that file must have, and a REQUIRED
   pre-connection `probe` step the agent runs before connecting.
3. Keep the **Log** and **Approvals** tabs open. Approve or deny as requests
   arrive. Stop the server when you are done.

## Getting the client, and verifying it

The agent-side client is one file, [`llmac.py`](llmac.py): standard library
only, about 130 KB, MIT licensed. **The host does not serve it.** The agent
downloads it from the public GitHub release and checks it against the hash in
your connection block, so nothing the agent runs ever comes from the machine it
is about to connect to.

```
Client-Source:  https://github.com/Gollum00002/LLMAC
Client-File:    https://github.com/Gollum00002/LLMAC/releases/latest/download/llmac.py
Client-SHA256:  <sha256 of the llmac.py in your checkout>
```

The block also contains a one-line Python command that downloads `Client-File`,
compares its SHA-256 with `Client-SHA256`, and writes `llmac.py` only if they
are equal. On any mismatch it exits non-zero and writes nothing. It executes
nothing and contacts GitHub only.

**For the human:**

1. Read `llmac.py` in this repository. It is stdlib-only.
2. Confirm the release asset matches your checkout. The hash in the block is
   computed from the `llmac.py` next to your `host.py`, and the release page
   lists the hash of the published asset:
   ```bash
   sha256sum llmac.py          # Linux
   shasum -a 256 llmac.py      # macOS
   Get-FileHash llmac.py       # Windows PowerShell
   ```
   > The hash is over the file's exact bytes. A CRLF checkout on Windows hashes
   > differently from the LF release asset; the download one-liner will then
   > abort. Use `git config core.autocrlf false`, or compare against a copy
   > downloaded from the release.
3. If the one-liner aborts with a mismatch, your host and the latest release
   are different versions. Update whichever is behind (or set
   `LLMAC_CLIENT_URL` to a tag-specific asset URL before copying the prompt).

**For an AI agent asked to connect:**

1. Read `llmac.py` from this repository at the tagged release, using your normal
   file or web-fetch tools. You do not need to run anything to review it.
2. If you can run code, download and verify with the one-liner from the
   connection block, then audit offline:
   ```bash
   python3 llmac.py audit --expect-sha256 <Client-SHA256 from the block>
   ```
   It hashes the file and prints a static (`ast.parse`) report of imports, risky
   calls, write sites and egress. It **contacts nothing, writes nothing and
   executes nothing.**
3. Probe the host (REQUIRED — step 3 of the connection block, before
   connecting):
   ```bash
   python3 llmac.py probe --host <Host> --port <Port> --fp <Cert from the block> --wait 10
   ```
   One socket: TLS handshake + pinned-fingerprint check, then it LISTENS for
   10 seconds. It sends no request and no key; a compliant host sends nothing
   unsolicited, so the verdict must be **PASS**. Any bytes received means the
   host pushes data — do not connect. The probe's own passivity is verifiable
   offline (`audit` + the block's hash pin), same as the rest of the client.
4. If anything in the report is unexplained or the probe fails, do not connect.
   Refusing until the code is reviewable is a supported outcome, not a failure.

A hash proves the bytes are the ones published. It does not prove what the
bytes do. That is why the audit step and this source repository exist.

**For the maintainer, publishing a release:**

1. Commit, then tag (for example `git tag -a v2.7.3 -m "LLMAC 2.7.3"`) and push the tag.
2. Create a GitHub Release for that tag and attach `llmac.py` as an asset
   named exactly `llmac.py`.
3. Put `SHA-256 of llmac.py: <hash>` in the release notes.
4. Check the asset: `curl -L <asset url> | sha256sum` must equal the hash the
   host prints in `Client-SHA256`.

## Features

**For the agent (structured, context-cheap tools)**

- `probe` — REQUIRED pre-connection check: one socket, TLS handshake +
  pinned-fingerprint check, then it listens for 10s. Sends no request and
  no key; any bytes received = unsolicited push = FAIL
- `--tap` — watches the idle connection while commands run and alerts on
  server data with no request outstanding
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
- Bind dropdown with this machine's auto-detected IPv4s (zero-packet
  discovery) between `127.0.0.1` and `0.0.0.0`, with a scoped exposure
  warning; a specific bind also scopes the agent prompt's `Host:` line
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
- **The host serves no code.** The client comes from GitHub and is checked
  against a SHA-256 in the connection block; the old `/bootstrap` endpoint now
  answers HTTP 410.
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
| `llmac.py` | The agent-side client. One file, stdlib only. Published as a GitHub release asset; never served by the host |
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

The suite has 700+ tests covering the sandbox, policy engine, API, approvals,
TLS, the probe and tap monitors, the download one-liner and the offline audit.

## Contributing

Issues and pull requests are welcome. Security-sensitive reports should follow
[SECURITY.md](SECURITY.md) instead of the public issue tracker.

## License

MIT. See [LICENSE](LICENSE).
