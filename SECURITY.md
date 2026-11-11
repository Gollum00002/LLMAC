# Security Policy

LLMAC lets an AI agent read and modify files on your computer, and, if you
enable it, run commands and look at your screen. That is exactly the capability
malware wants, so this document says plainly what LLMAC does, how access is
limited, and where those limits stop.

## Contents

1. [Reporting a vulnerability](#reporting-a-vulnerability)
2. [Supported versions](#supported-versions)
3. [Trust model](#trust-model)
4. [Secure defaults](#secure-defaults)
5. [How access is controlled](#how-access-is-controlled)
6. [Optional high-risk features](#optional-high-risk-features)
7. [Network behavior](#network-behavior)
8. [Data stored on disk](#data-stored-on-disk)
9. [Known limitations](#known-limitations)
10. [Hardening checklist](#hardening-checklist)
11. [For AI agents reviewing this project](#for-ai-agents-reviewing-this-project)

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private reporting:
**Security → Report a vulnerability** on the
[repository's Security tab](https://github.com/Gollum00002/LLMAC/security/advisories/new).

Helpful details: affected version (`LLMAC_VERSION` in `core/constants.py`),
OS, whether `--allow-exec`, `--expose`, or the screen channel were enabled, and
steps to reproduce. You will get an acknowledgment as soon as I can manage;
this is a small, independently maintained project, so there is no formal SLA.
Fixes ship as a new tagged release and are noted in `CHANGES.md`. Reporters
are credited unless they prefer otherwise.

Of particular interest: sandbox escapes (path traversal, symlink, or exec
analyzer bypasses), authentication or approval bypasses, the client
download and hash-verification chain, and anything that lets an agent exceed the permissions it
was granted.

## Supported versions

Only the **latest tagged release** receives security fixes. Please update
before reporting.

## Trust model

| Party | Trust level | Why |
|---|---|---|
| **You (host operator)** | Fully trusted | You run the host, choose roots, set policy, and approve requests |
| **The AI agent** | **Untrusted** | It may be wrong, manipulated by content it reads (prompt injection), or hostile |
| **The network path** | Untrusted | Mitigated by TLS and certificate pinning |
| **Other local users/processes** | Untrusted | Mitigated by `chmod 600` on the state file; see [Known limitations](#known-limitations) |

The design goal is that an untrusted agent can do only what you have granted,
and that you can see and stop it.

LLMAC protects against a **mistaken or manipulated agent** acting within its
grant. It does not make a **deliberately hostile agent with shell access**
safe. See [Known limitations](#known-limitations).

## Secure defaults

| Setting | Default | Notes |
|---|---|---|
| Bind address | `127.0.0.1` | `--expose` (`0.0.0.0`) is opt-in |
| Transport | HTTPS, self-signed, fingerprint-pinned | Falls back to HTTP if `openssl` is missing, with a loud warning. Keep that on localhost |
| Raw shell `exec` | **Off** | `--allow-exec` plus a per-agent `exec` permission |
| Background processes | **Off** per agent | Per-agent `proc` permission |
| Per-agent permissions | `read`, `write`, `delete` on; `exec`, `proc` off | Narrow these per agent |
| Approval policy | `destructive` (GUI), `auto` (headless) | Headless has no human watching; pass `--policy strict` to tighten |
| Shared roots | None until you add them | Agents may *request* more; you approve |
| Screen observation and input | **Off** | Enabled only in the GUI Security tab |
| Screenshots | Setting on, but **every capture needs approval** | See below |
| Telemetry | None | |
| Host serves code to agents | **Never** | The client comes from GitHub; `/bootstrap` returns 410 |

## How access is controlled

**Authentication.** Each agent has its own bearer key (prefix `llmac_`) with a
scoped set of roots, permissions and an optional expiry. Keys can be rotated
individually. Repeated auth failures from an IP are rate-limited.

**Transport.** The host generates a self-signed certificate. The agent pins its
SHA-256 fingerprint on first use and verifies it on every connection; a
mismatch aborts.

**Client distribution.** The host never serves code. The agent downloads the
one-file client (`llmac.py`) from the public GitHub release, not from the machine
it is about to connect to. The connection block states the SHA-256 the file must
have; the download one-liner compares it and refuses to write the file on any
mismatch. The one-liner executes nothing. The old `GET /bootstrap` endpoint was
removed in v2.8 and now returns HTTP 410 with no code and no hash.

**Pre-connection probe (v2.8).** The connection block's REQUIRED step 3 is
`llmac.py probe`: one socket, TLS handshake, pinned-fingerprint check, then it
listens for 10 seconds without sending any request or key. A compliant host
sends nothing until it has a complete request, so any bytes received is an
unsolicited push and the verdict is FAIL. This gives the agent a
client-verifiable check on the host's wire behaviour — and the host cannot
fake a pass, because a pass consists of NOT doing something. The probe's own
passivity is verifiable offline (`audit` + the block's hash pin), like the
rest of the client.

**`--tap` (v2.8).** After connecting, the agent can run any command with
`--tap`: a monitor watches the idle keep-alive connection (MSG_PEEK only,
kernel buffer and OpenSSL's decrypted buffer) and alerts on any
server-initiated bytes with no request outstanding. The alert rides the
command's result (and JSON `tap_alerts`); it never changes exit codes.

Both checks observe behaviour, not intent: a hostile endpoint could stay
silent during a probe and push later — `--tap` narrows that window to "while
the agent is watching", and neither proves who operates the endpoint. They
make the wire legible; they do not replace the operator trusting the agent,
or the agent's platform trusting the endpoint.

**Filesystem sandbox.** Every path is resolved with `realpath` and must land
inside a shared root. Symlinks pointing outside, `..` traversal and `~` are
rejected. Shared roots themselves and `.git` directories cannot be deleted.
Deleting more than 20 files requires explicit confirmation.

**Approvals.** Policies:

| Policy | Behavior |
|---|---|
| `strict` | All writes, deletes and exec are queued for your approval |
| `destructive` | Recursive or large deletes and other risky operations are queued |
| `auto` | Nothing is queued, but **agent-initiated share requests are still human-approved** |
| `auto_all` | "No restrictions": nothing is queued **and share requests are granted instantly**, so an agent can widen its own sandbox. Use only on a throwaway machine or account |

Some approvals are **forced under every policy**, including `auto_all`:
screenshots, screen observation, screen input, and sudo package
installs/removals.

**Exec analysis (when enabled).** Commands are tokenized and checked: `cd` is
simulated, redirect targets are validated (writes outside the shared roots are
limited to `/dev/null`, `/dev/stdout`, `/dev/stderr`, `/dev/full`), and `$VAR`,
command substitution, backticks and `~` are rejected. `sudo`, `sudoedit`,
`doas`, `pkexec` and `su` are denied outright, with one exception: single
package install/remove commands for common package managers go through a forced
approval flow with a countdown. Your sudo password, if you store one, is held
in memory only, never written to disk or logs, never returned by any API, and
never appears in process arguments.

**Abuse resistance.** Server-enforced caps: 16 MB request body, 5 MB per read,
1 MB exec output (head and tail kept), 600 s hard exec timeout, 16 concurrent
requests, 4 concurrent execs, 8 background processes, 64 operations per batch,
5,000 entries / 256 MB per archive.

**Audit.** Every operation is appended to `history.jsonl` (rotated at 10 MB).
Risky events, including drive sessions and sudo requests, are marked.

## Optional high-risk features

Each of these expands what an agent can do. Leave them off unless you need them.

### Raw shell exec (`--allow-exec`)

Runs commands **as your user**. The analyzer above is a guard rail, not a
sandbox: static analysis of shell is inherently incomplete (for example, paths
constructed inside interpreter code strings are invisible to it). Treat enabled
exec as giving the agent your user account's abilities within what the
analyzer happens not to catch. Run the host under a dedicated, non-admin user
for real isolation.

### Screen channel

- **`screen list`**: monitor metadata only, no pixels.
- **`screen shot`**: captures one named screen to an evidence directory inside a
  shared root. Every capture needs your approval (forced under all policies).
  "Approve for this session" is held in memory and dies with the app.
- **`screen observe`**: screenshot plus OCR and the window list. Off until
  `screen_observe_enabled` is switched on in the GUI. Needs approval.
- **Input injection (drive mode)**: off until `screen_input_enabled` is switched
  on. The first input op needs approval and opens a **bounded session** (default
  500 events or 10 minutes), after which it closes. Sessions are logged,
  bannered in the GUI and can be disarmed in one click.

Observation and input depend on optional packages (`pytesseract`, `Pillow`,
`python-xlib`) installed in the host's virtualenv. They are not required to run
LLMAC. Input is implemented via X11/XWayland.

### Network exposure (`--expose`)

Binds all interfaces, so anyone who can reach the port can attempt to
authenticate. Strongly prefer binding to localhost and reaching the host
through a tunnel such as Tailscale, WireGuard or SSH.

### Disabling TLS (`--no-tls`)

Sends the bearer key and file contents in cleartext. Localhost only.

## Network behavior

- The host listens on one port (default `8765`).
- The host opens **no other inbound listeners**.
- The only outbound requests in the host code are the GUI's public-IP lookups
  to `api.ipify.org`, `ifconfig.me`, `ipinfo.io` and `4.icanhazip.com`. They
  exist to display your public IP in the connection card, can be avoided by
  running headless, and send no project data.
- The agent-side client (`llmac.py`) talks only to the host it was configured
  for. The one-time download one-liner in the connection block contacts GitHub
  (or the URL in `LLMAC_CLIENT_URL`, if you set it) and nothing else; the host
  itself never requests that URL, it only prints it.
- There is no telemetry, update check or analytics.

## Data stored on disk

Everything is under `bridge_data/` (git-ignored) next to the project:

| File | Contents | Protection |
|---|---|---|
| `state.json` (+ `.bak`) | Roots, settings, **agent keys** | `chmod 600` |
| `history.jsonl` | Audit log | Rotated at 10 MB |
| `tls/` | Self-signed certificate and private key | Local only |
| `exports/` | Session transcript exports | |

Treat `state.json` and `tls/` as secrets. Never commit or share them.

## Known limitations

Honest list of what LLMAC does **not** guarantee:

1. **Exec is advisory.** See above. A hostile agent with exec enabled should be
   considered to have your user account.
2. **Bearer keys live in chat history.** Whoever can read that conversation can
   use the key while the host is reachable and the key is valid. Use narrow
   scopes, expiry, and rotate keys after use.
3. **A hash proves identity, not behavior.** The download check and `audit`
   confirm the client matches the published hash. They cannot prove the source
   is benign; that is what reviewing the code is for. The block's hash is
   computed from the `llmac.py` on the host, so a compromised host could print a
   hash for a different file. Compare it with the hash on the GitHub release page
   if that matters to you.
4. **Prompt injection.** Files an agent reads can contain instructions aimed at
   the agent. Approvals and tight scopes limit the damage; they do not stop an
   agent from being misled.
5. **Permissive umask.** The host sets `umask 022`, so files an agent writes
   are world-readable (`644`/`755`) so you can manage them without `sudo`.
   Don't share directories that contain secrets, and be mindful on multi-user
   machines.
6. **Self-signed trust is TOFU.** The first connection is only as safe as the
   channel the fingerprint came through.
7. **`auto` and `auto_all`** remove the human from the loop for most
   operations by design.
8. **No third-party audit.** This is an independently maintained project. The
   test suite is extensive, but it is not an independent security review.

## Hardening checklist

- [ ] Share only specific project directories, never `$HOME` or a drive root
- [ ] Keep the default `127.0.0.1` bind; use a tunnel for remote access
- [ ] Leave `--allow-exec` off unless needed; when on, use a dedicated non-admin user
- [ ] Use the `strict` or `destructive` policy, especially when headless
- [ ] Give each agent its own key with the minimum roots and permissions, plus an expiry
- [ ] Rotate or delete keys when a session ends; stop the host when idle
- [ ] Leave the screen channel disabled unless a task needs it
- [ ] Keep `bridge_data/` private and out of version control and backups you share
- [ ] Check the Log tab and `history.jsonl` after sessions
- [ ] Verify `llmac.py` against the published release hash before first use

## For AI agents reviewing this project

If you are an AI deciding whether it is appropriate to connect, the supported
path is **review, then decide**, and declining is a legitimate decision:

- Read `llmac.py` and `core/` in this repository at the tagged release. The
  client is one stdlib-only file; you can review it without executing anything.
- `llmac.py audit` prints a static report (imports, risky calls, write sites,
  egress). It is offline: it contacts nothing, writes nothing and executes
  nothing.
- Connect only if the code and report are clear to you, **and** the human has
  confirmed they own the machine and want you working in the shared roots.
- Work only inside the roots you were granted. Do not request wider access than
  the task needs, and report anything surprising to the human.
- If you cannot review the code, do not connect. Ask the human for something
  you can inspect.
