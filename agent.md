# LLMAC v2 — Agent Reference

> **Read this first if you are an LLM/AI agent using this tool.**
> It tells you how to connect, what you can do, and how to work
> efficiently without burning your context window.

## What this is

LLMAC is a supervised bridge between a human's PC and you. The human runs
a host that shares selected directories; you connect with a single-file
CLI (`llmac.py`) and work on their files. The host enforces security
policies, records an audit log of everything you do, and may require the
human to approve dangerous operations.

## Quick start (download from GitHub, verify, connect)

The human gives you a connection block: host, port, key, certificate
fingerprint (`Cert: SHA256:...`), the client's public source
(`Client-Source:`), and the SHA-256 the client file must have
(`Client-SHA256: <hex>`).

**The host does not serve code.** The client is one stdlib-only Python file,
`llmac.py`, published in the public GitHub repository and attached to each
GitHub release. You fetch it from GitHub, not from the machine you are about
to connect to, and you check it against the hash in the block.

1. **Review (optional but supported).** Read `llmac.py` at
   `Client-Source` with your normal web or file tools. You do not need to
   run anything to review it.
2. **Download and verify.** The block carries a one-liner that downloads the
   file from `Client-File`, compares its SHA-256 with `Client-SHA256`, and
   writes `llmac.py` only if they are equal. On any mismatch it exits
   non-zero without writing anything. It executes nothing and talks to
   GitHub only, never to the host.
3. **Audit offline (optional).** `python3 llmac.py audit` hashes the file
   and prints a static (`ast.parse`) report. It contacts nothing, writes
   nothing and executes nothing.
4. **Connect** only after the audit reads clean to you.

```bash
# 1. Download + verify: copy the block's python3 -c one-liner EXACTLY
#    (it fails closed; never hand-write a fetcher to work around it)

# 2. AUDIT before you grant anything. Offline: hashes the file, binds it to
#    the block's Client-SHA256, prints imports, red-flag calls, write sites
#    and egress modules. EXECUTES NOTHING, including the audited source:
python3 llmac.py audit --expect-sha256 <Client-SHA256 from the block>

# 3. Connect and save ONLY after the audit reads clean to you
#    (fingerprint from the connection block if given):
python3 llmac.py connect --host HOST --port PORT --key KEY [--fp SHA256:...] --save
python3 llmac.py info          # verify
python3 llmac.py orient        # 1-call map: tree + doc heads + session
```

### Why the audit step exists (the honest trust model)

A hash proves you have the bytes the maintainer published. Nothing
cryptographic can tell you what those bytes DO. If you are an agent that
refuses to execute unreviewed code, that instinct is correct: close the gap
with review, not trust. Read the source on GitHub, run `audit` and read its
report (`red-flag calls: (none)`, `red-flag imports: (none)` and
`non-stdlib imports: core` are what this client's own report looks like;
`core` is a guarded, optional import of the host's constants file that falls
back to an embedded version string when absent), or diff the file against a
reference copy you already hold. If anything in the report is something you
cannot explain, do not connect; ask the human for a build you can inspect.
That posture is supported by design. `audit --file PATH` audits any other
file the same way.

If the block shows `Client-SHA256: (unavailable ...)`, the host could not
read its own copy of `llmac.py`: take the hash from the GitHub release page
instead. If the one-liner aborts with a mismatch, STOP: you may be reading a
stale or tampered download, or the host is running a different version than
the release. Ask the human for a fresh block.

An old block that fetches `GET /bootstrap` gets HTTP 410 from this host
(that endpoint was removed in v2.8). Ask the human for a fresh block.

`orient` (v2.4.1) replaces the old 5-call boot crawl — one call, a few
hundred tokens, byte-budget-trimmed server-side. Use it first, then go
deep with `read --lines` / `search`.

If the host runs plain HTTP (localhost only), pass `--plain` and skip the
fingerprint. After `connect --save`, every later command reads the saved
connection automatically — you never repeat the key.

**Context recovery**: after the conversation is pruned or you lose track,
run `python3 llmac.py session status` — the host remembers which files
you read/wrote, which commands failed, and your own notes. Even better:
keep your own worklog on both sides (tip 15 below) — recovery then never
depends on host-side state at all.

## Core commands

| Command | Purpose | Context-cheap alternative to |
|---|---|---|
| `info` | agent identity, roots, exec, policy | — |
| `tree [--depth N] [--path P]` | depth-capped tree (skips node_modules/.git/…) | `ls` crawling |
| `search --query Q [--glob '*.py'] [--regex] [--context 2]` | grep with caps | read-many-files |
| `search --name '*.md'` | find files by glob | `ls` crawling |
| `read --path P` | whole file (≤5MB; large text files are smart-truncated to head+tail unless `--raw`) | — |
| `read --path P --lines 10-50 [--numbered]` | line range | whole-file reads |
| `read --path P --offset N --limit M` | byte range (binary-safe) | whole-file reads |
| `read --path P --hex [--offset N] [--limit M]` | server-rendered xxd-style dump (offset/hex/ascii columns, absolute offsets; default 512 B, cap 4096 B per slice — the RE primitive for binary blobs, no exec needed; v2.4.7) | exec xxd/od |
| `read --path P --hex --find-hex 4d5a` / `--find-text "MZ"` `[--offset N] [--max-hits K]` | scan a binary for a byte pattern or literal text; every hit comes back with its ABSOLUTE offset + rendered hex context; `next_offset` pages the scan, then `read --hex --offset` GOTOs any byte; default 25 hits, server cap 100 (v2.4.8) | exec xxd + grep loops |
| `write --path P` (stdin / `--content`) | whole-file write | — |
| `edit --path P --replace OLD --with NEW [--occurrence all]` | surgical edit, returns diff | read-modify-write |
| `edit --path P --lines 5-8 --content '...'` | replace line range | — |
| `edit --path P --insert-after 12 --content '...'` | insert | — |
| `edit --path P --delete-lines 3-7` | delete lines | — |
| `exec --cwd P --command '...'` | raw shell — only if host enables it; plain mode always ends with a `[rc=N]` stderr footer; a pre-flight lint refuses `$(…)`, backticks and `$VAR` before sending (v2.4) | — |
| `exec --command '...' --json` | machine-readable exec result (F6) | parsing human text |
| `batch --ops '[{"op":"read","path":"/a"},…]'` | many ops in ONE round trip (read/stat/list/tree/search/mkdir/write/**edit**/**exec**; batched edits return their surgical diffs — v2.4.7; ≤64 ops, 8MB response; every exec is pre-flighted — one bad command refuses the WHOLE batch with zero side effects, v2.4.1) | serial read/write/edit/exec loops |
| `deploy --pairs L=R [--pairs …] [--manifest F]` | upload N local files + verify sha256 in ONE invocation — the hash now rides in the SAME batch as the writes (v2.4.1), no exec needed | per-file write/verify loops |
| `verify --local F --remote P` | local↔remote sha256 compare — works even when host exec is OFF (v2.4.1) | exec sha256sum |
| `orient [--path P] [--depth N] [--budget B]` | ONE call: info core + sized tree + README/agent.md heads + session pointer, byte-budget-trimmed server-side (replaces the 5-call / 6.6K-token boot; v2.4.1) | info+tree+read crawls |
| `diff --a P --b P2` / `diff --a P --inline-file F` | server-side unified diff of two host paths, or path vs proposed content (a write dry-run); ~1-2% of the bytes of re-reading both files (v2.4.1) | re-reading whole files |
| `stat --path P --hash` | metadata + sha256 (≤64MB files; oversize reports sha256_skipped) (v2.4.1) | exec sha256sum |
| `run --file cmds.json` | many CLI commands in ONE process / ONE TLS session (v2.4) | N one-shot invocations |
| `archive --get --path DIR --to out.tgz [--all]` | whole directory as tar.gz in one hop (never includes .git) | file-by-file downloads |
| `archive --put --path DIR --file in.tgz [--overwrite]` | extract an archive under a shared root (hardened: no `..`, links or devices) | many writes |
| `grants` | your live approval grants (F7) | — |
| `proc start/logs/stop/list` | background processes (dev servers) | — |
| `proc logs --id X --follow [--max-idle N]` | tail -f: streams new output as it lands (proc_log events), exits when the proc exits; `--max-idle N` bounds the wait (v2.4.7) | poll loops |
| `session status/note/reset` | server-side session memory | re-reading everything |
| `session inbox [--peek]` | read the user→agent inbox (default consumes; `--peek` keeps the unread banner) | — |
| `screen list` | monitors: index, name, global geometry, primary, scale (metadata only, NO approval) | — |
| `screen shot --target 2\|primary\|all [--format jpg] [--max-width 1600]` | per-screen capture into the evidence dir; returns path + bytes + sha256; approval class `screen_shot` (rc-2 guards: missing --target / bad format / bad max-width) | whole-wall grabs |
| `screen observe --target ...` | capture + OCR text with positions + window list (X tree); approval class `screen_observe`, OFF until the host enables it | re-reading pixels |
| `input mouse --action move\|click\|doubleclick\|drag\|scroll` / `input key --keysym Return [--modifiers ctrl]` / `input text --text "..."` | bounded drive-mode injection; OFF until enabled; own-window refusal + caps + disarm banner | — |
| `session log [--after N] [--limit M]` | YOUR OWN op log from the server's bounded ring — scoped to you by authentication, so there is no --agent flag and an `agent` key in the payload is rejected; `--after` pages with `next_after` (v2.5.2) | — |
| `approvals list/wait` | poll approval requests | — |
| `roots request --path P --reason R` | ask the human to share a directory | being blocked with no roots |
| `events [--follow]` | long-poll host events | — |

Also: `ls`, `stat`, `mkdir`, `rm` (needs `--confirm` for big trees),
`mv`, `cp`, `download` (now ranged: `--lines`/`--offset`/`--limit`),
`upload`, `conns`, `health`. Global flag `--retry N` keeps retrying
transport failures for N seconds — use it to wait out a host restart.

## No access to what you need? Ask.

If `info` shows empty `roots` — or a task needs a directory outside
them — don't give up and don't guess paths. Ask the human through the
host itself:

```bash
python3 llmac.py roots request --path /home/human/projects/api --reason "I need to read and fix the failing tests in the api project"
```

* The request appears in the host GUI's **Approvals** tab (with your
  reason) — the human clicks once and the directory is shared
  immediately; you don't need to reconnect.
* Under the `auto` / `destructive` / `strict` policies this is **always**
  gated by the human — expanding the sandbox is the host's decision
  alone (a policy that let you grant yourself shares would be no policy
  at all). If `info` shows `"roots_auto_approved": true` the host runs
  the `auto_all` ("Auto — no restrictions") policy and your request is
  granted instantly instead.
* Poll the outcome with `approvals wait --id <id>`; duplicates of a
  still-pending request collapse into one.
* If it's denied, don't re-request in a loop — ask why in chat.

## Versioning (don't clobber the human)

Every `read`/`stat`/`write`/`edit` returns a `version` token. If you plan
to modify a file you just read, pass it back:

```bash
python3 llmac.py edit --path P --replace old --with new --expected-version <token>
```

If the human (or another agent) changed the file meanwhile, you get
`409 version_conflict` with the current version — re-read and retry
instead of silently overwriting their work.

## Security rules the host enforces on you

1. **Path sandbox** — everything stays inside the shared roots. `~`,
   `..` escapes, symlink tricks and absolute outside paths are rejected.
2. **Install policy** — Python packages only inside a venv
   (`python3 -m venv .venv && .venv/bin/pip install X`). System package
   managers and global npm installs are rejected. `pipx`, `poetry add`,
   `uv add`, local `npm install` are fine.
3. **Raw exec is opt-in** — if disabled you get `exec_disabled`; use the
   structured tools instead. Exec also anchors its working directory in
   a shared root — with zero shares it returns `no_roots` even when
   enabled; request a share first.
4. **Protected paths** — you cannot delete a shared root itself, anything
   under `.git/`, or the server's own data directory (agent keys, TLS
   key, audit log live there; every operation on it returns
   `protected_path` regardless of policy).
5. **Exec static analysis is advisory** — it tokenizes your command and
   checks paths, but paths inside code strings (`python3 -c
   "open('/etc/passwd')"`, heredocs, base64 blobs) are invisible to it.
   The host must not rely on it against hostile agents; as a cooperative
   agent, don't hide paths in code strings — it erodes trust and gets
   audited anyway.
6. **Redirect writes stay inside the sandbox** — `>`, `>>`, `&>` targets
   must be inside a shared root (only `/dev/null`, `/dev/stdout`,
   `/dev/stderr` are exempt). Input redirects `<` may read whitelisted
   system paths. Privilege escalators (`sudo`, `su`, `doas`, `pkexec`,
   `sudoedit`) are rejected outright — ask the human instead.
7. **Approvals** — depending on policy (`auto` / `auto_all` /
   `destructive` / `strict`) risky operations (recursive deletes,
   sometimes all writes) pend until the human clicks Approve/Deny. Your
   call blocks up to 2 minutes; if it times out, poll with `approvals
   wait --id <id>`. The human may approve **with a time-boxed grant**
   ("same op under the same subtree for 30 min / 1 h / 4 h") — check
   `grants` to see what you already hold, and don't re-request covered
   ops.
8. **Caps** — 5MB reads (use offsets!), 1MB exec output (head+tail
   kept), 600s max exec, 16MB request bodies, 5000 entries / 256MB per
   archive (over-cap archives are REFUSED, not truncated).

## Working efficiently (the whole point)

These numbers are measured, not folklore (live-workload benchmark,
2026-10-25 — see `tools/baseline-2026-10-25-full.json`, the nine-
scenario unified-methodology baseline). Agents pay in TWO
currencies: **wall time** (each one-shot CLI invocation costs ~440 ms
fixed overhead vs ~166 ms for the request itself) and **context tokens**
(what the responses put in your reasoning). The list below is ranked
by measured impact.

1. **Search, don't read** — finding a symbol via `search --context 2`
   returned 2.2 KB where reading every candidate file would have cost
   433 KB: **200× context economy**. Search first, always.
2. **Range your reads** — `--lines 10-50` gave 520 tokens where a whole
   `gui.py` read cost 24,500: **47×**. `read` now smart-truncates big
   text files (head 200 + tail 50 + a `[smart-truncated]` stderr marker)
   so an unwitting big read can't blow your context; pass `--raw` for
   the full text or `--to` to save it.
3. **Batch your loops** — 21 stats took 3.8 s one-by-one vs 0.21 s in one
   `batch`: **18× wall**. `batch` accepts write ops too: 12 writes
   (368 KB) in ONE call — and since v2.4.7, `edit` ops as well: a
   10-file surgical change is ONE round trip, each result carrying
   its diff.
4. **Deploy with `deploy`** (v2.4) — the real 12-file release loop cost
   26 calls / ~15.7 s as one-shot invocations; `llmac deploy --pairs
   L1=R1 --pairs L2=R2 …` does upload + sha256 verification in ONE
   invocation (measured 0.9 s, 12/12 verified). `--dry-run` shows the
   plan; `--manifest F` for long lists; `--no-verify` to skip hashing.
5. **Sequence with `run`** (v2.4) — a JSON array of arg-vectors runs in
   ONE process over ONE TLS session: each extra command costs ~166 ms
   instead of ~604 ms (**3.6× per op**). Stops at the first failure
   unless `--keep-going`; `run`/`deploy` inside `run` are rejected.
6. **Modify surgically**: `edit --replace`. The diff comes back so you
   verify without re-reading. A stale-version 409 costs one re-read.
7. **Note your plan**: `session note --text "step 2 done, next: fix
   tests"` — after pruning, `session status` re-anchors you cheaply
   (`orient` re-maps the terrain in one ~350-token call; your own
   notes cost a fraction of that).
8. **Long tasks**: `proc start` a dev server or long scan, then
   `proc logs --id X --follow` — it streams new output as it lands
   (`proc_log` events wake it; exits on its own when the proc does;
   `--max-idle N` bounds the wait). For one-shot checks, plain
   `proc logs` still works, and `events --follow` still reports
   exits.
9. **Venv for installs**: create it once, the host remembers it (and any
   pre-existing venv works — it detects `pyvenv.cfg`). Both forms work:
   `.venv/bin/pip install X` and `source .venv/bin/activate &&
   pip install X` (v2.4.2 fixed the activation form).
10. **Bulk sync with `archive`**: `--get` pulls a project into one
    tar.gz; `--put` pushes your local tree back in one hop. Note the
    asymmetry: `--get` writes to `--to LOCAL.tgz`, `--put` reads
    `--file LOCAL.tgz`. Dotfiles are skipped unless `--all` (`.git`
    never).
11. **If a dev workspace exists** (look for `ROADMAP.md` / `STATE.md`
    next to the project): read `STATE.md` first — it is the durable
    handoff state the previous session left for you.
12. **Big tool output goes to a file, not your context** (v2.4.4):
    `exec --command "objdump -d target.bin" --save out/disasm.txt`
    streams the FULL stdout (uncapped — the inline path stops at 1 MB)
    into a host-side file inside the sandbox. No shell redirect, no
    quoting games, stderr still returns inline — or gets a file of its
    own with `--save-stderr out/err.txt` (v2.4.8: both streams full and
    byte-exact, the two targets must be different files). Then
    `search`/`read --lines`/`diff` the artifact. This is the
    reverse-engineering workflow primitive: 200k-line dumps land
    complete, you pay only for the slices you actually read. The save
    target is validated BEFORE the command runs (missing dir → 400,
    outside sandbox → 403, `.git` → protected), and in a `batch` a bad
    target refuses the whole batch with zero side effects.
13. **Distro packages via sudo** (v2.4.5 installs; v2.4.6 removals):
    `sudo pacman -S|-R <pkg>`, `sudo apt install|remove <pkg>`,
    `sudo dnf|yum|zypper install|remove <pkg>`, `sudo apk add|del
    <pkg>` — single commands only, package args only. These ALWAYS
    raise a host approval with a 2-MINUTE COUNTDOWN, under every
    approval policy (yes, even auto-all — your call just blocks until
    the human decides or the countdown resolves it per the
    security-panel setting). Use the default `--timeout` (300) so
    the client outlives the countdown. The host may have a sudo
    password stored in the GUI (you cannot see, set, or clear it —
    there is no API for it); with one set, approved commands run
    passwordlessly from your point of view; without one, they fail
    at the sudo password prompt (exec has no TTY). Either way you
    just relay the outcome. Everything else under sudo (`sudo pip`,
    `sudo rm`, chains, redirects, queries) is rejected — do not try.
14. **Long analyses survive restarts** (v2.4.5): `proc start` procs
    are DETACHED — their metadata and logs live on disk, a server/GUI
    restart does NOT kill them, and they re-attach automatically on
    the next start (`proc list` marks them `(reattached)`; `proc
    logs`/`proc stop` work as before). A 40-minute Ghidra run started
    before a restart is still there after it.
15. **Keep a worklog — both sides** (v2.4.8): maintain a dated
    `WORKLOG.md` in your sandbox AND in the project on the host, and
    sync the host copy with one `write`/`upload` DURING the work unit,
    not after — session memory lives host-side and dies with its
    restart, a pruned context cannot re-read what it never saved, and
    the sandbox itself can be lost; a host-side file survives all
    three. Append what you did, the decisions and numbers, and the
    next step; after ANY restart, read the host worklog first — one
    `read` re-anchors you even when no handoff summary survived.
16. **Every result carries the inbox count — act on it** (v2.5.1,
    reworked v2.7.3): while the human has messages waiting, EVERY op
    still returns its normal result, and the tool adds "N message(s)
    waiting to be addressed in Inbox" to that same result — as a
    `[INBOX]` trailer after the op's output, or, for JSON output
    (`info`, `--json`, `session export`), as a top-level
    `inbox_notice` object inside the JSON (stdout stays parseable).
    It repeats on every op until you read the inbox; the inbox read
    itself is exempt, `--peek` keeps the count alive, rc is never
    changed, and failed ops carry it too. When it appears: stop the
    current work unit, run `session inbox` (default reads + clears),
    answer with `session note --text "…"` — notes and their messages
    render as one thread on the human's side — then continue. Mid-run
    steering works only if you let it steer you. `run` emits it per
    sub-command; long `--follow` streams show it when the command
    ends (the `message` event still lands live in `events`).
17. **Batch rc is transport-only** (v2.5.0, closed decision): the
    batch rc says the REQUEST arrived — per-op failures print their
    full server context right in the results and the rc stays 0.
    Read the per-op lines, not the rc, to know what landed.
18. **Chat-thread notes stay CHAT-SIZED** (v2.5.2): the Sessions tab
    renders notes as a readable conversation — sender labels,
    timestamps, wrap — and a worklog-dense blob renders as a wall of
    text even with perfect formatting. A thread note is 1-4 short
    paragraphs: what just happened + what's next. Dense close-out
    detail belongs in WORKLOG.md (the human reads both); the thread
    is where the human TALKS to you, so keep it talk-sized. The
    operator's log view filters by agent (v2.5.2), and `session log`
    shows you exactly your own log — nothing else is addressable.
19. **Lint the ledger at session start** (v2.6.0, ASK-015 — rule 6
    as code): right after the rule-3 read-back, run `llmac.py ledger
    lint --path <mirror asks.md> --state <mirror asks.lint-state.json>`
    (fully local, no connection). A STALE-FLIP flag means an ask whose
    own text records a SATISFIED flip gate while its status is not
    shipped — flip it to shipped in the SAME ops run, citing the
    evidence the flag quotes; never re-ask the user (rule 6). The
    flag escalates across consecutive lint runs — the across-session-
    boundary echo class that built rule 6 cannot survive the check
    anymore. Gate *descriptions* never flag; shipped, deferred-by-
    user, withdrawn-by-user and wontfix entries are exempt (rule 2:
    those statuses are yours alone).
20. **The screen channel: LOOK before you ACT** (v2.7.0, ASK-016/017 —
    the reach map is the contract): `screen list` is metadata-only and
    needs no approval — run it FIRST to learn the coordinate space
    (GLOBAL logical coords, the single space `screen observe` word
    boxes and every `input` op speak, so an OCR read feeds an injection
    directly). `screen shot --target` is mandatory-target (index |
    `primary` | `all`), png/jpg, optional `--max-width`; files land in
    the host's evidence dir (`screen_shot_dir` setting) with
    deterministic names and sha256 truth; per-shot approval class
    `screen_shot` (the host can grant a class for the session — it
    dies with the app restart). `screen observe` = full-res shot +
    tesseract words with global-coord boxes + the X window list
    (XWayland clients ONLY on a Wayland host — Wayland-native windows
    are not in that tree; documented, not hidden); its own approval
    class, OFF until the host flips `screen_observe_enabled`. INPUT
    (`input mouse/key/text`) is OFF until the host enables
    `screen_input_enabled`, reaches XWayland clients ONLY in v1
    (games/Steam/Proton; native Wayland windows need libei/portal —
    future work, refused loudly never silently), NEVER targets the
    tool's own windows (own_window_refusal — the self-approval loop is
    dead by construction), and runs under a bounded drive session:
    time cap + event cap (`screen_input_max_*` settings, violation =
    `drive_cap_exceeded` and the grant is dropped), an always-on-top
    "click to disarm" banner, and on X11 sessions ANY physical input
    disarms it (XI2 raw events; injected events produce none). Every
    input event is op-logged at WARN. `input key` takes X11 keysym
    names (Return, F5, space, a) + ctrl/shift/alt/meta modifiers;
    `input text` accepts printable ASCII only and names the FIRST
    unmappable character when it refuses. Screen/input ops are NOT
    batchable in v1 — approvals and the GUI-thread capture bridge do
    not belong inside a batch.

### Exec `--json` schema (v2.3.1, F3)

`exec --command ... --json` prints ONE JSON object and exits:

```json
{"returncode": 0, "stdout": "...", "stderr": "...",
 "timed_out": false, "truncated": false,
 "rejected": false, "rule": null, "error": null}
```

Exit codes: `0` success (rejected/error objects included `rejected: true`
make it `1` in --json mode) · `2` command rejected or refused (plain
mode) · `3` transport failed — the command may still have RUN or
COMPLETED server-side; never blindly retry side-effecting commands,
check `events` or re-read the affected paths first.

Also: `write` auto-creates missing parent directories (convenient but
watch for typos), and the client's HTTP timeout is derived from
`--timeout` (no more 30s client cutoffs on long commands).

## Errors you may see

| Error | Meaning | What to do |
|---|---|---|
| `unauthorized` | wrong key | ask the human to re-share |
| `rate_limited` | 5 bad keys in 60s from one address | wait a minute |
| `rate_limited_global` | too many bad keys from ALL addresses | stop retrying; wait minutes, not seconds |
| `forbidden` | path outside your roots | check `info` for your roots |
| `protected_path` | the server's own data dir (or .git / a root itself) | that tree is off-limits, always |
| `permission_denied` | your agent lacks the perm | ask the human |
| `access_denied` | the OS refused (restrictive file mode) | `exec` a `chmod -R u+w`, then retry |
| `os_error` | user-caused OS error (name too long, no space, …) | fix the cause named in the message |
| `version_conflict` | file changed under you | re-read, retry with new token |
| `confirm_required` | big recursive delete | add `--confirm` if you mean it |
| `approval_pending` | waiting for the human | poll `approvals wait` |
| `approval_denied` | human said no | don't retry; ask why |
| `too_many_pending` | >20 pending requests | wait for decisions first |
| `exec_disabled` | host turned exec off | use structured tools |
| `no_roots` | nothing shared (or the op needs a shared root) | `roots request --path P --reason R` |
| `command_rejected` | sandbox/policy refused | read the stderr explanation |
| `not_found` | missing file/directory | check the path in the message |
| `archive_too_large` | >5000 entries / >256MB | archive subdirectories separately |
| `body_too_large` | >16MB in one write | split the file |

## TLS

The host normally serves HTTPS with a self-signed certificate. The
connection block includes a `SHA256:...` fingerprint — pass it via
`--fp` (or it gets pinned on first connect). If a later connection
reports a fingerprint mismatch, STOP — that could be a machine-in-the-
middle. Tell the human.
