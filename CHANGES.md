# CHANGES — v2 ("LLM Directory Bridge" → "LLMAC")

## Unreleased (post-2.7.3) — the host no longer serves code

Cautious agents refuse to run code fetched from the machine they are about to
connect to, however well it is hash-checked. The client is now distributed from
GitHub, and the host serves nothing executable.

* **`cli.py` renamed to `llmac.py`** (the name agents already saved it under).
  `core/constants.py` `CLI_PATH`, launchers, tools and tests follow.
* **`GET`/`POST /bootstrap` removed.** It now returns HTTP 410
  `bootstrap_removed` with the GitHub source and download URLs and no code and
  no hash, so an agent holding an old block gets an actionable error.
* **New connection block.** `Payload-SHA256` is replaced by `Client-Source`,
  `Client-File` and `Client-SHA256`. The self-verifying host-fetch one-liner is
  replaced by a stdlib one-liner that downloads from GitHub (default
  `releases/latest/download/llmac.py`, overridable with `LLMAC_CLIENT_URL`),
  compares the SHA-256 and writes `llmac.py` only on a match. It contains no
  `!`, `$`, backtick or double quote, and contacts neither the host nor uses the
  key.
* **`Client-SHA256` is byte-exact.** It is the hash of the file's raw bytes (what
  `sha256sum llmac.py` prints). The old hash was taken over newline-normalised
  text.
* **`llmac.py audit` is now offline.** `audit [--file PATH] [--expect-sha256
  HEX]` hashes the file and prints the same static `ast.parse` report. It
  contacts nothing, writes nothing and executes nothing. Removed: `--host`,
  `--port`, `--key`, `--fp`, `--plain`, `--local`, `--save-to` (they existed to
  fetch and save the host-served payload).
* README, agent.md and SECURITY.md describe the new flow, including how to
  publish a release. Tests rewritten for the new contract
  (`test_bootstrap_prompt`, `test_selfverifying_bootstrap`,
  `test_v272_verify_audit`, `test_api`).
* Known: because the block's hash is computed from the host's local
  `llmac.py`, host and release must be the same version or the one-liner aborts.

## v2.7.3 — The inbox notice rides every result

Field problem: agents ignored mid-execution human messages. The v2.5.1
enforcement was a stderr banner printed in the middle of the request,
before the result — easy to scroll past or lose to tool-output
collapsing. v2.7.3 moves the notice INTO the result.

* While the acting agent has unread inbox messages, every operation
  returns its normal result plus "N message(s) waiting to be addressed
  in Inbox" (exact count, singular/plural) and the command to read it.
  * plain output: an `[INBOX]` trailer on stdout, after the last byte
    of the op's own output;
  * JSON output (`info`, `batch --json`, `exec --json`, `stat`,
    `session export` to stdout, every `_pjson` result): a top-level
    `inbox_notice` {unread, message} object inside the document, so
    stdout stays machine-parseable;
  * failing ops carry it too; rc is never touched (tip 17 holds);
  * exempt: `session inbox` (reading is the acknowledgement; `--peek`
    keeps the count alive); `session export --out FILE` keeps the file
    byte-clean (only the stdout confirmation carries the notice);
  * `run` emits it per sub-command (no double trailer at the end).
* The server side is unchanged: X-LLMAC-Unread (v2.5.1) is still the
  source of truth; the stderr "HUMAN MESSAGE WAITING" banner is gone.
* agent.md tip 16 rewritten; LLMAC_VERSION -> 2.7.3 in both copies,
  era pins flipped. `tests/test_v273_inbox_notice.py` (19 tests) +
  the v2.5.1 CLI pins moved to the new stdout contract. Suite: 681
  passed.

## v2.7.2 — `llmac.py audit`: verify without trusting this message

Field feedback was blunt: cautious agents still refuse the bootstrap,
and their stated reason is correct — a hash authenticates bytes, it
cannot vouch for what the bytes DO. v2.7.1 closed the transport;
v2.7.2 closes the review gap with a mechanical, no-authority audit
step the connection block now offers BEFORE connect.

* NEW `llmac.py audit --host --port --key [--fp] [--expect-sha256]
  [--local] [--save-to]`: one pinned one-shot fetch of `/bootstrap`,
  then
  * binds the payload to the block's `Payload-SHA256:` (MISMATCH =>
    exit 1) and to the block's cert fingerprint (mismatch => exit 3
    before any HTTP bytes);
  * byte-compares the local `llmac.py` (default when present) against
    the served payload — the same reference-build dissolution the
    v2.7.1 chain allows;
  * prints a STATIC `ast.parse` audit of the source: import
    inventory, non-stdlib imports, red-flag calls (eval / exec /
    compile / `__import__` / `os.system` / `os.popen`), red-flag
    imports (pickle / marshal / ctypes / subprocess), `open(...w/a/x)`
    write sites, egress modules;
  * writes NOTHING without explicit `--save-to` (refused outright on
    any failed check) and NEVER executes the audited source — the
    report is produced even when checks fail, because that is exactly
    when an auditor wants to read the code.
* The generated connection block now orders the flow fetch → audit →
  connect and carries the audit command pre-filled with host, key,
  fingerprint and the expected payload hash.
* agent.md gains "Why the audit step exists (the honest trust
  model)": what crypto can and cannot prove, and the supported
  refuse-until-reviewable posture for agents without a reference
  build.
* LLMAC_VERSION → 2.7.2 in both copies; era pins flipped per release
  convention. New regression suite `tests/test_v272_verify_audit.py`
  (8 tests: clean report, wrong-fp abort, expect-mismatch exit,
  local-tamper detection, --save-to exact bytes, writes-nothing-by-
  default, block carries the audit step).

## v2.7.1 — Self-verifying bootstrap (pin + hash, fail closed)

The agent-side bootstrap no longer asks anyone to trust anything.
Every step in the chain paste → fetch → write → run is now a checkable
equality, and every failure aborts BEFORE llmac.py is written.

* `GET/POST /bootstrap` now returns `cli_sha256` (SHA-256 of the served
  `cli_py` string, utf-8).
* The connection block carries a `Payload-SHA256:` line (computed from
  `cli.py` on the host; shows `(unavailable)` if unreadable) and
  generates a bootstrap one-liner that:
  1. pins the host certificate fingerprint DURING connect — a pinned
     `HTTPSConnection` subclass checks sha256(peer DER cert) before any
     HTTP bytes are sent; mismatch abandons the connection with nothing
     transmitted. The blind `ssl._create_unverified_context()` fetch is
     gone; the unverified context now only stands in for the missing CA
     chain while the explicit pin does the verifying;
  2. verifies the served payload against the response's `cli_sha256`;
  3. refuses to write or run `llmac.py` on a missing or mismatched
     hash, exiting non-zero with an explicit ABORT reason.
* Plain-HTTP mode keeps payload-hash verification (transport pinning is
  impossible there by definition; keep plain HTTP on localhost/tunnels).
* HTTPS without a fingerprint available still hash-verifies the payload
  and the block warns that transport is unpinned.
* New regression tests (`tests/test_selfverifying_bootstrap.py`):
  verbatim happy-path execution (TLS + plain), tampered fingerprint
  (must abort before the request, no file), tampered payload hash
  (must abort, no file), missing hash (must abort, no file), and
  prompt carries `Payload-SHA256:` equal to the served payload's hash.
* Docs updated: README (self-bootstrap + transport bullets), agent.md
  (Quick start rewritten around the verification chain).

## v2.7.0 — The Screen Channel: the agent can LOOK (per-screen shots, OCR reads) and — only if you switch it on — ACT

Two pinned asks, one release. ASK-016 makes multiple monitors
first-class: enumerate them, capture ONE specific screen instead of
always the whole wall. ASK-017 opens observation (the screen as TEXT
with positions, plus the window list) and input injection behind a
non-negotiable safety floor — OFF until the host enables it, bounded
by caps, banner'd, one-click-disarmable, every event op-logged.
Grounded in live recon: KDE Plasma Wayland + XWayland on CachyOS,
tesseract / spectacle already present; build-time installs are
venv-only (pytesseract + Pillow + python-xlib) — no system packages.

**screen.list + screen.shot (ASK-016)**
* NEW Qt-free `core/screen.py` (the transcript.py pattern): pure
  helpers the suite imports on any platform — deterministic naming
  (`screen-YYYYmmdd-HHMMSS-<index>.<ext>`), target/format/max-width
  validation with named refusals, global-coordinate math
  (`crop_rect` for the merged-capture physical layout, `to_global`
  for local-physical → global-logical), the X11 keysym tables
  (modifiers, specials, printable-ASCII text mapping — pinned by
  test), the DriveSessions state machine, and the ScreenService /
  InputBackend protocols.
* `POST /screen/list` — monitors as metadata ONLY (index, name,
  global geometry, primary, scale): zero pixels, deliberately NO
  approval. A headless host refuses cleanly (`screen_unavailable`
  naming the reason).
* `POST /screen/shot` — target is explicit and MANDATORY (index |
  'primary' | 'all'; missing → 400 `shot_target_required`, unknown →
  400 `screen_not_found` naming it); png/jpg (quality 85); optional
  max-width downscale (aspect kept). Files land in the evidence dir
  (`screen_shot_dir` setting, default the llmac-work shots
  neighborhood; a dir outside the shared roots refuses
  `screen_dir_not_shared`) with deterministic names; the response
  carries {path, screen, geometry, format, width, height, bytes,
  sha256} per file plus the screens[] snapshot. Every shot op-logged.
* Approval class `screen_shot` is FORCED (prompts under every policy,
  auto_all included — a screenshot is a privacy decision) with a new
  "Approve for this session" grant on the approval card —
  until-restart, MEMORY-ONLY (dies with the app; nothing lands in
  state.json), every op still op-logged.
* Capture backends (QtScreenService lives in gui.py, executes ON the
  GUI main thread through a new postEvent bridge — the HTTP handler
  never touches Qt): X11/Windows `QScreen.grabWindow(0)` per screen
  (the native per-screen crop); KDE Wayland `spectacle -b -n -f` →
  merged full-desktop PNG → per-screen crop by geometry × scale (the
  "all" target keeps the merged source as an extra evidence file;
  mixed-DPI caveat documented in agent.md tip 20); other Wayland
  compositors refuse `screen_capture_unsupported` — no silent black
  frames, ever.
* CLI: `screen list`; `screen shot --target 2|primary|all
  [--format jpg] [--max-width 1600]` with rc-2 pre-request guards
  (missing --target / bad format / bad max-width).

**screen.observe (ASK-017 part A)**
* `POST /screen/observe` — OFF until `screen_observe_enabled` is
  flipped in the GUI (refusal names the setting). Full-resolution
  shot on the Item-1 rails + OCR (pytesseract → words with
  confidence, boxes in GLOBAL coordinates so input ops can target
  them directly, plus a per-screen plain-text digest — the read path
  for text-channel agents) + the X window list via python-xlib
  (_NET_CLIENT_LIST: titles, absolute geometry, visible, focused —
  XWayland clients on this host; Wayland-native windows are
  documented as out of that tree). `max_width` is REFUSED here
  (`observe_max_width_unsupported` — OCR truth needs full
  resolution; loud contracts beat silent ignores). Own approval class
  `screen_observe`; the window list degrades loudly
  (`windows_error`) when X is unreachable, never silently.
* CLI: `screen observe --target ...`.

**Input injection — the safety floor IS the design (ASK-017 part B)**
* `POST /input/mouse` (move|click|doubleclick|drag|scroll,
  left|middle|right, coordinates in the SAME global space),
  `POST /input/key` (X11 keysym + ctrl/shift/alt/meta modifiers),
  `POST /input/text` (keysym-mappable characters only; the FIRST
  unmappable character is named in the refusal). Backend: X11/XTest
  via python-xlib from the SERVER thread (no Qt); Windows SendInput
  is interface-compatible future work.
* The floor, non-negotiable: (1) own-window refusal — the hit test
  resolves the window at the point (or the focused window for
  key/text) FIRST; a hit on the tool's own windows refuses with
  `own_window_refusal` before any approval, session or injection
  (and on this Wayland host the self-approval loop is platform-dead:
  the GUI is a native Wayland window, out of XWayland's reach). (2)
  Bounded drive mode — an approved input op opens a drive session
  with the `screen_input_max_minutes` (default 10) and
  `screen_input_max_events` (default 500) caps enforced SERVER-side
  before every op; a violation closes the session AND drops the
  session grant (`drive_cap_exceeded` — the caps are a real bound,
  not a soft bump; the next op needs a fresh approval). (3) A live
  frameless always-on-top banner — "LLMAC agent is driving input —
  click to disarm" — kills every session in one click; on X11
  sessions an XI2 raw-event listener disarms on ANY physical input
  (injected events produce no raw events); on Wayland the banner
  click + the caps are the breakout, stated in agent.md, not hidden.
  (4) Every input event op-logged at WARN. (5) The whole capability
  stays OFF until `screen_input_enabled` is set in the GUI.
* Honest reach caveat pinned everywhere: injected input reaches
  XWayland clients (games, Steam, Proton) — native Wayland windows
  are NOT reachable in v1 (libei/portal route = documented future
  work; ops that need it refuse loudly, never silently no-op).

**GUI + settings surface**
* Security tab gains a "Screen access" group (the sudo_timeout
  pattern: settings.setdefault at boot, persistence via
  `_save_state(event_type="screen_settings_change")`): screenshots
  on/off (default ON, still approval-gated), observe on/off (default
  OFF), input on/off (default OFF, with the reach-map warning), the
  shot-folder picker, the two drive caps. The Approvals card gains
  "Approve for this session" for the three screen classes. The drive
  banner + XI2 listener ride the 1s approvals poll. Tab indices stay
  widget-derived (the v2.5.1 fix holds; no new tab).
* Screen/input ops are NOT batchable in v1 — the batch handler
  refuses them by name (`not_batchable`): approvals + the GUI-thread
  capture bridge do not belong inside a batch.

**Version truth + ship ritual (unchanged)**
* LLMAC_VERSION → 2.7.0 in BOTH copies (core/constants.py + cli.py
  bootstrap fallback, keep-in-sync pinned); era pins flipped; CHANGES
  entry (this one); agent.md tip 20 + command-table rows;
  requirements.txt documents the three venv-only optionals.
* Suite 568 → 647 (79 new, RED first: tests/test_v270_screen_channel.
  py — FakeScreenService + FakeInputBackend injected into
  AppContext; every route contract, the safety floor, the naming/
  coordinate math, the keysym tables, CLI rc-2 guards, gui.py source
  pins, version pins); local py3.12 AND host py3.14.8. Offscreen
  host acceptance on PyQt6: the settings group, the overlay
  show/clear, the grant card option.
* Ship-gate checked BEFORE the zip; bench gate vs the v260 baseline
  (FILE-GREW expected on api.py/gui.py/cli.py per lesson #10);
  zip 3-way byte-verified + filebin + deploy as always.

## v2.6.0 — Durable Evidence: the transcript becomes an artifact, the ledger enforces its own rule 6

The readable thread (v2.5.2) was still just readable — finding one
sentence meant scrolling, and proving what was said meant screenshots.
v2.6.0 makes the Sessions tab a source of evidence and turns rule 6
from convention into code, so the ASK-012 stale-echo class can never
recur. Scope ratified by the user 2026-10-29 (Task 43): ASK-014 +
ASK-015. Same ops run, the ledger also recorded the standing
carry-over clicks CLOSED by capture (ASK-013) and the withdrawal of
one parked candidate (scrubbed; WITHDRAWN tombstone in ASKS.md).

**Transcript search/export in the Sessions tab (ASK-014)**
* NEW `core/transcript.py` — Qt-free pure helpers both the GUI and the
  test suite import: `count_hits` (case-insensitive, regex-escaped),
  `transcript_markdown` / `transcript_plaintext` / `transcript_html`
  (metadata preamble — agent, exported-at, time range, entry count —
  plus the FULL merged thread, the same ts-ordered notes + user
  messages the tab renders), `default_export_name`,
  `guess_format` (extension + filter tiebreak, md default).
* The Sessions tab gains a search/export row between the transcript
  and the input: a search box (live hit count, Enter next,
  Shift+Enter previous, Esc clears) whose find/highlight re-applies
  after the 1 s re-render, and an Export… button (QFileDialog,
  .md/.txt/.html) that writes the FULL thread with provenance and
  confirms on the status bar. The v2.5.2 render is untouched — the
  export builds its own HTML.

**Ledger linter — rule 6 as code (ASK-015)**
* NEW `llmac.py ledger lint --path <asks.md> [--state S] [--json]` —
  fully local, stdlib only, no connection. Parses `### ASK-NNN`
  entries and the status ladder; flags any ask whose own text records
  a SATISFIED flip gate while its status is not shipped:
  tier 1 = an explicit `- gate-evidence:` field; tier 2 = rule-6
  satisfaction signals (flip captured / gate was satisfied / already
  done / looks good / pasted the GUI transcript / eyeball happened /
  confirmed at one point), scanned with the entry's own status and
  flip-gate description lines skipped so gate wordings never
  false-flag. Shipped, deferred-by-user, withdrawn-by-user and
  wontfix entries are exempt (rule 2 — those statuses are the user's
  alone). Never mutates the ledger.
* `--state` escalates: the same flag surviving to the next lint run
  reports "flagged for N consecutive lint runs" — the
  across-session-boundary echo class, caught. Entries that clean up
  drop out of the state.
* The actual pre-flip ASK-002/006/007 texts are pinned test fixtures
  (tests/test_v260_transcript_export_lint.py) so the exact ASK-012
  incident shape stays detected forever. rc contract: 0 clean /
  1 flags / 2 usage (missing --path, ledger_file_not_found — both
  refuse loudly naming the path).
* agent.md tip 19: lint the mirror right after the rule-3 read-back;
  a flag is work for the SAME ops run, never a question to ask.

**Version truth + release plumbing**
* LLMAC_VERSION → '2.6.0' in BOTH copies (core/constants.py + the
  cli.py bootstrap fallback); era pins in the v250/v251/v252 test
  modules flip with the release as always.
* The production file set grows by core/transcript.py and
  tests/test_v260_transcript_export_lint.py (the live manifest
  carries both; 13/13 becomes 15/15 at the next full verify).
* Suite: 537 + 31 new (v260 module), RED first, green on local py3.12
  and host py3.14.8. Gate vs tools/baseline-2026-10-29-v252-full.json;
  gui.py grows so expect the lesson-#10 FILE-GREW branch; fresh v260
  baseline lands post-restart per precedent.

## v2.5.2 — The Readable Channel: the transcript reads like a chat, the log filters by agent, the agent log is scoped by construction

The transcript the user pasted back was the bug report: the live-session
thread rendered as one wall of text — no sender labels, no wrap, no
breaks. v2.5.2 rebuilds it as a readable conversation, gives the Log tab
the agent filter that was missing, and adds the server-side log surface
that never existed — scoped to the acting agent by authentication, so a
second agent's log is not even addressable.

**Transcript readability (ASK-008)**
* The Sessions chat pane is a QTextBrowser rendering HTML: colored
  sender labels (YOU blue, the agent's real name green), muted
  timestamps, word wrap at the pane width, and blank space between
  entries. Long notes are paragraph-split at sentence boundaries
  (~300-char packs) — a dense close-out note reads as paragraphs, not
  a blob. All text is HTML-escaped.
* agent.md tip 18: thread notes stay CHAT-SIZED — 1-4 short
  paragraphs; dense detail belongs in WORKLOG.md. The convention
  starts with this release's own notes.

**op_log agent field + Log-tab filter (ASK-009)**
* Every op_log call site passes its agent (write/edit/delete/exec/
  proc/batch/archive/share/approvals); the callback tuple widened to
  ("OP", level, msg, agent) — pre-2.5.2 3-tuples still tolerated.
* The Log tab gains a Filter combo (All agents default): the retained
  500-entry buffer keeps EVERY entry (the filter is a view, never a
  gate); the live tail honors it, a filter change re-renders from the
  buffer, and the combo self-registers agents as they appear.
* gui.log + stderr lines carry the agent tag on OP entries.

**Agent-scoped log view (ASK-010)**
* NEW server-side op ring (bounded, 1000 entries, monotonic seq)
  recording {seq, ts, agent, level, msg} for every op_log call.
* NEW POST /session/log: an authenticated agent gets ONLY its own
  entries — scoping is by authentication alone. There is no client
  `agent` parameter and an explicit one is a clean 400
  (agent_scoping_is_automatic); `after`/`next_after` page the cursor,
  `limit` clamps server-side (default 200, max 1000).
* CLI: `session log [--after N] [--limit M]` prints the scoped view +
  the next cursor. The operator GUI keeps the full in-process view.

**S4 harness rider (Task-38's flapping-ratio fix, harness-only)**
* tools/bench_llmac.py S4 records batch_median_s — median-of-3
  idempotent batch probes; the in-scenario call stays single so byte
  metrics stay comparable.
* scripts/compare_bench.py gates S4 on the batch median (single-shot
  fallback for pre-2.5.2 baselines); the speedup ratio is
  eyeball-class only. No server bytes.

Version truth: 2.5.2 in constants + CLI fallback; era pins flipped
(v241 x3, v244, v245, v250 x3, v251 x3). Suite 504 → 537 (33 new in
tests/test_v252_readable_channel.py: 8 route, 3 ring, 3 CLI, 5
transcript pins, 7 log-filter pins, 2 harness pins, 5 version pins —
31 feature tests + the negative guards that passed red).
Gate expectation vs the v251 baseline: FILE-GREW on api.py, gui.py,
cli.py (lesson #10); fresh v252 baseline records post-restart.
Ship-gate (ASKS rule 4) checked before the zip; ASK-008/009/010 flip
shipped on the user's post-restart eyeball (protocol rule 6:
assertion or demonstrated use closes it — no re-asking).

## v2.5.1 — The Straightened Channel: the notice is enforced, the tabs are straightened, the prompt follows your pick

The first live use of the v2.5.0 human channel exposed the gap the
user called immediately: messages landed in the inbox but the agent
read them at its own convenience. v2.5.1 makes the notice UNMISSABLE,
fixes the tab miswiring that shipped with the Sessions insertion,
and adds the Overview agent picker.

**Enforced notice (ASK-005)**
* The server stamps X-LLMAC-Unread — the acting agent's unread
  count — on EVERY authenticated response, success and error, JSON
  and raw (archive streams included). Unauthenticated responses
  carry nothing.
* The CLI prints a loud "HUMAN MESSAGE WAITING (N unread)" banner
  after ANY op while unread > 0 — except the inbox read itself. An
  agent cannot do a single unit of work without the message state
  appearing in its context. rc is never touched (the tip-17
  transport-only contract holds); run/batch inherit the banner
  per-op through the shared transport.
* True mid-op interruption still needs the resident agent loop =
  Phase 3 (2.6.0 candidates, explicit user go).

**Tabs straightened (ASK-006 — the v2.5.0 bug, user-reported)**
* The TAB_ index constants still described a 6-tab bar after the
  Sessions insertion made 7; _update_pills relabeled the SESSIONS
  tab "Approvals" and APPROVALS "Processes" — two "Processes"
  tabs, the "Live sessions" card under an approvals label,
  approve/deny under a processes label. Symptom for symptom, one
  stale line.
* Indices are now WIDGET-DERIVED — captured from addTab return
  values (self.TAB_*); a future insertion can never desync the
  badge and pill sites again. Pinned by test.

**Overview agent picker (ASK-007)**
* The Connection card gains a "Prompt agent" picker: the copied
  agent prompt is built with the SELECTED agent's key + name, not
  the hardcoded default; the selected agent's key fingerprint
  shows beside the combo, and the combo tracks Agents-tab changes
  (_sync_prompt_agents).

**Suite** 477 -> 504 both platforms (27 new tests, red first);
version truth 2.5.1 in both copies, era pins flipped.

## v2.5.0 — The Human Channel: talk to your agents while they work

The release the two ORIGINAL asks finally ride — mid-run chat and
multi-session in the GUI. Both predate the v2 history reset and were
never even written down (the fact-check that opened Task 35 found
zero hits for either); the new ASKS.md ledger (see STATE.md) exists
so that never happens again, and both asks are its first entries.
Scope locked by the user 2026-10-29: everything except Phase 3 (MCP
adapter / built-in loop), which stays parked on the 2.6.0 candidates.

**core/sessions.py: the user->agent inbox (ASK-001)**
* Each AgentSession gains an inbox beside notes — the human->agent
  direction notes never had. Messages are {seq, ts, text}, capped at
  SESSION_INBOX_CAP=200 drop-oldest; `inbox_seen` is a consume
  watermark, so `read` returns only NEW messages while the transcript
  list stays intact for the GUI (history survives consumption).
* SessionRegistry grows: `inbox(agent, text, events=…)` (the GUI
  passes ctx.events and the `message` event fires for live /events
  pollers), `read_inbox`, `agents_snapshot` (sidebar data: name,
  last_seen, op/note counts, unread) and `thread` (notes + messages
  merged ts-ordered — what the chat pane renders). digest() now
  reports `unread` + `last_inbox_ts`.

**core/api.py: POST /session/inbox (+1 route, nothing else moves)**
* The authenticated agent reads its own inbox; default consumes, the
  `peek` boolean only looks. `text` in the payload 400s
  `text_belongs_to_note` (the note route is the agent->record
  direction; mixing the two is a lesson-#11 client bug, refused
  loudly on both ends). Reading records an op like every other verb.

**core/events.py: `message`**
* New typed event on the existing stream (data: agent, seq, text) —
  any live long-polling client sees a chat message land in real time;
  agents get it on their next `session inbox` poll.

**gui.py: the Sessions tab (ASK-001 + ASK-002)**
* New tab between Agents and Approvals: left sidebar = every live
  agent session (op count, live/dormant by last-op age, unread
  badges); right = the merged transcript for the selected agent
  (its notes + your messages, ts-ordered) + an input box. Sending
  writes the registry IN-PROCESS — the GUI owns the AppContext, so a
  human message is never an HTTP op, and the whole feature adds ZERO
  new HTTP surface beyond /session/inbox.
* Selection survives the 1 s poll refresh; the transcript auto-scrolls
  unless you scrolled up to read; the input enables per selected
  session. (The plan said "Agents tab upgrade"; a dedicated tab keeps
  key management and the human channel cleanly separate.)

**cli.py: `session inbox [--peek]`**
* New verb beside status/note/reset/export: prints each message with
  its seq + ts and an unread footer; default consumes, --peek only
  looks. The lesson-#11 `--text` guard already covers it (rc 2,
  text_needs_note). The standalone bootstrap fallback version literal
  is bumped in lockstep (pinned keep-in-sync by test).
* `session status` digest now carries the unread count — an agent can
  see "message waiting" without consuming it.

**Version truth (ASK-003)**
* LLMAC_VERSION -> "2.5.0" in BOTH copies (core/constants.py + the
  cli.py standalone fallback). The GUI showed 2.4.9 through 2.4.10
correctly — that release touched zero server bytes; after deploy +
  restart the UI reads 2.5.0.

**batch CLI rc — transport-only, now a documented contract**
* Closed decision (Task 35, user-accepted): batch rc reports the
  TRANSPORT, not the ops — per-op failures print their full server
  context, rc stays 0. Pinned by test (test_batch_rc_is_transport_only)
  and documented as agent.md tip 17 so the contract can't drift.

**Suite: 454 -> 477 (23 new), both platforms**
* tests/test_v250_human_channel.py, written RED first against 2.4.10:
  the inbox model (consume/peek/cap/watermark/unread/event), the route
  contract (roundtrip, peek, text_belongs_to_note, bad peek, empty,
  digest unread, event flows to wait), CLI roundtrip + guards, the
  batch-rc pin, GUI source pins (the test_v246 pattern), and the
  version-truth pins. Green on py3.12 AND host py3.14.8.
* Era version pins flipped (v240 x2, v241 x3, v244, v245 -> 2.5.0) —
  the same per-release flip those pins always take.

## v2.4.10 — harness truth: the comparator's v2.4.7 S5 policy restored, bench --big-file indices fixed

A harness-only release: the server and client bytes are UNTOUCHED —
the live 2.4.9 keeps serving, no version string changes anywhere.
Both defects fired live in the v2.4.9 post-restart gate (Task 31);
neither was hypothetical. The same commit carries the fresh gate
baseline recorded on the live 2.4.9 into tools/ (the 9c4512f
pattern), making the next gate the first SAME-BYTES run since the
host reorg.

**scripts/compare_bench.py: the v2.4.7 S5 carve-out the rebuild lost**
* The v2.4.8 restore followed "the same verdict policy the v2.4.7
  gate was read with" but missed one line of it: the S5 scenario
  wall is naive single-shot WAN-leg noise (v2.4.7: 1.05→2.44 s on
  untouched code; Task 31: +61.6% probe → −13.9% parity run) and is
  EXCLUDED from the wall gate. With the carve-out missing, the
  first Task-31 probe FALSE-FAILED the gate on noise — a gate that
  false-fails trains ignoring gates (the lesson-#10 class).
* S5 now gates on the derived `llmac_deploy_median_s` instead
  (fail-pct band, the sub-second band under 1 s, WARN in-band, same
  as the walls; improvements never fail), falling back to the
  single-shot `llmac_deploy_wall_s` only when a run lacks the
  median. The excluded wall is still printed with its delta and the
  exclusion reason, for the eyeball pass.

**tools/bench_llmac.py: s7/s8 derived metrics index call_log BY OP**
* Under `--big-file` the /stat size-fill lands inside the S7
  scenario, so the fixed indices read the /stat response as the
  whole read — the Task-31 probe reported "whole_read 173 B" (every
  call was 200) and ranged/waste_ratio were off by one the same
  way. s7/s8 now pick their records by op (`_by_op`: the first and
  second /read, the /stat), which is stable under --big-file and
  any other insertion; the walk path records values identical to
  the pre-fix harness, so the fresh v249 baseline stays directly
  comparable.
* Pinned end-to-end: s7 AND s8 run twice against a headless host —
  walk-mode vs --big-file-pinned on the SAME file — and the derived
  read/stat/waste numbers must be identical.

**tools/baseline-2026-10-28-v249-full.json: the gate reference**
* The baseline recorded on the live 2.4.9 right after the FILE-GREW
  refusal (identity self-gate PASS, pins OK, meta.repo recorded)
  moves from llmac-work/ into repo tools/, flipping STATE.md's gate
  reference with it: the next gate compares core/api.py at 116107 B
  on both sides — the first same-bytes comparison since the reorg.

## v2.4.9 — loud contracts: flag-drop sweep (lesson #11), comparator disambiguation (lesson #10), search on a single file

The v2.4.9 queue exactly as RE-RANKED in STATE.md (Task 29):
agent-safety first. The v2.4.8 find-hex incident proved a silently
dropped flag can kill a run sequence; this release sweeps the whole
client for that pattern and refuses loudly before any request, fixes
the bench comparator's wrong-repo/file-grew conflation, and lets
`search` run on a single file instead of dying with a context-free
not_a_directory (found live in Task 29 while hunting tip 15 in
agent.md — the error printed `not_a_directory: ` with an empty
subject because the client dropped the server's `path` field).

**Client flag-drop sweep (lesson #11 — one rc-2 pre-request refusal
per dropped-flag class, one test per guard; the 9c4512f pattern)**
* read: `--max-hits` without `--find-hex`/`--find-text` → rc 2
  `find_max_hits_needs_find` (the cap was sent only inside the
  hex+find branch and silently ignored otherwise — on both sides).
* search: `--context` without `--query` → rc 2 `context_needs_query`
  (name search has no context lines); `--regex` without `--query` →
  rc 2 `regex_needs_query`; `--name` together with `--glob` → rc 2
  `name_glob_conflict` (the server's `name or glob` silently kept
  only the first).
* proc: `--max-idle` without `--follow` → rc 2 `max_idle_needs_follow`
  (it was consumed only inside the follow loop; its own help text
  already said "requires --follow").
* write: `--content` together with `--file` → rc 2
  `content_file_conflict` (the file silently won).
* edit: `--occurrence`/`--regex` without `--replace` → rc 2
  `modifier_needs_replace`; `--content` with no op that consumes it
  (only --replace/--delete-lines given) → rc 2 `unused_content`.
* batch: `--ops` together with `--file` → rc 2 `ops_file_conflict`.
* diff: `--b` together with `--inline-file` → rc 2
  `diff_targets_conflict`.
* session: `--text` with a verb other than `note` → rc 2
  `text_needs_note`.

**Error renderer: server context is never dropped client-side**
* One canonical `_err_from_resp()` renders error + message + path +
  field + expected + rule/op + any other scalar context the server
  sent; the ~18 hand-rolled `error: message` printers (which blanked
  payloads like {"error": "not_a_directory", "path": …} into
  `not_a_directory: `) now route through it, and the batch per-op
  failure lines use the same field renderer. Every 400/404 now names
  its subject.

**Server: read-op field guards + search on a single file**
* /read (direct AND as a batch read op): a bare `max_hits` field 400s
  `max_hits_unknown_field` (the Task 28 payload mistake — the API
  field is find_max_hits and the bare form was silently ignored);
  `find_max_hits` without `find_hex`/`find_text` 400s
  `find_max_hits_needs_find`.
* /search --path <FILE> now searches that ONE file (content grep or
  name match against its basename) instead of 400ing; a nonexistent
  path is a clean 404 `not_found` naming the path. Directories keep
  the old walk; tree/overview still require directories — their
  not_a_directory now renders WITH the path via the client renderer.

**Bench: the S7/S8 same-file refusal distinguishes wrong-repo from
file-grew (lesson #10)**
* scripts/compare_bench.py: same file_path but different file_bytes →
  "the SAME file GREW/SHRANK from A to B — legitimate code change:
  compare per-byte throughput, then record a FRESH baseline for the
  next gate (lesson #10)". A moved file_path → "biggest file MOVED:
  baseline X (A B) vs results Y (B B) — wrong --repo (lesson #8) OR
  growth moved the target: verify --repo, then re-baseline". When
  both runs record meta.repo (bench_llmac.py now writes it), a repo
  mismatch asserts the wrong-repo branch outright and a match asserts
  the moved/growth branch. The check also compares file_path now —
  a moved target with coincidentally equal byte counts used to pass
  the gate silently.

**Version pins**: core.constants.LLMAC_VERSION and the cli.py
standalone fallback are 2.4.9; the live-version literal sites
(test_v240 ×2, test_v241 ×3, test_v244, test_v245 + the v248
comparator fixture) bumped per the release convention. 29 new tests
pin the guards, the renderer, the server refusals, single-file search
and the comparator branches; the full suite is 445.

## v2.4.8 — hex find (GOTO/search), exec --save-stderr, GUI log tail, bench walk fix

The v2.4.8 queue exactly as re-ranked in STATE.md: the RE follow-up to
v2.4.7's hex dumps (find the bytes, then GOTO them), the stderr half
of exec --save, a tail window in the GUI, and the bench-harness fix
lesson #8 demanded. DXHR-RE ergonomics stays the top rank driver; the
primitives are tool-side only.

**`read --hex --find-hex P` / `--find-text T` (scan a binary, land on
its bytes)**
* The GOTO/search primitive for binary blobs: scan a file for a hex
  byte pattern (`--find-hex "4d 5a"`) or a literal string
  (`--find-text "This program"`, UTF-8 bytes) from `--offset`, and get
  every hit's ABSOLUTE offset plus a rendered hex context (the v2.4.7
  xxd rows, 16-aligned, 32 B before / 32 B past the hit). GOTO was
  already one call — `read --hex --offset N` — so locate-then-jump is
  now exec-free for signatures, strings and structures in binaries.
* Server-side chunked scan (~1 MB chunks with pattern-length carryover
  so a hit spanning a chunk boundary is never missed; whole-file loads
  never happen). Hit cap: `--max-hits` (default 25, server cap 100);
  when the cap cuts the scan short the response says `more` and the
  CLI prints a continuation hint (`--find-hex P --offset next`). Scan
  paging is `next_offset = last hit + 1` — overlapping occurrences
  ("aa" inside "aaa") page correctly.
* Validation fails loudly instead of guessing: find without hex=true
  is a 400 `find_needs_hex`, find_hex+find_text together 400
  `find_conflict`, malformed hex 400 `bad_find_hex`, find+limit 400
  `find_limit_conflict`, >1024-byte patterns 400
  `find_pattern_too_long`. Spaces-only find_hex is simply "no pattern"
  (plain hex dump). Works inside `batch` read ops like plain hex —
  the batch line reports `(find: N hit(s))`.

**`exec --save-stderr` (stderr artifacts beside stdout)**
* `exec --command C --save out.log --save-stderr out.err` streams BOTH
  streams full and uncapped into their own host-side files: each pipe
  goes straight into its file handle (no capture thread at all — the
  artifacts are byte-exact), the inline response streams go empty, and
  the response carries saved_path/saved_bytes plus
  saved_stderr_path/saved_stderr_bytes (also in `--json`). stdout-only
  or stderr-only saving works independently; the old `--save`
  behavior (stderr inline) is untouched.
* The two targets must differ — a shared file would interleave two
  pipes into garbage — 400 `save_same_path`, before anything runs.
  Same pre-run validation rules as --save (outside sandbox 403, missing
  dir 400 with the right flag named in the message); in a `batch`,
  a bad stderr target refuses the WHOLE batch atomically (B4 rule).
* On a timeout with --save-stderr, the `[command timed out after Ns]`
  note lands IN the stderr artifact (written after the pipes drain —
  no interleaving) instead of vanishing with the discarded inline
  stderr.

**GUI "Tail logs" (proc log following, in the supervisor)**
* The Processes tab grows a Tail logs button: select a row, click, and
  a modeless ProcTailDialog follows that proc's output — the GUI twin
  of `llmac proc logs --follow`. It polls the in-process ProcManager
  once a second with INDEPENDENT stdout/stderr cursors (stderr lines
  prefixed `[err]`), auto-scrolls, mirrors the server's 20000-line
  readable window via a ring-buffered view (a runaway proc grows the
  log file, never the window's memory), resurfaces the v2.4.7
  window-rolled warning, and stops polling when the proc exits —
  final state goes into the title and the view.
* One window per pid (re-clicking raises the existing one); windows
  are WA_DeleteOnClose and self-remove from the supervisor's list.
  Source-level wiring is pinned by the v2.4.8 test suite (PyQt is
  unavailable headless — same convention as the v2.4.6 GUI guards).

**Bench: S7/S8 biggest-file walk fix (lesson #8)**
* The nine-scenario gate runs with `--repo` = the DEV REPO, but the
  first v2.4.7 gate attempt used the live tree and measured the
  user's 225 KB archive (Its/02Archive.zip) instead of gui.py — S7/S8
  walls inflated 35%, waste_ratio collapsed, "different code" was
  actually "different file". The walk now skips archive suffixes
  (.zip/.tar/.tgz/.gz/.7z/.rar/.xz/.bz2/.zst) by default, and
  `--big-file PATH` pins the S7/S8 target explicitly when even
  code-size heuristics are wrong (size filled via /stat).
* Both scenarios now record `derived.file_path` next to file_bytes —
  the "ALWAYS read file_bytes before diagnosing" lesson becomes a
  one-glance check. The walk helper is module-level and unit-tested
  (a zip bigger than every code file loses to the biggest code file;
  an explicit --big-file wins outright). Dev-repo numbers are
  unchanged (gui.py was and stays the target) — the baseline
  comparison remains apples-to-apples.

**Version pins**: the six legacy tests that assert the live version
literal (240/241/242/244/245 + the harness-coverage wiring) were
bumped per the release convention; `core.constants.LLMAC_VERSION` and
the cli.py standalone fallback are both 2.4.8. 29 new tests pin the
four features; the full suite is 415 and green (post-release
correction — this entry first said 24/410).

**Post-release polish (same day)**: the post-restart live check caught
the standalone CLI quietly DROPPING `--find-hex`/`--find-text` given
without `--hex` (the server 400s `find_needs_hex`, but the client
fell back to a plain read — an agent could believe the scan ran and
pull raw bytes into its context instead). cli.py now refuses loudly
with the same message and exit 2 before any request; a 30th test in
the v248 module pins it (suite: 416). agent.md grew tip 15 — keep a
dated WORKLOG.md in your sandbox AND in the host project, synced
during each work unit — after the v2.4.8 build session lost its own
log to two restarts; the Quick-start recovery paragraph points at
it. Bench: the v2.4.8 code growth made core/api.py (114,786 B) the
biggest dev-repo file, so the S7/S8 same-file gate correctly REFUSED
comparison against the gui.py-era baseline (per-byte throughput was
flat-to-better: S7 +1.0% on +7.6% bytes, S8 flat); a fresh baseline
(tools/baseline-2026-10-28-v248-full.json, recorded on the live
2.4.8) is the reference for the v2.4.9 gate.

## v2.4.7 — proc log streaming, batch edits, hex dumps, S5 median

The v2.4.7 queue re-ranked for the reverse-engineering workload
(DXHR-RE): watch long scans produce output without polling, push
multi-file edits in one round trip, and read binary blobs without exec.

**proc_log events + `proc logs --follow` (tail -f for agents)**
* One watcher thread per server stat()s every RUNNING proc's log files
  once a second and emits a `proc_log` event (id/name/stream/size) when
  output landed. Agents long-polling /events wake the moment a build or
  strings-dump produces output, then slice it with /proc/logs — no
  polling loop, no missed quiescence. The first observation of a file
  baselines its size: no event spam on start or restart re-attach, and
  finished procs are skipped entirely.
* `llmac proc logs --id X --follow` implements client-side streaming
  on top: independent stdout/stderr cursors (new after_stdout /
  after_stderr request fields), prints only new lines, exits cleanly
  when the proc exits, `--max-idle N` bounds the wait for scans that
  might hang. The old one-shot `proc logs` is unchanged.
* **Slice-protocol fix found while building this**: _read_log sliced a
  TRUNCATED window with lines[after:] — a proc that produced >20 000
  lines while the agent was away silently dropped the oldest lines and
  mis-labeled the rest (the agent believed it had everything; `next`
  also desynced). The response now carries per-stream stdout_resynced /
  stdout_skipped (stderr likewise), `*_next` always equals the TRUE
  line count, and the CLI prints a visible resync warning.

**Batch edit ops (the diff-in-edit item, closed after six deferrals)**
* `edit` is now a batchable op — with the same all-or-nothing op
  semantics as individual edits: each result carries the surgical
  unified diff, so a 10-file change costs ONE round trip and still
  proves itself line by line. Strict policy refuses batched edits, same
  principle as writes; the aggregate 8 MB response cap guards bloat.
* The CLI prints each batched edit's diff by default (`--no-diffs`
  suppresses); `run` batches inherit the same output. Unknown-op error
  text now lists edit.

**`read --hex` (xxd-style dumps, no exec)**
* POST /read accepts hex=true: byte slicing via offset/limit (default
  slice 512 B, hard cap 4096 B), rendered on the HOST into offset /
  hex / printable-ascii columns with absolute file offsets, so jumping
  to `read --hex --offset` for any interesting byte is one call.
  Works on text and binary alike, in single calls AND inside batches;
  hex + line-range is a clean 400 (hex slices bytes).

**Bench: S5 median-of-3 (session-19 lesson #4)**
* The ~2s deploy CLI spiked +50% single-shot on untouched code twice;
  the harness now records llmac_deploy_median_s (2 extra probes) and
  the gate compares medians when both runs carry them — same treatment
  S2/S3/S6/S8 got in 2.4.6, extended to the 2-second scale.

## v2.4.6 — sudo removals, GUI password + approval responsiveness

Three user-scoped items from session 17 plus a bench-hardening carry-over.

**Sudo package REMOVALS (user request: "add the removal as you did for
the package installation")**
* Removal forms join the exact v2.4.5 flow: `sudo pacman -R*` (also
  --remove), `sudo apt(-get) remove|purge`, `sudo dnf|yum
  remove|erase`, `sudo zypper remove|rm`, `sudo apk del|remove` —
  single commands, package args only, ALWAYS forced approval under
  every policy, same 2-minute countdown, same security-panel timeout
  setting, `decided_by="timeout"` audits.
* The Approvals tab labels them `[sudo remove]` (installs stay
  `[sudo install]`); the audit trail records sudo_remove_requested /
  sudo_remove_approved markers (and the same for installs).
* Detection stays fail-closed: chains (`a && b`), redirects, pipes,
  queries (`pacman -Q`), bare argless forms (`sudo apt remove`), and
  every other sudo shape (rm, pip, bash, sudoedit, ...) are rejected
  exactly as before. The combined shape lives in ONE regex pair
  (_SUDO_INSTALL_RE/_SUDO_REMOVE_RE) that sandbox.py imports, so the
  token exemption cannot drift between installs and removals.

**Sudo password field (user request: "type my sudo password in, filled
in by the program itself, never revealed to the AI/LLM")**
* New password field in the Security tab's sudo card. The password is
  stored in MEMORY ONLY — on the shared AppContext object, never in
  settings/state.json, never logged, never in ANY API response. There
  is deliberately NO API to set, read, or clear it: an agent must not
  even have a guessing oracle. It survives server stop/start within
  the same GUI session and vanishes on app exit; the status line says
  so, and Clear wipes it immediately.
* On the APPROVED sudo path only, _run_exec swaps `sudo <rest>` for
  `sudo -S -p '' <rest>` and pipes the password on stdin — no TTY
  needed. The password never appears in argv (ps-safe), in the
  session/audit records, or in the response (those keep the ORIGINAL
  command string). Wrong password surfaces as sudo's own "incorrect
  password attempt" in stderr — nothing secret crosses the wire.

**Approvals responsiveness (user report: "no highlight on the selected
approval, feels unresponsive")**
* Root causes fixed: the selected-row style was a 30%-alpha wash over
  a near-black list (now a strong fill + accent bar + bold white,
  hover brightened); Approve/Deny were always-enabled and silently
  no-op'd without a selection (now they track the selection live,
  start disabled, and say so in their tooltips); double-clicking an
  entry now approves it. The 1s countdown tick keeps rebuilding the
  pending list incrementally, so selections survive the refresh.

**Bench: median-of-N for sub-second scenarios (session-17 lesson #3)**
* S2/S3/S6/S8 now record median_wall_s (warm-up + 5 timed passes) in
  tools/bench_llmac.py; scripts/compare_bench.py gates on it whenever
  both runs carry it. Single-shot sub-second walls jitter ±15% on
  unchanged code (live evidence: S3 flagged +10–15% twice while an
  N=9 probe showed −1.2%); medians end the false alarms.

## v2.4.5 — sudo package installs (forced approval + countdown) and restart-surviving procs

Two user-scoped features: distribution package installs through sudo
with an ALWAYS-ON approval flow, and background procs that survive
server/GUI restarts.

**Sudo package installs (user request, session 16)**
* Agents may now install distro packages: `sudo pacman -S <pkg>` /
  `sudo apt(-get) install <pkg>` / `sudo dnf|yum install <pkg>` /
  `sudo zypper install <pkg>` / `sudo apk add <pkg>` (also pacman
  -Sy/-Syu upgrade forms). Single command only — no `;`, `&&`, `|`,
  redirects, or non-package arguments; anything else under sudo
  remains rejected (`sudo_not_package_install`), as do all removal
  forms and `sudoedit`/`doas`/`pkexec`/`su`.
* Such commands ALWAYS raise a host approval — REGARDLESS of the
  approval policy (auto and auto_all included; the policy
  short-circuit and the grants system are deliberately skipped for
  them, so there is no silent path and no reusable grant).
* The approval carries a 2-MINUTE COUNTDOWN (default 120 s; the
  `sudo_timeout_s` settings key exists for hosts that want to tune
  it, floor 5 s). If the human does not decide in time, the request
  auto-ACCEPTS or auto-REJECTS per the NEW security-panel setting
  "On 2-minute timeout" (default auto-REJECT — fail closed). The
  resolution is recorded with decided_by="timeout" so audits
  distinguish machine decisions from human ones.
* GUI: new "Sudo package installs" card in the Security tab (the
  timeout-action combo); the Approvals card shows a live MM:SS
  countdown per sudo request (ticks on the 1 s poll) with the
  auto-action that will fire.
* Layers share one shape: the allowed sudo form is defined once in
  policy.py and imported by sandbox.py (which previously banned
  every sudo token) — the sandbox now lets exactly that form through
  to the policy layer, which always attaches the forced approval or
  a rejection. Background `proc start` refuses sudo outright (no
  approval flow exists there — closed bypass).
* In a `batch`, a sudo exec pre-flights as allowed and gates at run
  time; a denied/timed-out approval is a per-op result, not a batch
  abort.

**Restart-surviving detached procs (the RE-campaign resilience item)**
* `proc start` procs are now truly detached: metadata (meta.json:
  id/name/command/cwd/os_pid/started_at/returncode) and logs
  (stdout.log/stderr.log) persist under `<data_dir>/procs/<id>/`.
* Server shutdown NO LONGER kills running procs (the headless runner
  now prints which procs were left running). On the next start the
  manager re-attaches every persisted proc whose os_pid is still
  alive (liveness via /proc + kill(pid,0); stop via killpg — the
  child was made a session leader at spawn), so `proc list` /
  `proc logs` / `proc stop` keep working across restarts, with a
  `(reattached)` marker. Finished procs stay readable for their logs
  and are pruned after 24 h.
* `proc logs` now reads the on-disk files (tail-capped at 4 MB per
  read), so log history also survives restarts.

Tests: tests/test_v245_sudo_and_detached.py (23: policy matrix x5,
registry countdown x5, forced-approval E2E under auto/auto_all x6
incl. timeout-approve-runs-the-command + human approve/deny + proc
bypass closed + batch per-op, detached procs x5 incl. shutdown-
no-kill + re-attach + stop-reattached + finished-reload + prune +
full-context rebuild, version). Version literals in v240/v241/v244
suites bumped to 2.4.5.

## v2.4.4 — RE ergonomics: exec --save, stale-conn hint, session export

Re-ranked against the new goal (large-scale reverse-engineering
workloads): the platform's measured context-economy wins (47x ranged
reads, 200x search, 22x batch) only pay off on an RE project if the
multi-MB tool OUTPUTS also bypass the agent's context. Three items:

**exec --save PATH (the RE workflow primitive)**
* `POST /exec` (and exec ops in `batch`) accept `save`: an absolute
  path inside the sandbox. The command's stdout streams FULL and
  UNCAPPED into that file (the inline path caps at 1 MB and truncates);
  stderr still returns inline; the response carries `saved_path` +
  `saved_bytes` instead of stdout. No shell redirect in the command
  string, so no redirect-target lint, no quoting games.
* The target is validated BEFORE anything runs: missing parent dir ->
  400 `save_dir_missing`, outside the sandbox -> 403
  `save_outside_sandbox`, `.git` -> 403 `protected_path`. In a batch a
  bad target refuses the WHOLE batch (B4 atomicity preserved — proven
  by test: an earlier exec's marker file never appears).
* A timeout keeps the partial output written so far (`timed_out=true`
  plus whatever landed in the file — 40-minute Ghidra runs that hit
  the ceiling still leave their progress inspectable).
* CLI: `llmac exec --command ... --save HOST/PATH` prints
  `[saved N B -> PATH]` with a follow-up tip; `--json` gains
  `saved_path`/`saved_bytes`.

**Stale-connection UX hint (client)**
* `Client._request` now distinguishes "a live connection died under
  me" (reused socket -> the server was most likely RESTARTED; hint:
  wait and re-run, or `--retry N`) from "could never connect" (down /
  wrong host/port / TLS-plain mismatch; hint: check flags). The hint
  lives in the ONE place all 26+ command paths print from, so every
  subcommand benefits. exec still refuses auto-retry (F20 rule).

**session export**
* `POST /session/status {all_notes: true}` returns the FULL notes log
  (up to the 100-note cap) instead of the last 10.
* `llmac session export [--out F]` dumps agent/started_at/exported_at/
  note_count/notes as JSON — the hand-off artifact for the next
  session, written locally for zero context cost.

Tests: tests/test_v244_re_ergonomics.py (17: hint x3, save x10 incl.
1.29 MB uncapped + timeout-partial + batch atomicity, export x3,
version). Version-coupled literals in v240/v241 suites bumped.

## v2.4.3 — venv visibility: configured vs discovered (user-reported bug)

Found live by the user after the v2.4.2 restart: venvs created by
agents during the session-13 venv/package tests "never showed up in
install venvs in the GUI". Root cause: two different lists that looked
like one — the GUI "Install venvs" card renders `settings["venvs"]`
(the manually configured allow-list, human-managed via Add/Remove),
while venvs created via agent exec (`python -m venv X`) were tracked
ONLY in the server's runtime set. The GUI never read that set, and
`_sync_policy_venv()` (any GUI add/remove) overwrote it wholesale —
wiping the runtime discoveries from the running server. `/info` mashed
both into one opaque `venvs` list, and the v2.4.2 pruning could even
silently drop CONFIGURED entries whose directory was missing.

**Policy: configured vs discovered split**
* `InstallPolicy` now keeps two sets: `venvs` (configured allow-list,
  seeded from settings, GUI-managed) and `discovered_venvs`
  (agent-created this run, runtime-only, never persisted). Install
  scoping checks (tool-token and activation forms) accept roots from
  either set — behavior is a superset of before, nothing that worked
  regresses.

**API: `/info` reports both lists, pruning scoped correctly**
* `/info` now returns `venvs` (configured) and a new
  `venvs_discovered` (agent-created) — old clients just display the
  JSON, so the extra key is fully backward compatible. The v2.4.2
  dead-venv pruning now touches ONLY the discovered set: a configured
  entry survives `/info` even if its directory is (temporarily)
  missing — it is the human's configuration, not a runtime observation.

**GUI: "Discovered venvs" list in the Install venvs card**
* The card grows a read-only "Discovered venvs — created by agents
  this session" list, polled every 5s straight from the running
  server's policy (no flicker — rebuilds only on change; placeholder
  while the server is stopped). The configured list above it stays
  exactly as before (editable, persisted). The human finally sees
  every venv agents created, live, without touching anything.

Suite: 289 existing + new tests/test_v243_venv_visibility.py on
Python 3.12 and 3.14.8.

## v2.4.2 — policy correctness + gate completeness (user: "do whatever you want")

Scope re-ranked against fresh session-12 live data (post-restart smoke
8/8, live acceptance B1/B2/B4, full live bench, and a user-requested
venv/package-management test that found a real bug). Suite: 289/289
(21 new, tests/test_v242_policy_and_polish.py) on Python 3.12 and
3.14.8.

**Activation-form install fix (the live-found bug)**
* The install-policy rejection hint advertises `source
  .venv/bin/activate && pip install X` as an allowed form — but the
  analyzer had NO detection for it (only `bin/pip`|`bin/python` tool
  tokens counted as venv-scoped), so the exact form from the hint was
  rejected as `install_not_in_venv`. Found live on the host during the
  session-12 venv test. Fixed: activation tokens (`bin/activate*`,
  `Scripts/Activate.*`, all shell variants) are recognized; the token's
  grandparent must be a marker-detected (pyvenv.cfg) or tracked venv,
  and the activation must PRECEDE the first pip-family attempt in the
  token stream (activation afterwards scopes nothing → still
  rejected). Covers `pip`/`pip3`/`python -m pip` after activation.

**/info venv pruning**
* Remembered venvs that no longer exist on disk (agent deleted them)
  now disappear from `/info` without a restart — session-12 finding:
  a stale entry lingered until the next GUI restart. Liveness test =
  `pyvenv.cfg` at the remembered root (entries are always roots created
  via `python -m venv X`). One cheap stat per remembered venv.

**Deploy output: transport cost surfaced**
* `deploy` success line now reads `N/N verified (M batch call(s), no
  exec)` on v2.4.1+ servers — or `… (M batch call(s), exec fallback)`
  on older servers — so a deploy is self-verifying in its own output
  (the session-12 checklist had to prove the zero-exec property via
  the session exec counter; now the line says it).

**Bench gate completeness (harness)**
* `tools/bench_llmac.py` now covers ALL nine baseline scenarios:
  S6_edit_cas (edit loop incl. the stale-version 409 — doubles as a
  guard for the v2.4.1 status change) and S8_transfer (redesigned
  self-contained: the repo's biggest file pulled three ways — /read,
  stat --hash, CLI download — with a three-way sha256 agreement check,
  no pinned zip constants) were ported in from the pre-release harness.
  Fresh baseline committed from the unified methodology.

**Bootstrap prompt + agent.md teach orient (B1 adoption)**
* The GUI "Copy agent prompt" block now says `orient --path <root>` as
  the first look-around move and mentions deploy/run/verify/diff;
  agent.md Quick start + efficiency list updated the same way, and the
  venv entry documents both install forms as working. Measured: orient
  replaces the 5-call / 6.6K-token boot with 1 call / ~350 tokens.

## v2.4.1 — Tier B: server-side agent-efficiency + real HTTP statuses

Scope re-ranked against the same-day bench baseline (the server was
unchanged since those measurements); user approved all four Tier B
items + the error-status fix as ONE release. Suite: 268/268
(41 new, tests/test_v241_tier_b.py) on Python 3.12 and 3.14.8.

**Error statuses (the queued finding, fixed)**
* Handler "business" errors used to return HTTP 200 + `{"error":…}`.
  They now carry real statuses — 404 not_found/cwd_not_found/src_not_found,
  400 missing_field/bad_request/not_a_directory/range_invalid/binary_file,
  403 no_roots, 409 dest_exists/confirm_required, 413 file_too_large,
  503 exec_busy/bootstrap_unavailable — with **bodies unchanged**, so
  v2.3–v2.4.0 clients (which parse JSON regardless of status and check
  `"error" in resp`) work unmodified. Analyzer REJECTIONS stay
  HTTP 200 `{"rejected":true}` — a rejection is a result, not an error.
  Batch per-op errors stay embedded in the 200 envelope (and now carry
  the op name on the OpBlocked path too).

**B3 — `/stat {hash:true}` + `verify` (ships first: unblocks no-exec verification)**
* `stat --path P --hash` streams sha256 server-side (≤64 MB; above that
  `sha256_skipped` with a note). Batch stat ops accept it. `llmac verify
  --local F --remote P` hashes both sides and compares — acceptance:
  MATCH and MISMATCH both verified on a host with **exec disabled**.
* `deploy` (A1) now rides stat-hash ops in the SAME batch, right after
  each write — upload+verify is ONE call, zero exec, on v2.4.1 servers;
  old servers (stat without sha256) transparently fall back to the one
  sha256sum exec (previous behavior).

**B1 — `POST /overview` + `orient` (orientation in one call)**
* `llmac orient [--path P] [--depth N] [--doc-heads N] [--budget B]`
  returns the info core (version/policy/exec/roots), a depth-capped
  sized tree, heads of README*/agent.md, and a session pointer —
  trimmed to a byte budget (default 4000) by a documented ladder
  (doc heads → tree tail → docs → tree). Acceptance vs the measured
  5-call / 6.6K-token fresh-agent boot: 1 call, ~2K tokens.

**B2 — `POST /diff` (server-side unified diff)**
* `llmac diff --a P --b P2` or `--a P --inline-file F` (write dry-run).
  Unified diff + `+added/-removed` counts, 200KB cap with head/tail
  trim, `same:true` for identical, sandbox/protected checks identical
  to read, binary refused cleanly (400). Replaces the re-read-both-
  files loop; diff is typically 1–2% of the compared bytes.

**B4 — exec inside batch (mixed ops, deliberately last)**
* `{"op":"exec","command":…,"timeout":…}` in `/batch`. EVERY exec op is
  pre-flighted (cwd + sandbox analyzer + install policy) BEFORE anything
  executes: one bad command refuses the whole batch (400
  `exec_preflight` + index) with ZERO side effects — tested by writing
  a file and then a rejected exec, asserting the file was never created.
  Ops run in order (exec sees preceding writes); non-zero rc/timeout is
  a normal per-op result; `exec_busy` is a per-op error; strict policy
  refuses batched exec like it refuses batched writes; exec-disabled
  hosts refuse with 403 before any op runs.
* h_exec was refactored into `_exec_cwd/_exec_timeout/_preflight_exec/
  _run_exec` shared by /exec, /proc and batch so the semantics cannot
  drift. `llmac batch` plain output now shows `exec: ok rc=N | preview`.

**Constants**: `STAT_HASH_MAX_BYTES` 64MB, `MAX_DIFF_BYTES` 200KB,
`OVERVIEW_*` (budget 4000/16000, depth ≤4, doc heads ≤200, 200 tree
entries). Version 2.4.1 everywhere (core.constants + standalone
fallback literal).

## v2.4.0 — agent-efficiency tier (client-side; measured, benchmark-gated)

Every item below is justified by a number from the live-workload
benchmark (`tools/bench_llmac.py`, baseline
`tools/baseline-2026-10-25.json`; full report: AGENT-BENCH-2026-10-25.md).
Suite: 227/227 (30 new, tests/test_v240_tier_a.py). All changes are
client-side, so every feature works against a running v2.3.1 host.

**A1 — `deploy`: upload + verify in ONE invocation**
* `llmac deploy --pairs LOCAL=REMOTE [--pairs …] [--manifest F]` sends
  one `batch` of write ops (auto-chunked under the 64-op / 4MB caps),
  then one `sha256sum` exec, and prints a per-file ok/MISMATCH table.
* Measured: the real 12-file release loop (as done in v2.3.1 work) cost
  26 calls / ~15.7 s of one-shot invocations + bash-loop footguns;
  `deploy` does it in ONE invocation — 0.9 s, 12/12 hashes verified.
* `--dry-run` shows the plan without sending; `--no-verify` skips the
  hash pass (e.g. exec disabled on the host); per-op failures (e.g. a
  protected_path target) abort with "nothing verified".

**A2 — `run`: many commands, ONE process, ONE TLS session**
* Each one-shot CLI invocation pays ~439 ms fixed overhead (interpreter
  62 ms + TCP/TLS handshake ~190 ms + parser/imports) vs ~166 ms for
  the actual request — measured over WAN. `run --file cmds.json` (JSON
  array of arg-vectors) amortizes that: each extra command costs ~166 ms
  (3.6× per op). Stops at the first failure (rc propagates) unless
  `--keep-going`; summary line to stderr; `run`/`deploy` inside `run`
  are rejected (recursion/atomicity).
* Fixed en route (caught by the new tests, masked in live smoke because
  the saved default connection happened to be the intended host):
  sub-parsers don't see the top-level connection flags — `run` now
  propagates `--host/--port/--key/--fp/--plain/--retry/--conn/
  --no-verify` into each sub-command before executing it.
* The client is now cached per (host,port,key,fp,tls) within a process,
  so all sub-commands share one keep-alive TLS session.

**A3 — exec hygiene: `[rc=N]` footer + pre-flight lint**
* Plain exec always ends with `[rc=N]` on stderr (or `[rc=timeout]`),
  so scripted agents stop mistaking completed commands for transport
  failures — the stress round nearly re-ran a *completed* 30 s command
  for this exact reason. `--json` output is unchanged.
* Pre-flight lint (client-side, zero network, exit 2): `$(...)`, backticks
  and `$VAR` in `--command` are refused with an explanation — command
  substitution is evaluated by the agent's LOCAL shell before LLMAC
  ever sees the string (both traps were hit in real agent sessions,
  producing wrong-but-plausible results). `--i-know` overrides.

**A4 — smart reads: big text files can't blow context anymore**
* Reading a 93 KB text file whole put ~24.5K tokens into the agent's
  context (measured on gui.py) — one call cost more than an entire
  orientation boot. Plain `read` of a text file >32 KB with no range/
  `--to`/`--numbered` now returns head 200 + tail 50 lines plus a
  `[smart-truncated: …]` stderr marker with the recovery hints.
  `--raw` restores byte-exact full output; ranges were always exact.
* Fixed W6 en route: `download` without `--to` used to create a file
  literally named `-` (the default was never mapped to stdout).

**A5 — `--version` is honest**
* `cli.py` VERSION now derives from `core.constants.LLMAC_VERSION` when
  the package is importable (repo checkout) with a literal fallback for
  the standalone bootstrap file — v2.3.1 shipped a client reporting
  "2.3.0" everywhere.

**agent.md — efficiency playbook with measured numbers** (search 200×,
ranged reads 47×, batch 18×, the 2-call deploy recipe, `run` economics,
session-notes-vs-orientation costs). `tools/bench_llmac.py` is committed
as the efficiency regression gate: re-run before releases, compare
against the baseline.

Queued for v2.4.1 (server-side, from this round's work): error dict
bodies should carry proper HTTP statuses (e.g. `/read` of a missing file
returns 200 + `{"error":"not_found"}`), `stat --hash`, `/overview`
context pack, `/diff`, exec-in-batch (V24-PLAN.md, Tier B).

## v2.3.1 — stress-test remediation + "Auto - no restrictions" policy

Result of the ~230-check live stress test (report:
LLMAC-v2.3.0-STRESS-REPORT.md). Every fix below ships with a regression
test; suite is now 197/197 (42 new).

**New: `auto_all` — "Auto - no restrictions" approval policy**
* A fourth policy (GUI dropdown) identical to `auto` except **root-share
  requests are granted instantly by the server**: agents can expand
  their own sandbox. Grants are logged loudly, emitted as `roots_changed`
  events, and queued (`ctx.share_queue`) for the owner app to persist —
  the GUI's poll timer (main thread, Qt-safe) or a headless drain
  thread. Scoped agents also gain the share in their own scope.
  `/info` now reports `roots_auto_approved: true/false` so agents know
  which behavior to expect. Plain `auto` STILL human-gates shares by
  design — the approval card, CLI output and agent.md now say so
  explicitly (it surprised even the host: "why was it pending when I
  set auto?").

**Critical security fixes (from the stress report)**
* **F21/F22 — the server's own data dir is now a protected tree**
  (`Sandbox(roots, protected=[data_dir])`). It holds state.json (all
  agent keys), the TLS private key and the audit log and used to be
  fully readable through read/exec/search/archive when it sat inside a
  shared root. Every surface refuses it with `protected_path`:
  read/write/edit/stat/list, exec path tokens (reads AND redirect
  writes), and the search/tree/archive walkers never descend into it.
  Key/cert rotation is still recommended once (host-side, GUI) because
  the material was exposed before this fix.
* **F14 — `cp` copies symlinks AS LINKS** (`copytree(symlinks=True)`).
  Following them materialized the entire `/etc` inside the sandbox,
  smuggling data past every realpath defense.
* **F16 — output-redirect write targets must be inside the sandbox**.
  `EXEC_ALLOWED_OUTSIDE` (with its writable /tmp, /var/tmp, /run/user)
  is now read-only; writes allow only roots + `/dev/null`, `/dev/stdout`,
  `/dev/stderr`, `/dev/full`. Kills the /tmp file-drop and the
  tmpfs RAM-DoS vector.

**High fixes**
* **F1/F2 — connect actually verifies pinned fingerprints**:
  `connect --fp X` probes and compares BEFORE anything else (exit 3 on
  mismatch), TLS probe failures fail CLOSED everywhere (no more
  silently-unpinned saves), and `--save` refuses to persist a
  fingerprint-less TLS connection.
* **F18 — privilege-escalator token ban**: sudo/su/doas/pkexec/sudoedit
  rejected outright (`sudo reboot` used to reach the OS and fail only at
  the password prompt).
* **F20 — exec output amplification**: `_BoundedCapture` is bytearray +
  amortized compaction, the exec pump reads binary 64KB chunks (was
  per-line with quadratic tail re-slicing — 21MB pinned a core for 30s
  while the client reported transport failure for a command that
  actually completed). The client's HTTP timeout is now derived from
  `exec --timeout` (+30s), exec never auto-retries, and a transport
  failure prints an explicit "may still have completed server-side"
  warning.
* **F28 — binary-looking text is base64**: NUL/control bytes decode as
  valid UTF-8 but are binary in practice; a 200KB zero-filled file used
  to return as `binary:false` with 6x json-escaped bloat.
* **F29/F29a — archive integrity**: over-cap directories are REFUSED
  (`archive_too_large`, 400) instead of silently truncating into a
  valid-looking tar; `GET /archive` errors now return real HTTP error
  statuses (the CLI already checks them) — a nonexistent dir used to be
  saved as a 95-byte .tgz containing the error JSON, exit 0.

**Quality fixes**
* F4: read of a missing file → `not_found` + message (was `not_a_file`,
  empty). F5: user-caused OSErrors map to clean 4xx (`os_error` /
  `access_denied` with a chmod hint) instead of `500 internal` dumps.
* F11: edit insert/append/lines no longer add a stray blank line for
  content ending in `\n`. F6: the replace no-match error quotes the
  actual needle (was the literal word 'find'). F12: atomic-write temp
  files use a short `.llmac_tmp_<12hex>` name — 250-char filenames work.
* F19: refused exec cwd → HTTP 403 and CLI exit 2 (plain) / exit 1 with
  `error` (json); was exit 0 with only a buried JSON key.
* F27: `batch` plain mode prints a bounded read preview (content was
  --json-only). F24: archive --get prints a dotfile-skip reminder.
* F30: global auth-failure counter (per-IP limiting was defeatable by
  rotating cloud egress IPs) — 40 failures/5min from ANYWHERE pauses
  auth with `rate_limited_global`.

## v2.3.0 — Tier 1 + Tier 2: round-trip economy, workflow, grants

Theme: make the agent fast *using the host's resources* by cutting
round trips and context bytes, and give the host time-boxed approval
grants so supervising stops meaning "click Approve every 10 seconds".
Server stays stdlib-only. 155/155 tests (26 new).

**Tier 1 — protocol**
* **Keep-alive + gzip (F1)**: responses no longer force
  `Connection: close`; HTTP/1.1 sessions persist so one TCP+TLS
  handshake covers many ops. JSON bodies ≥512B are gzipped when the
  client sends `Accept-Encoding: gzip`. The CLI reuses one
  `http.client` connection per process, decompresses transparently,
  and gets one free retry when a server-closed keep-alive socket dies
  mid-request.
* **`POST /batch` (F2)**: up to 64 ops (read, stat, list, tree,
  search, mkdir, write) in one request with per-op error isolation, an
  8MB aggregate response cap, per-op policy checks and session
  recording. Deletes/moves/copies stay single-op by design, and under
  `strict` policy batch refuses writes so every write keeps its own
  human approval. CLI: `batch --ops '…'` / `--file ops.json` / stdin.
* **Archive endpoints (F3)**: `GET /archive?path=…` streams a
  directory as tar.gz (5000 entries / 256MB caps, respects the usual
  ignore set, `all=1` includes hidden files, `.git` is *never*
  archived). `POST /archive` extracts under a shared root with
  hardened validation: rejects absolute/`..` names, symlinks,
  devices, `.git` targets, refuses existing files without
  `overwrite=true`, and extracts through tarfile's `data` filter as
  a second line of defense. CLI: `archive --get/--put`.

**Tier 2 — workflow + policy**
* **Time-boxed approval grants (F7)**: approving a gated op now
  offers "also grant this op under this subtree for 30m/1h/4h".
  Grants live in `settings.grants` (persisted), are scoped by path
  prefix and checked *before* any interactive approval, expire by
  themselves, merge when re-granted for the same scope, and can be
  revoked from the new **Active grants** card in the Approvals tab.
  CLI: `grants` lists your live grants.
* **`exec --json` (F6)**: machine-readable exec results for scripted
  use.
* **`--retry N` (W4)**: the CLI now survives host restarts —
  `llmac.py --retry 90 info` keeps retrying transport failures for N
  seconds instead of burning a conversation round trip.

**Fixes from live sessions**
* **W1**: `GET /info` and root-less `POST /list` keep working when
  *zero* directories are shared (a live session hit a stale-bytecode
  mix that returned `no_roots` from `/info` and stranded the agent;
  the regression test now pins the correct behavior).
* **W2**: every `no_roots` error carries a human-readable message
  (and points at `roots request`).
* **W5**: `download` crashed with `AttributeError` — its subparser
  never defined `--lines/--offset/--limit` that the shared
  `cmd_read` implementation reads (the v2.1.1 lesson again: the
  served client's every subcommand must be exercised verbatim).
  Download now supports ranged downloads; regression-tested via a
  CLI subprocess.
* **W3**: verified + regression-tested that `allow_exec`, agent exec
  perms and grants all survive host restarts through `state.json`.

## v2.2.0 — modern GUI theme

**The problem**: the v2.1 GUI was functional but visually broken — a VLM
audit of offscreen screenshots rated it 3/10: the bind-host dropdown was
literally invisible (Qt stops painting the native chevron as soon as QSS
styles a combo box, and the stylesheet never drew one), everything was a
1px-bordered rectangle stacked inside other rectangles, the scrollbar
read as a divider line, and secondary text was too dim.

* **Affordances are now drawn, never assumed**: `gui._ensure_theme_assets`
  paints the combo chevron and the checkbox tick into
  `<data_dir>/assets/*.png` at startup (QPainter, anti-aliased) and the
  stylesheet references them. The invisible-dropdown bug cannot recur —
  the glyphs exist as real images.
* **Elevation, not frames** (VLM-verified 3/10 → 9/10 over three review
  rounds): cards are deep-slate surfaces with near-invisible hairlines;
  lists/tables/log are borderless inset wells; section titles are
  small-caps overlines instead of boxed headers; tables lost their grid
  lines in favor of alternating rows; the processes table got taller
  rows.
* **New palette**: window `#0b0e14`, surfaces `#121722`, inset wells
  `#0a0d13`, one indigo accent (`#7c8cf8`) for focus/selection/primary,
  brighter muted text, semantic green/amber/red for state. Scrollbars
  are now a visible rail + thumb with hover feedback. Danger buttons are
  tint-style (fill on hover) instead of heavy red slabs.
* **Fusion + dark QPalette app-wide** (`gui.apply_theme`): native bits
  QSS cannot reach (dialogs, scroll interaction, disabled states) no
  longer flash white or go unreadable. `host.py` calls `apply_theme`
  instead of applying the raw stylesheet.
* Verified offscreen at 940x660 and 700x500 across all six tabs plus 2x
  close-up crops; final VLM pass: PASS on all six checks (chevron
  contrast, borderless wells, scrollbar, text legibility, checkbox tick
  rendering, artifacts), overall 9/10.

## v2.1.1 — bootstrap one-liner hotfix

**What broke**: the self-install one-liner that the host hands every new
agent (GUI "Copy Prompt", headless banner, agent.md) passed the
Authorization key as the positional `data` argument of
`urllib.request.Request(...)` instead of as a header. Two consequences:
(1) with dict data, http.client walks the chunked-encoding path,
iterates the dict, gets string keys and dies with
`TypeError: can't concat str to bytes` on CPython — the command crashed
before even sending; (2) had it survived, the key would have landed in
the request body (401) and the implied POST would have hit a GET-only
route (404). Found the hard way by the first agent to run the generated
command verbatim against a live host — the test suite never caught it
because tests/helpers.py always used the correct `headers=` form.

* `build_prompt_text` now emits `headers={'Authorization':'Bearer KEY'}`
  with no data — a clean GET that works on every CPython.
* `/bootstrap` additionally accepts POST (defensive: hand-rolled
  clients that pass an empty body turn the request into a POST).
* `core/__init__.py` no longer carries a stale hardcoded version; it
  re-exports `LLMAC_VERSION` from `core.constants`.
* New regression tests: the exact one-liner rendered by
  `build_prompt_text` (TLS and plain) is executed verbatim in a clean
  temp dir against a live local host and must produce a working
  `llmac.py`; POST `/bootstrap` is covered too.

## v2.1.0 — share requests + tabbed GUI

**The big idea**: the host can now start with zero shared directories.
The agent connects, asks for the directories it needs through the host
itself, and the human approves with one click. Plus the GUI was rebuilt
around tabs so it stays usable at any window size.

* **Agent-initiated shares**: `POST /roots/request` (CLI: `roots
  request --path P --reason R`). The request lands in the GUI approval
  queue with the full reason; approving it adds the directory to the
  shared roots immediately (no reconnect needed). Always human-gated —
  even under the `auto` policy — because expanding the sandbox is a
  pure trust decision. Duplicates collapse; >20 pending requests get
  `too_many_pending`; paths must exist on the host. `/info` advertises
  `can_request_roots`.
* **GUI rebuilt as a tabbed supervisor** (was six stacked panels that
  clipped when the window was small):
  * Tabs: Overview (connection card + shared directories), Agents,
    Approvals, Processes, Security, Log. Every tab scrolls instead of
    clipping; the window works down to 640×480.
  * Header pills + tab badges for pending approvals and running
    processes (click a pill to jump to the tab); status bar with
    run state and address.
  * Approving a share request applies it; denying just declines.
    Recent decisions list.
  * New Processes tab: table of agent-started background processes
    with Stop selected / Stop all.
  * Security tab: approval policy with plain-language descriptions,
    exec toggle, TLS state + full fingerprint, **install-venv manager**
    (add/remove venv directories, synced live to the policy).
  * Starting the server with no directories is allowed and guided
    (the agent can request shares).
  * Add-agent is one dialog now (name + scope + key lifetime + perms)
    and the key is auto-copied.
  * Flat dark theme (GitHub-dark-inspired), card layout, modern tabs.
* **Bug fixed (latent, v2.0)**: `POST /approvals/wait` crashed with a
  500 (`AttributeError: 'dict' object has no attribute 'to_dict'`) —
  the registry's `status()` already returns a dict; the handler
  double-converted it.
* Tests: 115 → **125** (new `test_roots_request.py`: gating under
  `auto`, dedup, already-shared, validation, deny/approve flows,
  zero-root agent regains access, flood cap, payload propagation).

v2 is a breaking rewrite of the wire protocol, driven by a security
audit of v1 plus the goal of turning the bridge into a real harness
adapter. Old `cli.py` (v1) does not speak v2.

## Security fixes (Phase 0)

* **Default bind is 127.0.0.1** (was 0.0.0.0). Network exposure is now
  an explicit opt-in (`--expose` / GUI). Plaintext-on-LAN by default is
  gone.
* **TLS by default** with an auto-generated self-signed cert (openssl).
  Agents verify the certificate fingerprint (SSH-style trust-on-first-
  use, pinned via `--fp`); mismatches abort the connection.
* **Real containment**: `Sandbox.resolve()` now requires both the
  lexical and the realpath to be inside the same root — defeats
  symlinks pointing outside (v1 escaped trivially).
* **Exec checking rewritten**: shlex tokenization instead of regex over
  the raw string; simulates `cd` so relative-path escapes are caught;
  validates redirect targets (`>`, `>>`, `<`); rejects `~`, `$VAR`,
  command/process substitution. Windows drive-letter paths handled.
* **Install policy v2**: venvs recognized by marker files (`pyvenv.cfg`
  / `conda-meta`) — a venv created before the server restarted still
  works (v1 lost tracking and locked agents out). npm/yarn/pnpm global
  installs detected position-aware (`npm i pkg -g` was a v1 bypass).
  Added: apk, snap, gem, choco, winget, flatpak rejected; pipx/poetry/
  pdm/uv/cargo/go classified as scoped; conda requires `-n`/`-p`.
* **Auth hardening**: per-agent keys (constant-time compare), scopes,
  permissions, expiry; per-IP failure rate limiting (5/min → 60s lock).
* **Server-enforced caps** (client values are clamped, never trusted):
  request body 16MB (drained on 413 so clients get a clean error),
  exec output 1MB head+tail, exec timeout 1..600s, concurrency
  semaphores (16 requests / 4 execs).
* **Protected paths**: a shared root itself and everything under `.git`
  can never be deleted/moved-overwritten. Recursive deletes >20 files
  require explicit client `confirm=true`.
* **DoS fixes**: exec output is no longer buffered unboundedly (v1 OOM
  on `head -c 10G /dev/urandom`); long-poll endpoints don't hold the
  request semaphore.
* `state.json` back to chmod 600 (data dir stays 755 so contents remain
  deletable without sudo).
* Removed side effects: reading a file no longer chmods it (v1 did!),
  writes preserve the existing file mode (v1 dropped exec bits).

## Harness features (Phase 1)

* **Self-bootstrap**: `GET /bootstrap` serves the CLI to the agent;
  `Copy Prompt` emits a two-command incantation (connect + save).
* **CLI v2** (`cli.py`): single file, stdlib only, saved connections
  (`~/.llmac/connections.json`), TOFU fingerprint pinning, compact
  output, all new commands.
* **Context economy**: `/search` (regex+glob grep, capped, context
  lines), `/tree` (gitignore-aware, depth/entry capped), ranged reads
  (`--lines A-B`, `--offset/--limit`, numbered), `/edit` with five op
  kinds returning unified diffs.
* **Write versioning**: `expected_version` tokens → `409
  version_conflict` instead of silent clobbering.
* **Background processes**: `/proc/start|list|logs|stop` with ring
  buffers, exit events, group-kill on stop/shutdown.
* **Session memory** (server-side): every op recorded; agent notes;
  `session status` returns a compact digest — context recovery after
  chat pruning without re-reading files.
* **Events**: `/events?since=&wait=` long-poll: proc exits, approvals,
  writes by other agents, notes.

## Supervision (Phase 2 core)

* **Agents panel**: named keys with root scope, per-op permissions,
  expiry; add/revoke live while the server runs.
* **Approval queue** (GUI): `auto` / `destructive` (default) / `strict`
  policies; ops block until you click Approve/Deny (or return 202
  `approval_pending` with an id to poll).
* **Audit**: every op — including exec commands, exit codes, and
  rejections — lands in the rotating append-only `history.jsonl`.

## Structural

* `server.py` monolith split into the `core/` package (sandbox, policy,
  api, state, sessions, approvals, events, procs, edits, search,
  tlsutil, server); `server.py` is a headless back-compat shim.
* Unified naming (LLMAC), unified docs (README + agent.md), v1 state
  files migrate transparently to the v2 schema (agents + settings).
* 115 tests (sandbox bypasses, policy, edits, search, API integration,
  approvals, sessions, TLS, CLI end-to-end) — v1 had none.
* Exports contain agents+settings; keys fingerprinted in all logs.

## Known limitations (documented, by design)

* Exec sandbox is static analysis — advisory, not a security boundary.
  Strong isolation: run the host under a dedicated user (or don't
  enable exec).
* Search's .gitignore support is a pragmatic subset (no anchored or
  negated rules).
* MCP adapter and built-in agent loop (the v2 plan's Phase 3) are the
  next milestones; the core API was shaped so both are thin layers.
