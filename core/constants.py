"""Constants for the LLMAC host: defaults, caps, protocol values."""
from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# Identity / protocol
# ---------------------------------------------------------------------------

LLMAC_VERSION = "2.7.3"
KEY_PREFIX = "llmac_"
STATE_SCHEMA_VERSION = 2
EXPORT_FORMAT = "llmac-session-export"
EXPORT_VERSION = 2

# ---------------------------------------------------------------------------
# Network defaults
# ---------------------------------------------------------------------------

DEFAULT_PORT = 8765
# SECURITY (v2): bind localhost by default. Exposing to the network is an
# explicit opt-in (--expose / GUI combo). The old 0.0.0.0 default invited
# accidental exposure of the bearer key + file contents in cleartext.
DEFAULT_HOST = "127.0.0.1"
EXPOSED_HOST = "0.0.0.0"

# ---------------------------------------------------------------------------
# Resource caps (server-enforced; client values are clamped to these)
# ---------------------------------------------------------------------------

MAX_BODY_BYTES = 16 * 1024 * 1024          # 16 MB request body
MAX_READ_BYTES = 5 * 1024 * 1024           # 5 MB per read call (offset/limit allows paging)
MAX_SEARCH_RESULTS = 200                   # grep/glob hits per call
MAX_SEARCH_FILES = 3000                   # files walked per search
MAX_TREE_ENTRIES = 500
MAX_BATCH_OPS = 64                         # ops accepted per POST /batch
MAX_BATCH_RESPONSE_BYTES = 8 * 1024 * 1024  # aggregate /batch response cap
MAX_ARCHIVE_ENTRIES = 5000                 # members per archive GET/PUT
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024      # uncompressed bytes per archive
GZIP_MIN_BYTES = 512                       # don't gzip responses below this
GRANT_MAX_MINUTES = 24 * 60                # longest approval-grant lifetime
EXEC_TIMEOUT_MIN = 1
EXEC_TIMEOUT_DEFAULT = 300
EXEC_TIMEOUT_MAX = 600                     # hard server-side ceiling
EXEC_OUTPUT_CAP = 1024 * 1024              # 1 MB combined stdout+stderr
EXEC_HEAD_KEEP = 256 * 1024                # bytes kept from the top
EXEC_TAIL_KEEP = 256 * 1024                # bytes kept from the bottom
MAX_CONCURRENT_REQUESTS = 16
MAX_CONCURRENT_EXEC = 4
MAX_PROCS = 8                              # background processes
PROC_LOG_LINES = 500                       # ring-buffer lines per stream
DELETE_CONFIRM_THRESHOLD = 20              # files beyond which confirm=true is required
APPROVAL_WAIT_MAX = 120                    # seconds a call may block for a decision
SUDO_APPROVAL_TIMEOUT_S = 120              # sudo package installs: countdown
SUDO_TIMEOUT_MIN_S = 5                    # settings['sudo_timeout_s'] clamp
SUDO_TIMEOUT_MAX_S = 600
PROC_META_KEEP_HOURS = 24                  # finished proc dirs pruned after this
SESSION_OPS_CAP = 500
SESSION_NOTES_CAP = 100
SESSION_INBOX_CAP = 200   # v2.5.0 (ASK-001): user->agent inbox messages
                         # kept per agent, drop-oldest like notes
OP_RING_CAP = 1000                     # v2.5.2 (ASK-010): op-log ring entries (host-wide)
SESSION_LOG_DEFAULT = 200              # v2.5.2 (ASK-010): POST /session/log default limit
SESSION_LOG_MAX = 1000                # v2.5.2 (ASK-010): POST /session/log hard cap
STAT_HASH_MAX_BYTES = 64 * 1024 * 1024   # /stat hash=true files above this skip hashing
MAX_DIFF_BYTES = 200 * 1024            # unified-diff text cap on POST /diff
HEX_DEFAULT_BYTES = 512                # read hex=true slice when no limit given
MAX_HEX_DUMP_BYTES = 4096                # read hex=true hard cap per response
HEX_FIND_MAX_HITS = 25                 # read hex=true find: default hit cap
HEX_FIND_MAX_HITS_CAP = 100           #   server-side hard cap (find_max_hits)
HEX_FIND_CTX_BEFORE = 32              #   context bytes before each hit (16-aligned down)
HEX_FIND_CTX_AFTER = 32               #   context bytes past each hit's end
HEX_FIND_PATTERN_MAX = 1024           #   longest find_hex/find_text pattern (bytes)
PROC_LOG_EVENT_MIN_S = 1.0              # proc_log event watcher poll interval
OVERVIEW_BUDGET_DEFAULT = 4000         # /overview response byte budget
OVERVIEW_BUDGET_MAX = 16000
OVERVIEW_DEPTH_MAX = 4
OVERVIEW_DOC_HEADS_MAX = 200
OVERVIEW_TREE_ENTRIES = 200            # tree lines kept before budget trimming
HISTORY_ROTATE_BYTES = 10 * 1024 * 1024    # rotate history.jsonl at 10 MB

# ---------------------------------------------------------------------------
# The screen channel (v2.7.0 — ASK-016/017)
# ---------------------------------------------------------------------------
DEFAULT_SHOT_DIR = "/mnt/Tera/Process/llmac-work/shots"  # evidence dir (setting screen_shot_dir)
MAX_SHOT_WIDTH = 20000                  # screen.shot max-width clamp
SHOT_JPG_QUALITY = 85                   # jpg encode quality
SCREEN_INPUT_MAX_EVENTS_DEFAULT = 500   # drive-mode event cap (setting screen_input_max_events)
SCREEN_INPUT_MAX_MINUTES_DEFAULT = 10   # drive-mode time cap, minutes (setting screen_input_max_minutes)
HISTORY_KEEP_GENERATIONS = 2

# Directory names skipped by search/tree (unless all=true)
DEFAULT_IGNORES = {
    "node_modules", ".venv", "venv", "env", "__pycache__", ".git",
    ".hg", ".svn", "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "target", ".idea", ".vscode", ".next", ".cache",
    "vendor", "bower_components", ".terraform",
}

# Paths outside the sandbox that exec commands may reference (POSIX).
# NOTE: this whitelist is for READS. Redirect WRITE targets are checked
# separately (EXEC_WRITE_ALLOWED_OUTSIDE): a world-writable whitelist entry
# such as /tmp would otherwise be a file-drop / tmpfs-RAM-DoS escape hatch.
EXEC_ALLOWED_OUTSIDE = frozenset({
    "/dev/null", "/dev/urandom", "/dev/zero", "/dev/random",
    "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/fd",
    "/proc/self", "/proc/version", "/proc/sys",
    "/sys",
    "/tmp", "/var/tmp",
    "/usr/bin", "/usr/lib", "/usr/local", "/usr/share", "/usr/include",
    "/bin", "/sbin", "/lib", "/lib64", "/lib32",
    "/etc/hostname", "/etc/os-release", "/etc/timezone",
    "/etc/localtime", "/etc/resolv.conf",
    "/run/user",
    "/opt",
})

# The ONLY non-sandbox paths an output redirect (>, >>, &>) may target.
# Everything else must live inside a shared root. Input redirects (<)
# still use EXEC_ALLOWED_OUTSIDE (reading system paths is far less
# dangerous than writing them).
EXEC_WRITE_ALLOWED_OUTSIDE = frozenset({
    "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/full",
})

# Privilege-escalation commands, banned at exact-token granularity anywhere
# in the token stream. Unlike path checks this is reliably detectable, so
# the analyzer owns it: a NOPASSWD sudo on the host turns 'sudo reboot' into
# a real reboot. (Paths inside code strings remain invisible — see agent.md.)
EXEC_TOKEN_DENYLIST = frozenset({
    "sudo", "sudoedit", "doas", "pkexec", "su",
})

# Approval policy values
POLICY_AUTO = "auto"                # no approvals (headless default);
                                    # root-share requests still human-gated
POLICY_FULLAUTO = "auto_all"         # 'Auto - no restrictions': like auto,
                                    # plus agents may expand their own sandbox
                                    # (share requests are granted instantly)
POLICY_DESTRUCTIVE = "destructive" # recursive/large deletes + strict ops gated
POLICY_STRICT = "strict"           # all writes + deletes + exec gated

VALID_POLICIES = (POLICY_AUTO, POLICY_FULLAUTO, POLICY_DESTRUCTIVE,
                   POLICY_STRICT)

# Default per-agent permission set
DEFAULT_PERMS = {
    "read": True,
    "write": True,
    "delete": True,
    "exec": False,
    "proc": False,
}

# ---------------------------------------------------------------------------
# Filesystem locations
# ---------------------------------------------------------------------------

try:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))          # .../core
    PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)                       # repo root
except NameError:
    PROJECT_ROOT = os.getcwd()
DEFAULT_DATA_DIR = os.path.join(PROJECT_ROOT, "bridge_data")
CLI_PATH = os.path.join(PROJECT_ROOT, "cli.py")
