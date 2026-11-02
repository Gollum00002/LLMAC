"""
LLMAC core package — host-side server engine.

Layout:
  constants.py  defaults, caps, protocol constants
  state.py      StateStore v2 (agents, settings), History, audit, export/import
  sandbox.py    path containment + exec command checking (v2, hardened)
  policy.py     install policy v2 (marker-based venv detection, token-aware npm)
  tlsutil.py    self-signed cert generation + fingerprinting
  events.py     global event bus (long-poll)
  sessions.py   server-side per-agent session memory
  approvals.py  approval request registry (GUI approve/deny)
  edits.py      surgical file edit primitives
  search.py     grep/glob/tree with ignore handling
  procs.py      background process manager
  api.py        HTTP request handlers (v2 protocol)
  server.py     HTTP server plumbing + headless runner
"""
from .constants import LLMAC_VERSION  # single source of truth
