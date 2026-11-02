"""v2.5.0 — THE HUMAN CHANNEL tests (tests-first: written red against
2.4.10, made green by the build).

Covers the release items:
  * ASK-001 user->agent inbox — the sessions model (store / read+consume
    / peek / cap / unread / 'message' event), the POST /session/inbox
    route contract, and the CLI `session inbox` verb + the lesson-#11
    --text guard.
  * ASK-002 multi-session — agents_snapshot shape + the merged thread
    the GUI sidebar renders (the GUI itself is pinned as source markers
    per the test_v246 pattern; live acceptance is the user's eyeball).
  * ASK-003 version truth — LLMAC_VERSION == 2.5.0 in BOTH copies
    (core/constants.py + the cli.py standalone bootstrap fallback) and
    GET /info reporting it.
  * batch-rc transport-only contract (decision closed Task 35) — op
    failures print their full context, rc stays 0; pinned so it can
    never silently regress.
"""
import json
import os
import subprocess
import sys
import time
import unittest

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost, make_tree

from core.constants import LLMAC_VERSION, SESSION_INBOX_CAP
from core.events import EventBus
from core.sessions import SessionRegistry

CLI = os.path.join(_PARENT, "cli.py")
GUI_SRC = os.path.join(_PARENT, "gui.py")
EVENTS_SRC = os.path.join(_PARENT, "core", "events.py")


def run_cli(host, *args, timeout=90, cwd=None):
    return subprocess.run(
        [sys.executable, CLI, "--plain", "--host", "127.0.0.1",
         "--port", str(host.port), "--key", host.key, *args],
        capture_output=True, text=True, timeout=timeout, cwd=cwd)


# ---------------------------------------------------------------------------
# Sessions model — the user->agent inbox beside notes
# ---------------------------------------------------------------------------

class TestInboxModel(unittest.TestCase):
    def test_inbox_store_read_consume(self):
        reg = SessionRegistry()
        reg.inbox("a", "steer left")
        reg.inbox("a", "then brake")
        out = reg.read_inbox("a", mark=True)
        self.assertEqual(len(out["messages"]), 2)
        self.assertEqual(out["messages"][0]["text"], "steer left")
        self.assertEqual(out["messages"][1]["seq"], 2)
        self.assertEqual(out["unread"], 0)          # mark consumes
        self.assertEqual(reg.read_inbox("a")["messages"], [])

    def test_inbox_peek_keeps_unread(self):
        reg = SessionRegistry()
        reg.inbox("a", "ping")
        out = reg.read_inbox("a", mark=False)
        self.assertEqual(len(out["messages"]), 1)
        self.assertEqual(out["unread"], 1)          # peek keeps the banner
        out2 = reg.read_inbox("a", mark=False)
        self.assertEqual(out2["unread"], 1)
        self.assertEqual(len(out2["messages"]), 1)  # still fetchable

    def test_digest_reports_unread_and_last_ts(self):
        reg = SessionRegistry()
        d0 = reg.digest("a")
        self.assertEqual(d0["unread"], 0)
        self.assertIsNone(d0["last_inbox_ts"])
        reg.inbox("a", "hello")
        reg.inbox("a", "again")
        d1 = reg.digest("a")
        self.assertEqual(d1["unread"], 2)
        self.assertIsNotNone(d1["last_inbox_ts"])
        reg.read_inbox("a", mark=True)
        d2 = reg.digest("a")
        self.assertEqual(d2["unread"], 0)
        # the ts persists after consumption — the sidebar keeps history
        self.assertIsNotNone(d2["last_inbox_ts"])

    def test_inbox_cap_drops_oldest(self):
        self.assertEqual(SESSION_INBOX_CAP, 200)
        reg = SessionRegistry()
        for i in range(SESSION_INBOX_CAP + 5):
            reg.inbox("a", f"m{i}")
        s = reg.get("a")
        self.assertEqual(len(s.inbox), SESSION_INBOX_CAP)
        self.assertEqual(s.inbox[0]["seq"], 6)       # oldest dropped
        out = reg.read_inbox("a", mark=True)
        self.assertEqual(out["messages"][0]["text"], "m5")
        self.assertEqual(out["unread"], 0)

    def test_message_event_emitted_on_inbox(self):
        ev = EventBus()
        reg = SessionRegistry()
        reg.inbox("a", "mid-run steer", events=ev)
        events = ev.wait(0, timeout=1.0)
        self.assertTrue(events)
        self.assertEqual(events[-1]["type"], "message")
        self.assertEqual(events[-1]["data"]["agent"], "a")
        self.assertEqual(events[-1]["data"]["seq"], 1)
        self.assertEqual(events[-1]["data"]["text"], "mid-run steer")

    def test_agents_snapshot_shape(self):
        reg = SessionRegistry()
        reg.inbox("alpha", "hi")
        reg.note("beta", "working")
        reg.inbox("beta", "status?")
        reg.read_inbox("beta", mark=True)
        snap = reg.agents_snapshot()
        names = {s["agent"] for s in snap}
        self.assertEqual(names, {"alpha", "beta"})
        by = {s["agent"]: s for s in snap}
        self.assertEqual(by["alpha"]["unread"], 1)
        self.assertEqual(by["beta"]["unread"], 0)
        self.assertEqual(by["beta"]["note_count"], 1)
        self.assertIn("last_seen", by["alpha"])
        self.assertIn("op_count", by["alpha"])

    def test_thread_merges_notes_and_messages_ts_ordered(self):
        reg = SessionRegistry()
        reg.note("a", "starting the build")
        time.sleep(1.05)                    # ts has second resolution
        reg.inbox("a", "actually, stop")
        time.sleep(1.05)
        reg.note("a", "stopped as asked")
        items = reg.thread("a")
        self.assertEqual(len(items), 3)
        kinds = [i["kind"] for i in items]
        self.assertEqual(kinds, ["note", "message", "note"])
        self.assertEqual(items[1]["text"], "actually, stop")
        # agent consumed the message -> its CLI view is empty, but the
        # GUI thread KEEPS the history (sidebar + transcript):
        reg.read_inbox("a", mark=True)
        self.assertEqual(reg.read_inbox("a")["messages"], [])
        self.assertEqual(len(reg.thread("a")), 3)


# ---------------------------------------------------------------------------
# POST /session/inbox — the route contract
# ---------------------------------------------------------------------------

class TestInboxRoute(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)

    def test_roundtrip_read_and_consume(self):
        # the human side (GUI in-process) drops a message mid-run:
        self.host.ctx.sessions.inbox("default", "steer: use the v249 gate")
        resp, status = self.host.post("/session/inbox", {})
        self.assertEqual(status, 200)
        self.assertEqual(resp["messages"][0]["text"],
                         "steer: use the v249 gate")
        self.assertEqual(resp["unread"], 0)     # default marks read
        resp2, _ = self.host.post("/session/inbox", {})
        self.assertEqual(resp2["messages"], [])   # consumed

    def test_peek_keeps_unread(self):
        self.host.ctx.sessions.inbox("default", "ping")
        resp, _ = self.host.post("/session/inbox", {"peek": True})
        self.assertEqual(resp["unread"], 1)
        self.assertEqual(len(resp["messages"]), 1)
        resp2, _ = self.host.post("/session/inbox", {})
        self.assertEqual(resp2["unread"], 0)

    def test_rejects_text_field(self):
        resp, status = self.host.post("/session/inbox", {"text": "nope"})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "text_belongs_to_note")

    def test_rejects_non_bool_peek(self):
        resp, status = self.host.post("/session/inbox", {"peek": "yes"})
        self.assertEqual(status, 400)
        self.assertIn("peek", json.dumps(resp))

    def test_empty_inbox_is_clean_200(self):
        resp, status = self.host.post("/session/inbox", {})
        self.assertEqual(status, 200)
        self.assertEqual(resp["messages"], [])
        self.assertEqual(resp["unread"], 0)

    def test_status_digest_carries_unread(self):
        self.host.ctx.sessions.inbox("default", "one")
        self.host.ctx.sessions.inbox("default", "two")
        resp, status = self.host.post("/session/status", {})
        self.assertEqual(status, 200)
        self.assertEqual(resp["unread"], 2)

    def test_message_event_flows_to_wait(self):
        ev = self.host.ctx.events
        since = ev.latest_seq()
        self.host.ctx.sessions.inbox("default", "live ping", events=ev)
        events = ev.wait(since, timeout=2.0)
        self.assertTrue(any(e["type"] == "message" for e in events))


# ---------------------------------------------------------------------------
# CLI — `session inbox` + the lesson-#11 guard + the batch-rc contract
# ---------------------------------------------------------------------------

class TestInboxCli(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)
        make_tree(self.host.root, {"f.txt": "x"})

    def test_cli_inbox_roundtrip(self):
        self.host.ctx.sessions.inbox("default", "steer now")
        r = run_cli(self.host, "session", "inbox")
        self.assertEqual(r.returncode, 0)
        self.assertIn("steer now", r.stdout)
        self.assertIn("unread", r.stdout)

    def test_cli_peek_flag(self):
        self.host.ctx.sessions.inbox("default", "keep unread")
        r = run_cli(self.host, "session", "inbox", "--peek")
        self.assertEqual(r.returncode, 0)
        self.assertIn("keep unread", r.stdout)
        self.assertIn("unread: 1", r.stdout)
        r2 = run_cli(self.host, "session", "inbox")
        self.assertIn("unread: 0", r2.stdout)

    def test_cli_text_guard_fires_pre_request(self):
        # lesson #11 family: --text belongs to 'session note' only.
        r = run_cli(self.host, "session", "--text", "x", "inbox")
        self.assertEqual(r.returncode, 2)
        self.assertIn("text_needs_note", r.stderr)

    def test_batch_rc_is_transport_only(self):
        # decision closed Task 35: op failures print their FULL context,
        # the batch rc stays 0 (transport-only). Pinned so the contract
        # can never silently regress.
        ops = [{"op": "read", "path": os.path.join(self.host.root, "f.txt")},
               {"op": "read", "path": os.path.join(self.host.root, "nope.txt")}]
        r = run_cli(self.host, "batch", "--ops", json.dumps(ops))
        self.assertEqual(r.returncode, 0)                # transport rc only
        self.assertIn("f.txt", r.stdout)                # ok op printed
        self.assertIn("not_found", r.stdout + r.stderr)  # full error context


# ---------------------------------------------------------------------------
# GUI source pins + version truth
# ---------------------------------------------------------------------------

class TestGUISourcePins(unittest.TestCase):
    """GUI acceptance is the user's live eyeball (the standing carry-over);
    these pins lock the human-channel feature into gui.py so a regression
    cannot hide (the test_v246 pattern)."""

    def test_chat_pane_markers(self):
        with open(GUI_SRC, encoding="utf-8") as f:
            src = f.read()
        for marker in ("chat_input", "chat_view", "chat_agent_list",
                       "_send_chat_message", "_poll_chat", "Sessions"):
            self.assertIn(marker, src)

    def test_message_event_documented(self):
        with open(EVENTS_SRC, encoding="utf-8") as f:
            src = f.read()
        self.assertIn("* ``message``", src)


class TestVersionTruth(unittest.TestCase):
    def test_constants_version(self):
        self.assertEqual(LLMAC_VERSION, "2.7.3")

    def test_cli_fallback_in_sync(self):
        with open(CLI, encoding="utf-8") as f:
            src = f.read()
        self.assertIn('VERSION = "2.7.3"', src)

    def test_info_reports_version(self):
        host = TestHost()
        self.addCleanup(host.stop)
        resp, status = host.get("/info")
        self.assertEqual(status, 200)
        self.assertEqual(resp["version"], "2.7.3")


if __name__ == "__main__":
    unittest.main()
