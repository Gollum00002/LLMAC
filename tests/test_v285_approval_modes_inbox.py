"""v2.8.5 — per-class approval modes (screenshots, input injection),
Inbox tab rename + unseen-message badge, input-control inbox notice."""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from helpers import TestHost
from test_v270_screen_channel import (
    FakeInputBackend, FakeScreenService, _decide_pending, _post_thread)
from core.sessions import SessionRegistry

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _host(**settings):
    base = {"screen_input_enabled": True}
    base.update(settings)
    host = TestHost(settings=base)
    host.ctx.screen = FakeScreenService(host.root)
    host.ctx.input = FakeInputBackend()
    host.settings["screen_shot_dir"] = os.path.join(host.root, "shots")
    return host


class TestShotModes(unittest.TestCase):

    def test_always_skips_approval(self):
        host = _host(screen_shots_approval="always")
        self.addCleanup(host.stop)
        r, code = host.post("/screen/shot", {"target": "all"})
        self.assertEqual(code, 200)
        self.assertEqual(host.ctx.approvals.pending(), [])

    def test_per_shot_asks_every_time(self):
        host = _host(screen_shots_approval="per_shot")
        self.addCleanup(host.stop)
        for _ in range(2):
            t, box = _post_thread(host, "/screen/shot", {"target": "all"})
            apr = _decide_pending(host, True)
            self.assertIsNotNone(apr)
            t.join(timeout=15)
            self.assertEqual(box["r"][1], 200)

    def test_session_mode_asks_once(self):
        host = _host(screen_shots_approval="session")
        self.addCleanup(host.stop)
        t, box = _post_thread(host, "/screen/shot", {"target": "all"})
        self.assertIsNotNone(_decide_pending(host, True))
        t.join(timeout=15)
        self.assertEqual(box["r"][1], 200)
        r, code = host.post("/screen/shot", {"target": "all"})
        self.assertEqual(code, 200)
        self.assertEqual(host.ctx.approvals.pending(), [])

    def test_session_mode_denied_grants_nothing(self):
        host = _host(screen_shots_approval="session")
        self.addCleanup(host.stop)
        t, box = _post_thread(host, "/screen/shot", {"target": "all"})
        _decide_pending(host, False)
        t.join(timeout=15)
        self.assertEqual(box["r"][1], 403)
        self.assertFalse(host.ctx.screen_session_grants.get("screen_shot"))

    def test_unknown_mode_fails_closed(self):
        host = _host(screen_shots_approval="bogus")
        self.addCleanup(host.stop)
        t, box = _post_thread(host, "/screen/shot", {"target": "all"})
        self.assertIsNotNone(_decide_pending(host, True))
        t.join(timeout=15)


class TestInputModes(unittest.TestCase):

    def test_always_opens_session_and_announces(self):
        host = _host(screen_input_approval="always")
        self.addCleanup(host.stop)
        r, code = host.post("/input/mouse",
                            {"action": "move", "x": 1, "y": 2})
        self.assertEqual(code, 200)
        self.assertEqual(host.ctx.approvals.pending(), [])
        notes = host.ctx.sessions.get("default").notes
        self.assertTrue(any("[INPUT CONTROL]" in n["text"] for n in notes))
        self.assertEqual(host.ctx.sessions.unseen_total(), 1)

    def test_announces_once_per_drive_session(self):
        host = _host(screen_input_approval="always")
        self.addCleanup(host.stop)
        for i in range(3):
            host.post("/input/mouse", {"action": "move", "x": i, "y": i})
        notes = [n for n in host.ctx.sessions.get("default").notes
                 if "[INPUT CONTROL]" in n["text"]]
        self.assertEqual(len(notes), 1)

    def test_per_shot_still_prompts_and_announces_after_approval(self):
        host = _host(screen_input_approval="per_shot")
        self.addCleanup(host.stop)
        t, box = _post_thread(host, "/input/mouse",
                              {"action": "move", "x": 1, "y": 1})
        self.assertIsNotNone(_decide_pending(host, True))
        t.join(timeout=15)
        self.assertEqual(box["r"][1], 200)
        self.assertTrue(any("[INPUT CONTROL]" in n["text"]
                            for n in host.ctx.sessions.get("default").notes))

    def test_denied_input_posts_no_notice(self):
        host = _host(screen_input_approval="per_shot")
        self.addCleanup(host.stop)
        t, box = _post_thread(host, "/input/mouse",
                              {"action": "move", "x": 1, "y": 1})
        _decide_pending(host, False)
        t.join(timeout=15)
        self.assertEqual(box["r"][1], 403)
        self.assertEqual(host.ctx.sessions.unseen_total(), 0)

    def test_session_mode_regrant_after_cap_exceeded(self):
        host = _host(screen_input_approval="session",
                     screen_input_max_events=1)
        self.addCleanup(host.stop)
        t, box = _post_thread(host, "/input/mouse",
                              {"action": "move", "x": 1, "y": 1})
        _decide_pending(host, True)
        t.join(timeout=15)
        r, code = host.post("/input/mouse",
                            {"action": "move", "x": 2, "y": 2})
        self.assertEqual(r["error"], "drive_cap_exceeded")
        texts = [n["text"] for n in host.ctx.sessions.get("default").notes]
        self.assertTrue(any("CLOSED" in t for t in texts))


class TestUnseenCounter(unittest.TestCase):

    def test_counts_and_marks_seen(self):
        reg = SessionRegistry()
        reg.note("a", "hi")
        reg.note("a", "again")
        reg.note("b", "yo")
        self.assertEqual(reg.unseen_total(), 3)
        snap = {s["agent"]: s["unseen_notes"] for s in reg.agents_snapshot()}
        self.assertEqual(snap, {"a": 2, "b": 1})
        reg.mark_seen("a")
        self.assertEqual(reg.unseen_total(), 1)

    def test_counter_survives_note_cap(self):
        reg = SessionRegistry()
        from core.constants import SESSION_NOTES_CAP
        for i in range(SESSION_NOTES_CAP + 5):
            reg.note("a", str(i))
        self.assertEqual(reg.unseen_total(), SESSION_NOTES_CAP + 5)
        reg.mark_seen("a")
        self.assertEqual(reg.unseen_total(), 0)


class TestDefaultsAndGuiPins(unittest.TestCase):

    def test_defaults(self):
        from core.state import default_settings
        d = default_settings()
        self.assertEqual(d["screen_shots_approval"], "per_shot")
        self.assertEqual(d["screen_input_approval"], "per_shot")

    def test_gui_source_pins(self):
        with open(os.path.join(ROOT, "gui.py"), encoding="utf-8") as f:
            src = f.read()
        self.assertRegex(src, r'_build_sessions_tab\(\)\), "Inbox"')
        self.assertNotRegex(src, r'_build_sessions_tab\(\)\), "Sessions"')
        for marker in ("_update_inbox_badge", "_on_tab_changed",
                       "_on_screen_approval_mode", "screen_approval_combos",
                       "screen_shots_approval", "screen_input_approval"):
            self.assertIn(marker, src)


if __name__ == "__main__":
    unittest.main()
