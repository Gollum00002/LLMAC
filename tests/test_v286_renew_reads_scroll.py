"""v2.8.6 — three fixes.

  R1  Input injection under a pre-approved mode ('Ask once per session' with
      a live grant, or 'Always approve') no longer re-prompts after a drive
      session hits its time/event cap: the session is renewed in place,
      loudly (WARN log + Inbox note). 'Ask each time' and the
      screen_input_auto_renew=False opt-out keep the old strict behaviour.
  R2  Reads: a host-side DEFAULT response cap (READ_DEFAULT_BYTES) for unsized
      whole-file reads, streaming line-range reads (any file size, response
      capped at a line boundary with next_line), raw/max_bytes/limit overrides,
      and client hints / bounded --raw.
  R3  GUI source pins for the Inbox scroll fix + auto-renew checkbox + disarm
      revoking the input grant (Qt itself is exercised by hand).
"""
import base64
import os
import sys
import time
import unittest

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost
from test_v270_screen_channel import (
    FakeInputBackend, FakeScreenService, _decide_pending, _post_thread)
from test_v240_tier_a import run_cli
from core.constants import READ_DEFAULT_BYTES

ROOT = _PARENT


def _host(**settings):
    base = {"screen_input_enabled": True}
    base.update(settings)
    host = TestHost(settings=base)
    host.ctx.screen = FakeScreenService(host.root)
    host.ctx.input = FakeInputBackend()
    host.settings["screen_shot_dir"] = os.path.join(host.root, "shots")
    return host


def _notes(host):
    return [n["text"] for n in host.ctx.sessions.get("default").notes]


def _move(host, i):
    return host.post("/input/mouse", {"action": "move", "x": i, "y": i})


# ---------------------------------------------------------------------------
# R1: drive-session auto-renewal
# ---------------------------------------------------------------------------

class TestDriveAutoRenew(unittest.TestCase):

    def test_session_mode_event_cap_renews_without_prompt(self):
        host = _host(screen_input_approval="session",
                     screen_input_max_events=1)
        self.addCleanup(host.stop)
        t, box = _post_thread(host, "/input/mouse",
                              {"action": "move", "x": 1, "y": 1})
        self.assertIsNotNone(_decide_pending(host, True))
        t.join(timeout=15)
        self.assertEqual(box["r"][1], 200)
        for i in (2, 3, 4):                     # each hits the 1-event cap
            r, code = _move(host, i)
            self.assertEqual(code, 200, r)
            self.assertEqual(host.ctx.approvals.pending(), [])
        # the grant survived
        self.assertIn("default",
                      host.ctx.screen_session_grants.get("screen_input", ()))
        texts = _notes(host)
        self.assertEqual(sum("RENEWED" in t for t in texts), 3)
        self.assertFalse(any("CLOSED" in t for t in texts))

    def test_session_mode_time_cap_renews_without_prompt(self):
        host = _host(screen_input_approval="session")
        self.addCleanup(host.stop)
        t, box = _post_thread(host, "/input/mouse",
                              {"action": "move", "x": 1, "y": 1})
        _decide_pending(host, True)
        t.join(timeout=15)
        # fast-forward: the drive session's time cap elapsed
        host.ctx.screen_drive._sessions["default"]["expires"] = (
            time.monotonic() - 1)
        r, code = _move(host, 2)
        self.assertEqual(code, 200, r)
        self.assertEqual(host.ctx.approvals.pending(), [])
        self.assertTrue(any("RENEWED" in t and "time cap" in t
                            for t in _notes(host)))
        # and the renewed session is live with a fresh budget
        self.assertEqual(host.ctx.screen_drive.count("default"), 2)

    def test_always_mode_renews(self):
        host = _host(screen_input_approval="always",
                     screen_input_max_events=2)
        self.addCleanup(host.stop)
        for i in range(7):
            r, code = _move(host, i)
            self.assertEqual(code, 200, r)
        self.assertEqual(host.ctx.approvals.pending(), [])
        self.assertTrue(any("RENEWED" in t for t in _notes(host)))

    def test_per_shot_never_auto_renews(self):
        host = _host(screen_input_approval="per_shot",
                     screen_input_max_events=1)
        self.addCleanup(host.stop)
        t, box = _post_thread(host, "/input/mouse",
                              {"action": "move", "x": 1, "y": 1})
        _decide_pending(host, True)
        t.join(timeout=15)
        r, code = _move(host, 2)
        self.assertEqual(r["error"], "drive_cap_exceeded")
        self.assertFalse(any("RENEWED" in t for t in _notes(host)))

    def test_opt_out_keeps_strict_behaviour_and_drops_grant(self):
        host = _host(screen_input_approval="session",
                     screen_input_max_events=1,
                     screen_input_auto_renew=False)
        self.addCleanup(host.stop)
        t, box = _post_thread(host, "/input/mouse",
                              {"action": "move", "x": 1, "y": 1})
        _decide_pending(host, True)
        t.join(timeout=15)
        r, code = _move(host, 2)
        self.assertEqual(r["error"], "drive_cap_exceeded")
        self.assertNotIn("default", host.ctx.screen_session_grants.get(
            "screen_input", ()))
        # the next op needs a fresh approval, as before
        t, box = _post_thread(host, "/input/mouse",
                              {"action": "move", "x": 3, "y": 3})
        self.assertIsNotNone(_decide_pending(host, True))
        t.join(timeout=15)
        self.assertEqual(box["r"][1], 200)

    def test_zero_minute_cap_cannot_loop_forever(self):
        host = _host(screen_input_approval="always",
                     screen_input_max_minutes=0)
        self.addCleanup(host.stop)
        r, code = _move(host, 1)
        self.assertEqual(code, 403)
        self.assertEqual(r["error"], "drive_cap_exceeded")

    def test_defaults(self):
        from core.state import default_settings
        self.assertTrue(default_settings()["screen_input_auto_renew"])


# ---------------------------------------------------------------------------
# R2: reads
# ---------------------------------------------------------------------------

def _write(host, name, data: bytes) -> str:
    p = os.path.join(host.root, name)
    with open(p, "wb") as f:
        f.write(data)
    return p


class TestReadCaps(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = TestHost()
        cls.lines = [f"row-{i:06d}-" + "y" * 40 for i in range(4000)]
        cls.text = "\n".join(cls.lines) + "\n"          # ~210 KB
        cls.big = _write(cls.host, "big.txt", cls.text.encode())

    @classmethod
    def tearDownClass(cls):
        cls.host.stop()

    def test_unsized_read_is_capped_on_a_line_boundary(self):
        r, code = self.host.post("/read", {"path": self.big})
        self.assertEqual(code, 200)
        self.assertTrue(r["truncated"])
        self.assertTrue(r["soft_capped"])
        self.assertLessEqual(len(r["content"].encode()), READ_DEFAULT_BYTES)
        self.assertTrue(r["content"].endswith("\n"))
        self.assertEqual(r["next_offset"], len(r["content"].encode()))
        self.assertIn("offset=", r["hint"])

    def test_paging_with_next_offset_reassembles_the_file(self):
        out, off = [], 0
        for _ in range(20):
            r, code = self.host.post(
                "/read", {"path": self.big, "offset": off,
                          "limit": 50000})
            self.assertEqual(code, 200)
            out.append(r["content"])
            if not r["truncated"]:
                break
            off = r["next_offset"]
        self.assertEqual("".join(out), self.text)

    def test_default_cap_pages_through_with_offset_only(self):
        out, off = [], 0
        for _ in range(10):
            r, _c = self.host.post("/read", {"path": self.big,
                                             "offset": off})
            out.append(r["content"])
            if not r["truncated"]:
                break
            off = r["next_offset"]
        self.assertEqual("".join(out), self.text)

    def test_raw_returns_everything(self):
        r, _c = self.host.post("/read", {"path": self.big, "raw": True})
        self.assertEqual(r["content"], self.text)
        self.assertFalse(r["truncated"])
        self.assertNotIn("soft_capped", r)

    def test_max_bytes_is_honoured_not_soft_capped(self):
        r, _c = self.host.post("/read", {"path": self.big,
                                         "max_bytes": 100000})
        self.assertEqual(len(r["content"].encode()), 100000)
        self.assertTrue(r["truncated"])
        self.assertNotIn("soft_capped", r)

    def test_small_file_untouched(self):
        p = _write(self.host, "small.txt", b"a\nb\n")
        r, _c = self.host.post("/read", {"path": p})
        self.assertEqual(r["content"], "a\nb\n")
        self.assertFalse(r["truncated"])
        self.assertNotIn("soft_capped", r)

    def test_multibyte_text_is_not_mistaken_for_binary(self):
        p = _write(self.host, "uni.txt", ("é" * 100000).encode())
        r, _c = self.host.post("/read", {"path": p})
        self.assertFalse(r["binary"])
        self.assertTrue(r["soft_capped"])
        self.assertEqual(set(r["content"]), {"é"})

    def test_explicit_limit_mid_character_is_trimmed_not_binary(self):
        p = _write(self.host, "uni2.txt", ("é" * 50).encode())
        r, _c = self.host.post("/read", {"path": p, "limit": 3})
        self.assertFalse(r["binary"])
        self.assertEqual(r["content"], "é")
        self.assertEqual(r["next_offset"], 2)

    def test_limit_without_offset_is_honoured(self):
        r, _c = self.host.post("/read", {"path": self.big, "limit": 10})
        self.assertEqual(r["content"], self.text[:10])
        self.assertTrue(r["truncated"])
        self.assertEqual(r["next_offset"], 10)

    def test_binary_is_capped_too(self):
        p = _write(self.host, "blob.bin", bytes(range(256)) * 1000)
        r, _c = self.host.post("/read", {"path": p})
        self.assertTrue(r["binary"])
        self.assertTrue(r["truncated"])
        self.assertEqual(len(base64.b64decode(r["content_b64"])),
                         READ_DEFAULT_BYTES)


class TestLineWindows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = TestHost()
        # ~7.4 MB: BIGGER than MAX_READ_BYTES (5 MB), which the old
        # read-then-slice implementation could not reach past.
        cls.n = 120000
        data = "".join(f"L{i:07d}-" + "z" * 50 + "\n"
                       for i in range(1, cls.n + 1)).encode()
        cls.huge = _write(cls.host, "huge.txt", data)
        assert len(data) > 5 * 1024 * 1024

    @classmethod
    def tearDownClass(cls):
        cls.host.stop()

    def test_window_past_the_5mb_mark(self):
        r, code = self.host.post("/read", {
            "path": self.huge, "from_line": self.n - 2, "to_line": self.n})
        self.assertEqual(code, 200)
        self.assertEqual(r["lines"], [self.n - 2, self.n])
        self.assertEqual(r["total_lines"], self.n)
        self.assertTrue(r["content"].startswith(f"L{self.n - 2:07d}-"))
        self.assertFalse(r.get("truncated"))

    def test_window_in_the_middle(self):
        r, _c = self.host.post("/read", {
            "path": self.huge, "from_line": 5000, "to_line": 5002})
        self.assertEqual([ln[:8] for ln in r["content"].split("\n")],
                         ["L0005000", "L0005001", "L0005002"])

    def test_oversized_window_is_capped_at_a_line_boundary(self):
        r, code = self.host.post("/read", {
            "path": self.huge, "from_line": 1, "to_line": self.n})
        self.assertEqual(code, 200)
        self.assertTrue(r["truncated"])
        got = len(r["content"].split("\n"))
        self.assertEqual(r["lines"], [1, got])
        self.assertEqual(r["next_line"], got + 1)
        self.assertLessEqual(len(r["content"].encode()), READ_DEFAULT_BYTES)
        # every returned line is whole
        self.assertTrue(all(len(ln) == 8 + 1 + 50 for ln in
                            r["content"].split("\n")))
        r2, _c = self.host.post("/read", {
            "path": self.huge, "from_line": r["next_line"],
            "to_line": r["next_line"] + 1})
        self.assertTrue(r2["content"].startswith(
            f"L{r['next_line']:07d}-"))

    def test_max_bytes_widens_the_window(self):
        r, _c = self.host.post("/read", {
            "path": self.huge, "from_line": 1, "to_line": 3000,
            "max_bytes": 1024 * 1024})
        self.assertFalse(r.get("truncated"))
        self.assertEqual(len(r["content"].split("\n")), 3000)

    def test_numbered(self):
        r, _c = self.host.post("/read", {
            "path": self.huge, "from_line": 7, "to_line": 8,
            "numbered": True})
        first = r["content"].split("\n")[0]
        self.assertTrue(first.lstrip().startswith("7\tL0000007-"))

    def test_invalid_ranges_still_400(self):
        r, code = self.host.post("/read", {
            "path": self.huge, "from_line": self.n + 5})
        self.assertEqual((code, r["error"]), (400, "range_invalid"))
        r, code = self.host.post("/read", {
            "path": self.huge, "from_line": 10, "to_line": 5})
        self.assertEqual((code, r["error"]), (400, "range_invalid"))

    def test_no_trailing_newline_and_empty_file(self):
        p = _write(self.host, "nonl.txt", b"a\nb\nc")
        r, _c = self.host.post("/read", {"path": p, "from_line": 2})
        self.assertEqual(r["content"], "b\nc")
        self.assertEqual(r["total_lines"], 3)
        e = _write(self.host, "empty.txt", b"")
        r, code = self.host.post("/read", {"path": e, "from_line": 1})
        self.assertEqual((code, r["error"]), (400, "range_invalid"))

    def test_one_giant_line_is_cut_loudly(self):
        p = _write(self.host, "oneline.txt", b"x" * 200000 + b"\nnext\n")
        r, code = self.host.post("/read", {"path": p, "from_line": 1,
                                           "to_line": 1})
        self.assertEqual(code, 200)
        self.assertTrue(r["truncated"] and r["line_cut"])
        self.assertEqual(len(r["content"]), READ_DEFAULT_BYTES)

    def test_binary_file_with_line_range_still_reports_binary(self):
        p = _write(self.host, "b2.bin", b"\x00\x01\x02\xff" * 10)
        r, _c = self.host.post("/read", {"path": p, "from_line": 1,
                                         "to_line": 2})
        self.assertTrue(r["binary"])

    def test_batch_read_uses_the_same_caps(self):
        r, code = self.host.post("/batch", {"ops": [
            {"op": "read", "path": self.huge, "from_line": 1,
             "to_line": self.n}]})
        self.assertEqual(code, 200, r)
        res = r["results"][0]["ok"]
        self.assertTrue(res.get("truncated"))
        self.assertEqual(res["lines"][0], 1)


# ---------------------------------------------------------------------------
# R2: the CLI
# ---------------------------------------------------------------------------

class TestReadCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = TestHost()
        cls.lines = [f"line-{i:05d}-" + "q" * 60 for i in range(5000)]
        cls.text = "\n".join(cls.lines) + "\n"          # ~365 KB
        cls.big = _write(cls.host, "cli_big.txt", cls.text.encode())

    @classmethod
    def tearDownClass(cls):
        cls.host.stop()

    def test_default_read_shows_head_only_with_continue_hint(self):
        r = run_cli(self.host, "read", "--path", self.big)
        self.assertEqual(r.returncode, 0)
        self.assertIn("smart-truncated", r.stderr)
        self.assertIn("--offset", r.stderr)
        self.assertIn("line-00000", r.stdout)
        self.assertNotIn("line-04999", r.stdout)   # NOT a fake 'tail'
        self.assertEqual(len(r.stdout.split("\n")), 201)  # 200 lines + ''
        # the advertised offset really continues where the head stopped
        consumed = len(("\n".join(self.lines[:200]) + "\n").encode())
        self.assertIn(f"--offset {consumed}", r.stderr)
        r2 = run_cli(self.host, "read", "--path", self.big, "--offset",
                     str(consumed), "--limit", "200")
        self.assertTrue(r2.stdout.startswith("line-00200-"))

    def test_raw_to_terminal_is_bounded(self):
        r = run_cli(self.host, "read", "--path", self.big, "--raw")
        self.assertEqual(r.returncode, 0)
        self.assertLessEqual(len(r.stdout.encode()), 256 * 1024)
        self.assertGreater(len(r.stdout.encode()), 100 * 1024)
        self.assertIn("read capped", r.stderr)
        self.assertIn("--to", r.stderr)

    def test_to_file_saves_the_whole_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "o.txt")
            r = run_cli(self.host, "read", "--path", self.big, "--to", out)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out, encoding="utf-8") as f:
                self.assertEqual(f.read(), self.text)

    def test_capped_line_window_prints_the_next_lines_hint(self):
        r = run_cli(self.host, "read", "--path", self.big,
                    "--lines", "1-5000")
        self.assertEqual(r.returncode, 0)
        self.assertIn("continue with --lines", r.stderr)
        n = len(r.stdout.split("\n"))
        self.assertIn(f"--lines {n + 1}-", r.stderr)

    def test_small_range_has_no_hints(self):
        r = run_cli(self.host, "read", "--path", self.big,
                    "--lines", "10-12")
        self.assertEqual(r.stderr.strip(), "")
        self.assertEqual(len(r.stdout.strip().split("\n")), 3)


# ---------------------------------------------------------------------------
# R3: GUI source pins
# ---------------------------------------------------------------------------

class TestGuiPins(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, "gui.py"), encoding="utf-8") as f:
            cls.src = f.read()

    def test_inbox_scroll_is_restored_after_rerender(self):
        i = self.src.index("def _refresh_chat_thread")
        j = self.src.index("def _chat_thread_hits")
        body = self.src[i:j]
        for marker in ("old_val = sb.value()", "_chat_scroll_target",
                       "_chat_apply_scroll_target()",
                       "_chat_release_scroll_target", "_chat_render_agent"):
            self.assertIn(marker, body)
        # the target is re-applied AFTER the search re-apply, which scrolls
        self.assertGreater(body.rindex("self._chat_apply_scroll_target()"),
                           body.index("self._chat_apply_search(n)"))
        # lazy layout: the target is re-applied on every range change, and
        # a user scroll cancels it
        self.assertIn("rangeChanged.connect(self._chat_on_range_changed)",
                      self.src)
        self.assertIn("actionTriggered.connect(self._chat_user_scrolled)",
                      self.src)

    def test_agent_list_scroll_preserved(self):
        self.assertIn("list_scroll = list_sb.value()", self.src)

    def test_auto_renew_checkbox_and_default(self):
        self.assertIn("screen_input_renew_check", self.src)
        self.assertIn('setdefault("screen_input_auto_renew", True)',
                      self.src)

    def test_disarm_revokes_the_input_grant(self):
        i = self.src.index("def _disarm_drive")
        body = self.src[i:i + 1600]
        self.assertIn('screen_session_grants.pop("screen_input", None)',
                      body)


if __name__ == "__main__":
    unittest.main()
