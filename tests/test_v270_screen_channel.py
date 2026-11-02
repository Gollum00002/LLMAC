"""v2.7.0 — THE SCREEN CHANNEL tests (tests-first: written red against
2.6.0, made green by the build).

Covers the release items (V270-PLAN.md):
  * ASK-016 screen.list + screen.shot — per-screen multi-monitor
    capture behind per-shot approvals with an until-restart session
    grant; deterministic evidence files with sha256 truth; pure
    coordinate/naming/validation helpers in the NEW Qt-free
    core/screen.py (the transcript.py pattern).
  * ASK-017 part A screen.observe — OCR text-with-positions (boxes in
    GLOBAL coords) + window list, own approval class, OFF by default.
  * ASK-017 part B input injection — the safety floor IS the design:
    own-window refusal BEFORE any injection, bounded drive mode (time
    + event caps, drive_cap_exceeded), every event op-logged at WARN,
    OFF until enabled in settings.
  * Screen/input ops are NOT batchable (documented refusal naming the
    op).
  * GUI surface source pins (the v252 house style) + version truth
    2.7.0 in BOTH copies + /info (era pins in the older modules flip
    with the release as always).
"""
import hashlib
import http.client
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost

from core.constants import LLMAC_VERSION

CLI = os.path.join(_PARENT, "cli.py")
GUI_SRC = os.path.join(_PARENT, "gui.py")
CHANGES_SRC = os.path.join(_PARENT, "CHANGES.md")
AGENT_SRC = os.path.join(_PARENT, "agent.md")
API_SRC = os.path.join(_PARENT, "core", "api.py")

# The core.screen module is NEW in 2.7.0 — importing it here is the red
# gate (ImportError until the build lands it).
from core.screen import (
    DriveSessions, MODIFIER_KEYSYMS, ScreenError, SPECIAL_KEYSYMS,
    TEXT_KEYSYMS, crop_rect, keysym_valid, shot_filename, to_global,
    validate_format, validate_max_width, validate_shot_target,
    validate_text,
)


def run_cli_locally(*args, timeout=60):
    """rc-2 pre-request guards fire before any connection attempt."""
    return subprocess.run([sys.executable, CLI, *args],
                          capture_output=True, text=True, timeout=timeout)


# ---------------------------------------------------------------------------
# Fakes — deterministic services injected into AppContext (the plan's
# FakeScreenService / FakeInputBackend; the suite never needs PyQt6, a
# real display, tesseract or Xlib).

FAKE_SCREENS = [
    {"index": 0, "name": "DP-1", "x": 0, "y": 0, "width": 1920,
     "height": 1080, "primary": True, "scale": 1.0, "available": True},
    {"index": 1, "name": "HDMI-1", "x": 1920, "y": 0, "width": 1280,
     "height": 720, "primary": False, "scale": 1.25, "available": True},
]


class FakeScreenService:
    """Writes real bytes with deterministic names, records every call."""

    name = "fake"

    def __init__(self, root, screens=None):
        self.root = root
        self.screens = screens or FAKE_SCREENS
        self.calls = []

    def list_screens(self):
        self.calls.append(("list",))
        return [dict(s) for s in self.screens]

    def capture(self, targets, fmt, quality, max_width, out_dir, when):
        self.calls.append(("capture", [t["index"] for t in targets],
                           fmt, quality, max_width))
        os.makedirs(out_dir, exist_ok=True)
        files = []
        for t in targets:
            fname = shot_filename(t["index"], when,
                                  "jpg" if fmt == "jpg" else "png")
            path = os.path.join(out_dir, fname)
            data = (b"FAKESCREEN-" + bytes([65 + t["index"]]) * 8
                    + (b"J" if fmt == "jpg" else b"P"))
            with open(path, "wb") as f:
                f.write(data)
            files.append({
                "path": path, "screen": t["index"],
                "geometry": [t["x"], t["y"], t["width"], t["height"]],
                "format": fmt, "width": t["width"], "height": t["height"],
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest()})
        return files


class FakeInputBackend:
    """Records injections; never touches a display."""

    name = "fake"

    def __init__(self):
        self.events = []
        self.own_window_ids = set()
        self.window_map = {}          # (x, y) -> window id
        self.focused = None

    def window_at(self, x, y):
        return self.window_map.get((int(x), int(y)))

    def focused_window(self):
        return self.focused

    def mouse_move(self, x, y):
        self.events.append(("move", x, y))

    def mouse_click(self, button, x, y):
        self.events.append(("click", button, x, y))

    def mouse_doubleclick(self, button, x, y):
        self.events.append(("doubleclick", button, x, y))

    def mouse_drag(self, button, fx, fy, tx, ty):
        self.events.append(("drag", button, fx, fy, tx, ty))

    def mouse_scroll(self, x, y, dx, dy):
        self.events.append(("scroll", x, y, dx, dy))

    def key(self, keysym, modifiers):
        self.events.append(("key", keysym, tuple(modifiers)))

    def type_text(self, text):
        self.events.append(("text", text))


def _screen_host(**settings):
    host = TestHost(settings=settings or None)
    host.ctx.screen = FakeScreenService(host.root)
    host.ctx.input = FakeInputBackend()
    return host


def _grant(ctx, op, agent="default"):
    """Until-restart session grant (in-memory, dies with the process)."""
    ctx.screen_session_grants.setdefault(op, set()).add(agent)


def _post_thread(host, path, payload):
    box = {}

    def run():
        box["r"] = host.post(path, payload)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t, box


def _decide_pending(host, approved, timeout=10):
    """Approve/deny the first pending approval (the human's click)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pend = host.ctx.approvals.pending()
        if pend:
            host.ctx.approvals.decide(pend[0]["id"], approved, "test")
            return pend[0]
        time.sleep(0.02)
    return None


# ---------------------------------------------------------------------------
# Pure helpers (core/screen.py — Qt-free, both platforms)

class TestShotHelpers(unittest.TestCase):

    def test_filename_deterministic(self):
        import datetime as _dt
        when = _dt.datetime(2026, 10, 29, 12, 34, 56)
        self.assertEqual(shot_filename(2, when, "png"),
                         "screen-20261029-123456-2.png")
        self.assertEqual(shot_filename(0, when, "jpg"),
                         "screen-20261029-123456-0.jpg")
        # same inputs -> same name (deterministic evidence)
        self.assertEqual(shot_filename(2, when, "png"),
                         shot_filename(2, when, "png"))

    def test_filename_regex(self):
        name = shot_filename(11, None, "png")
        self.assertRegex(name, r"^screen-\d{8}-\d{6}-11\.png$")

    def test_validate_target_all_primary_index(self):
        all_t = validate_shot_target("all", FAKE_SCREENS)
        self.assertEqual(len(all_t), 2)
        pri = validate_shot_target("primary", FAKE_SCREENS)
        self.assertEqual([s["index"] for s in pri], [0])
        one = validate_shot_target("1", FAKE_SCREENS)
        self.assertEqual([s["index"] for s in one], [1])
        one_int = validate_shot_target(1, FAKE_SCREENS)
        self.assertEqual([s["index"] for s in one_int], [1])

    def test_validate_target_refusals(self):
        with self.assertRaises(ScreenError) as e:
            validate_shot_target("", FAKE_SCREENS)
        self.assertEqual(e.exception.error, "shot_target_required")
        with self.assertRaises(ScreenError) as e:
            validate_shot_target("7", FAKE_SCREENS)
        self.assertEqual(e.exception.error, "screen_not_found")
        self.assertIn("7", e.exception.message)
        with self.assertRaises(ScreenError) as e:
            validate_shot_target(True, FAKE_SCREENS)   # bool is not an index
        self.assertEqual(e.exception.error, "screen_not_found")
        with self.assertRaises(ScreenError) as e:
            validate_shot_target("banana", FAKE_SCREENS)
        self.assertEqual(e.exception.error, "screen_not_found")

    def test_validate_format(self):
        self.assertEqual(validate_format(None), "png")
        self.assertEqual(validate_format("png"), "png")
        self.assertEqual(validate_format("jpg"), "jpg")
        self.assertEqual(validate_format("JPG"), "jpg")
        with self.assertRaises(ScreenError) as e:
            validate_format("bmp")
        self.assertEqual(e.exception.error, "shot_format_invalid")

    def test_validate_max_width(self):
        self.assertIsNone(validate_max_width(None))
        self.assertEqual(validate_max_width(1600), 1600)
        for bad in (0, -5, "abc", 99999999):
            with self.assertRaises(ScreenError) as e:
                validate_max_width(bad)
            self.assertEqual(e.exception.error, "max_width_invalid")

    def test_crop_rect_math(self):
        # scale 1: identity
        self.assertEqual(crop_rect(FAKE_SCREENS[0]), (0, 0, 1920, 1080))
        # scale 1.25: logical -> physical pixels of the merged capture
        self.assertEqual(crop_rect(FAKE_SCREENS[1]), (2400, 0, 1600, 900))

    def test_crop_rect_offset_screen(self):
        s = {"x": 100, "y": 200, "width": 800, "height": 600, "scale": 2.0}
        self.assertEqual(crop_rect(s), (200, 400, 1600, 1200))

    def test_to_global_math(self):
        # local physical px -> global logical coords (the space input
        # ops and screen.list speak)
        self.assertEqual(to_global(FAKE_SCREENS[1], 800, 450), (2560, 360))
        self.assertEqual(to_global(FAKE_SCREENS[0], 100, 50), (100, 50))

    def test_to_global_inverse_of_crop(self):
        s = FAKE_SCREENS[1]
        x, y, w, h = crop_rect(s)
        self.assertEqual(to_global(s, w, h),
                         (s["x"] + s["width"], s["y"] + s["height"]))


class TestKeysymTables(unittest.TestCase):
    """The X11 keysym mapping tables, pinned."""

    def test_modifier_table(self):
        self.assertEqual(set(MODIFIER_KEYSYMS),
                         {"ctrl", "shift", "alt", "meta"})
        self.assertEqual(MODIFIER_KEYSYMS["ctrl"], "Control_L")
        self.assertEqual(MODIFIER_KEYSYMS["shift"], "Shift_L")
        self.assertEqual(MODIFIER_KEYSYMS["alt"], "Alt_L")
        self.assertEqual(MODIFIER_KEYSYMS["meta"], "Meta_L")

    def test_special_keysyms(self):
        for name in ("Return", "Tab", "space", "Escape", "BackSpace",
                     "Delete", "Home", "End", "Left", "Right", "Up",
                     "Down", "F1", "F12"):
            self.assertIn(name, SPECIAL_KEYSYMS.values(),
                          msg=f"missing keysym {name}")
        # friendly aliases resolve to canonical X11 names
        self.assertEqual(SPECIAL_KEYSYMS.get("enter"), "Return")
        self.assertEqual(SPECIAL_KEYSYMS.get("esc"), "Escape")

    def test_text_table_covers_printable_ascii(self):
        for code in range(0x20, 0x7F):
            ch = chr(code)
            self.assertIn(ch, TEXT_KEYSYMS, msg=f"missing char {ch!r}")
        self.assertEqual(TEXT_KEYSYMS["\n"], "Return")
        self.assertEqual(TEXT_KEYSYMS["\t"], "Tab")

    def test_keysym_valid(self):
        self.assertTrue(keysym_valid("a"))
        self.assertTrue(keysym_valid("Return"))
        self.assertTrue(keysym_valid("F5"))
        self.assertTrue(keysym_valid("space"))
        self.assertFalse(keysym_valid(""))
        self.assertFalse(keysym_valid("Banana"))
        self.assertFalse(keysym_valid("ctrl"))

    def test_validate_text_first_offender(self):
        # clean ASCII passes
        self.assertEqual(validate_text("Hello, World 42!"), "Hello, World 42!")
        # the FIRST unmappable char is named with its position
        with self.assertRaises(ScreenError) as e:
            validate_text("ab€cd")
        self.assertEqual(e.exception.error, "input_text_unsupported")
        self.assertIn("€", e.exception.message)
        self.assertIn("2", e.exception.message)     # position of the offender
        with self.assertRaises(ScreenError) as e:
            validate_text("héllo")
        self.assertEqual(e.exception.error, "input_text_unsupported")
        self.assertIn("é", e.exception.message)


class TestDriveSessions(unittest.TestCase):
    """Bounded drive mode — the pure state machine."""

    def test_open_authorize_count(self):
        ds = DriveSessions()
        self.assertEqual(ds.active(), [])
        ds.open("default", max_events=3, max_minutes=10)
        sess, reason = ds.authorize("default")
        self.assertIsNone(reason)
        self.assertEqual(sess["events"], 0)
        self.assertEqual(ds.count("default"), 1)
        self.assertEqual(ds.count("default"), 2)
        self.assertEqual(ds.active()[0]["agent"], "default")

    def test_event_cap_closes_session(self):
        ds = DriveSessions()
        ds.open("default", max_events=2, max_minutes=10)
        self.assertIsNone(ds.authorize("default")[1])
        ds.count("default")
        self.assertIsNone(ds.authorize("default")[1])
        ds.count("default")
        sess, reason = ds.authorize("default")
        self.assertEqual(reason, "events")
        self.assertIsNone(sess)
        # violation CLOSED the session: nothing stays active
        self.assertEqual(ds.active(), [])

    def test_time_cap_closes_session(self):
        ds = DriveSessions()
        ds.open("default", max_events=500, max_minutes=0)   # instant expiry
        sess, reason = ds.authorize("default")
        self.assertEqual(reason, "time")
        self.assertIsNone(sess)
        self.assertEqual(ds.active(), [])

    def test_authorize_without_session(self):
        ds = DriveSessions()
        sess, reason = ds.authorize("nobody")
        self.assertEqual(reason, "no_session")
        self.assertIsNone(sess)

    def test_close_all(self):
        ds = DriveSessions()
        ds.open("a", max_events=5, max_minutes=5)
        ds.open("b", max_events=5, max_minutes=5)
        self.assertEqual(len(ds.active()), 2)
        ds.close_all()
        self.assertEqual(ds.active(), [])
        self.assertEqual(ds.authorize("a")[1], "no_session")


# ---------------------------------------------------------------------------
# /screen/list + /screen/shot route contracts (ASK-016)

class TestScreenListRoutes(unittest.TestCase):

    def test_list_metadata_only_no_approval(self):
        host = _screen_host()
        self.addCleanup(host.stop)
        r, code = host.post("/screen/list", {})
        self.assertEqual(code, 200)
        self.assertEqual(len(r["screens"]), 2)
        s = r["screens"][0]
        for key in ("index", "name", "x", "y", "width", "height",
                    "primary", "scale", "available"):
            self.assertIn(key, s)
        # zero pixels moved, zero approvals raised
        self.assertEqual(host.ctx.approvals.pending(), [])
        self.assertEqual(host.ctx.screen.calls, [("list",)])

    def test_headless_refuses_cleanly(self):
        host = TestHost()          # ctx.screen is None by default
        self.addCleanup(host.stop)
        r, code = host.post("/screen/list", {})
        self.assertEqual(code, 403)
        self.assertEqual(r["error"], "screen_unavailable")
        self.assertIn("headless", r["message"].lower())


class TestScreenShotRoutes(unittest.TestCase):

    def test_headless_refuses(self):
        host = TestHost()
        self.addCleanup(host.stop)
        r, code = host.post("/screen/shot", {"target": "all"})
        self.assertEqual(code, 403)
        self.assertEqual(r["error"], "screen_unavailable")

    def test_target_mandatory(self):
        host = _screen_host()
        self.addCleanup(host.stop)
        _grant(host.ctx, "screen_shot")
        r, code = host.post("/screen/shot", {})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "shot_target_required")

    def test_unknown_index_names_it(self):
        host = _screen_host()
        self.addCleanup(host.stop)
        _grant(host.ctx, "screen_shot")
        r, code = host.post("/screen/shot", {"target": 7})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "screen_not_found")
        self.assertIn("7", r["message"])

    def test_bad_format_and_max_width(self):
        host = _screen_host()
        self.addCleanup(host.stop)
        _grant(host.ctx, "screen_shot")
        r, code = host.post("/screen/shot", {"target": 0, "format": "bmp"})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "shot_format_invalid")
        r, code = host.post("/screen/shot", {"target": 0,
                                             "max_width": "abc"})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "max_width_invalid")
        r, code = host.post("/screen/shot", {"target": 0, "max_width": 0})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "max_width_invalid")

    def test_dir_outside_roots_refuses(self):
        host = _screen_host(screen_shot_dir="/nonexistent-outside-shots")
        self.addCleanup(host.stop)
        _grant(host.ctx, "screen_shot")
        r, code = host.post("/screen/shot", {"target": 0})
        self.assertEqual(code, 403)
        self.assertEqual(r["error"], "screen_dir_not_shared")
        self.assertIn("screen_shot_dir", r["message"])

    def test_happy_path_all_shots_with_sha256_truth(self):
        host = _screen_host()
        self.addCleanup(host.stop)
        shots = os.path.join(host.root, "shots")
        host.settings["screen_shot_dir"] = shots
        _grant(host.ctx, "screen_shot")
        r, code = host.post("/screen/shot", {"target": "all"})
        self.assertEqual(code, 200)
        self.assertEqual(len(r["files"]), 2)
        self.assertEqual(len(r["screens"]), 2)
        for f in r["files"]:
            self.assertRegex(os.path.basename(f["path"]),
                             r"^screen-\d{8}-\d{6}-\d+\.png$")
            self.assertTrue(os.path.isfile(f["path"]))
            with open(f["path"], "rb") as fh:
                data = fh.read()
            self.assertEqual(f["bytes"], len(data))
            self.assertEqual(f["sha256"],
                             hashlib.sha256(data).hexdigest())
            self.assertIn(f["format"], ("png", "jpg"))
        # the shot is op-logged
        ring = [e for e in host.ctx.op_ring if "SCREEN SHOT" in e["msg"]]
        self.assertTrue(ring)
        self.assertEqual(ring[-1]["agent"], "default")

    def test_primary_and_single_index_and_jpg(self):
        host = _screen_host()
        self.addCleanup(host.stop)
        host.settings["screen_shot_dir"] = os.path.join(host.root, "shots")
        _grant(host.ctx, "screen_shot")
        r, code = host.post("/screen/shot", {"target": "primary"})
        self.assertEqual(code, 200)
        self.assertEqual([f["screen"] for f in r["files"]], [0])
        r, code = host.post("/screen/shot",
                            {"target": 1, "format": "jpg",
                             "max_width": 800})
        self.assertEqual(code, 200)
        f = r["files"][0]
        self.assertTrue(f["path"].endswith(".jpg"))
        self.assertEqual(f["screen"], 1)
        # the capture call saw the downscale + quality
        cap = [c for c in host.ctx.screen.calls if c[0] == "capture"][-1]
        self.assertEqual(cap[2], "jpg")
        self.assertEqual(cap[4], 800)

    def test_approval_gating_blocks_until_decided(self):
        host = _screen_host()
        self.addCleanup(host.stop)
        host.settings["screen_shot_dir"] = os.path.join(host.root, "shots")
        t, box = _post_thread(host, "/screen/shot", {"target": 0})
        apr = _decide_pending(host, True)
        self.assertIsNotNone(apr, "no approval request appeared")
        self.assertEqual(apr["op"], "screen_shot")
        t.join(timeout=15)
        self.assertFalse(t.is_alive())
        r, code = box["r"]
        self.assertEqual(code, 200)
        self.assertEqual(len(r["files"]), 1)

    def test_approval_denied_is_403(self):
        host = _screen_host()
        self.addCleanup(host.stop)
        host.settings["screen_shot_dir"] = os.path.join(host.root, "shots")
        t, box = _post_thread(host, "/screen/shot", {"target": 0})
        _decide_pending(host, False)
        t.join(timeout=15)
        self.assertFalse(t.is_alive())
        r, code = box["r"]
        self.assertEqual(code, 403)
        self.assertEqual(r["error"], "approval_denied")

    def test_session_grant_short_circuits(self):
        host = _screen_host()
        self.addCleanup(host.stop)
        host.settings["screen_shot_dir"] = os.path.join(host.root, "shots")
        _grant(host.ctx, "screen_shot")
        r, code = host.post("/screen/shot", {"target": 0})
        self.assertEqual(code, 200)
        # no approval was ever requested
        self.assertEqual(host.ctx.approvals.pending(), [])
        self.assertEqual(len(host.ctx.approvals.recent_decided()), 0)
        ring = [e for e in host.ctx.op_ring
                if "SESSION GRANT" in e["msg"]]
        self.assertTrue(ring)

    def test_shots_disabled_by_setting(self):
        host = _screen_host(screen_shots_enabled=False)
        self.addCleanup(host.stop)
        _grant(host.ctx, "screen_shot")
        r, code = host.post("/screen/shot", {"target": 0})
        self.assertEqual(code, 403)
        self.assertEqual(r["error"], "screen_shots_disabled")
        self.assertIn("screen_shots_enabled", r["message"])


# ---------------------------------------------------------------------------
# /screen/observe route contracts (ASK-017 part A)

class TestObserveRoutes(unittest.TestCase):

    def test_off_by_default(self):
        host = _screen_host()
        self.addCleanup(host.stop)
        r, code = host.post("/screen/observe", {"target": 0})
        self.assertEqual(code, 403)
        self.assertEqual(r["error"], "screen_observe_disabled")
        self.assertIn("screen_observe_enabled", r["message"])

    def test_max_width_refused_loudly(self):
        host = _screen_host(screen_observe_enabled=True)
        self.addCleanup(host.stop)
        host.settings["screen_shot_dir"] = os.path.join(host.root, "shots")
        _grant(host.ctx, "screen_observe")
        r, code = host.post("/screen/observe",
                            {"target": 0, "max_width": 800})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "observe_max_width_unsupported")

    def test_observe_returns_ocr_words_and_windows(self):
        import core.screen as screen_mod
        host = _screen_host(screen_observe_enabled=True)
        self.addCleanup(host.stop)
        host.settings["screen_shot_dir"] = os.path.join(host.root, "shots")
        _grant(host.ctx, "screen_observe")

        fake_words = ([{"text": "Hello", "conf": 91, "x": 100, "y": 50,
                        "w": 60, "h": 20}], "Hello")
        fake_windows = [{"id": 123, "title": "Game", "x": 0, "y": 0,
                         "width": 1920, "height": 1080, "visible": True,
                         "focused": True}]
        with mock.patch.object(screen_mod, "ocr_words",
                               return_value=fake_words), \
                mock.patch.object(screen_mod, "window_list",
                                  return_value=fake_windows):
            r, code = host.post("/screen/observe", {"target": 0})
        self.assertEqual(code, 200)
        self.assertEqual(len(r["files"]), 1)
        self.assertEqual(r["observe"][0]["screen"], 0)
        self.assertEqual(r["observe"][0]["words"][0]["text"], "Hello")
        self.assertEqual(r["observe"][0]["text"], "Hello")
        self.assertEqual(r["windows"][0]["title"], "Game")

    def test_observe_headless_and_target_validation(self):
        host = TestHost()
        self.addCleanup(host.stop)
        r, code = host.post("/screen/observe", {"target": 0})
        self.assertEqual(code, 403)
        self.assertEqual(r["error"], "screen_observe_disabled")

    def test_observe_approval_class_is_own(self):
        import core.screen as screen_mod
        host = _screen_host(screen_observe_enabled=True)
        self.addCleanup(host.stop)
        host.settings["screen_shot_dir"] = os.path.join(host.root, "shots")
        with mock.patch.object(screen_mod, "ocr_words",
                               return_value=([], "")), \
                mock.patch.object(screen_mod, "window_list",
                                  return_value=[]):
            t, box = _post_thread(host, "/screen/observe",
                                  {"target": "primary"})
            apr = _decide_pending(host, True)
            self.assertEqual(apr["op"], "screen_observe")
            t.join(timeout=15)
        r, code = box["r"]
        self.assertEqual(code, 200)

    def test_window_list_failure_is_loud_not_silent(self):
        import core.screen as screen_mod
        host = _screen_host(screen_observe_enabled=True)
        self.addCleanup(host.stop)
        host.settings["screen_shot_dir"] = os.path.join(host.root, "shots")
        _grant(host.ctx, "screen_observe")

        def boom(_path, _screen):
            return [], ""

        def no_windows():
            raise ScreenError("windows_unavailable",
                              "no X display for the window tree")
        with mock.patch.object(screen_mod, "ocr_words", side_effect=boom), \
                mock.patch.object(screen_mod, "window_list",
                                  side_effect=no_windows):
            r, code = host.post("/screen/observe", {"target": 0})
        self.assertEqual(code, 200)
        self.assertEqual(r["windows"], [])
        self.assertIn("windows_error", r)
        self.assertIn("windows_unavailable", r["windows_error"])


# ---------------------------------------------------------------------------
# /input/* route contracts (ASK-017 part B — the safety floor)

def _input_host(**settings):
    base = {"screen_input_enabled": True,
            "screen_input_max_minutes": 10,
            "screen_input_max_events": 500}
    base.update(settings)
    host = TestHost(settings=base)
    host.ctx.screen = FakeScreenService(host.root)
    host.ctx.input = FakeInputBackend()
    _grant(host.ctx, "screen_input")
    return host


class TestInputRoutes(unittest.TestCase):

    def test_off_by_default(self):
        host = _screen_host()
        self.addCleanup(host.stop)
        r, code = host.post("/input/mouse", {"action": "move", "x": 1,
                                             "y": 2})
        self.assertEqual(code, 403)
        self.assertEqual(r["error"], "screen_input_disabled")
        self.assertIn("screen_input_enabled", r["message"])

    def test_no_backend_refuses(self):
        host = TestHost(settings={"screen_input_enabled": True})
        self.addCleanup(host.stop)
        r, code = host.post("/input/mouse", {"action": "move", "x": 1,
                                             "y": 2})
        self.assertEqual(code, 403)
        self.assertEqual(r["error"], "screen_unavailable")

    def test_mouse_action_required_and_valid(self):
        host = _input_host()
        self.addCleanup(host.stop)
        r, code = host.post("/input/mouse", {"x": 1, "y": 2})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "input_action_required")
        r, code = host.post("/input/mouse", {"action": "hop", "x": 1,
                                             "y": 2})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "input_action_invalid")

    def test_mouse_button_and_coords_validation(self):
        host = _input_host()
        self.addCleanup(host.stop)
        r, code = host.post("/input/mouse", {"action": "click",
                                             "button": "middle",
                                             "x": 5, "y": 6})
        self.assertEqual(code, 200)      # middle is a valid button
        r, code = host.post("/input/mouse", {"action": "click",
                                             "button": "thumbside",
                                             "x": 5, "y": 6})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "input_button_invalid")
        r, code = host.post("/input/mouse", {"action": "move"})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "input_coords_required")
        self.assertEqual(r["field"], "x")
        r, code = host.post("/input/mouse", {"action": "drag",
                                             "from_x": 1, "from_y": 2,
                                             "to_x": 9})
        self.assertEqual(code, 400)
        self.assertEqual(r["field"], "to_y")
        r, code = host.post("/input/mouse", {"action": "scroll",
                                             "x": 1, "y": 2, "dx": 3})
        self.assertEqual(code, 400)
        self.assertEqual(r["field"], "dy")
        r, code = host.post("/input/mouse", {"action": "click",
                                             "x": "left", "y": 2})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "input_coords_invalid")

    def test_mouse_actions_reach_backend(self):
        host = _input_host()
        self.addCleanup(host.stop)
        r, code = host.post("/input/mouse", {"action": "move", "x": 10,
                                             "y": 20})
        self.assertEqual(code, 200)
        r, code = host.post("/input/mouse",
                            {"action": "doubleclick", "button": "right",
                             "x": 30, "y": 40})
        self.assertEqual(code, 200)
        r, code = host.post("/input/mouse",
                            {"action": "drag", "from_x": 1, "from_y": 2,
                             "to_x": 3, "to_y": 4})
        self.assertEqual(code, 200)
        r, code = host.post("/input/mouse",
                            {"action": "scroll", "x": 5, "y": 6,
                             "dx": 0, "dy": -3})
        self.assertEqual(code, 200)
        ev = host.ctx.input.events
        self.assertEqual(ev[0], ("move", 10, 20))
        self.assertEqual(ev[1], ("doubleclick", "right", 30, 40))
        self.assertEqual(ev[2], ("drag", "left", 1, 2, 3, 4))
        self.assertEqual(ev[3], ("scroll", 5, 6, 0, -3))
        self.assertEqual(r["drive"]["events_used"], 4)

    def test_own_window_refusal_before_any_injection(self):
        host = _input_host()
        self.addCleanup(host.stop)
        host.ctx.input.window_map[(100, 100)] = 4242
        host.ctx.input.own_window_ids = {4242}
        r, code = host.post("/input/mouse", {"action": "click",
                                             "x": 100, "y": 100})
        self.assertEqual(code, 403)
        self.assertEqual(r["error"], "own_window_refusal")
        self.assertIn("(100, 100)", r["message"])
        # nothing was injected — the refusal fired FIRST
        self.assertEqual(host.ctx.input.events, [])
        # drag hit-tests BOTH endpoints
        host.ctx.input.window_map[(500, 500)] = 4242
        r, code = host.post("/input/mouse",
                            {"action": "drag", "from_x": 1, "from_y": 1,
                             "to_x": 500, "to_y": 500})
        self.assertEqual(code, 403)
        self.assertEqual(r["error"], "own_window_refusal")
        self.assertEqual(host.ctx.input.events, [])

    def test_key_and_text_own_window_via_focus(self):
        host = _input_host()
        self.addCleanup(host.stop)
        host.ctx.input.focused = 4242
        host.ctx.input.own_window_ids = {4242}
        r, code = host.post("/input/key", {"keysym": "Return"})
        self.assertEqual(code, 403)
        self.assertEqual(r["error"], "own_window_refusal")
        r, code = host.post("/input/text", {"text": "hi"})
        self.assertEqual(code, 403)
        self.assertEqual(r["error"], "own_window_refusal")
        self.assertEqual(host.ctx.input.events, [])

    def test_key_validation(self):
        host = _input_host()
        self.addCleanup(host.stop)
        r, code = host.post("/input/key", {})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "input_keysym_required")
        r, code = host.post("/input/key", {"keysym": "Banana"})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "input_keysym_unknown")
        self.assertIn("Banana", r["message"])
        r, code = host.post("/input/key", {"keysym": "a",
                                           "modifiers": ["ctrl", "warp"]})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "input_modifier_invalid")
        self.assertIn("warp", r["message"])

    def test_key_reaches_backend_with_modifiers(self):
        host = _input_host()
        self.addCleanup(host.stop)
        r, code = host.post("/input/key", {"keysym": "c",
                                           "modifiers": ["ctrl"]})
        self.assertEqual(code, 200)
        self.assertEqual(host.ctx.input.events,
                         [("key", "c", ("ctrl",))])

    def test_text_validation_and_round_trip(self):
        host = _input_host()
        self.addCleanup(host.stop)
        r, code = host.post("/input/text", {})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "input_text_required")
        r, code = host.post("/input/text", {"text": "héllo"})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "input_text_unsupported")
        self.assertIn("é", r["message"])
        r, code = host.post("/input/text", {"text": "Hello, World 42!"})
        self.assertEqual(code, 200)
        self.assertEqual(host.ctx.input.events,
                         [("text", "Hello, World 42!")])

    def test_drive_event_cap_enforced(self):
        host = _input_host(screen_input_max_events=2)
        self.addCleanup(host.stop)
        r, c1 = host.post("/input/mouse", {"action": "move", "x": 1,
                                           "y": 1})
        self.assertEqual(c1, 200)
        r, c2 = host.post("/input/mouse", {"action": "move", "x": 2,
                                           "y": 2})
        self.assertEqual(c2, 200)
        r, c3 = host.post("/input/mouse", {"action": "move", "x": 3,
                                           "y": 3})
        self.assertEqual(c3, 403)
        self.assertEqual(r["error"], "drive_cap_exceeded")
        self.assertIn("event", r["message"].lower())
        # the session closed: the NEXT op needs a fresh approval
        t, box = _post_thread(host, "/input/mouse",
                              {"action": "move", "x": 4, "y": 4})
        apr = _decide_pending(host, True)
        self.assertEqual(apr["op"], "screen_input")
        t.join(timeout=15)
        self.assertEqual(box["r"][1], 200)

    def test_drive_time_cap_enforced(self):
        host = _input_host(screen_input_max_minutes=0)
        self.addCleanup(host.stop)
        r, code = host.post("/input/mouse", {"action": "move", "x": 1,
                                             "y": 1})
        self.assertEqual(code, 403)
        self.assertEqual(r["error"], "drive_cap_exceeded")
        self.assertIn("time", r["message"].lower())
        self.assertEqual(host.ctx.input.events, [])

    def test_first_input_op_requires_approval(self):
        host = _input_host()
        self.addCleanup(host.stop)
        # no session grant this time
        host.ctx.screen_session_grants = {}
        t, box = _post_thread(host, "/input/mouse",
                              {"action": "move", "x": 8, "y": 9})
        apr = _decide_pending(host, True)
        self.assertIsNotNone(apr)
        self.assertEqual(apr["op"], "screen_input")
        self.assertIn("drive", apr["summary"].lower())
        t.join(timeout=15)
        r, code = box["r"]
        self.assertEqual(code, 200)
        self.assertEqual(host.ctx.input.events, [("move", 8, 9)])
        # an approved op OPENS the session — the next op runs grant-free
        r, code = host.post("/input/mouse", {"action": "move", "x": 10,
                                             "y": 11})
        self.assertEqual(code, 200)
        self.assertEqual(host.ctx.input.events[-1], ("move", 10, 11))

    def test_every_input_event_op_logged_warn(self):
        host = _input_host()
        self.addCleanup(host.stop)
        host.post("/input/mouse", {"action": "click", "x": 1, "y": 2})
        host.post("/input/key", {"keysym": "Return"})
        host.post("/input/text", {"text": "abc"})
        warns = [e for e in host.ctx.op_ring
                 if e["level"] == "WARN" and "INPUT" in e["msg"]
                 and e["agent"] == "default"]
        self.assertEqual(len(warns), 3)


# ---------------------------------------------------------------------------
# Screen/input ops are not batchable

class TestNotBatchable(unittest.TestCase):

    def test_screen_ops_refuse_in_batch_naming_op(self):
        host = _screen_host()
        self.addCleanup(host.stop)
        ops = [{"op": "read", "path": host.root},
               {"op": "screen_shot", "target": "all"},
               {"op": "screen_list"},
               {"op": "screen_observe", "target": 0},
               {"op": "input_mouse", "action": "move", "x": 1, "y": 2},
               {"op": "input_key", "keysym": "a"},
               {"op": "input_text", "text": "x"}]
        r, code = host.post("/batch", {"ops": ops})
        self.assertEqual(code, 200)
        by_idx = {res["index"]: res for res in r["results"]}
        self.assertEqual(by_idx[0]["op"], "read")     # reads still fine
        for i, opname in ((1, "screen_shot"), (2, "screen_list"),
                          (3, "screen_observe"), (4, "input_mouse"),
                          (5, "input_key"), (6, "input_text")):
            self.assertEqual(by_idx[i].get("error"), "not_batchable")
            self.assertEqual(by_idx[i].get("op"), opname)
            self.assertIn(opname, by_idx[i].get("message", ""))


# ---------------------------------------------------------------------------
# GUI source pins (the v252 house style — the suite never imports PyQt6)

class TestGuiSourcePins(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = open(GUI_SRC, encoding="utf-8").read()

    def test_screen_service_and_bridge_exist(self):
        self.assertIn("class QtScreenService", self.src)
        self.assertIn("class MainThreadCaller", self.src)
        self.assertIn("postEvent", self.src)

    def test_capture_backends_present(self):
        # KDE Wayland path: spectacle -b -n -f (merged full desktop)
        self.assertIn("spectacle", self.src)
        self.assertIn("-b", self.src)
        # X11 / Windows path: native per-screen grab
        self.assertIn("grabWindow", self.src)
        # other compositors refuse loudly, never black frames
        self.assertIn("screen_capture_unsupported", self.src)

    def test_security_tab_screen_access_group(self):
        self.assertIn("Screen access", self.src)
        self.assertIn("self.screen_shots_check", self.src)
        self.assertIn("self.screen_observe_check", self.src)
        self.assertIn("self.screen_input_check", self.src)
        self.assertIn("self.screen_shot_dir_edit", self.src)
        self.assertIn("self.screen_input_max_minutes_spin", self.src)
        self.assertIn("self.screen_input_max_events_spin", self.src)
        # persistence rides the sudo_timeout pattern
        self.assertIn('event_type="screen_settings_change"', self.src)

    def test_drive_banner_exists(self):
        self.assertIn("class DriveBanner", self.src)
        self.assertIn("click to disarm", self.src)
        self.assertIn("WindowStaysOnTopHint", self.src)

    def test_session_grant_button_wired(self):
        self.assertIn("self.apr_session_btn", self.src)
        self.assertIn("screen_session_grants", self.src)

    def test_own_window_registration(self):
        self.assertIn("own_window_ids", self.src)

    def test_context_grows_screen_channel(self):
        self.assertIn("QtScreenService(", self.src)
        self.assertIn("make_input_backend", self.src)

    def test_x11_disarm_listener_best_effort(self):
        self.assertIn("xi2", self.src.lower())
        self.assertIn("xinput", self.src.lower())


class TestApiSourcePins(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = open(API_SRC, encoding="utf-8").read()

    def test_routes_registered(self):
        for path in ('"/screen/list"', '"POST", "/screen/shot"',
                     '"POST", "/screen/observe"', '"POST", "/input/mouse"',
                     '"POST", "/input/key"', '"POST", "/input/text"'):
            self.assertIn(path, self.src, msg=path)

    def test_appcontext_grows_screen(self):
        self.assertIn("self.screen = None", self.src)
        self.assertIn("self.input = None", self.src)
        self.assertIn("self.screen_drive", self.src)
        self.assertIn("self.screen_session_grants", self.src)

    def test_not_batchable_list(self):
        self.assertIn("_NOT_BATCHABLE_OPS", self.src)


# ---------------------------------------------------------------------------
# Version truth (era pins in the older modules flip as always)

class TestVersionTruth270(unittest.TestCase):

    def test_constants_version(self):
        self.assertEqual(LLMAC_VERSION, "2.7.3")

    def test_both_copies_pin(self):
        c = open(os.path.join(_PARENT, "core", "constants.py"),
                 encoding="utf-8").read()
        self.assertIn('LLMAC_VERSION = "2.7.3"', c)
        cli = open(CLI, encoding="utf-8").read()
        self.assertIn('VERSION = "2.7.3"', cli)

    def test_live_info_reports_270(self):
        host = TestHost()
        self.addCleanup(host.server.shutdown)
        conn = http.client.HTTPConnection("127.0.0.1", host.port,
                                          timeout=30)
        conn.request("GET", "/info",
                     headers={"Authorization": f"Bearer {host.key}"})
        resp = conn.getresponse()
        data = json.loads(resp.read())
        self.assertEqual(resp.status, 200)
        self.assertEqual(data["version"], "2.7.3")

    def test_changes_has_entry(self):
        src = open(CHANGES_SRC, encoding="utf-8").read()
        self.assertIn("## v2.7.2", src)
        self.assertIn("Screen Channel", src)

    def test_agent_md_tip_20_screen_ops(self):
        src = open(AGENT_SRC, encoding="utf-8").read()
        self.assertIn("20.", src)
        self.assertRegex(src, r"screen\s+list")
        self.assertIn("own_window_refusal", src)

    def test_requirements_lists_screen_deps(self):
        src = open(os.path.join(_PARENT, "requirements.txt"),
                   encoding="utf-8").read()
        for dep in ("pytesseract", "Pillow", "python-xlib"):
            self.assertIn(dep, src)


# ---------------------------------------------------------------------------
# CLI rc-2 pre-request guards (no connection needed — they fire first)

class TestCliGuards(unittest.TestCase):

    def test_screen_shot_target_required(self):
        r = run_cli_locally("screen", "shot")
        self.assertEqual(r.returncode, 2)
        self.assertIn("shot_target_required", r.stderr)

    def test_screen_shot_bad_format(self):
        r = run_cli_locally("screen", "shot", "--target", "1",
                            "--format", "bmp")
        self.assertEqual(r.returncode, 2)
        self.assertIn("shot_format_invalid", r.stderr)

    def test_screen_shot_bad_max_width(self):
        r = run_cli_locally("screen", "shot", "--target", "1",
                            "--max-width", "abc")
        self.assertEqual(r.returncode, 2)
        self.assertIn("max_width_invalid", r.stderr)
        r = run_cli_locally("screen", "shot", "--target", "1",
                            "--max-width", "0")
        self.assertEqual(r.returncode, 2)
        self.assertIn("max_width_invalid", r.stderr)

    def test_screen_subcommands_exist(self):
        r = run_cli_locally("screen", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("list", r.stdout)
        self.assertIn("shot", r.stdout)
        self.assertIn("observe", r.stdout)

    def test_input_subcommands_exist(self):
        r = run_cli_locally("input", "--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("mouse", r.stdout)
        self.assertIn("key", r.stdout)
        self.assertIn("text", r.stdout)

    def test_input_key_needs_keysym(self):
        r = run_cli_locally("input", "key")
        self.assertEqual(r.returncode, 2)

    def test_input_mouse_action_validated(self):
        r = run_cli_locally("input", "mouse", "--action", "hop")
        self.assertEqual(r.returncode, 2)

    def test_input_text_needs_text(self):
        r = run_cli_locally("input", "text")
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
