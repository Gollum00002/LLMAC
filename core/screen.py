"""v2.7.0 (ASK-016/017) — the Screen Channel: pure logic + backends.

Qt-free by design (the core/transcript.py pattern): the helpers,
keysym tables, the drive-session state machine and the service
PROTOCOLS live here so the test suite imports them directly on any
platform. The Qt-backed capture service (QtScreenService) lives in
gui.py and executes on the GUI main thread through a queued bridge —
the HTTP handler never touches Qt. The X11/XTest input backend
(python-xlib) is constructed lazily and runs on the SERVER thread.

Reach map (pinned by live recon, 2026-10-29 — agent.md tip 20):
  CAPTURE sees the whole desktop on KDE Wayland (spectacle -b -n -f,
  merged full-resolution PNG, per-screen crop by QScreen geometry x
  scale) and natively per screen on X11/Windows (QScreen.grabWindow).
  Other Wayland compositors refuse cleanly: screen_capture_unsupported.
  INPUT reaches X11/XWayland clients (games, Steam, Proton) via XTest;
  native Wayland windows are NOT reachable in v1 — the libei/portal
  route is documented future work, and ops that need it refuse loudly,
  never silently no-op. Windows SendInput is interface-compatible
  future work (the InputBackend protocol is the forward-compat).
"""
from __future__ import annotations

import threading
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Errors (api.py converts these to OpBlocked(status, body))
# ---------------------------------------------------------------------------


class ScreenError(Exception):
    """A named refusal. error is the wire code, message the remedy."""

    def __init__(self, error: str, message: str, status: int = 400,
                 **extra):
        super().__init__(message)
        self.error = error
        self.message = message
        self.status = status
        self.extra = extra


# ---------------------------------------------------------------------------
# Pure helpers: naming, validation, coordinate math
# ---------------------------------------------------------------------------

def shot_filename(index: int, when=None, ext: str = "png") -> str:
    """screen-YYYYmmdd-HHMMSS-<index>.<ext> — deterministic evidence
    names (same inputs -> same name; sorts by capture time then
    screen). `when` is a datetime (None = now)."""
    stamp = (when or datetime.now()).strftime("%Y%m%d-%H%M%S")
    return f"screen-{stamp}-{int(index)}.{ext}"


def validate_shot_target(target, screens: list) -> list:
    """Resolve the MANDATORY shot target to the screen list to capture.

    Accepted: a screen index (int or numeric string), 'primary', 'all'.
    Refuses: shot_target_required (missing), screen_not_found (unknown
    index/wording — the message names what was sent)."""
    if target is None or (isinstance(target, str) and not target.strip()):
        raise ScreenError(
            "shot_target_required",
            "target is mandatory: a screen index, 'primary' or 'all' "
            "(multiple monitors are first-class — pick the one you want).")
    if isinstance(target, bool):
        raise ScreenError(
            "screen_not_found",
            f"unknown screen target {target!r} — use an index, 'primary' "
            f"or 'all'.")
    if isinstance(target, int):
        idx = target
    elif isinstance(target, str):
        word = target.strip().lower()
        if word == "all":
            return list(screens)
        if word == "primary":
            for s in screens:
                if s.get("primary"):
                    return [s]
            raise ScreenError(
                "screen_not_found",
                "no primary screen in the current screen list.")
        try:
            idx = int(word)
        except ValueError:
            raise ScreenError(
                "screen_not_found",
                f"unknown screen target {target!r} — use an index, "
                f"'primary' or 'all'.") from None
    else:
        raise ScreenError(
            "screen_not_found",
            f"unknown screen target {target!r} — use an index, 'primary' "
            f"or 'all'.")
    for s in screens:
        if s.get("index") == idx:
            return [s]
    have = ", ".join(str(s.get("index")) for s in screens) or "none"
    raise ScreenError(
        "screen_not_found",
        f"no screen with index {idx} (screen list has: {have}).")


def validate_format(fmt) -> str:
    """png (default) or jpg, case-insensitive; anything else refuses
    shot_format_invalid — loud contracts beat silent fallbacks."""
    if fmt is None or fmt == "":
        return "png"
    f = str(fmt).strip().lower()
    if f in ("png", "jpg"):
        return f
    raise ScreenError(
        "shot_format_invalid",
        f"format must be 'png' or 'jpg' (got {fmt!r}).")


def validate_max_width(v, cap: int = 20000) -> int | None:
    """Optional downscale width (aspect kept). None passes through; a
    non-int or out-of-range value refuses max_width_invalid."""
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int):
        raise ScreenError(
            "max_width_invalid",
            f"max_width must be an integer 1..{cap} (got {v!r}).")
    if not (1 <= v <= cap):
        raise ScreenError(
            "max_width_invalid",
            f"max_width must be an integer 1..{cap} (got {v}).")
    return v


def crop_rect(screen: dict) -> tuple:
    """The screen's rect in the MERGED full-desktop capture, physical
    pixels: global logical geometry x device scale, rounded. Mixed-DPI
    caveat: the merged image's physical layout is assumed to be the
    union of the per-screen physical rects (the KDE/Spectacle shape on
    this host); exotic layouts are documented in agent.md tip 20."""
    s = float(screen.get("scale") or 1.0)
    return (round(float(screen.get("x", 0)) * s),
            round(float(screen.get("y", 0)) * s),
            round(float(screen.get("width", 0)) * s),
            round(float(screen.get("height", 0)) * s))


def to_global(screen: dict, px: int, py: int) -> tuple:
    """Local PHYSICAL pixels (an OCR box inside one screen's crop) to
    GLOBAL logical coordinates — the single space screen.list reports,
    observe's word boxes use and input ops target, so a vision read
    feeds an injection directly."""
    s = float(screen.get("scale") or 1.0)
    return (round(float(screen.get("x", 0)) + px / s),
            round(float(screen.get("y", 0)) + py / s))


# ---------------------------------------------------------------------------
# Keysym tables (X11) — pinned by test
# ---------------------------------------------------------------------------

MODIFIER_KEYSYMS = {
    "ctrl": "Control_L",
    "shift": "Shift_L",
    "alt": "Alt_L",
    "meta": "Meta_L",
}

SPECIAL_KEYSYMS = {
    # friendly alias -> canonical X11 keysym name
    "enter": "Return", "return": "Return",
    "tab": "Tab",
    "space": "space", "spc": "space",
    "esc": "Escape", "escape": "Escape",
    "backspace": "BackSpace", "bs": "BackSpace",
    "del": "Delete", "delete": "Delete",
    "ins": "Insert", "insert": "Insert",
    "home": "Home", "end": "End",
    "pgup": "Prior", "pgdn": "Next",
    "left": "Left", "right": "Right", "up": "Up", "down": "Down",
    "f1": "F1", "f2": "F2", "f3": "F3", "f4": "F4", "f5": "F5",
    "f6": "F6", "f7": "F7", "f8": "F8", "f9": "F9", "f10": "F10",
    "f11": "F11", "f12": "F12",
}

# Every printable ASCII char maps to its own X11 keysym (Latin-1 range
# is identity); newline and tab map to their key keysyms.
TEXT_KEYSYMS = {chr(c): chr(c) for c in range(0x20, 0x7F)}
TEXT_KEYSYMS["\n"] = "Return"
TEXT_KEYSYMS["\t"] = "Tab"

_SPECIAL_NAMES = frozenset(SPECIAL_KEYSYMS.values())


def keysym_valid(name) -> bool:
    """True when /input/key can map it: a printable ASCII char, or a
    canonical special keysym name (Return, F5, space, ...)."""
    if not isinstance(name, str) or not name:
        return False
    if len(name) == 1:
        return name in TEXT_KEYSYMS
    return name in _SPECIAL_NAMES


def validate_text(text: str) -> str:
    """input/text contract: keysym-mappable characters only. The FIRST
    unmappable character is named (value + position) in the refusal —
    honest and testable, no mojibake ever reaches the keyboard."""
    if not isinstance(text, str) or text == "":
        raise ScreenError(
            "input_text_required",
            "text is required and must be a non-empty string.")
    for i, ch in enumerate(text):
        if ch not in TEXT_KEYSYMS:
            raise ScreenError(
                "input_text_unsupported",
                f"character at position {i} ({ch!r}, "
                f"U+{ord(ch):04X}) has no X11 keysym mapping — input "
                f"text supports printable ASCII, newline and tab only; "
                f"special keys go through input key --keysym.")
    return text


# ---------------------------------------------------------------------------
# Drive sessions — bounded drive mode, the pure state machine
# ---------------------------------------------------------------------------


class DriveSessions:
    """One drive session per agent, opened by an APPROVED input op,
    bounded by an event cap and a time cap (both enforced server-side
    before every op). A violation CLOSES the session; the next input
    op then needs a fresh approval. The GUI shows the disarm banner
    while `active()` is non-empty and kills everything with close_all()
    (banner click / any physical input on X11 sessions)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: dict = {}

    def open(self, agent: str, max_events: int, max_minutes: float) -> dict:
        now = time.monotonic()
        sess = {
            "agent": agent,
            "started": now,
            "expires": now + max(0.0, float(max_minutes)) * 60.0,
            "events": 0,
            "max_events": max(1, int(max_events)),
            "max_minutes": float(max_minutes),
        }
        with self._lock:
            self._sessions[agent] = sess
        return dict(sess)

    def authorize(self, agent: str) -> tuple:
        """(session, None) when an op may run under the live session.
        (None, reason) otherwise: 'no_session', or the violated cap
        ('events' / 'time') — in which case the session is CLOSED."""
        with self._lock:
            sess = self._sessions.get(agent)
            if sess is None:
                return None, "no_session"
            now = time.monotonic()
            if now >= sess["expires"]:
                del self._sessions[agent]
                return None, "time"
            if sess["events"] + 1 > sess["max_events"]:
                del self._sessions[agent]
                return None, "events"
            return dict(sess), None

    def count(self, agent: str) -> int:
        """Record one more executed event; returns the new count."""
        with self._lock:
            sess = self._sessions.get(agent)
            if sess is None:
                return 0
            sess["events"] += 1
            return sess["events"]

    def active(self) -> list:
        with self._lock:
            return [dict(s) for s in self._sessions.values()]

    def close(self, agent: str) -> bool:
        with self._lock:
            return self._sessions.pop(agent, None) is not None

    def close_all(self) -> int:
        with self._lock:
            n = len(self._sessions)
            self._sessions.clear()
        return n


# ---------------------------------------------------------------------------
# Service protocols (gui.py implements capture; the X11 backend here)
# ---------------------------------------------------------------------------


class ScreenService:
    """Protocol: list_screens() -> [{index, name, x, y, width, height,
    primary, scale, available}]; capture(targets, fmt, quality,
    max_width, out_dir, when) -> file records
    [{path, screen, geometry, format, width, height, bytes, sha256}].
    The Qt implementation lives in gui.py and runs on the GUI main
    thread; a headless host leaves ctx.screen None."""

    name = "abstract"

    def list_screens(self) -> list:
        raise ScreenError("screen_unavailable",
                          "no screen service on this host (headless).",
                          status=403)

    def capture(self, targets, fmt, quality, max_width, out_dir,
                when=None) -> list:
        raise ScreenError("screen_unavailable",
                          "no screen service on this host (headless).",
                          status=403)


class InputBackend:
    """Protocol: window resolution (the own-window hit test) + XTest
    injection. `own_window_ids` is the set the host GUI registers (X11
    sessions) — the self-approval loop dies by construction because a
    hit on any of those ids refuses BEFORE anything is injected."""

    name = "abstract"

    def __init__(self):
        self.own_window_ids: set = set()

    def window_at(self, x, y):
        raise ScreenError("screen_unavailable", "no input backend.",
                          status=403)

    def focused_window(self):
        raise ScreenError("screen_unavailable", "no input backend.",
                          status=403)

    def mouse_move(self, x, y):
        raise ScreenError("screen_unavailable", "no input backend.",
                          status=403)

    def mouse_click(self, button, x, y):
        raise ScreenError("screen_unavailable", "no input backend.",
                          status=403)

    def mouse_doubleclick(self, button, x, y):
        raise ScreenError("screen_unavailable", "no input backend.",
                          status=403)

    def mouse_drag(self, button, from_x, from_y, to_x, to_y):
        raise ScreenError("screen_unavailable", "no input backend.",
                          status=403)

    def mouse_scroll(self, x, y, dx, dy):
        raise ScreenError("screen_unavailable", "no input backend.",
                          status=403)

    def key(self, keysym, modifiers=()):
        raise ScreenError("screen_unavailable", "no input backend.",
                          status=403)

    def type_text(self, text):
        raise ScreenError("screen_unavailable", "no input backend.",
                          status=403)


# ---------------------------------------------------------------------------
# OCR + window list (lazy optional deps — venv-only installs)
# ---------------------------------------------------------------------------


def ocr_words(image_path: str, screen: dict) -> tuple:
    """OCR one captured screen: tesseract words with confidence and
    boxes in GLOBAL logical coordinates (to_global), plus a plain-text
    digest — the read path for text-channel agents. Lazy imports:
    pytesseract + Pillow are venv-only optionals; a host without them
    refuses screen_unavailable naming the missing module."""
    try:
        import pytesseract
        from PIL import Image
    except ImportError as e:
        raise ScreenError(
            "screen_unavailable",
            f"observe needs pytesseract + Pillow in the host venv "
            f"(missing module: {e.name}); install them with "
            f".venv/bin/pip install pytesseract Pillow.",
            status=403) from None
    try:
        img = Image.open(image_path)
    except OSError as e:
        raise ScreenError(
            "observe_failed",
            f"could not open the shot for OCR: {e}", status=500) from None
    data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
    scale = float(screen.get("scale") or 1.0)
    words: list = []
    texts: list = []
    n = len(data.get("text", []))
    for i in range(n):
        txt = str(data["text"][i]).strip()
        try:
            conf = float(data["conf"][i])
        except (TypeError, ValueError):
            conf = -1.0
        if not txt or conf < 0:
            continue
        gx, gy = to_global(screen, data["left"][i], data["top"][i])
        words.append({
            "text": txt, "conf": round(conf, 1), "x": gx, "y": gy,
            "w": round(float(data["width"][i]) / scale),
            "h": round(float(data["height"][i]) / scale)})
        texts.append(txt)
    return words, " ".join(texts)


def window_list(display_name=None) -> list:
    """The X client tree via _NET_CLIENT_LIST: XWayland clients on this
    host (games, Steam, Proton) with titles, absolute geometry,
    visibility and focus. Wayland-native windows are NOT in this tree —
    documented reach map, not a silent gap. Raises ScreenError
    (windows_unavailable) when X or python-xlib is unreachable."""
    try:
        from Xlib import X, display as _xdisplay
    except ImportError as e:
        raise ScreenError(
            "windows_unavailable",
            f"the window list needs python-xlib in the host venv "
            f"(missing module: {e.name}).") from None
    try:
        d = _xdisplay.Display(display_name)
    except Exception as e:
        raise ScreenError(
            "windows_unavailable",
            f"no X display for the window tree ({e}).") from None
    out: list = []
    try:
        root = d.screen().root
        prop = root.get_full_property(
            d.get_atom("_NET_CLIENT_LIST"), X.AnyPropertyType)
        if not prop or not prop.value:
            return out
        focus_id = None
        try:
            focus_id = d.get_input_focus().focus.id
        except Exception:
            pass
        for wid in prop.value:
            try:
                w = d.create_resource_object("window", int(wid))
                title = w.get_wm_name() or ""
                try:
                    nm = w.get_full_property(
                        d.get_atom("_NET_WM_NAME"), X.AnyPropertyType)
                    if nm and nm.value:
                        title = nm.value.decode("utf-8", "replace")
                except Exception:
                    pass
                g = w.get_geometry()
                tr = root.translate_coords(int(wid), 0, 0)
                mapped = True
                try:
                    mapped = w.get_attributes().map_state == X.IsViewable
                except Exception:
                    pass
                out.append({
                    "id": int(wid), "title": title,
                    "x": int(tr.dest_x), "y": int(tr.dest_y),
                    "width": int(g.width), "height": int(g.height),
                    "visible": bool(mapped),
                    "focused": focus_id == int(wid)})
            except Exception:
                continue     # a window died mid-list — skip it, keep going
    finally:
        try:
            d.close()
        except Exception:
            pass
    return out


# ---------------------------------------------------------------------------
# X11 / XTest input backend (server thread, no Qt)
# ---------------------------------------------------------------------------

_BUTTON_NUM = {"left": 1, "middle": 2, "right": 3}
_SCROLL_CAP = 200          # max scroll units injected per op


class X11InputBackend(InputBackend):
    """XTest fake-input via python-xlib + window resolution by tree
    walk. Constructed from the SERVER thread (make_input_backend); the
    Display is used only from request threads (llmac serializes input
    ops behind the drive session + request semaphore)."""

    name = "x11-xtest"

    def __init__(self, display_name=None):
        super().__init__()
        from Xlib import X, XK, display as _xdisplay
        from Xlib.ext import xtest
        self._X = X
        self._XK = XK
        self._xtest = xtest
        self._d = _xdisplay.Display(display_name)
        self._root = self._d.screen().root

    # -- window resolution (the own-window hit test) --------------------

    def window_at(self, x, y):
        """Deepest child of the root whose rect contains (x, y),
        topmost-first (children are returned bottom-to-top). Approximate
        under compositors — v1 documented; the refusal set is what
        matters, not perfect z-order."""
        try:
            win = self._root
            while True:
                try:
                    children = win.query_tree().children
                except Exception:
                    return win.id
                hit = None
                for c in reversed(children):
                    try:
                        tr = self._root.translate_coords(c.id, 0, 0)
                        g = c.get_geometry()
                        if (tr.dest_x <= x < tr.dest_x + g.width
                                and tr.dest_y <= y < tr.dest_y + g.height):
                            hit = c
                            break
                    except Exception:
                        continue
                if hit is None:
                    return win.id
                win = hit
        except Exception:
            return None

    def focused_window(self):
        try:
            return int(self._d.get_input_focus().focus.id)
        except Exception:
            return None

    # -- injection ---------------------------------------------------------

    def _flush(self):
        try:
            self._d.flush()
        except Exception:
            pass

    def _motion(self, x, y):
        self._xtest.fake_input(self._d, self._X.MotionNotify,
                               x=int(round(x)), y=int(round(y)))
        self._flush()

    def _button(self, num: int, pressed: bool):
        ev = (self._X.ButtonPress if pressed
              else self._X.ButtonRelease)
        self._xtest.fake_input(self._d, ev, detail=num)
        self._flush()

    def _click_button(self, button: str):
        num = _BUTTON_NUM.get(button, 1)
        self._button(num, True)
        self._button(num, False)

    def _keycode_for(self, keysym_name: str):
        """(keycode, needs_shift) for an X11 keysym name, or (None,
        False) when the keyboard cannot produce it."""
        ks = self._XK.string_to_keysym(keysym_name)
        if not ks:
            return None, False
        code = self._d.keysym_to_keycode(ks)
        if not code:
            return None, False
        try:
            syms = self._d.get_keyboard_mapping(code, 1) or []
        except Exception:
            syms = []
        return int(code), ks not in syms[:1]

    def _press_key(self, code: int):
        self._xtest.fake_input(self._d, self._X.KeyPress, detail=code)

    def _release_key(self, code: int):
        self._xtest.fake_input(self._d, self._X.KeyRelease, detail=code)

    def mouse_move(self, x, y):
        self._motion(x, y)

    def mouse_click(self, button, x, y):
        self._motion(x, y)
        self._click_button(button)

    def mouse_doubleclick(self, button, x, y):
        self._motion(x, y)
        self._click_button(button)
        time.sleep(0.05)
        self._click_button(button)

    def mouse_drag(self, button, from_x, from_y, to_x, to_y):
        num = _BUTTON_NUM.get(button, 1)
        self._motion(from_x, from_y)
        self._button(num, True)
        self._motion(to_x, to_y)
        self._button(num, False)

    def mouse_scroll(self, x, y, dx, dy):
        self._motion(x, y)
        units = {"up": min(int(abs(dy)), _SCROLL_CAP) if dy > 0 else 0,
                 "down": min(int(abs(dy)), _SCROLL_CAP) if dy < 0 else 0,
                 "right": min(int(abs(dx)), _SCROLL_CAP) if dx > 0 else 0,
                 "left": min(int(abs(dx)), _SCROLL_CAP) if dx < 0 else 0}
        buttons = {"up": 4, "down": 5, "right": 6, "left": 7}
        for direction, n in units.items():
            for _ in range(n):
                self._button(buttons[direction], True)
                self._button(buttons[direction], False)

    def key(self, keysym, modifiers=()):
        code, shift = self._keycode_for(keysym)
        if code is None:
            raise ScreenError(
                "input_keysym_unknown",
                f"keysym {keysym!r} has no keycode on this keyboard.")
        mod_codes = []
        for m in modifiers:
            mc, _ = self._keycode_for(MODIFIER_KEYSYMS[m])
            if mc:
                mod_codes.append(mc)
        if shift:
            sc, _ = self._keycode_for("Shift_L")
            if sc:
                mod_codes.append(sc)
        for c in mod_codes:
            self._press_key(c)
        self._press_key(code)
        self._release_key(code)
        for c in reversed(mod_codes):
            self._release_key(c)
        self._flush()

    def type_text(self, text):
        for ch in text:
            self.key(TEXT_KEYSYMS[ch], ())


def make_input_backend(display_name=None):
    """Best-effort X11/XTest backend; None when no X display is
    reachable (native Wayland without XWayland, headless host, missing
    python-xlib). Ops then refuse screen_unavailable naming it — never
    a silent no-op."""
    try:
        return X11InputBackend(display_name)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# XI2 raw-input disarm listener (X11 sessions — best-effort)
# ---------------------------------------------------------------------------


def xi2_disarm_listener(on_physical_input, display_name=None):
    """Daemon thread listening for XI2 RAW key/button/motion events on
    the root window and calling on_physical_input() on the FIRST one.
    Raw events come from hardware slaves only — XTest-injected events
    produce none — so ANY physical input disarms the drive session
    while injected input never trips it. Returns the Thread, or None
    when XI2 is unavailable (non-X11 session / old server / no
    python-xlib): the banner click + the caps remain the breakout,
    stated in agent.md, not hidden."""
    try:
        from Xlib import display as _xdisplay
        from Xlib.ext import xinput
        d = _xdisplay.Display(display_name)
        root = d.screen().root
        mask = (xinput.RawKeyPressMask | xinput.RawButtonPressMask
                | xinput.RawMotionMask)
        root.select_events([(xinput.AllMasterDevices, mask)])
    except Exception:
        return None

    def _run():
        try:
            # Only raw events arrive on this fresh connection: the
            # first event IS physical input.
            d.next_event()
            on_physical_input()
        except Exception:
            pass

    t = threading.Thread(target=_run, daemon=True,
                         name="llmac-xi2-disarm")
    t.start()
    return t
