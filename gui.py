#!/usr/bin/env python3
"""PyQt6 GUI for the LLMAC v2 host — tabbed supervisor layout.

This module is imported lazily by host.py ONLY when GUI mode is requested.
This means `python host.py --headless` works without PyQt6 installed.

v2.1 layout goals (learned from the v2.0 stacked layout):
* a window that stays usable when small — every tab scrolls instead of
  clipping, the log no longer competes with six stacked panels, and all
  controls remain reachable at 640x480;
* the approval queue is a first-class tab (with tab badge + header pill),
  including agent-initiated *share requests*: approving one actually adds
  the directory to the shared roots;
* every v2 capability is visible somewhere: named agents, approval
  policies, TLS fingerprint, install venvs, background processes;
* the server can start with zero shared directories — an agent connects,
  then asks for the directories it needs via `roots request`, and the
  human approves them here.

Requires: pip install PyQt6
"""
from __future__ import annotations

import hashlib
import html
import os
import re
import subprocess
import sys
import tempfile
import time
import threading
from datetime import datetime
from typing import Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QFrame, QPushButton, QLineEdit, QLabel,
    QListWidget, QListWidgetItem, QPlainTextEdit, QComboBox,
    QFileDialog, QMessageBox, QAbstractItemView,
    QCheckBox, QDialog, QFormLayout, QDialogButtonBox, QInputDialog,
    QTabWidget, QScrollArea, QTableWidget, QTableWidgetItem, QHeaderView,
    QSizePolicy, QScrollBar, QTextBrowser, QTextEdit, QSpinBox,
)
from PyQt6.QtCore import (
    Qt, QTimer, QThread, pyqtSignal, QEvent, QObject,
    QIODevice, QBuffer,
)
from PyQt6.QtGui import (
    QColor, QTextCursor, QFont, QGuiApplication,
    QImage,
)

from core.constants import (
    DEFAULT_DATA_DIR, DEFAULT_HOST, DEFAULT_PORT, LLMAC_VERSION,
    POLICY_AUTO, POLICY_DESTRUCTIVE, POLICY_STRICT, VALID_POLICIES,
    DEFAULT_SHOT_DIR,
)
from core.state import (
    History, StateStore, export_session, import_session, key_fingerprint,
    make_default_agent, new_key, normalize_agent, now_iso,
)
from core import tlsutil
from core.api import add_grant
from core.transcript import (
    count_hits, default_export_name, guess_format, transcript_html,
    transcript_markdown, transcript_plaintext, EXPORT_FILTERS,
)
from core.screen import (
    ScreenError, crop_rect, make_input_backend, shot_filename,
    xi2_disarm_listener,
)
from core.server import (
    build_context, build_prompt_text, fetch_public_ip, make_server,
)
from core import netinfo

# ---------------------------------------------------------------------------
# Theme — modern dark UI (v2.2)
#
# Design rules, straight from the v2.1 visual audit (VLM-reviewed):
#   1. Elevation, not frames. Cards separate from the canvas by surface
#      color with a near-invisible hairline — the v2.1 theme drew a 1px
#      grid around everything ("boxes inside boxes", ~6 stacked rectangles
#      per view) and read as a 1990s Java applet.
#   2. Affordances are drawn, never assumed. Once QSS touches a QComboBox
#      or QCheckBox, Qt stops painting the native chevron / tick — v2.1
#      shipped exactly that bug: the bind-host dropdown was literally
#      invisible ("a dead text field"). Both glyphs are now painted into
#      <data_dir>/assets at startup and referenced from the stylesheet.
#   3. One accent color (indigo) for focus / selection / primary actions;
#      green / amber / red are reserved for state meaning.
# ---------------------------------------------------------------------------

# Palette — single source of truth for QSS and the inline code styles.
C_BG        = "#0b0e14"   # window canvas
C_SURFACE   = "#121722"   # cards
C_SURFACE2  = "#161c29"   # popups, tooltips, elevated strips
C_INSET     = "#0a0d13"   # fields / lists / tables (recessed wells)
C_BTN       = "#1b2231"   # neutral button surface
C_TEXT      = "#dbe3f0"
C_MUTED     = "#a6b1c6"
C_DIM       = "#5b6478"
C_ACCENT    = "#7c8cf8"
C_ACCENT_DK = "#5b6ee1"
C_GREEN     = "#4ade80"
C_AMBER     = "#e3b341"
C_RED       = "#ff7b72"


def _ensure_theme_assets(data_dir: str = "") -> str:
    """Paint the glyphs QSS cannot draw itself into <data_dir>/assets.

    Returns the assets directory (absolute, forward slashes) that the
    stylesheet references. Requires a live QApplication — callers only
    invoke this after one exists.
    """
    from PyQt6.QtCore import QPointF
    from PyQt6.QtGui import QPixmap, QPainter, QPen, QPolygonF

    base = os.path.abspath(data_dir or DEFAULT_DATA_DIR)
    assets = os.path.join(base, "assets")
    os.makedirs(assets, exist_ok=True)

    def _paint(points, color, width, out_name):
        pm = QPixmap(16, 16)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor(color))
        pen.setWidthF(width)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.drawPolyline(QPolygonF([QPointF(x, y) for x, y in points]))
        p.end()
        pm.save(os.path.join(assets, out_name))

    _paint([(3.5, 6.5), (8.0, 11.0), (12.5, 6.5)], "#d7deea", 2.2,
           "chevron-down.png")          # combo affordance
    _paint([(3.2, 8.6), (6.6, 12.0), (12.8, 4.4)], "#ffffff", 2.6,
           "check.png")                 # checkbox tick
    return assets


def build_stylesheet(data_dir: str = "") -> str:
    """The v2.2 stylesheet. `data_dir` decides where the glyph assets live."""
    chevron = check = ""
    if QApplication.instance() is not None:
        assets = _ensure_theme_assets(data_dir)
        chevron = os.path.join(assets, "chevron-down.png").replace("\\", "/")
        check = os.path.join(assets, "check.png").replace("\\", "/")
    qss = _QSS_TEMPLATE
    if chevron:
        qss = qss.replace("/*__CHEVRON__*/", f"image: url({chevron});")
        qss = qss.replace("/*__CHECK__*/", f"image: url({check});")
    return qss


def apply_theme(app: QApplication, data_dir: str = "") -> None:
    """Fusion style + dark palette + QSS. Call once after creating the app.

    The palette matters for everything QSS cannot reach (native dialogs,
    scroll interaction states, accessibility) — without it a QSS-dark app
    still shows white flashes and unreadable native bits.
    """
    from PyQt6.QtWidgets import QStyleFactory
    from PyQt6.QtGui import QPalette

    app.setStyle(QStyleFactory.create("Fusion"))
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor(C_BG))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(C_TEXT))
    pal.setColor(QPalette.ColorRole.Base, QColor(C_INSET))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor("#0e1219"))
    pal.setColor(QPalette.ColorRole.Text, QColor(C_TEXT))
    pal.setColor(QPalette.ColorRole.Button, QColor(C_BTN))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor(C_TEXT))
    pal.setColor(QPalette.ColorRole.Highlight, QColor(C_ACCENT_DK))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(C_SURFACE2))
    pal.setColor(QPalette.ColorRole.ToolTipText, QColor(C_TEXT))
    pal.setColor(QPalette.ColorRole.Link, QColor(C_ACCENT))
    pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(C_DIM))
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text,
                 QColor(C_DIM))
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText,
                 QColor(C_DIM))
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText,
                 QColor(C_DIM))
    app.setPalette(pal)
    app.setStyleSheet(build_stylesheet(data_dir))


_QSS_TEMPLATE = """
* { outline: none; }
QMainWindow, QDialog, QWidget {
    background-color: #0b0e14;
    color: #dbe3f0;
    font-family: 'Segoe UI', 'Noto Sans', 'Ubuntu', 'Sans';
    font-size: 10pt;
}

/* ---- cards: elevation, not frames ------------------------------------ */
QFrame[card="true"] {
    background-color: #121722;
    border: 1px solid rgba(255,255,255,0.055);
    border-radius: 12px;
}
QFrame[callout="true"] {
    background-color: #151d2c;
    border: 1px solid rgba(124,140,248,0.22);
    border-radius: 12px;
}

/* ---- text ------------------------------------------------------------- */
QLabel[section="true"] { color: #bcc7db; font-weight: 700; }
QLabel[muted="true"]   { color: #a6b1c6; }
QLabel[mono="true"] {
    font-family: 'Cascadia Code', 'Consolas', 'DejaVu Sans Mono', monospace;
}

/* ---- buttons ----------------------------------------------------------- */
QPushButton {
    background-color: #1b2231;
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 8px;
    padding: 5px 14px;
    color: #dbe3f0;
    min-height: 22px;
    font-weight: 500;
}
QPushButton:hover { background-color: #232c40;
                    border-color: rgba(255,255,255,0.16); }
QPushButton:pressed { background-color: #151b29; }
QPushButton:disabled { color: #5b6478; background-color: #12161f;
                       border-color: rgba(255,255,255,0.04); }
QPushButton[variant="primary"] {
    background-color: #5b6ee1; border: none; color: #ffffff;
    font-weight: 600;
}
QPushButton[variant="primary"]:hover { background-color: #7181ec; }
QPushButton[variant="primary"]:pressed { background-color: #4d5fd1; }
QPushButton[variant="primary"]:disabled {
    background-color: #23283c; color: #5b6478;
}
QPushButton[variant="danger"] {
    background-color: rgba(248,81,73,0.12);
    border: 1px solid rgba(248,81,73,0.50);
    color: #ff8b81;
    font-weight: 600;
}
QPushButton[variant="danger"]:hover {
    background-color: #e5524a; border-color: #e5524a; color: #ffffff;
}
QPushButton[variant="danger"]:pressed { background-color: #c53f38; }
QPushButton[variant="danger"]:disabled {
    background-color: #1a1418; border-color: rgba(255,255,255,0.04);
    color: #5b6478;
}
QPushButton[variant="pill"] {
    background-color: #2a2113; border: 1px solid #9e6a03; color: #e3b341;
    border-radius: 12px; padding: 2px 12px; min-height: 16px;
    font-weight: 600;
}
QPushButton[variant="pill"]:hover { background-color: #9e6a03; color: #0b0e14; }

/* ---- inputs ------------------------------------------------------------ */
QLineEdit, QComboBox {
    background-color: #0a0d13;
    border: 1px solid rgba(255,255,255,0.09);
    border-radius: 8px;
    padding: 5px 10px;
    min-height: 22px;
    color: #dbe3f0;
    selection-background-color: #5b6ee1;
    selection-color: #ffffff;
}
QLineEdit:hover, QComboBox:hover { border-color: rgba(255,255,255,0.18); }
QLineEdit:focus, QComboBox:focus { border-color: #7c8cf8; }
QLineEdit:read-only { background-color: #10141d; color: #a6b1c6; }
QLineEdit:disabled, QComboBox:disabled {
    color: #5b6478; background-color: #10141d;
}

/* The combo affordance, drawn explicitly so it can never vanish:
   Qt stops painting the native chevron as soon as QSS styles the box
   (the v2.1 invisible-dropdown bug). */
QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: right center;
    width: 26px;
    border: none;
    border-left: 1px solid rgba(255,255,255,0.05);
}
QComboBox::drop-down:hover {
    background: rgba(255,255,255,0.07);
    border-top-right-radius: 8px;
    border-bottom-right-radius: 8px;
}
QComboBox::down-arrow {
    /*__CHEVRON__*/
    width: 13px; height: 13px;
}
QComboBox QAbstractItemView {
    background-color: #161c29;
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 8px;
    padding: 4px;
    outline: none;
    color: #dbe3f0;
    selection-background-color: rgba(124,140,248,0.45);
    selection-color: #ffffff;
}
QComboBox QAbstractItemView::item {
    padding: 5px 10px;
    border-radius: 5px;
    min-height: 20px;
}

/* ---- lists / tables / text wells (borderless inset wells: the
   recessed background IS the control boundary, no 1px frames) ------------- */
QListWidget, QTableWidget, QPlainTextEdit, QTextEdit {
    background-color: #0a0d13;
    border: none;
    color: #dbe3f0;
    selection-background-color: rgba(124,140,248,0.45);
    selection-color: #ffffff;
    alternate-background-color: rgba(255,255,255,0.022);
}
QListWidget::item { padding: 4px 6px; border-radius: 5px; }
QListWidget::item:hover { background: rgba(255,255,255,0.08); }
/* v2.4.6 (user report: "no highlight on the selected approval, feels
   unresponsive"): the old 0.30-alpha selection over a near-black well
   was nearly invisible. Strong fill + accent bar + bold white so the
   clicked row is unmistakable in EVERY list. */
QListWidget::item:selected {
    background: rgba(124,140,248,0.55);
    color: #ffffff;
    border-left: 3px solid #8b9aff;
}
QListWidget::item:selected:disabled { background: rgba(124,140,248,0.35); }
QTableWidget { gridline-color: transparent; }
QHeaderView::section {
    background-color: transparent;
    border: none;
    border-bottom: 1px solid rgba(255,255,255,0.09);
    padding: 6px 8px;
    color: #a6b1c6;
    font-weight: 600;
}
QTableCornerButton::section { background: transparent; border: none; }
QPlainTextEdit {
    padding: 6px;
    font-family: 'Cascadia Code', 'Consolas', 'DejaVu Sans Mono', monospace;
    font-size: 9pt;
}

/* ---- tabs --------------------------------------------------------------- */
QTabWidget::pane {
    border: 1px solid rgba(255,255,255,0.055);
    border-radius: 10px;
    background: transparent;
}
QTabBar::tab {
    background: transparent;
    color: #a6b1c6;
    padding: 8px 16px;
    margin-right: 2px;
    border-bottom: 2px solid transparent;
    font-weight: 500;
}
QTabBar::tab:selected { color: #e6ebf4; border-bottom: 2px solid #7c8cf8; }
QTabBar::tab:hover:!selected {
    color: #dbe3f0;
    background: rgba(255,255,255,0.04);
}

/* ---- checkboxes ----------------------------------------------------------- */
QCheckBox { spacing: 8px; }
QCheckBox:disabled { color: #5b6478; }
QCheckBox::indicator {
    width: 17px; height: 17px;
    border: 1px solid rgba(255,255,255,0.25); border-radius: 5px;
    background-color: #0a0d13;
}
QCheckBox::indicator:hover { border-color: #7c8cf8; }
QCheckBox::indicator:checked {
    background-color: #5b6ee1; border-color: #7c8cf8;
    /*__CHECK__*/
}
QCheckBox::indicator:disabled {
    border-color: rgba(255,255,255,0.06); background-color: #10141d;
}

/* ---- scrollbars: rail + thumb so they read as controls ---------------- */
QScrollBar:vertical {
    background: rgba(255,255,255,0.028); width: 12px; margin: 2px;
    border-radius: 6px;
}
QScrollBar::handle:vertical {
    background: #3a465f; border-radius: 5px; min-height: 30px;
}
QScrollBar::handle:vertical:hover { background: #4d5c7d; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: transparent;
}
QScrollBar:horizontal {
    background: rgba(255,255,255,0.028); height: 12px; margin: 2px;
    border-radius: 6px;
}
QScrollBar::handle:horizontal {
    background: #3a465f; border-radius: 5px; min-width: 30px;
}
QScrollBar::handle:horizontal:hover { background: #4d5c7d; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
    background: transparent;
}

/* ---- tooltips + status bar ------------------------------------------------- */
QToolTip {
    background-color: #161c29;
    color: #dbe3f0;
    border: 1px solid rgba(255,255,255,0.14);
    border-radius: 6px;
    padding: 6px 8px;
}
QStatusBar { background-color: #10141d;
             border-top: 1px solid rgba(255,255,255,0.06); }
QStatusBar::item { border: none; }
"""

# Log level -> HTML color
LOG_COLORS = {
    "INFO":     "#7c8cf8",  # indigo
    "OK":       "#4ade80",  # green
    "WARN":     "#e3b341",  # amber
    "ERROR":    "#ff7b72",  # red
    "REJECTED": "#ff7b72",  # red
    "REQUEST":  "#64748b",  # gray
    "OP":       "#d2a8ff",  # purple
}

# v2.5.1 (ASK-006): tab indices are WIDGET-DERIVED — captured from
# addTab return values in _build_ui (self.TAB_*). The module-level
# range(6) constants silently survived the Sessions insertion and
# _update_pills relabeled the wrong tabs (the user's bug report);
# insertion-proof by construction now.


def _elide_mid(s: str, keep: int = 18) -> str:
    """Shorten long strings keeping head and tail (for fingerprints/paths)."""
    if len(s) <= keep * 2 + 1:
        return s
    return f"{s[:keep]}…{s[-keep:]}"


def _split_thread_paragraphs(text: str, cap: int = 300) -> list:
    """v2.5.2 (ASK-008): break a long thread entry into chat-readable
    paragraphs at sentence boundaries, packing sentences up to ~cap
    chars per paragraph. Short entries come back as one paragraph.
    The wall-of-text transcript the user pasted is what this cures."""
    if len(text) <= cap:
        return [text]
    parts = re.split(r"(?<=[.!?])\s+", text)
    out, cur = [], ""
    for p in parts:
        if cur and len(cur) + 1 + len(p) > cap:
            out.append(cur)
            cur = p
        else:
            cur = f"{cur} {p}".strip()
    if cur:
        out.append(cur)
    return out


# ---------------------------------------------------------------------------
# Public IP fetch worker (runs in a background QThread)
# ---------------------------------------------------------------------------

class IPFetchWorker(QThread):
    """Fetches the public IP in a background thread, emits a signal when done."""
    ip_fetched = pyqtSignal(str)  # emits the IP string, or "" if failed

    def run(self):
        ip = fetch_public_ip()
        self.ip_fetched.emit(ip if ip else "")


# ---------------------------------------------------------------------------
# v2.7.0 (ASK-016/017): the screen channel — the GUI-thread bridge, the
# Qt capture service and the drive-mode disarm banner.
# ---------------------------------------------------------------------------

# Approval classes that offer the until-restart session grant (the
# "Approve for this session" card button).
_SCREEN_GRANT_OPS = ("screen_shot", "screen_observe", "screen_input")


class _CallEvent(QEvent):
    """Carries one callable to the GUI main thread."""

    _TYPE = None

    @classmethod
    def type_id(cls) -> int:
        if cls._TYPE is None:
            cls._TYPE = QEvent.registerEventType()
        return cls._TYPE

    def __init__(self, fn, done, box):
        super().__init__(_CallEvent.type_id())
        self.fn = fn
        self.done = done
        self.box = box


class MainThreadCaller(QObject):
    """v2.7.0: runs a callable ON the GUI main thread; the calling
    (server) thread blocks on an Event until it completes — the queued
    bridge the approval ring uses, expressed with postEvent (thread-
    safe, no slot/Q_ARG plumbing). The HTTP handler never touches Qt;
    it calls into QtScreenService which hops across here."""

    def __init__(self, parent=None):
        super().__init__(parent)

    def event(self, e):
        if e.type() == _CallEvent.type_id():
            try:
                e.box["value"] = e.fn()
            except Exception as exc:
                e.box["error"] = exc
            finally:
                e.done.set()
            return True
        return super().event(e)

    def call(self, fn, timeout: float = 30.0):
        # Same-thread invocation runs directly — a direct call from the
        # GUI thread would otherwise self-deadlock on the event wait
        # (the server threads are the normal callers; this guard also
        # lets acceptance scripts exercise the service inline). The Qt
        # event loop lives on the Python main thread, so Python-level
        # identity is the reliable check (sip wrappers are not).
        if threading.current_thread() is threading.main_thread():
            return fn()
        done = threading.Event()
        box = {"value": None, "error": None}
        QApplication.postEvent(self, _CallEvent(fn, done, box))
        if not done.wait(timeout):
            raise ScreenError(
                "screen_unavailable",
                f"the GUI main thread did not answer within {timeout}s "
                f"(busy or shutting down)", status=403)
        if box["error"] is not None:
            raise box["error"]
        return box["value"]


class QtScreenService:
    """v2.7.0 (ASK-016): the ScreenService protocol on Qt. All Qt work
    executes on the GUI main thread through MainThreadCaller; file IO
    + sha256 stay on the calling (server) thread.

    Backends (the reach map, pinned by live recon):
      * X11 session / Windows: QScreen.grabWindow(0) per screen — the
        native per-screen crop, exactly what the ask demands.
      * KDE Wayland (this host): `spectacle -b -n -f -o <tmp>` writes
        the merged full-desktop PNG at native resolution; per-screen
        crop by QScreen geometry x scale (core.screen.crop_rect,
        unit-tested; mixed-DPI caveat documented in agent.md tip 20).
        When the target is ALL screens the merged source is kept as an
        extra evidence file (screen-<stamp>-all.<ext>).
      * Other Wayland compositors: screen_capture_unsupported naming
        the desktop — no silent black frames, ever."""

    name = "qt"

    def __init__(self, caller: MainThreadCaller):
        self._caller = caller

    # -- platform helpers -------------------------------------------------

    @staticmethod
    def _platform() -> str:
        try:
            return QGuiApplication.platformName().lower()
        except Exception:
            return ""

    @staticmethod
    def _is_kde() -> bool:
        blob = (os.environ.get("XDG_CURRENT_DESKTOP", "") + " "
                + os.environ.get("XDG_SESSION_DESKTOP", ""))
        return "kde" in blob.lower()

    # -- protocol (server thread) -----------------------------------------

    def list_screens(self):
        try:
            return self._caller.call(self._list_screens_qt)
        except ScreenError:
            raise
        except Exception as e:
            raise ScreenError("screen_unavailable",
                              f"screen enumeration failed: {e}",
                              status=403) from None

    def capture(self, targets, fmt, quality, max_width, out_dir, when=None):
        payload = {"targets": [dict(t) for t in targets], "fmt": fmt,
                   "quality": quality, "max_width": max_width}
        try:
            blobs = self._caller.call(lambda: self._capture_qt(payload))
        except ScreenError:
            raise
        except Exception as e:
            raise ScreenError("shot_failed", f"capture failed: {e}",
                              status=500) from None
        os.makedirs(out_dir, exist_ok=True)
        when = when or datetime.now()
        files = []
        for (index, data, w, h, geom) in blobs:
            fname = shot_filename(index, when, fmt)
            path = os.path.join(out_dir, fname)
            with open(path, "wb") as f:
                f.write(data)
            files.append({
                "path": path, "screen": index, "geometry": geom,
                "format": fmt, "width": w, "height": h,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest()})
        return files

    # -- main-thread work ---------------------------------------------------

    def _list_screens_qt(self):
        if QApplication.instance() is None:
            raise ScreenError("screen_unavailable",
                              "no QApplication on this host",
                              status=403)
        out = []
        screens = QGuiApplication.screens()
        primary = QGuiApplication.primaryScreen()
        for i, scr in enumerate(screens):
            g = scr.geometry()
            out.append({
                "index": i, "name": scr.name(),
                "x": g.x(), "y": g.y(),
                "width": g.width(), "height": g.height(),
                "primary": scr is primary,
                "scale": round(float(scr.devicePixelRatio()), 3),
                "available": True})
        return out

    def _encode(self, img, fmt, quality):
        buf = QBuffer()
        buf.open(QIODevice.OpenModeFlag.ReadWrite)
        if fmt == "jpg":
            img.save(buf, "JPG", int(quality))
        else:
            img.save(buf, "PNG")
        data = bytes(buf.data())
        buf.close()
        return data

    def _scale(self, img, max_width):
        if max_width and img.width() > int(max_width):
            h = max(1, round(img.height() * int(max_width)
                            / img.width()))
            return img.scaled(int(max_width), h,
                              Qt.AspectRatioMode.KeepAspectRatio,
                              Qt.TransformationMode.SmoothTransformation)
        return img

    def _capture_qt(self, payload):
        fmt = payload["fmt"]
        quality = payload["quality"]
        max_width = payload["max_width"]
        platform = self._platform()
        if platform in ("", "xcb", "windows", "winrt", "direct2d"):
            pairs = self._grab_native(payload["targets"])
            merged = None
        elif platform == "wayland":
            if not self._is_kde():
                raise ScreenError(
                    "screen_capture_unsupported",
                    f"Wayland compositor "
                    f"{os.environ.get('XDG_CURRENT_DESKTOP', 'unknown')!r}"
                    f" has no capture path in v1 (KDE uses Spectacle; "
                    f"X11 and Windows are native).", status=403)
            pairs, merged = self._grab_spectacle(payload["targets"])
        else:
            raise ScreenError(
                "screen_capture_unsupported",
                f"the {platform!r} Qt platform has no capture path in "
                f"v1.", status=403)
        out = []
        for (t, img) in pairs:
            img = self._scale(img, max_width)
            geom = [t["x"], t["y"], t["width"], t["height"]]
            out.append((t["index"], self._encode(img, fmt, quality),
                        img.width(), img.height(), geom))
        if merged is not None and len(pairs) > 1:
            # "all" on the Spectacle path keeps the merged source too
            out.append(("all", self._encode(merged, fmt, quality),
                        merged.width(), merged.height(),
                        [0, 0, merged.width(), merged.height()]))
        return out

    def _grab_native(self, targets):
        screens = QGuiApplication.screens()
        out = []
        for t in targets:
            idx = int(t["index"])
            if idx >= len(screens):
                raise ScreenError(
                    "screen_not_found",
                    f"screen {idx} vanished mid-capture.", status=400)
            pm = screens[idx].grabWindow(0)
            if pm.isNull():
                raise ScreenError(
                    "shot_failed",
                    f"QScreen.grabWindow returned null for screen {idx}.",
                    status=500)
            out.append((t, pm.toImage()))
        return out

    def _grab_spectacle(self, targets):
        """Merged full-desktop PNG via Spectacle, then per-screen crop
        (crop_rect: logical geometry x scale = physical pixels)."""
        fd, tmp = tempfile.mkstemp(suffix=".png",
                                   prefix="llmac-shot-")
        os.close(fd)
        try:
            cp = subprocess.run(
                ["spectacle", "-b", "-n", "-f", "-o", tmp],
                capture_output=True, timeout=60)
            if cp.returncode != 0 or not os.path.getsize(tmp):
                raise ScreenError(
                    "screen_capture_unsupported",
                    "Spectacle failed (rc="
                    f"{cp.returncode}): "
                    f"{cp.stderr.decode('utf-8', 'replace')[:200]}",
                    status=403)
            full = QImage(tmp)
            if full.isNull():
                raise ScreenError(
                    "shot_failed",
                    "Spectacle produced no readable image.",
                    status=500)
            out = []
            for t in targets:
                x, y, w, h = crop_rect(t)
                x = max(0, x)
                y = max(0, y)
                w = max(1, min(w, full.width() - x))
                h = max(1, min(h, full.height() - y))
                out.append((t, full.copy(x, y, w, h)))
            return out, full
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass


class DriveBanner(QWidget):
    """v2.7.0 (ASK-017 part B): the live disarm surface while a drive
    session runs — frameless, always-on-top, ONE click kills every
    drive session instantly. On X11 sessions an XI2 raw-event listener
    (the XInput2 'xinput' extension's raw events — hardware only;
    XTest-injected events produce none) disarms on ANY physical input;
    on Wayland the banner click + the caps are the breakout (apps
    cannot hook global input there — stated in agent.md, not hidden)."""

    disarmClicked = pyqtSignal()

    def __init__(self):
        super().__init__(None, Qt.WindowType.FramelessWindowHint
                         | Qt.WindowType.WindowStaysOnTopHint
                         | Qt.WindowType.Tool)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        lay = QHBoxLayout(self)
        lbl = QLabel("LLMAC agent is driving input — click to disarm")
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(lbl)
        self.setStyleSheet(
            "DriveBanner {background:#b91c1c;border-radius:8px;}"
            "QLabel {color:#ffffff;font-weight:700;}")
        self.setMinimumHeight(34)

    def showEvent(self, e):
        # bottom-center of the primary screen: unmissable, out of the
        # way of most work
        try:
            g = QGuiApplication.primaryScreen().availableGeometry()
            self.adjustSize()
            self.move(g.center().x() - self.width() // 2,
                      g.bottom() - self.height() - 12)
        except Exception:
            pass
        super().showEvent(e)

    def mousePressEvent(self, _e):
        self.disarmClicked.emit()


# ---------------------------------------------------------------------------
# v2.4.8: live log tail window for one background process — the GUI
# twin of `llmac proc logs --follow`.
# ---------------------------------------------------------------------------

class ProcTailDialog(QDialog):
    """Follows one proc's logs in a modeless window: polls the in-process
    ProcManager once a second with INDEPENDENT stdout/stderr cursors
    (stderr lines get an [err] prefix), auto-scrolls while output lands,
    and stops polling when the proc exits — the final state goes into
    both the title and the view. The view is ring-buffered at 20000
    blocks, mirroring the server's readable log window: a runaway proc
    can grow the log file, never this window's memory."""

    def __init__(self, parent, ctx, pid: str):
        super().__init__(parent)
        self.ctx = ctx
        self.pid = pid
        self.cur_out = 0
        self.cur_err = 0
        name = ""
        info = ctx.procs.get(pid) if ctx is not None else None
        if info is not None:
            name = getattr(info, "name", "") or ""
        self.setWindowTitle(f"Proc {pid} — {name} (tail)".rstrip(" —"))
        self.resize(760, 480)
        v = QVBoxLayout(self)
        v.setContentsMargins(10, 10, 10, 10)
        v.setSpacing(8)
        self._view = QPlainTextEdit()
        self._view.setReadOnly(True)
        self._view.setMaximumBlockCount(20000)
        self._view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        v.addWidget(self._view)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        v.addWidget(buttons)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._poll)
        self._timer.start(1000)
        self._poll()                    # first slice immediately

    def _autoscroll(self) -> None:
        sb = self._view.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _poll(self) -> None:
        if self.ctx is None or not self._timer.isActive():
            return
        try:
            r = self.ctx.procs.logs(self.pid, after=self.cur_out,
                                    after_err=self.cur_err)
        except Exception:
            return
        if r.get("error"):
            self._finish(f"[{r['error']}]")
            return
        for line in r.get("stdout", []):
            self._view.appendPlainText(str(line))
        for line in r.get("stderr", []):
            self._view.appendPlainText(f"[err] {line}")
        if r.get("stdout_resynced") or r.get("stderr_resynced"):
            self._view.appendPlainText(
                f"[window rolled: {r.get('stdout_skipped', 0)} stdout / "
                f"{r.get('stderr_skipped', 0)} stderr older line(s) are no "
                "longer readable — see the log files on disk]")
        self._autoscroll()
        self.cur_out = r.get("stdout_next", self.cur_out)
        self.cur_err = r.get("stderr_next", self.cur_err)
        if not r.get("running"):
            self._finish(f"exited rc={r.get('returncode')}")

    def _finish(self, note: str) -> None:
        if not self._timer.isActive():
            return
        self._timer.stop()
        self._view.appendPlainText(f"— {note} —")
        self._autoscroll()
        self.setWindowTitle(f"{self.windowTitle()}  [{note}]")

    def closeEvent(self, event):
        self._timer.stop()
        super().closeEvent(event)


# ---------------------------------------------------------------------------
# Main GUI window (PyQt6 / QMainWindow)
# ---------------------------------------------------------------------------

class HostWindow(QMainWindow):
    """PyQt6 front-end for the LLMAC v2 host — tabbed supervisor layout."""

    def __init__(self, data_dir: str = DEFAULT_DATA_DIR,
                 cli_overrides: Optional[dict] = None,
                 app: Optional[QApplication] = None):
        super().__init__()
        self.app = app
        self.setWindowTitle(f"LLMAC v{LLMAC_VERSION} — Host")
        self.resize(940, 660)
        self.setMinimumSize(640, 480)

        # Persistence
        self.data_dir = os.path.abspath(data_dir)
        self.state_store = StateStore(self.data_dir)
        self.history = History(self.data_dir)
        self.cli_overrides = cli_overrides or {}

        # Load persisted state, then apply CLI overrides.
        persisted = self.state_store.load()
        self.roots: list[str] = list(persisted.get("roots") or [])
        self.host_addr: str = persisted.get("host") or DEFAULT_HOST
        self.port: int = int(persisted.get("port") or DEFAULT_PORT)
        self.agents: list[dict] = [
            normalize_agent(a) for a in (persisted.get("agents") or [])]
        self.settings: dict = dict(persisted.get("settings") or {})
        self.settings.setdefault("tls", True)
        self.settings.setdefault("allow_exec", False)
        self.settings.setdefault("approval_policy", POLICY_DESTRUCTIVE)
        self.settings.setdefault("venvs", [])
        self.settings.setdefault("sudo_timeout_action", "reject")   # v2.4.5
        # v2.7.0 (ASK-016/017): the screen channel — screenshots ON
        # (still approval-gated per shot), observe + input OFF until
        # the host flips them here (Security tab, Screen access).
        self.settings.setdefault("screen_shots_enabled", True)
        self.settings.setdefault("screen_observe_enabled", False)
        self.settings.setdefault("screen_input_enabled", False)
        self.settings.setdefault("screen_shot_dir", DEFAULT_SHOT_DIR)
        self.settings.setdefault("screen_input_max_minutes", 10)
        self.settings.setdefault("screen_input_max_events", 500)
        if not self.agents:
            self.agents = [make_default_agent()]

        ov = self.cli_overrides
        if ov.get("roots"):
            self.roots = list(ov["roots"])
        if ov.get("key"):
            self.agents[0] = dict(self.agents[0])
            self.agents[0]["key"] = ov["key"]
        if ov.get("host"):
            self.host_addr = ov["host"]
        if ov.get("expose"):
            self.host_addr = "0.0.0.0"
        if ov.get("port"):
            self.port = int(ov["port"])
        if ov.get("allow_exec"):
            self.settings["allow_exec"] = True
            self._sync_default_agent_exec(True)
        if ov.get("policy"):
            self.settings["approval_policy"] = ov["policy"]
        if ov.get("tls") is False:
            self.settings["tls"] = False

        self.server = None
        self.server_thread: Optional[threading.Thread] = None
        self.ctx = None                      # AppContext (built on start)
        # v2.4.6: sudo password staged before the first server start;
        # pushed into the AppContext when it is built (memory only —
        # never in settings, never in state.json).
        self._sudo_pw_staged = None
        self.public_ip: Optional[str] = None
        self.fingerprint: Optional[str] = None

        # Thread-safe queue for log events from server threads.
        import queue
        self._log_queue: queue.Queue = queue.Queue()
        # In-memory log buffer for rebuilds (capped at 500 lines).
        self._log_buffer: list[dict] = []
        self._log_timer: Optional[QTimer] = None
        self._approvals_timer: Optional[QTimer] = None
        self._procs_timer: Optional[QTimer] = None
        self._venvs_timer: Optional[QTimer] = None
        self._chat_timer: Optional[QTimer] = None      # v2.5.0
        self._chat_agent: Optional[str] = None
        self._chat_last_render: str = ""
        self._chat_items: list = []                    # v2.6.0 (ASK-014)
        self._chat_search_idx: int = 0                # v2.6.0 (ASK-014)
        self._chat_export_dir: str = ""               # v2.6.0 (ASK-014)
        self._ip_worker: Optional[IPFetchWorker] = None
        self._proc_tail_windows: list = []   # live ProcTailDialogs (v2.4.8)

        # Build the UI
        self._build_ui()
        # v2.7.0 (ASK-016/017): the screen channel — the GUI-thread
        # bridge for capture, the drive-mode disarm banner (hidden
        # until a session runs), the XI2 listener slot.
        self._mt_caller = MainThreadCaller()
        self._drive_banner = DriveBanner()
        self._drive_banner.disarmClicked.connect(self._disarm_drive)
        self._xi2_thread = None
        self._refresh_dir_list()
        self._refresh_agents_list()
        self._refresh_venv_list()
        self._refresh_discovered_venvs()
        self._refresh_status()
        self._update_exposure_warning()
        self._update_public_addr_display()
        self._update_tls_panel()
        self._update_policy_description()

        # Apply the v2.2 stylesheet (host.py also applies it app-wide
        # together with the Fusion style + dark palette).
        self.setStyleSheet(build_stylesheet(self.data_dir))

        # Startup banner
        self._log(f"=== LLMAC v{LLMAC_VERSION} host started ===", "INFO")
        self._log(f"Data dir: {self.data_dir}", "INFO")
        self._log(f"Loaded: roots={len(self.roots)} "
                  f"agents={len(self.agents)} "
                  f"default_key={key_fingerprint(self.agents[0]['key'])} "
                  f"host={self.host_addr} port={self.port}", "INFO")
        if self.cli_overrides:
            self._log(f"CLI overrides applied: "
                      f"{list(self.cli_overrides.keys())}", "INFO")

        # Provision TLS cert up-front so the fingerprint is available for
        # the connection prompt even before the server starts.
        self._refresh_tls_fingerprint()

        # Pollers
        self._log_timer = QTimer()
        self._log_timer.timeout.connect(self._poll_log_queue)
        self._log_timer.start(100)
        self._approvals_timer = QTimer()
        self._approvals_timer.timeout.connect(self._poll_approvals)
        self._approvals_timer.start(1000)
        self._procs_timer = QTimer()
        self._procs_timer.timeout.connect(self._poll_procs)
        self._procs_timer.start(2000)
        # v2.4.3: poll agent-created (discovered) venvs so the card
        # below the configured list stays live without user action.
        self._venvs_timer = QTimer()
        self._venvs_timer.timeout.connect(self._refresh_discovered_venvs)
        self._venvs_timer.start(5000)

        # v2.5.0 (ASK-001/002): the human channel — poll live agent
        # sessions: sidebar (live/dormant + unread badges) + transcript.
        self._chat_timer = QTimer()
        self._chat_timer.timeout.connect(self._poll_chat)
        self._chat_timer.start(1000)

        # Persist the merged state.
        self._save_state(event_type="launch",
                         payload={"roots_n": len(self.roots),
                                  "host": self.host_addr,
                                  "port": self.port,
                                  "key_fp": key_fingerprint(
                                      self.agents[0]["key"])})

        # Kick off background IP fetch.
        self._fetch_public_ip_async()

        # If we have roots, auto-start the server.
        if self.roots:
            self._start_server()
        else:
            self._log("No shared directories yet. You can start the server "
                      "now — agents connect and request directories via "
                      "'roots request' (approve them in the Approvals tab).",
                      "INFO")

    # ------------------------------------------------------------------
    # UI construction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _card(title: str, subtitle: str = "") -> tuple:
        """An elevated panel. Returns (QFrame, content QVBoxLayout)."""
        frame = QFrame()
        frame.setProperty("card", True)
        v = QVBoxLayout(frame)
        v.setContentsMargins(16, 13, 16, 15)
        v.setSpacing(10)
        if title:
            h = QHBoxLayout()
            h.setSpacing(8)
            # Small-caps overline title: separation by typography,
            # not by another box.
            lab = QLabel(title.upper())
            lab.setProperty("section", True)
            f = lab.font()
            f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1.3)
            f.setPointSizeF(max(8.0, f.pointSizeF() - 1.5))
            lab.setFont(f)
            h.addWidget(lab)
            if subtitle:
                sub = QLabel(subtitle)
                sub.setProperty("muted", True)
                h.addWidget(sub)
            h.addStretch()
            v.addLayout(h)
        return frame, v

    def _make_pill(self, text: str, fg: str, bg: str,
                   clickable: bool = False) -> QLabel:
        pill = QPushButton(text) if clickable else QLabel(text)
        pill.setStyleSheet(
            f"background-color: {bg}; color: {fg}; border: none; "
            f"border-radius: 12px; padding: 3px 12px; font-weight: 600;")
        pill.setCursor(Qt.CursorShape.PointingHandCursor)
        return pill

    def _wrap_scroll(self, content: QWidget) -> QScrollArea:
        """Tab pages scroll instead of clipping when the window is small."""
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        sa.setFrameShape(QFrame.Shape.NoFrame)
        sa.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        content.setMinimumWidth(590)   # never squash below this — scroll
        sa.setWidget(content)
        return sa

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(14, 12, 14, 10)
        root.setSpacing(10)

        # ---- Header bar ------------------------------------------------
        header = QHBoxLayout()
        wordmark = QLabel("◈ LLMAC")
        wordmark.setStyleSheet(
            f"font-size: 15pt; font-weight: 700; color: {C_ACCENT}; "
            "background: transparent;")
        header.addWidget(wordmark)
        ver = QLabel(f"v{LLMAC_VERSION}")
        ver.setProperty("muted", True)
        header.addWidget(ver)
        header.addStretch()

        self.pend_pill = self._make_pill("● 0 pending", C_AMBER, "#2a2113",
                                         clickable=True)
        self.pend_pill.setVisible(False)
        self.pend_pill.clicked.connect(
            lambda: self.tabs.setCurrentIndex(self.TAB_APPROVALS))
        header.addWidget(self.pend_pill)

        self.procs_pill = self._make_pill("● 0 running", C_GREEN, "#12281c",
                                          clickable=True)
        self.procs_pill.setVisible(False)
        self.procs_pill.clicked.connect(
            lambda: self.tabs.setCurrentIndex(self.TAB_PROCS))
        header.addWidget(self.procs_pill)

        self.status_pill = self._make_pill("○ stopped", C_RED, "#2a1416")
        header.addWidget(self.status_pill)
        root.addLayout(header)

        # ---- Tabs ------------------------------------------------------
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        # v2.5.1 (ASK-006): indices captured from the addTab RETURN —
        # a future insertion can never desync the badge/pill sites.
        self.TAB_OVERVIEW = self.tabs.addTab(
            self._wrap_scroll(self._build_overview_tab()), "Overview")
        self.TAB_AGENTS = self.tabs.addTab(
            self._wrap_scroll(self._build_agents_tab()), "Agents")
        # v2.5.0 (ASK-001/002): the human channel — live agent sessions,
        # the merged notes+messages transcript, mid-run messaging.
        self.TAB_SESSIONS = self.tabs.addTab(
            self._wrap_scroll(self._build_sessions_tab()), "Sessions")
        self.TAB_APPROVALS = self.tabs.addTab(
            self._wrap_scroll(self._build_approvals_tab()), "Approvals")
        self.TAB_PROCS = self.tabs.addTab(
            self._wrap_scroll(self._build_procs_tab()), "Processes")
        self.TAB_SECURITY = self.tabs.addTab(
            self._wrap_scroll(self._build_security_tab()), "Security")
        self.TAB_LOG = self.tabs.addTab(self._build_log_tab(), "Log")
        root.addWidget(self.tabs, 1)

        # ---- Status bar -------------------------------------------------
        sb = self.statusBar()
        self.sb_status_label = QLabel("stopped")
        self.sb_status_label.setStyleSheet(
            f"color: {C_RED}; font-weight: 600;")
        sb.addWidget(self.sb_status_label)
        self.sb_local_label = QLabel("")
        self.sb_local_label.setProperty("mono", True)
        self.sb_local_label.setStyleSheet(
            f"color: {C_MUTED}; padding-left: 12px;")
        sb.addWidget(self.sb_local_label)
        sb.addPermanentWidget(QLabel("        "))
        self.sb_procs_label = QLabel("")
        self.sb_procs_label.setStyleSheet(f"color: {C_MUTED};")
        sb.addPermanentWidget(self.sb_procs_label)
        self.data_status_label = QLabel("saved")
        self.data_status_label.setStyleSheet(
            f"color: {C_MUTED}; font-style: italic; padding-left: 12px;")
        sb.addPermanentWidget(self.data_status_label)

    # ------------------------------------------------------------------
    # Tab builders
    # ------------------------------------------------------------------

    def _build_overview_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(14, 14, 14, 14)
        v.setSpacing(10)

        # == Connection card ==
        card, cv = self._card("Connection",
                              "what the agent prompt contains")
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(8)
        grid.addWidget(QLabel("Bind host"), 0, 0)
        self.host_combo = QComboBox()
        self.host_combo.setEditable(True)
        # v2.8: loopback, then this machine's real IPv4s (the missing
        # middle ground between 127.0.0.1 and 0.0.0.0), then wildcards.
        self._rebuild_host_items(preserve=self.host_addr)
        self.host_combo.currentTextChanged.connect(self._update_exposure_warning)
        grid.addWidget(self.host_combo, 0, 1)
        grid.addWidget(QLabel("Port"), 0, 2)
        self.port_edit = QLineEdit(str(self.port))
        self.port_edit.setMaximumWidth(90)
        self.port_edit.textChanged.connect(self._update_public_addr_display)
        grid.addWidget(self.port_edit, 0, 3)
        self.refresh_ip_btn = QPushButton("Refresh IP")
        self.refresh_ip_btn.clicked.connect(self._fetch_public_ip_async)
        grid.addWidget(self.refresh_ip_btn, 0, 4)
        # v2.8: re-detect local IPv4s (router/VPN changes) into the combo.
        self.host_refresh_btn = QPushButton("\u21bb")
        self.host_refresh_btn.setToolTip(
            "Re-detect this machine's IPv4 addresses for the bind "
            "dropdown (router/VPN changes)")
        self.host_refresh_btn.setMaximumWidth(34)
        self.host_refresh_btn.clicked.connect(self._refresh_local_ips)
        grid.addWidget(self.host_refresh_btn, 0, 5)
        grid.setColumnStretch(6, 1)

        self.tls_check = QCheckBox("TLS — self-signed cert, "
                                   "fingerprint-pinned (agents verify it)")
        self.tls_check.setChecked(bool(self.settings.get("tls", True)))
        self.tls_check.toggled.connect(self._on_tls_toggled)
        grid.addWidget(self.tls_check, 1, 0, 1, 3)
        self.exposure_label = QLabel()
        self.exposure_label.setWordWrap(True)
        grid.addWidget(self.exposure_label, 1, 3, 1, 3)
        cv.addLayout(grid)

        row = QHBoxLayout()
        self.start_btn = QPushButton("Start server")
        self.start_btn.setProperty("variant", "primary")
        self.start_btn.clicked.connect(self._start_server)
        row.addWidget(self.start_btn)
        self.stop_btn = QPushButton("Stop server")
        self.stop_btn.setProperty("variant", "danger")
        self.stop_btn.clicked.connect(self._stop_server)
        row.addWidget(self.stop_btn)
        self.restart_btn = QPushButton("Restart")
        self.restart_btn.clicked.connect(self._restart_server)
        row.addWidget(self.restart_btn)
        row.addStretch()
        self.copy_prompt_btn = QPushButton("Copy agent prompt")
        self.copy_prompt_btn.setProperty("variant", "primary")
        self.copy_prompt_btn.clicked.connect(self._copy_prompt)
        row.addWidget(self.copy_prompt_btn)
        cv.addLayout(row)

        addr_row = QHBoxLayout()
        lab_local = QLabel("Local")
        lab_local.setProperty("muted", True)
        addr_row.addWidget(lab_local)
        self.local_addr_label = QLabel(f"{self.host_addr}:{self.port}")
        self.local_addr_label.setProperty("mono", True)
        addr_row.addWidget(self.local_addr_label)
        addr_row.addSpacing(14)
        lab_pub = QLabel("Public")
        lab_pub.setProperty("muted", True)
        addr_row.addWidget(lab_pub)
        self.public_addr_label = QLabel("(fetching…)")
        self.public_addr_label.setProperty("mono", True)
        self.public_addr_label.setStyleSheet(
            f"font-family: 'Cascadia Code', monospace; color: {C_ACCENT}; "
            "font-weight: 600;")
        addr_row.addWidget(self.public_addr_label)
        addr_row.addStretch()
        cv.addLayout(addr_row)

        # v2.5.1 (ASK-007): the agent picker — WHICH agent the copied
        # prompt is built for (its key + name), not the hardcoded
        # default. The selected agent's key fingerprint shows beside
        # the combo so the change is visible at a glance.
        pick_row = QHBoxLayout()
        lab_pick = QLabel("Prompt agent")
        lab_pick.setProperty("muted", True)
        pick_row.addWidget(lab_pick)
        self.agent_picker = QComboBox()
        self._prompt_agent_idx = 0
        self.prompt_agent_fp = QLabel("")
        self.prompt_agent_fp.setProperty("mono", True)
        self._sync_prompt_agents()
        self.agent_picker.currentIndexChanged.connect(
            self._on_prompt_agent_changed)
        pick_row.addWidget(self.agent_picker)
        pick_row.addWidget(self.prompt_agent_fp)
        pick_row.addStretch()
        cv.addLayout(pick_row)

        fp_grid = QGridLayout()
        fp_grid.setHorizontalSpacing(10)
        fp_grid.setVerticalSpacing(4)
        lab_fp = QLabel("Cert fingerprint")
        lab_fp.setProperty("muted", True)
        fp_grid.addWidget(lab_fp, 0, 0)
        self.copy_fp_btn = QPushButton("Copy")
        self.copy_fp_btn.clicked.connect(self._copy_fingerprint)
        fp_grid.addWidget(self.copy_fp_btn, 0, 1,
                          Qt.AlignmentFlag.AlignVCenter)
        fp_grid.setColumnStretch(2, 1)
        self.fp_label = QLabel("—")
        self.fp_label.setProperty("mono", True)
        self.fp_label.setStyleSheet(
            f"font-family: 'Cascadia Code', monospace; color: {C_MUTED};")
        # Full width on its own row: the complete hash always renders
        # (wrapping to a second line only on very narrow windows).
        self.fp_label.setWordWrap(True)
        self.fp_label.setMinimumWidth(0)
        fp_grid.addWidget(self.fp_label, 1, 0, 1, 3)
        cv.addLayout(fp_grid)

        hint = QLabel("Paste the agent prompt into your AI chat — it "
                      "self-installs the client and connects over TLS.")
        hint.setProperty("muted", True)
        hint.setWordWrap(True)
        cv.addWidget(hint)
        v.addWidget(card)

        # == Shared directories card ==
        dcard, dv = self._card("Shared directories",
                               "the agent can only see what you list here")
        self.dir_list = QListWidget()
        self.dir_list.setAlternatingRowColors(True)
        self.dir_list.setWordWrap(True)
        self.dir_list.setMinimumHeight(96)
        self.dir_list.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection)
        dv.addWidget(self.dir_list)

        self.dirs_hint = QLabel(
            "Nothing shared yet. Add a directory, or start the server and "
            "let the agent request one — requests appear in the Approvals "
            "tab and only take effect when you approve them.")
        self.dirs_hint.setProperty("muted", True)
        self.dirs_hint.setWordWrap(True)
        dv.addWidget(self.dirs_hint)

        btns = QHBoxLayout()
        self.add_dir_btn = QPushButton("Add directory")
        self.add_dir_btn.setProperty("variant", "primary")
        self.add_dir_btn.clicked.connect(self._add_directory)
        btns.addWidget(self.add_dir_btn)
        self.remove_dir_btn = QPushButton("Remove selected")
        self.remove_dir_btn.clicked.connect(self._remove_directory)
        btns.addWidget(self.remove_dir_btn)
        self.clear_dir_btn = QPushButton("Clear all")
        self.clear_dir_btn.setProperty("variant", "danger")
        self.clear_dir_btn.clicked.connect(self._clear_directories)
        btns.addWidget(self.clear_dir_btn)
        btns.addStretch()
        dv.addLayout(btns)
        v.addWidget(dcard)

        v.addStretch()
        return w

    def _build_agents_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(14, 14, 14, 14)
        v.setSpacing(10)

        # == Default agent key card ==
        kcard, kv = self._card("Default agent",
                               "full permissions on all shared roots")
        self.key_edit = QLineEdit(self.agents[0]["key"])
        self.key_edit.setReadOnly(True)
        self.key_edit.setToolTip(self.agents[0]["key"])
        self.key_edit.setStyleSheet(
            "font-family: 'Cascadia Code', 'Consolas', monospace; "
            f"font-size: 10pt; color: {C_TEXT};")
        kv.addWidget(self.key_edit)
        row = QHBoxLayout()
        self.copy_key_btn = QPushButton("Copy key")
        self.copy_key_btn.clicked.connect(self._copy_key)
        row.addWidget(self.copy_key_btn)
        self.refresh_key_btn = QPushButton("Refresh key")
        self.refresh_key_btn.clicked.connect(self._refresh_key)
        row.addWidget(self.refresh_key_btn)
        row.addStretch()
        kv.addLayout(row)
        v.addWidget(kcard)

        # == Named agents card ==
        acard, av = self._card("Agents",
                               "keys with scoped roots and permissions")
        self.agent_list = QListWidget()
        self.agent_list.setAlternatingRowColors(True)
        self.agent_list.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.agent_list.setMinimumHeight(140)
        av.addWidget(self.agent_list)
        row = QHBoxLayout()
        self.add_agent_btn = QPushButton("Add agent")
        self.add_agent_btn.setProperty("variant", "primary")
        self.add_agent_btn.clicked.connect(self._add_agent)
        row.addWidget(self.add_agent_btn)
        self.show_agent_key_btn = QPushButton("Copy selected key")
        self.show_agent_key_btn.clicked.connect(self._copy_selected_agent_key)
        row.addWidget(self.show_agent_key_btn)
        self.revoke_agent_btn = QPushButton("Revoke selected")
        self.revoke_agent_btn.setProperty("variant", "danger")
        self.revoke_agent_btn.clicked.connect(self._revoke_agent)
        row.addWidget(self.revoke_agent_btn)
        row.addStretch()
        av.addLayout(row)
        hint = QLabel("Revoke works instantly (no restart needed). The "
                      "default agent is rotated with 'Refresh key'.")
        hint.setProperty("muted", True)
        hint.setWordWrap(True)
        av.addWidget(hint)
        v.addWidget(acard)

        v.addStretch()
        return w

    def _build_approvals_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(14, 14, 14, 14)
        v.setSpacing(10)

        # == Pending card ==
        pcard, pv = self._card("Pending approvals",
                               "dangerous ops (per policy) + share requests")
        self.approval_list = QListWidget()
        self.approval_list.setAlternatingRowColors(True)
        self.approval_list.setWordWrap(True)   # full reason/path always shown
        self.approval_list.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.approval_list.setMinimumHeight(150)
        pv.addWidget(self.approval_list)
        row = QHBoxLayout()
        self.approve_btn = QPushButton("Approve")
        self.approve_btn.setProperty("variant", "primary")
        self.approve_btn.clicked.connect(self._approve_selected)
        row.addWidget(self.approve_btn)
        self.deny_btn = QPushButton("Deny")
        self.deny_btn.setProperty("variant", "danger")
        self.deny_btn.clicked.connect(self._deny_selected)
        row.addWidget(self.deny_btn)
        # v2.7.0 (ASK-016/017): screen-class approvals gain the
        # until-restart session grant (memory-only; every op is still
        # op-logged).
        self.apr_session_btn = QPushButton("Approve for this session")
        self.apr_session_btn.setToolTip(
            "Screen classes only: covers this approval class until the "
            "app restarts — every op is still logged, and a drive-cap "
            "violation drops the grant")
        self.apr_session_btn.clicked.connect(
            self._approve_selected_session)
        self.apr_session_btn.setEnabled(False)
        row.addWidget(self.apr_session_btn)
        # v2.4.6 (user report: the approval menu "feels unresponsive"):
        # buttons used to be always-enabled and silently no-op'd without
        # a selection. Now they track the selection explicitly, and the
        # click affordance is unmissable (see also the :selected QSS).
        self.approve_btn.setEnabled(False)
        self.deny_btn.setEnabled(False)
        self._update_approval_buttons(None)
        self.approval_list.currentItemChanged.connect(
            self._update_approval_buttons)
        self.approval_list.itemDoubleClicked.connect(
            lambda _item: self._approve_selected())
        self.apr_status_label = QLabel("no server")
        self.apr_status_label.setProperty("muted", True)
        row.addWidget(self.apr_status_label)
        row.addStretch()
        pv.addLayout(row)
        hint = QLabel("Approving a share request adds that directory to the "
                      "shared roots immediately (the agent needs no "
                      "reconnect). Denying just declines it.")
        hint.setProperty("muted", True)
        hint.setWordWrap(True)
        pv.addWidget(hint)
        v.addWidget(pcard)

        # == Recent decisions card ==
        rcard, rv = self._card("Recent decisions")
        self.decided_list = QListWidget()
        self.decided_list.setAlternatingRowColors(True)
        self.decided_list.setWordWrap(True)
        self.decided_list.setMinimumHeight(90)
        rv.addWidget(self.decided_list)
        v.addWidget(rcard)

        # == Active grants card (v2.3: approve once, stop re-clicking) ==
        gcard, gv = self._card("Active grants",
                               "created via 'Approve + grant'; they expire "
                               "by themselves and can be revoked here")
        self.grants_list = QListWidget()
        self.grants_list.setAlternatingRowColors(True)
        self.grants_list.setWordWrap(True)
        self.grants_list.setMinimumHeight(70)
        self.grants_list.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        gv.addWidget(self.grants_list)
        grow = QHBoxLayout()
        self.revoke_grant_btn = QPushButton("Revoke selected grant")
        self.revoke_grant_btn.setProperty("variant", "danger")
        self.revoke_grant_btn.clicked.connect(self._revoke_selected_grant)
        grow.addWidget(self.revoke_grant_btn)
        grow.addStretch()
        gv.addLayout(grow)
        v.addWidget(gcard)

        v.addStretch()
        return w

    def _build_procs_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(14, 14, 14, 14)
        v.setSpacing(10)

        card, cv = self._card("Background processes",
                              "started by agents via 'proc start'")
        self.proc_table = QTableWidget(0, 5)
        self.proc_table.setHorizontalHeaderLabels(
            ["ID", "Name", "Command", "Status", "Exit"])
        hh = self.proc_table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.proc_table.verticalHeader().setVisible(False)
        self.proc_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.proc_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.proc_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.proc_table.setMinimumHeight(150)
        self.proc_table.setShowGrid(False)
        self.proc_table.setAlternatingRowColors(True)
        self.proc_table.verticalHeader().setDefaultSectionSize(34)
        cv.addWidget(self.proc_table)

        row = QHBoxLayout()
        self.proc_refresh_btn = QPushButton("Refresh")
        self.proc_refresh_btn.clicked.connect(self._poll_procs)
        row.addWidget(self.proc_refresh_btn)
        self.proc_tail_btn = QPushButton("Tail logs")
        self.proc_tail_btn.setToolTip(
            "Follow the selected process's output live — the GUI twin of "
            "the agent's 'proc logs --follow'.")
        self.proc_tail_btn.clicked.connect(self._tail_selected_proc)
        row.addWidget(self.proc_tail_btn)
        self.proc_stop_btn = QPushButton("Stop selected")
        self.proc_stop_btn.setProperty("variant", "danger")
        self.proc_stop_btn.clicked.connect(self._stop_selected_proc)
        row.addWidget(self.proc_stop_btn)
        self.proc_stopall_btn = QPushButton("Stop all")
        self.proc_stopall_btn.setProperty("variant", "danger")
        self.proc_stopall_btn.clicked.connect(self._stop_all_procs)
        row.addWidget(self.proc_stopall_btn)
        row.addStretch()
        cv.addLayout(row)
        hint = QLabel("Processes die automatically when the server stops. "
                      "Agents read logs with 'proc logs' — or select a row "
                      "and press 'Tail logs' to follow the output here.")
        hint.setProperty("muted", True)
        hint.setWordWrap(True)
        cv.addWidget(hint)
        v.addWidget(card)

        v.addStretch()
        return w

    def _build_security_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(14, 14, 14, 14)
        v.setSpacing(10)

        # == Approval policy card ==
        pcard, pv = self._card("Approval policy",
                               "what the agent must ask before doing")
        prow = QHBoxLayout()
        self.policy_combo = QComboBox()
        self.policy_combo.addItem("auto — no approvals (headless default)",
                                  "auto")
        self.policy_combo.addItem(
            "auto-all — no restrictions (agents may expand the sandbox)",
            "auto_all")
        self.policy_combo.addItem(
            "destructive — gate recursive/large deletes", "destructive")
        self.policy_combo.addItem(
            "strict — gate every write, delete and exec", "strict")
        idx = self.policy_combo.findData(
            self.settings.get("approval_policy", "destructive"))
        self.policy_combo.setCurrentIndex(max(0, idx))
        self.policy_combo.currentIndexChanged.connect(self._on_policy_changed)
        prow.addWidget(self.policy_combo)
        prow.addStretch()
        pv.addLayout(prow)
        self.policy_desc = QLabel()
        self.policy_desc.setProperty("muted", True)
        self.policy_desc.setWordWrap(True)
        pv.addWidget(self.policy_desc)
        v.addWidget(pcard)

        # == Raw exec card ==
        ecard, ev = self._card("Raw shell exec",
                               "off by default; sandbox checks apply")
        erow = QHBoxLayout()
        self.exec_check = QCheckBox("Allow agents to run shell commands")
        self.exec_check.setChecked(bool(self.settings.get("allow_exec")))
        self.exec_check.toggled.connect(self._on_exec_toggled)
        erow.addWidget(self.exec_check)
        self.exec_warn_label = QLabel()
        self.exec_warn_label.setStyleSheet(f"color: {C_AMBER};")
        self.exec_warn_label.setWordWrap(True)
        erow.addStretch()
        ev.addLayout(erow)
        ev.addWidget(self.exec_warn_label)
        v.addWidget(ecard)

        # == Sudo package changes card (v2.4.5 installs; v2.4.6
        #    removals + password) ==
        scard, sv = self._card(
            "Sudo package changes (install / remove)",
            "agents may install or remove distro packages; ALWAYS approved")
        srow = QHBoxLayout()
        sv.addLayout(srow)
        self.sudo_timeout_combo = QComboBox()
        self.sudo_timeout_combo.addItem(
            "On 2-minute timeout: auto-REJECT (recommended)", "reject")
        self.sudo_timeout_combo.addItem(
            "On 2-minute timeout: auto-APPROVE", "approve")
        _idx = self.sudo_timeout_combo.findData(
            self.settings.get("sudo_timeout_action", "reject"))
        self.sudo_timeout_combo.setCurrentIndex(max(0, _idx))
        self.sudo_timeout_combo.currentIndexChanged.connect(
            self._on_sudo_timeout_changed)
        srow.addWidget(self.sudo_timeout_combo)
        srow.addStretch()
        self.sudo_desc = QLabel(
            "Agents can run `sudo pacman -S|-R <pkg>` / `sudo apt "
            "install|remove <pkg>` and equivalents (installs AND removals,"
            "single commands only). Every such request prompts you in the "
            "Approvals tab REGARDLESS of the approval policy above — there "
            "is no silent path, not even under auto-all. If you do not "
            "decide within 2 minutes, the request resolves itself per this "
            "setting (auto-reject fails closed; auto-approve runs the "
            "change). Everything else under sudo stays blocked.")
        self.sudo_desc.setProperty("muted", True)
        self.sudo_desc.setWordWrap(True)
        sv.addWidget(self.sudo_desc)
        # v2.4.6 (user request: "add a field to type my sudo password in,"
        # "filled in by the program itself, never revealed to the AI").
        # MEMORY ONLY: kept on the AppContext (survives server stop/start
        # inside this GUI session, gone on app exit), never written to
        # state.json, never sent over the wire in either direction, and
        # the ONLY consumer is _run_exec piping it to `sudo -S` stdin
        # AFTER a human approved the command. There is deliberately NO
        # API to set or read it — an agent must never be able to probe.
        prow = QHBoxLayout()
        self.sudo_pw_edit = QLineEdit()
        self.sudo_pw_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.sudo_pw_edit.setPlaceholderText(
            "sudo password (optional) — piped to approved commands; "
            "memory only, never on disk, never shown to agents")
        self.sudo_pw_edit.setClearButtonEnabled(True)
        prow.addWidget(self.sudo_pw_edit)
        self.sudo_pw_save_btn = QPushButton("Save password")
        self.sudo_pw_save_btn.clicked.connect(self._save_sudo_password)
        prow.addWidget(self.sudo_pw_save_btn)
        self.sudo_pw_clear_btn = QPushButton("Clear")
        self.sudo_pw_clear_btn.clicked.connect(self._clear_sudo_password)
        prow.addWidget(self.sudo_pw_clear_btn)
        sv.addLayout(prow)
        self.sudo_pw_status = QLabel(
            "sudo password: not set — without it, approved commands fail "
            "at the sudo password prompt (exec has no TTY).")
        self.sudo_pw_status.setProperty("muted", True)
        self.sudo_pw_status.setWordWrap(True)
        sv.addWidget(self.sudo_pw_status)
        v.addWidget(scard)

        # == Screen access card (v2.7.0 — ASK-016/017) ==
        # The sudo_timeout pattern: settings.setdefault at boot (above),
        # persistence via _save_state(event_type="screen_settings_change").
        card2, cv2 = self._card(
            "Screen access",
            "screenshots, screen reading (OCR) and input injection "
            "(v2.7.0)")
        row_s = QHBoxLayout()
        self.screen_shots_check = QCheckBox(
            "Screenshots (per-shot approval)")
        self.screen_shots_check.setChecked(
            bool(self.settings.get("screen_shots_enabled", True)))
        self.screen_shots_check.toggled.connect(
            lambda v: self._save_screen_setting(
                "screen_shots_enabled", v))
        row_s.addWidget(self.screen_shots_check)
        self.screen_observe_check = QCheckBox(
            "Screen observe — OCR + window list")
        self.screen_observe_check.setChecked(
            bool(self.settings.get("screen_observe_enabled", False)))
        self.screen_observe_check.toggled.connect(
            lambda v: self._save_screen_setting(
                "screen_observe_enabled", v))
        row_s.addWidget(self.screen_observe_check)
        self.screen_input_check = QCheckBox(
            "Input injection (drive mode)")
        self.screen_input_check.setChecked(
            bool(self.settings.get("screen_input_enabled", False)))
        self.screen_input_check.toggled.connect(
            self._on_screen_input_toggled)
        row_s.addWidget(self.screen_input_check)
        row_s.addStretch()
        cv2.addLayout(row_s)
        self.screen_input_warn = QLabel(
            "Injected input reaches XWayland clients (games, Steam, "
            "Proton) — NOT native Wayland windows in v1. Drive "
            "sessions are time+event capped, the red banner disarms in "
            "one click, every event is logged at WARN.")
        self.screen_input_warn.setStyleSheet(f"color: {C_AMBER};")
        self.screen_input_warn.setWordWrap(True)
        self.screen_input_warn.setVisible(
            bool(self.settings.get("screen_input_enabled", False)))
        cv2.addWidget(self.screen_input_warn)
        # the evidence folder picker
        drow = QHBoxLayout()
        drow.addWidget(QLabel("Shot folder:"))
        self.screen_shot_dir_edit = QLineEdit(
            str(self.settings.get("screen_shot_dir", DEFAULT_SHOT_DIR)))
        self.screen_shot_dir_edit.editingFinished.connect(
            self._shot_dir_edited)
        drow.addWidget(self.screen_shot_dir_edit, 1)
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._pick_shot_dir)
        drow.addWidget(browse_btn)
        cv2.addLayout(drow)
        # the two drive-mode caps
        crow = QHBoxLayout()
        crow.addWidget(QLabel("Drive-mode caps:"))
        self.screen_input_max_minutes_spin = QSpinBox()
        self.screen_input_max_minutes_spin.setRange(1, 240)
        self.screen_input_max_minutes_spin.setValue(
            int(self.settings.get("screen_input_max_minutes", 10)))
        self.screen_input_max_minutes_spin.valueChanged.connect(
            lambda v: self._save_screen_setting(
                "screen_input_max_minutes", v))
        crow.addWidget(self.screen_input_max_minutes_spin)
        crow.addWidget(QLabel("minutes"))
        self.screen_input_max_events_spin = QSpinBox()
        self.screen_input_max_events_spin.setRange(1, 10000)
        self.screen_input_max_events_spin.setValue(
            int(self.settings.get("screen_input_max_events", 500)))
        self.screen_input_max_events_spin.valueChanged.connect(
            lambda v: self._save_screen_setting(
                "screen_input_max_events", v))
        crow.addWidget(self.screen_input_max_events_spin)
        crow.addWidget(QLabel("events"))
        crow.addStretch()
        cv2.addLayout(crow)
        sdesc = QLabel(
            "Screenshots and observe are approval-gated per call (the "
            "approval card can grant a class for this session — it "
            "dies with the app). Input injection is OFF until enabled "
            "here, then bounded: an approved op opens a drive session "
            "with these caps; the always-on-top banner disarms it in "
            "one click; on X11 any physical input disarms it too.")
        sdesc.setProperty("muted", True)
        sdesc.setWordWrap(True)
        cv2.addWidget(sdesc)
        v.addWidget(card2)

        # == TLS card ==
        tcard, tv = self._card("Transport security")
        self.tls_state_label = QLabel()
        self.tls_state_label.setWordWrap(True)
        tv.addWidget(self.tls_state_label)
        v.addWidget(tcard)

        # == Venvs card ==
        vcard, vv = self._card("Install venvs",
                               "package installs are allowed only inside these")
        self.venv_list = QListWidget()
        self.venv_list.setAlternatingRowColors(True)
        self.venv_list.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.venv_list.setMinimumHeight(80)
        vv.addWidget(self.venv_list)
        vrow = QHBoxLayout()
        self.add_venv_btn = QPushButton("Add venv directory")
        self.add_venv_btn.clicked.connect(self._add_venv)
        vrow.addWidget(self.add_venv_btn)
        self.remove_venv_btn = QPushButton("Remove selected")
        self.remove_venv_btn.clicked.connect(self._remove_venv)
        vrow.addWidget(self.remove_venv_btn)
        vrow.addStretch()
        vv.addLayout(vrow)
        # v2.4.3: agent-created venvs (runtime discoveries) were
        # invisible here before — the card only ever showed the
        # configured allow-list, so venvs created by agents via exec
        # never appeared (user-reported live).
        dh = QLabel("Discovered venvs — created by agents this session "
                    "(installs work automatically, no listing needed):")
        dh.setProperty("muted", True)
        dh.setWordWrap(True)
        vv.addWidget(dh)
        self.discovered_venv_list = QListWidget()
        self.discovered_venv_list.setAlternatingRowColors(True)
        self.discovered_venv_list.setSelectionMode(
            QAbstractItemView.SelectionMode.NoSelection)
        self.discovered_venv_list.setMinimumHeight(52)
        vv.addWidget(self.discovered_venv_list)
        vh = QLabel("Marker-based detection also recognizes any venv with a "
                    "pyvenv.cfg / conda-meta marker, even if not listed.")
        vh.setProperty("muted", True)
        vh.setWordWrap(True)
        vv.addWidget(vh)
        v.addWidget(vcard)

        # == Data card ==
        dcard, dv = self._card("Data & session",
                               f"{self.data_dir}")
        drow = QHBoxLayout()
        self.export_btn = QPushButton("Export settings")
        self.export_btn.clicked.connect(self._export_settings)
        drow.addWidget(self.export_btn)
        self.import_btn = QPushButton("Import settings")
        self.import_btn.clicked.connect(self._import_settings)
        drow.addWidget(self.import_btn)
        self.open_folder_btn = QPushButton("Open data folder")
        self.open_folder_btn.clicked.connect(self._open_data_folder)
        drow.addWidget(self.open_folder_btn)
        drow.addStretch()
        dv.addLayout(drow)
        dh = QLabel("Exports contain agent keys in plaintext — store them "
                    "securely.")
        dh.setProperty("muted", True)
        dh.setWordWrap(True)
        dv.addWidget(dh)
        v.addWidget(dcard)

        v.addStretch()
        return w

    def _build_log_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(14, 14, 14, 14)
        v.setSpacing(8)
        row = QHBoxLayout()
        lab = QLabel("Host log")
        lab.setProperty("section", True)
        row.addWidget(lab)
        row.addStretch()
        # v2.5.2 (ASK-009): agent filter — a VIEW over the retained
        # buffer (the buffer itself always keeps every entry).
        flab = QLabel("Filter:")
        flab.setProperty("muted", True)
        row.addWidget(flab)
        self.log_agent_filter = QComboBox()
        self.log_agent_filter.addItem("All agents")
        self.log_agent_filter.currentIndexChanged.connect(
            self._on_log_filter_changed)
        row.addWidget(self.log_agent_filter)
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._clear_log)
        row.addWidget(clear_btn)
        v.addLayout(row)
        self.log_widget = QPlainTextEdit()
        self.log_widget.setReadOnly(True)
        self.log_widget.setMaximumBlockCount(1000)
        v.addWidget(self.log_widget)
        return w

    # ------------------------------------------------------------------
    # Directory management
    # ------------------------------------------------------------------

    def _refresh_dir_list(self) -> None:
        self.dir_list.clear()
        for r in self.roots:
            self.dir_list.addItem(r)
        self.dirs_hint.setVisible(not self.roots)

    def _add_directory(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select a directory to share")
        if not path:
            return
        path = os.path.realpath(os.path.abspath(path))
        if path in self.roots:
            QMessageBox.information(self, "Already shared",
                                     "That directory is already in the list.")
            return
        self.roots.append(path)
        self._refresh_dir_list()
        self._on_roots_changed()
        self._log(f"Added directory: {path}")
        self._refresh_status()
        self._save_state(event_type="add_dir",
                         payload={"path": path, "roots_n": len(self.roots)})

    def _on_roots_changed(self) -> None:
        """Propagate root changes to a running server's sandbox."""
        if self.ctx is not None:
            from core.sandbox import Sandbox
            self.ctx.sandbox = Sandbox(self.roots,
                                       protected=[self.data_dir])
            self.ctx.auth.update(self.agents)

    def _sync_default_agent_exec(self, enabled: bool) -> None:
        """The GUI exec toggle also drives the default agent's perms."""
        if not self.agents:
            return
        a = self.agents[0]
        a["perms"] = dict(a.get("perms") or {})
        a["perms"]["exec"] = enabled
        a["perms"]["proc"] = enabled

    def _remove_directory(self) -> None:
        items = self.dir_list.selectedIndexes()
        if not items:
            return
        removed = []
        rows = sorted([i.row() for i in items], reverse=True)
        for row in rows:
            removed.append(self.roots.pop(row))
        self._refresh_dir_list()
        self._on_roots_changed()
        for p in removed:
            self._log(f"Removed directory: {p}")
        self._refresh_status()
        self._save_state(event_type="remove_dir",
                         payload={"paths": removed, "roots_n": len(self.roots)})

    def _clear_directories(self) -> None:
        if not self.roots:
            return
        reply = QMessageBox.question(
            self, "Confirm", "Remove all shared directories?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        old = list(self.roots)
        self.roots.clear()
        self._refresh_dir_list()
        self._on_roots_changed()
        self._log("Cleared all directories.")
        self._refresh_status()
        self._save_state(event_type="clear_dirs",
                         payload={"paths": old, "roots_n": 0})

    # ------------------------------------------------------------------
    # Key / fingerprint / prompt
    # ------------------------------------------------------------------

    @property
    def key(self) -> str:
        return self.agents[0]["key"] if self.agents else ""

    def _copy_key(self) -> None:
        QApplication.clipboard().setText(self.key)
        self._log("Key copied to clipboard.")

    def _copy_fingerprint(self) -> None:
        if not self.fingerprint:
            return
        QApplication.clipboard().setText(self.fingerprint)
        self._log("Certificate fingerprint copied.")

    def _sync_prompt_agents(self) -> None:
        """v2.5.1 (ASK-007): keep the picker current — agents are added
        and removed in the Agents tab; called at build time and from
        _refresh_agents_list. The selection survives when possible."""
        names = [a.get("name", "default") for a in self.agents]
        prev = (self._prompt_agent_idx
                if getattr(self, "_prompt_agent_idx", None) is not None
                else 0)
        self.agent_picker.blockSignals(True)
        self.agent_picker.clear()
        self.agent_picker.addItems(names)
        self._prompt_agent_idx = max(0, min(prev, len(names) - 1))
        if names:
            self.agent_picker.setCurrentIndex(self._prompt_agent_idx)
        self.agent_picker.blockSignals(False)
        self._update_prompt_agent_fp()

    def _on_prompt_agent_changed(self, idx: int) -> None:
        self._prompt_agent_idx = max(0, idx)
        self._update_prompt_agent_fp()
        if self.agents and 0 <= self._prompt_agent_idx < len(self.agents):
            self._log(f"Agent prompt target: "
                      f"{self.agents[self._prompt_agent_idx].get('name', 'default')}")

    def _update_prompt_agent_fp(self) -> None:
        if not getattr(self, "agents", None) or \
                not hasattr(self, "prompt_agent_fp"):
            return
        i = max(0, min(self._prompt_agent_idx, len(self.agents) - 1))
        self.prompt_agent_fp.setText(
            key_fingerprint(self.agents[i].get("key", "")))

    def _copy_prompt(self) -> None:
        if self.public_ip is None:
            self._log("Public IP not yet known - fetching...")
            self._fetch_public_ip_async()
        # v2.8: bind-scoped Host line. A specific bind (e.g. 192.168.1.50)
        # is the operator's explicit choice of interface — the prompt must
        # carry THAT address, not the public IP (behind NAT they differ;
        # the agent would be pointed at the wrong interface). The public
        # IP stays correct for the 0.0.0.0 bind-with-forwarding setup.
        bind = (self.host_combo.currentText().strip()
                if hasattr(self, "host_combo") else self.host_addr)
        if netinfo.bind_scope(bind) == "specific":
            host = bind
            self._log(f"Agent prompt uses the bind address {bind} "
                      f"(bind-scoped, not the public IP).")
        else:
            host = self.public_ip or self.host_addr
        tls = bool(self.settings.get("tls", True)) and self.fingerprint
        # v2.5.1 (ASK-007): the SELECTED agent's key + name — the
        # picker drives the prompt, not the hardcoded agents[0].
        if self.agents:
            i = max(0, min(self._prompt_agent_idx, len(self.agents) - 1))
            agent = self.agents[i]
        else:
            agent = {"key": "", "name": "default"}
        text = build_prompt_text(
            key=agent.get("key", ""), host=host, port=self.port,
            roots=self.roots,
            fingerprint=self.fingerprint if tls else "", tls=bool(tls),
            agent_name=agent.get("name", "default"))
        QApplication.clipboard().setText(text)
        self._log(f"Copied connection prompt to clipboard ({len(text)} chars).")
        if not tls and self.host_addr not in ("127.0.0.1", "localhost", "::1"):
            self._log("WARNING: prompt uses plain HTTP over a non-localhost "
                      "bind — consider enabling TLS.", "WARN")

    def _refresh_key(self) -> None:
        new_k = new_key()
        old_fp = key_fingerprint(self.key)
        self.agents[0] = dict(self.agents[0])
        self.agents[0]["key"] = new_k
        self.key_edit.setText(new_k)
        self.key_edit.setToolTip(new_k)
        if self.ctx is not None:
            self.ctx.auth.update(self.agents)
        self._log(f"Default agent key refreshed "
                  f"({old_fp} → {key_fingerprint(new_k)}).")
        self._save_state(event_type="key_refresh",
                         payload={"old_fp": old_fp,
                                  "new_fp": key_fingerprint(new_k)})

    # ------------------------------------------------------------------
    # Agents panel
    # ------------------------------------------------------------------

    def _refresh_agents_list(self) -> None:
        self.agent_list.clear()
        for a in self.agents:
            perms = ",".join(k for k, v in a["perms"].items() if v) or "none"
            roots = "all roots" if not a.get("roots") else "+".join(
                os.path.basename(r) or r for r in a["roots"])
            expiry = a.get("expires_at") or "no expiry"
            self.agent_list.addItem(
                f"{a['name']:<14} [{perms}]  {roots}  {expiry}")
        # v2.5.1 (ASK-007): keep the Overview picker current.
        self._sync_prompt_agents()
        # v2.5.2 (ASK-009): keep the Log-tab agent filter current.
        self._sync_log_filter_agents()

    def _add_agent(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("New agent")
        form = QFormLayout(dlg)
        name_edit = QLineEdit()
        name_edit.setPlaceholderText("e.g. claude, cursor, reviewer")
        form.addRow("Name", name_edit)
        scope_combo = QComboBox()
        scope_combo.addItem("All shared roots", [])
        for r in self.roots:
            scope_combo.addItem(r, [r])
        form.addRow("May access", scope_combo)
        ttl_combo = QComboBox()
        ttl_combo.addItem("No expiry", 0)
        ttl_combo.addItem("Expires in 1 day", 1)
        ttl_combo.addItem("Expires in 7 days", 7)
        ttl_combo.addItem("Expires in 30 days", 30)
        form.addRow("Key lifetime", ttl_combo)
        perms_row = QHBoxLayout()
        cbs = {}
        for perm in ("read", "write", "delete", "exec", "proc"):
            cb = QCheckBox(perm)
            cb.setChecked(perm in ("read", "write", "delete"))
            cbs[perm] = cb
            perms_row.addWidget(cb)
        perms_widget = QWidget()
        perms_widget.setLayout(perms_row)
        form.addRow("Permissions", perms_widget)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        form.addRow(buttons)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        name = name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Name required",
                                "Give the agent a name.")
            return
        if any(a["name"] == name for a in self.agents):
            QMessageBox.warning(self, "Duplicate", "That agent name exists.")
            return

        expires_at = None
        days = ttl_combo.currentData()
        if days:
            from datetime import datetime, timedelta, timezone
            expires_at = (datetime.now(timezone.utc)
                          + timedelta(days=int(days))).isoformat(
                              timespec="seconds")

        agent = {
            "name": name,
            "key": new_key(),
            "roots": list(scope_combo.currentData() or []),
            "perms": {k: cb.isChecked() for k, cb in cbs.items()},
            "expires_at": expires_at,
            "created_at": now_iso(),
        }
        self.agents.append(agent)
        if self.ctx is not None:
            self.ctx.auth.update(self.agents)
        self._refresh_agents_list()
        self._log(f"Agent '{name}' added (perms: "
                  f"{','.join(k for k, v in agent['perms'].items() if v)}).")
        self._save_state(event_type="agent_added", payload={"agent": name})
        QApplication.clipboard().setText(agent["key"])
        QMessageBox.information(
            self, "Agent key",
            f"Agent '{name}' key (copied to clipboard — shown once):\n\n"
            f"{agent['key']}")

    def _revoke_agent(self) -> None:
        row = self.agent_list.currentRow()
        if row < 0 or row >= len(self.agents):
            return
        agent = self.agents[row]
        if agent["name"] == "default":
            QMessageBox.warning(self, "Cannot revoke",
                                "Use 'Refresh key' to rotate the default agent.")
            return
        reply = QMessageBox.question(
            self, "Revoke", f"Revoke agent '{agent['name']}'? Its key "
            f"stops working immediately.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        self.agents.pop(row)
        if self.ctx is not None:
            self.ctx.auth.update(self.agents)
        self._refresh_agents_list()
        self._log(f"Agent '{agent['name']}' revoked.", "WARN")
        self._save_state(event_type="agent_revoked",
                         payload={"agent": agent["name"]})

    def _copy_selected_agent_key(self) -> None:
        row = self.agent_list.currentRow()
        if row < 0 or row >= len(self.agents):
            return
        QApplication.clipboard().setText(self.agents[row]["key"])
        self._log(f"Key for '{self.agents[row]['name']}' copied.")

    # ------------------------------------------------------------------
    # Policy / exec / TLS
    # ------------------------------------------------------------------

    _POLICY_TEXT = {
        "auto": "The agent never waits for you: everything allowed by its "
                "permissions just runs. Share (roots) requests still wait "
                "for your approval — expanding the sandbox is a scope "
                "decision only you can make under this policy. Best for "
                "headless/unattended runs.",
        "auto_all": "Auto — no restrictions. Identical to 'auto', plus "
                    "agents can share new host directories THEMSELVES: "
                    "roots requests are granted instantly, logged loudly "
                    "and appear in your Shared list. Run this only for "
                    "agents you fully trust — ideally under a dedicated "
                    "host user account.",
        "destructive": "Normal reads and writes run freely; recursive or "
                       "large deletes and other risky ops wait for your "
                       "approval in the Approvals tab. Recommended default.",
        "strict": "Every write, delete and exec waits for your approval. "
                  "Safest, but the agent will ping-pong through the "
                  "approval queue constantly.",
    }

    def _on_policy_changed(self) -> None:
        value = self.policy_combo.currentData()
        self.settings["approval_policy"] = value
        # settings dict is shared by reference with the server context.
        self._update_policy_description()
        self._log(f"Approval policy set to '{value}'.")
        self._save_state(event_type="policy_change", payload={"policy": value})

    def _update_policy_description(self) -> None:
        value = self.settings.get("approval_policy", POLICY_DESTRUCTIVE)
        self.policy_desc.setText(self._POLICY_TEXT.get(value, ""))

    def _on_exec_toggled(self, checked: bool) -> None:
        self.settings["allow_exec"] = checked
        self._sync_default_agent_exec(checked)
        if self.ctx is not None:
            self.ctx.auth.update(self.agents)
        self._update_exec_warning()
        self._log(f"Raw shell exec {'ENABLED' if checked else 'disabled'}.",
                  "WARN" if checked else "INFO")
        self._save_state(event_type="exec_toggle",
                         payload={"allow_exec": checked})

    def _on_sudo_timeout_changed(self) -> None:
        """v2.4.5: what a pending sudo approval does when its 2-minute
        countdown elapses. Baked into each approval at create time, so
        the change applies to FUTURE requests only. v2.4.6: governs
        installs AND removals."""
        value = self.sudo_timeout_combo.currentData()
        self.settings["sudo_timeout_action"] = value
        self._log(f"Sudo-change timeout action set to auto-{value.upper()} "
                  f"(future requests).", "WARN" if value == "approve"
                  else "INFO")
        self._save_state(event_type="sudo_timeout_change",
                         payload={"sudo_timeout_action": value})

    def _save_sudo_password(self) -> None:
        """v2.4.6: store the sudo password in MEMORY (AppContext), never
        in settings/state.json. If the server has not been started yet,
        the value is staged and pushed into the context when it is
        built. The edit field is cleared after saving so the password
        does not linger in the widget (the clear button + echo mode
        already hide it, but belt and braces)."""
        pw = self.sudo_pw_edit.text()
        if not pw:
            self._clear_sudo_password()
            return
        self._sudo_pw_staged = pw
        if self.ctx is not None:
            self.ctx.sudo_password = pw
        self.sudo_pw_edit.clear()
        self.sudo_pw_status.setText(
            "sudo password: SET (memory only — survives server stop/start "
            "in this session, cleared on app exit; never written to disk, "
            "never sent to agents).")
        self._log("Sudo password stored in memory only (never persisted, "
                  "never exposed to agents; used exclusively for "
                  "approved package changes).", "INFO")

    def _clear_sudo_password(self) -> None:
        """v2.4.6: wipe the staged + live password and the field."""
        self._sudo_pw_staged = None
        if self.ctx is not None:
            self.ctx.sudo_password = None
        self.sudo_pw_edit.clear()
        self.sudo_pw_status.setText(
            "sudo password: not set — without it, approved commands fail "
            "at the sudo password prompt (exec has no TTY).")
        self._log("Sudo password cleared.", "INFO")

    def _update_exec_warning(self) -> None:
        if self.settings.get("allow_exec"):
            self.exec_warn_label.setText(
                "⚠ sandbox checks are advisory — run exec-capable agents "
                "under a dedicated user account for real isolation.")
        else:
            self.exec_warn_label.setText("")

    def _on_tls_toggled(self, checked: bool) -> None:
        self.settings["tls"] = checked
        self._refresh_tls_fingerprint()
        self._log(f"TLS {'enabled' if checked else 'DISABLED (plaintext!)'}.",
                  "INFO" if checked else "WARN")
        self._save_state(event_type="tls_toggle", payload={"tls": checked})
        if self.server is not None:
            self._log("Restart the server to apply the TLS change.", "WARN")

    def _refresh_tls_fingerprint(self) -> None:
        self.fingerprint = None
        if not self.settings.get("tls", True):
            self._update_tls_panel()
            return
        if not tlsutil.openssl_available():
            self._log("openssl not found — TLS unavailable, staying on "
                      "plaintext HTTP. Keep the bind on localhost!", "WARN")
            self._update_tls_panel()
            return
        cert, _key = tlsutil.ensure_cert(self.data_dir)
        if cert:
            self.fingerprint = tlsutil.cert_fingerprint(cert)
            self._log(f"TLS cert fingerprint: {self.fingerprint}")
        self._update_tls_panel()

    def _update_tls_panel(self) -> None:
        fp = self.fingerprint or "—"
        self.fp_label.setText(fp)
        self.fp_label.setToolTip(self.fingerprint or "")
        if self.fingerprint:
            self.fp_label.setStyleSheet(
                f"font-family: 'Cascadia Code', monospace; color: {C_TEXT};")
        else:
            self.fp_label.setStyleSheet(
                f"font-family: 'Cascadia Code', monospace; color: {C_MUTED};")
        if self.settings.get("tls", True) and self.fingerprint:
            self.tls_state_label.setText(
                f"TLS enabled — self-signed certificate, agents pin the "
                f"fingerprint out-of-band (it is embedded in the agent "
                f"prompt).\nSHA256 fingerprint: {fp}")
            self.tls_state_label.setStyleSheet(f"color: {C_GREEN};")
        elif self.settings.get("tls", True):
            self.tls_state_label.setText(
                "TLS wanted but openssl was not found — running plaintext "
                "HTTP. Keep the bind on localhost!")
            self.tls_state_label.setStyleSheet(f"color: {C_AMBER};")
        else:
            self.tls_state_label.setText(
                "TLS disabled — the key and file contents travel in "
                "cleartext. Only acceptable on a localhost bind.")
            self.tls_state_label.setStyleSheet(f"color: {C_RED};")

    # ------------------------------------------------------------------
    # Install venvs
    # ------------------------------------------------------------------

    def _refresh_venv_list(self) -> None:
        self.venv_list.clear()
        for v in self.settings.get("venvs") or []:
            self.venv_list.addItem(v)

    def _refresh_discovered_venvs(self) -> None:
        """v2.4.3: live view of agent-created venvs (policy discoveries).

        Read-only — the configured allow-list above stays human-managed.
        Keyed on the SERVER running (not just ctx existing) so a stopped
        server shows the placeholder instead of stale last-run entries.
        """
        entries: list[str] = []
        if (self.server is not None and self.ctx is not None
                and getattr(self.ctx, "policy", None) is not None):
            try:
                entries = sorted(self.ctx.policy.discovered_venvs)
            except AttributeError:
                entries = []
        current = [self.discovered_venv_list.item(i).text()
                   for i in range(self.discovered_venv_list.count())]
        if current == entries:
            return  # nothing changed — no flicker on the 5s poll
        self.discovered_venv_list.clear()
        if entries:
            self.discovered_venv_list.addItems(entries)
        else:
            self.discovered_venv_list.addItem(
                "(none yet — appears when an agent creates a venv)")

    def _add_venv(self) -> None:
        path = QFileDialog.getExistingDirectory(
            self, "Select a virtual environment directory")
        if not path:
            return
        path = os.path.realpath(os.path.abspath(path))
        venvs = list(self.settings.get("venvs") or [])
        if path not in venvs:
            venvs.append(path)
        self.settings["venvs"] = venvs
        self._sync_policy_venvs()
        self._refresh_venv_list()
        self._log(f"Install venv registered: {path}")
        self._save_state(event_type="venv_added", payload={"path": path})

    def _remove_venv(self) -> None:
        row = self.venv_list.currentRow()
        if row < 0:
            return
        venvs = list(self.settings.get("venvs") or [])
        removed = venvs.pop(row)
        self.settings["venvs"] = venvs
        self._sync_policy_venvs()
        self._refresh_venv_list()
        self._log(f"Install venv removed: {removed}")
        self._save_state(event_type="venv_removed", payload={"path": removed})

    def _sync_policy_venvs(self) -> None:
        if self.ctx is not None:
            self.ctx.policy.venvs = set(self.settings.get("venvs") or [])

    # ------------------------------------------------------------------
    # Server management
    # ------------------------------------------------------------------

    def _start_server(self) -> None:
        if self.server is not None:
            self._log("Server already running.")
            return
        # v2.1: zero roots is fine — the agent connects and requests
        # directories, which the human approves in the Approvals tab.
        if not self.roots:
            self._log("Starting with NO shared directories — agents can "
                      "connect and request shares via 'roots request'.",
                      "WARN")
        # Read bind host / port from the GUI fields.
        new_host = self.host_combo.currentText().strip() or DEFAULT_HOST
        try:
            new_port = int(self.port_edit.text())
            if not (1 <= new_port <= 65535):
                raise ValueError("port out of range")
        except ValueError:
            QMessageBox.critical(self, "Invalid port",
                f"Port must be an integer in 1..65535 (got: {self.port_edit.text()!r}).")
            return
        self.host_addr = new_host
        self.port = new_port

        # TLS cert (if enabled and provisionable).
        cert = keyf = None
        if self.settings.get("tls") and self.fingerprint:
            cert, keyf = tlsutil.tls_paths(self.data_dir)

        # (Re)build the shared application context.
        if self.ctx is None:
            self.ctx = build_context(
                self.state_store, self.roots, self.agents, self.settings,
                self.history, log_callback=self._on_http_log)
            # v2.4.6: a password saved before the first start rides
            # into the fresh context.
            if self._sudo_pw_staged:
                self.ctx.sudo_password = self._sudo_pw_staged
            # v2.7.0 (ASK-016/017): the screen channel services — the
            # GUI owns capture (Qt main thread through the bridge);
            # the X11/XTest input backend runs on the server thread
            # (None when no X display is reachable — ops then refuse
            # screen_unavailable naming it).
            self.ctx.screen = QtScreenService(self._mt_caller)
            self.ctx.input = make_input_backend()
            self._register_own_windows()
        else:
            self._on_roots_changed()

        try:
            srv = make_server(self.host_addr, self.port, self.ctx,
                              cert, keyf)
        except OSError as e:
            QMessageBox.critical(self, "Cannot start server",
                f"Could not bind to {self.host_addr}:{self.port}\n{e}")
            return
        self.server = srv
        self.server_thread = threading.Thread(
            target=srv.serve_forever, daemon=True)
        self.server_thread.start()
        scheme = "https" if cert else "http"
        self._log(f"Server started on {scheme}://{self.host_addr}:{self.port}")
        if not cert and self.host_addr not in ("127.0.0.1", "localhost", "::1"):
            self._log("WARNING: plaintext HTTP on a non-localhost bind — "
                      "the key and file contents travel unencrypted!", "ERROR")
        self._set_bind_fields_enabled(False)
        self._refresh_status()
        self._poll_approvals()
        self._poll_procs()
        self._save_state(event_type="server_start",
                         payload={"host": self.host_addr, "port": self.port,
                                   "key_fp": key_fingerprint(self.key)})

    def _stop_server(self) -> None:
        if self.server is None:
            return
        if self.ctx is not None:
            n = self.ctx.procs.stop_all()
            if n:
                self._log(f"Stopped {n} background process(es).")
        self.server.shutdown()
        self.server.server_close()
        self.server = None
        self.server_thread = None
        self._log("Server stopped.")
        self._set_bind_fields_enabled(True)
        self._refresh_status()
        self._poll_procs()
        self._save_state(event_type="server_stop",
                         payload={"host": self.host_addr, "port": self.port})

    def _restart_server(self) -> None:
        self._stop_server()
        self._start_server()

    # ------------------------------------------------------------------
    # Approval queue
    # ------------------------------------------------------------------

    def _build_sessions_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(14, 14, 14, 14)
        v.setSpacing(10)

        # == Human channel card ==
        ccard, cv = self._card(
            "Live sessions",
            "talk to a working agent mid-run — your messages land in "
            "its inbox; replies are its session notes")
        split = QHBoxLayout()
        self.chat_agent_list = QListWidget()
        self.chat_agent_list.setAlternatingRowColors(True)
        self.chat_agent_list.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.chat_agent_list.setMinimumWidth(190)
        self.chat_agent_list.currentItemChanged.connect(
            self._chat_agent_selected)
        split.addWidget(self.chat_agent_list)

        right = QVBoxLayout()
        # v2.5.2 (ASK-008): a QTextBrowser, not a QPlainTextEdit —
        # the thread renders as HTML: colored sender labels,
        # timestamps, word wrap, paragraph-split long notes.
        self.chat_view = QTextBrowser()
        self.chat_view.setReadOnly(True)
        self.chat_view.setOpenExternalLinks(False)
        self.chat_view.setOpenLinks(False)
        self.chat_view.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        self.chat_view.setPlaceholderText(
            "Select an agent on the left — its notes and your messages "
            "appear here as one thread.")
        right.addWidget(self.chat_view, 1)
        # v2.6.0 (ASK-014): search + export — the readable thread
        # becomes a usable one; an export is the durable evidence
        # artifact a rule-6 capture cites.
        srow = QHBoxLayout()
        self.chat_search = QLineEdit()
        self.chat_search.setEnabled(False)
        self.chat_search.setPlaceholderText(
            "Search transcript (Enter next, Shift+Enter previous, Esc clear)")
        self.chat_search.textChanged.connect(self._chat_search_changed)
        self.chat_search.returnPressed.connect(self._chat_search_next)
        self.chat_search.installEventFilter(self)
        srow.addWidget(self.chat_search, 1)
        self.chat_search_hits = QLabel("")
        self.chat_search_hits.setProperty("muted", True)
        srow.addWidget(self.chat_search_hits)
        self.chat_export_btn = QPushButton("Export…")
        self.chat_export_btn.setEnabled(False)
        self.chat_export_btn.clicked.connect(self._chat_export)
        srow.addWidget(self.chat_export_btn)
        right.addLayout(srow)
        row = QHBoxLayout()
        self.chat_input = QLineEdit()
        self.chat_input.setEnabled(False)
        self.chat_input.setPlaceholderText(
            "Message the agent while it works (Enter to send)")
        self.chat_input.returnPressed.connect(self._send_chat_message)
        row.addWidget(self.chat_input, 1)
        self.chat_send_btn = QPushButton("Send")
        self.chat_send_btn.setProperty("variant", "primary")
        self.chat_send_btn.setEnabled(False)
        self.chat_send_btn.clicked.connect(self._send_chat_message)
        row.addWidget(self.chat_send_btn)
        right.addLayout(row)
        rw = QWidget()
        rw.setLayout(right)
        split.addWidget(rw, 1)
        cv.addLayout(split)
        v.addWidget(ccard)

        hint = QLabel(
            "Agents poll `session inbox` between work units; unread "
            "counts badge each session until the agent reads them. "
            "Sessions with an op in the last 15 minutes show as live.")
        hint.setProperty("muted", True)
        hint.setWordWrap(True)
        v.addWidget(hint)
        v.addStretch()
        return w

    # ------------------------------------------------------------------
    # v2.5.0 (ASK-001/002) — Sessions tab: the human channel
    # ------------------------------------------------------------------

    def _poll_chat(self) -> None:
        """Sidebar refresh: every known agent session (live/dormant by
        last-op age), unread badges, stable selection across rebuilds.
        Reads the registry IN-PROCESS — the GUI owns the AppContext, so
        the human channel adds no HTTP surface."""
        if self.ctx is None:
            return
        try:
            snap = self.ctx.sessions.agents_snapshot()
        except Exception:
            return
        prev = self._chat_agent
        self.chat_agent_list.blockSignals(True)
        self.chat_agent_list.clear()
        for s in sorted(snap, key=lambda x: x["agent"]):
            label = f"{s['agent']}  ({s['op_count']} ops"
            try:
                from datetime import datetime, timezone
                last = datetime.fromisoformat(s["last_seen"])
                age = (datetime.now(timezone.utc) - last).total_seconds()
                label += ", live" if age < 900 else ", dormant"
            except Exception:
                pass
            if s.get("unread"):
                label += f", {s['unread']} unread"
            label += ")"
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, s["agent"])
            self.chat_agent_list.addItem(item)
            if s["agent"] == prev:
                self.chat_agent_list.setCurrentItem(item)
        self.chat_agent_list.blockSignals(False)
        if prev and prev not in {s["agent"] for s in snap}:
            # the selected agent's session was reset away
            self._chat_agent = None
            self._chat_last_render = ""
            self._chat_items = []
            self._chat_search_idx = 0
            self.chat_view.clear()
            self.chat_input.setEnabled(False)
            self.chat_send_btn.setEnabled(False)
            self.chat_search.setEnabled(False)
            self.chat_search.clear()
            self.chat_search_hits.setText("")
            self.chat_export_btn.setEnabled(False)
        elif prev is None and self.chat_agent_list.count():
            self.chat_agent_list.setCurrentRow(0)
        self._refresh_chat_thread()

    def _chat_agent_selected(self, current, _previous) -> None:
        if current is None:
            return
        self._chat_agent = current.data(Qt.ItemDataRole.UserRole)
        self.chat_input.setEnabled(True)
        self.chat_send_btn.setEnabled(True)
        self.chat_search.setEnabled(True)
        self.chat_export_btn.setEnabled(True)
        self._chat_last_render = ""
        self._refresh_chat_thread()

    def _refresh_chat_thread(self) -> None:
        if self.ctx is None or self._chat_agent is None:
            return
        try:
            items = self.ctx.sessions.thread(self._chat_agent)
        except Exception:
            return
        # v2.6.0 (ASK-014): the full thread is the search/export
        # source — an export writes every entry the registry holds,
        # not just the visible window.
        self._chat_items = items
        # v2.5.2 (ASK-008): HTML thread render — sender labels with
        # colors (YOU blue, the agent green), muted timestamps, word
        # wrap, blank-space breaks, long notes paragraph-split at
        # sentence boundaries. All text is escaped; the render token
        # keeps the unchanged-skip + autoscroll behavior.
        blocks = []
        for it in items:
            ts = (it.get("ts") or "")[11:19]
            who = ("YOU" if it.get("kind") == "message"
                   else self._chat_agent)
            color = "#6cb6ff" if who == "YOU" else "#4ade80"
            raw = (it.get("text") or "").rstrip()
            paras = "".join(
                f"<p>{html.escape(p)}</p>"
                for p in _split_thread_paragraphs(raw))
            blocks.append(
                '<div style="margin:0 0 10px 0;">'
                f'<span style="color:#768390;">[{ts}]</span> '
                f'<span style="color:{color}; font-weight:bold;">'
                f"{html.escape(who)}</span>{paras}</div>")
        render = "".join(blocks)
        if render == self._chat_last_render:
            return
        self._chat_last_render = render
        sb = self.chat_view.verticalScrollBar()
        at_bottom = sb.value() >= sb.maximum() - 4
        self.chat_view.setHtml(render)
        if at_bottom:
            sb.setValue(sb.maximum())
        # v2.6.0 (ASK-014): setHtml reset the cursor — re-apply the
        # live search so it survives the 1 s re-render.
        term, n = self._chat_thread_hits()
        if term and n:
            self._chat_apply_search(n)
            self.chat_search_hits.setText(
                f"{self._chat_search_idx + 1}/{n}")

    # ------------------------------------------------------------------
    # v2.6.0 (ASK-014) — transcript search + export
    # ------------------------------------------------------------------

    def _chat_thread_hits(self):
        """(term, hit-count) over the cached thread — case-insensitive,
        regex-escaped via core.transcript.count_hits."""
        term = self.chat_search.text().strip()
        if not term or not self._chat_items:
            return term, 0
        text = "\n".join((it.get("text") or "")
                        for it in self._chat_items)
        return term, count_hits(text, term)

    def _chat_search_changed(self) -> None:
        term, n = self._chat_thread_hits()
        self._chat_search_idx = 0
        if not term:
            self.chat_search_hits.setText("")
            self.chat_view.setTextCursor(
                QTextCursor(self.chat_view.document()))
            return
        self.chat_search_hits.setText(
            f"{n} hit{'s' if n != 1 else ''}" if n else "no hits")
        self._chat_apply_search(n)

    def _chat_search_next(self) -> None:
        if (QApplication.queryKeyboardModifiers()
                & Qt.KeyboardModifier.ShiftModifier):
            self._chat_search_step(-1)
        else:
            self._chat_search_step(1)

    def _chat_search_step(self, delta: int) -> None:
        term, n = self._chat_thread_hits()
        if not term or not n:
            return
        self._chat_search_idx = (self._chat_search_idx + delta) % n
        self._chat_apply_search(n)
        self.chat_search_hits.setText(
            f"{self._chat_search_idx + 1}/{n}")

    def _chat_apply_search(self, n: int) -> None:
        """Jump the QTextBrowser cursor onto the current hit so it is
        highlighted; QTextBrowser.find is case-insensitive by default
        and moves the selection with it."""
        if not n:
            return
        cur = QTextCursor(self.chat_view.document())
        cur.movePosition(QTextCursor.MoveOperation.Start)
        self.chat_view.setTextCursor(cur)
        term = self.chat_search.text().strip()
        for _ in range(self._chat_search_idx + 1):
            if not self.chat_view.find(term):
                break

    def eventFilter(self, obj, event):
        # v2.6.0 (ASK-014): Esc clears the transcript search.
        if (obj is self.chat_search
                and event.type() == QEvent.Type.KeyPress
                and event.key() == Qt.Key.Key_Escape):
            self.chat_search.clear()
            self.chat_search.clearFocus()
            return True
        return super().eventFilter(obj, event)

    def _chat_export(self) -> None:
        """Export the FULL thread of the selected agent — the durable
        evidence artifact a rule-6 capture cites. The metadata
        preamble (agent, exported-at, time range, entries) travels
        with the file, so the artifact proves its own provenance."""
        if self.ctx is None or not self._chat_agent:
            return
        agent = self._chat_agent
        default = os.path.join(self._chat_export_dir or os.getcwd(),
                               default_export_name(agent))
        path, sel = QFileDialog.getSaveFileName(
            self, "Export transcript", default, EXPORT_FILTERS)
        if not path:
            return
        fmt = guess_format(path, sel)
        gen = datetime.now().isoformat(timespec="seconds")
        if fmt == "html":
            body = transcript_html(agent, self._chat_items, gen)
        elif fmt == "txt":
            body = transcript_plaintext(agent, self._chat_items, gen)
        else:
            body = transcript_markdown(agent, self._chat_items, gen)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(body)
        except OSError as exc:
            QMessageBox.critical(
                self, "Export failed", f"Export failed:\n{exc}")
            return
        self._chat_export_dir = os.path.dirname(os.path.abspath(path))
        self.statusBar().showMessage(
            f"Exported {len(self._chat_items)} entries -> {path}")

    def _send_chat_message(self) -> None:
        text = self.chat_input.text().strip()
        if not text or self.ctx is None or not self._chat_agent:
            return
        # The human's message is NEVER an HTTP op: the GUI owns the
        # AppContext, so it writes straight into the session registry
        # and emits the 'message' event for live /events pollers. The
        # working agent sees it on its next `session inbox` poll.
        self.ctx.sessions.inbox(self._chat_agent, text,
                                events=self.ctx.events)
        self.chat_input.clear()
        self._refresh_chat_thread()
        self._poll_chat()

    def _poll_approvals(self) -> None:
        if self.ctx is None:
            self.apr_status_label.setText("no server")
            return
        self._drain_server_shares()
        # v2.4.5: resolve any sudo countdowns that elapsed since the
        # last tick (also covers waiters whose client vanished).
        try:
            self.ctx.approvals.sweep_expired()
        except Exception:
            pass
        try:
            pending = self.ctx.approvals.pending()
            decided = self.ctx.approvals.recent_decided(15)
        except Exception:
            return
        # --- pending list (incremental, keeps selection) ---
        current = {self.approval_list.item(i).data(Qt.ItemDataRole.UserRole)
                   for i in range(self.approval_list.count())}
        for a in pending:
            if a["id"] not in current:
                self.approval_list.addItem(self._approval_item(a))
        # v2.4.5: sudo countdowns tick every poll (1s) — refresh the
        # text of items that carry an expires_in so the human always
        # sees the true remaining time and the auto-action.
        if any(a.get("expires_in") is not None for a in pending):
            by_id = {self.approval_list.item(i).data(Qt.ItemDataRole.UserRole):
                     self.approval_list.item(i)
                     for i in range(self.approval_list.count())}
            for a in pending:
                it = by_id.get(a["id"])
                if it is not None and a.get("expires_in") is not None:
                    it.setText(self._approval_item_text(a))
        ids = {a["id"] for a in pending}
        for i in range(self.approval_list.count() - 1, -1, -1):
            if self.approval_list.item(i).data(
                    Qt.ItemDataRole.UserRole) not in ids:
                self.approval_list.takeItem(i)
        # --- decided list (full rebuild, capped at 15) ---
        self.decided_list.clear()
        for a in reversed(decided):
            ok = a["status"] == "approved"
            item = QListWidgetItem(
                f"{'✓' if ok else '✕'} [{a['op']}] {a['summary']} — "
                f"{a['status']} by {a.get('decided_by')} at "
                f"{a.get('decided_at')}  ({a['id']})")
            item.setForeground(QColor(C_GREEN if ok else C_RED))
            self.decided_list.addItem(item)
        self.apr_status_label.setText(
            f"{len(pending)} pending" if pending else "queue empty")
        self._update_pills(pending_n=len(pending))
        self._refresh_grants()
        # v2.7.0: the drive banner rides the same 1s poll
        self._update_drive_banner()

    def _drain_server_shares(self) -> None:
        """Apply shares granted server-side (policy 'auto_all').

        The server queued them from request threads; Qt widgets may only
        be touched from the main thread, so the approvals poll timer drains
        the queue here. This also persists the new roots to state.json.
        """
        if self.ctx is None or not self.ctx.share_queue:
            return
        added = []
        while self.ctx.share_queue:
            p = self.ctx.share_queue.pop(0)
            if p not in self.roots:
                self.roots.append(p)
                added.append(p)
        if added:
            for p in added:
                self._log(f"Auto-shared under 'auto-all' policy: {p} "
                          f"(granted by the agent itself)", "WARN")
            self._refresh_dir_list()
            self._on_roots_changed()
            self._refresh_status()
            self._save_state(event_type="share_auto_approved",
                             payload={"paths": added,
                                      "roots_n": len(self.roots)})

    @staticmethod
    def _approval_item_text(a: dict) -> str:
        payload = a.get("payload") or {}
        if a["op"] == "share_root" and payload.get("path"):
            reason = payload.get("reason") or "(no reason given)"
            text = (f"[share] {payload['path']}\n"
                    f"        reason: {reason}\n"
                    f"        by '{a['agent']}' at {a['created_at']}  "
                    f"({a['id']})\n"
                    f"        note: root sharing is a scope expansion — it "
                    f"always needs your approval under 'auto'. Switch to "
                    f"'auto-all' if you want agents to expand the sandbox "
                    f"themselves.")
        elif a["op"] in ("sudo_install", "sudo_remove"):
            # v2.4.5: the countdown approval. expires_in is recomputed by
            # to_dict() on every poll, so the 1s approvals tick gives a
            # live MM:SS display. v2.4.6: the label carries the verb.
            label = ("sudo install" if a["op"] == "sudo_install"
                     else "sudo remove")
            left = a.get("expires_in")
            action = a.get("timeout_action") or "reject"
            if left is not None:
                mm, ss = divmod(max(0, int(round(left))), 60)
                text = (f"[{label}] {a['summary']}\n"
                        f"        by '{a['agent']}' at {a['created_at']}  "
                        f"({a['id']})\n"
                        f"        auto-{action.upper()} in {mm}:{ss:02d} — "
                        f"decide now, or the request resolves itself.\n"
                        f"        this prompt appears under EVERY approval "
                        f"policy; granting does NOT create a reusable "
                        f"grant.")
            else:
                text = (f"[{label}] {a['summary']}\n"
                        f"        by '{a['agent']}' at {a['created_at']}  "
                        f"({a['id']})")
        else:
            text = (f"[{a['op']}] {a['summary']}\n"
                    f"        by '{a['agent']}' at {a['created_at']}  "
                    f"({a['id']})")
        return text

    @staticmethod
    def _approval_item(a: dict) -> QListWidgetItem:
        item = QListWidgetItem(HostWindow._approval_item_text(a))
        item.setData(Qt.ItemDataRole.UserRole, a["id"])
        return item

    def _selected_approval_id(self) -> str | None:
        item = self.approval_list.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _update_approval_buttons(self, current, _previous=None) -> None:
        """v2.4.6: Approve/Deny track the pending-list selection. Wired
        to currentItemChanged, so a decided entry disappearing from the
        1s poll re-disables the buttons immediately — no silent no-op
        clicks. The tooltip doubles as the 'why is this disabled' hint."""
        has = current is not None
        self.approve_btn.setEnabled(has)
        self.deny_btn.setEnabled(has)
        # v2.7.0: the session-grant button only arms for screen classes
        screen_op = False
        if has and self.ctx:
            aid = current.data(Qt.ItemDataRole.UserRole)
            a = self.ctx.approvals.status(aid) if aid else None
            screen_op = bool(a and a.get("op") in _SCREEN_GRANT_OPS)
        self.apr_session_btn.setEnabled(screen_op)
        if has:
            self.approve_btn.setToolTip(
                "Approve the selected request (double-click also approves)")
            self.deny_btn.setToolTip("Deny the selected request")
        else:
            self.approve_btn.setToolTip("Select a request above first")
            self.deny_btn.setToolTip("Select a request above first")

    def _approve_selected(self) -> None:
        aid = self._selected_approval_id()
        if not aid or not self.ctx:
            return
        a = self.ctx.approvals.status(aid)
        if a and a["op"] == "share_root":
            ok, msg = self._apply_share_request(a)
            if not ok:
                self._log(f"Share request {aid} could not be applied: {msg}",
                          "WARN")
                self.ctx.approvals.decide(aid, False, by="host")
                self._log(f"Approval {aid} DENIED.", "WARN")
                self._poll_approvals()
                return
            self.ctx.approvals.decide(aid, True, by="host")
            self._log(f"Approval {aid} GRANTED — {msg}", "OK")
        else:
            grant = self._offer_grant(a)
            self.ctx.approvals.decide(aid, True, by="host")
            if grant:
                self._log(f"Approval {aid} GRANTED — grant {grant['id']} "
                          f"covers '{grant['scope']}' for "
                          f"{', '.join(grant['ops'])}.", "OK")
            else:
                self._log(f"Approval {aid} GRANTED.", "OK")
        self._refresh_grants()
        self._poll_approvals()
        self.approval_list.clearSelection()
        self._update_approval_buttons(None)

    def _deny_selected(self) -> None:
        aid = self._selected_approval_id()
        if aid and self.ctx:
            self.ctx.approvals.decide(aid, False, by="host")
            self._log(f"Approval {aid} DENIED.", "WARN")
            self._poll_approvals()
        self.approval_list.clearSelection()
        self._update_approval_buttons(None)

    def _apply_share_request(self, a: dict) -> tuple:
        """Add the requested directory to the shared roots.

        Called ONLY when the human approves the request. Returns
        (ok, message)."""
        path = (a.get("payload") or {}).get("path")
        if not path:
            return False, "request carries no path"
        if not os.path.isdir(path):
            return False, f"{path} no longer exists on this machine"
        real = os.path.realpath(path)
        if real in self.roots:
            return True, f"{real} already shared"
        self.roots.append(real)
        self._refresh_dir_list()
        self._on_roots_changed()
        self._refresh_status()
        self._save_state(event_type="share_request_approved",
                         payload={"path": real, "approval": a["id"],
                                  "agent": a.get("agent"),
                                  "roots_n": len(self.roots)})
        self._log(f"Shared {real} (approved for agent "
                  f"'{a.get('agent', '?')}').")
        return True, f"{real} is now shared"

    # ------------------------------------------------------------------
    # Screen channel (v2.7.0 — ASK-016/017)
    # ------------------------------------------------------------------

    def _register_own_windows(self) -> None:
        """Arm the own-window guard: register the main window's X id
        with the input backend. X11 sessions only — on Wayland the GUI
        is a native window OUTSIDE XWayland's tree, so the
        self-approval loop is platform-dead there; the hit-test guard
        still covers the X11 case where the GUI IS an X client."""
        try:
            if (self.ctx is None or self.ctx.input is None
                    or getattr(self, "_mt_caller", None) is None):
                return
            if QtScreenService._platform() != "xcb":
                return
            wid = int(self.winId())
            self.ctx.input.own_window_ids.add(wid)
            self._log(f"Own-window guard armed (X window {wid}).")
        except Exception:
            pass

    def _update_drive_banner(self) -> None:
        """1s poll: show the disarm banner while a drive session runs,
        clear it when none does; start the XI2 listener (X11 only)."""
        banner = getattr(self, "_drive_banner", None)
        if banner is None or self.ctx is None:
            return
        sessions = self.ctx.screen_drive.active()
        if sessions and not banner.isVisible():
            banner.show()
            self._log(f"Drive session ACTIVE (agent "
                      f"'{sessions[0].get('agent')}') — the banner is "
                      f"up; click it (or any physical input on X11) to "
                      f"disarm.", "WARN")
            self._ensure_xi2_disarm()
        elif not sessions and banner.isVisible():
            banner.hide()

    def _ensure_xi2_disarm(self) -> None:
        """Start the XI2 raw-input disarm listener once per process,
        X11 sessions only. The listener thread lives for the process
        (it blocks on its display; the callback no-ops when no session
        is active) — restarting it per session would leak displays."""
        if self._xi2_thread is not None:
            return
        try:
            if QtScreenService._platform() != "xcb":
                return
        except Exception:
            return
        t = xi2_disarm_listener(self._disarm_drive)
        if t is not None:
            self._xi2_thread = t
            self._log("XI2 raw-input disarm listener active (X11): any "
                      "physical key, button or motion disarms the "
                      "drive session; injected events never trip it.")

    def _disarm_drive(self) -> None:
        """One click on the banner (GUI thread) — or, on X11 sessions,
        the first physical input event (XI2 listener thread) — kills
        every drive session. Banner updates are marshalled back to the
        GUI thread when this runs on the listener thread."""
        if self.ctx is None:
            return
        n = self.ctx.screen_drive.close_all()
        if not n:
            return
        self.ctx.op_log("WARN", f"DRIVE DISARMED — {n} session(s) "
                                f"closed from the host GUI")
        self._log(f"Drive session DISARMED ({n} closed).", "WARN")
        banner = getattr(self, "_drive_banner", None)
        if banner is not None and banner.isVisible():
            if threading.current_thread() is threading.main_thread():
                banner.hide()
            else:
                try:
                    self._mt_caller.call(banner.hide)
                except Exception:
                    pass

    def _approve_selected_session(self) -> None:
        """v2.7.0: 'Approve for this session' — the screen-class grant
        that survives until the app restarts (memory-only; every op is
        still op-logged; a drive-cap violation drops it)."""
        aid = self._selected_approval_id()
        if not aid or not self.ctx:
            return
        a = self.ctx.approvals.status(aid)
        if not a or a.get("op") not in _SCREEN_GRANT_OPS:
            return
        self.ctx.screen_session_grants.setdefault(a["op"], set()).add(
            a.get("agent"))
        self.ctx.approvals.decide(aid, True, by="host")
        self._log(f"Approval {aid} GRANTED + until-restart session "
                  f"grant: '{a['op']}' for agent '{a.get('agent')}' "
                  f"(every op still logged; the grant dies with this "
                  f"app).", "OK")
        self._poll_approvals()
        self.approval_list.clearSelection()
        self._update_approval_buttons(None)

    def _save_screen_setting(self, key: str, value) -> None:
        """The sudo_timeout pattern: mutate the live settings dict (the
        server's ctx shares it by reference) + one persisted save."""
        self.settings[key] = value
        self._save_state(event_type="screen_settings_change",
                         payload={key: value})
        self._log(f"Screen setting {key} = {value!r} (persisted).")

    def _on_screen_input_toggled(self, on: bool) -> None:
        self._save_screen_setting("screen_input_enabled", bool(on))
        self.screen_input_warn.setVisible(bool(on))
        if on:
            self._log("INPUT INJECTION ENABLED — drive sessions are "
                      "capped, banner'd and op-logged; OFF again the "
                      "moment you untick this.", "WARN")

    def _shot_dir_edited(self) -> None:
        d = self.screen_shot_dir_edit.text().strip()
        if d:
            self._save_screen_setting("screen_shot_dir", d)

    def _pick_shot_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(
            self, "Choose the screenshot evidence folder",
            self.screen_shot_dir_edit.text()
            or os.path.expanduser("~"))
        if d:
            self.screen_shot_dir_edit.setText(d)
            self._save_screen_setting("screen_shot_dir", d)

    # ------------------------------------------------------------------
    # Approval grants (v2.3 — time-boxed 'approve once' for a subtree)
    # ------------------------------------------------------------------

    _GRANT_CHOICES = (
        ("Approve only", 0),
        ("Also grant 30 min", 30),
        ("Also grant 1 hour", 60),
        ("Also grant 4 hours", 240),
    )

    def _offer_grant(self, a: dict) -> dict | None:
        """After approving a gated op with a path, offer the host a
        time-boxed grant so the same op under the same subtree stops
        asking. Returns the grant dict, or None for approve-only."""
        path = (a.get("payload") or {}).get("path") or ""
        op = a.get("op") or ""
        if not path or op in ("share_root", "exec") or self.ctx is None:
            return None
        scope = os.path.dirname(path) or path
        box = QMessageBox()
        box.setWindowTitle("Approve with grant?")
        box.setIcon(QMessageBox.Icon.Question)
        box.setText(
            f"Approve this '{op}' and also grant '{op}' under\n{scope}\n"
            f"to agent '{a.get('agent', '?')}' for a while, so similar "
            "ops there stop asking for approval?")
        for label, _mins in self._GRANT_CHOICES:
            box.addButton(label, QMessageBox.ButtonRole.ActionRole)
        box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        clicked = box.clickedButton()
        if clicked is None:
            return None
        minutes = 0
        for label, mins in self._GRANT_CHOICES:
            if label == clicked.text():
                minutes = mins
                break
        if minutes <= 0:
            return None
        try:
            grant = add_grant(self.ctx, a.get("agent", "default"),
                              op, scope, minutes)
        except Exception as e:
            self._log(f"Could not create grant: {e}", "WARN")
            return None
        self._save_state(event_type="grant_added",
                         payload={"grant": grant["id"], "op": op,
                                  "scope": grant["scope"],
                                  "agent": grant.get("agent"),
                                  "expires_at": grant["expires_at"]})
        return grant

    def _refresh_grants(self) -> None:
        """Rebuild the Active grants card when the live set changes
        (skips identical rebuilds so the selection stays stable)."""
        if not hasattr(self, "grants_list"):
            return
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        alive = []
        for g in (self.settings.get("grants") or []):
            try:
                if datetime.fromisoformat(g.get("expires_at")) > now:
                    alive.append(g)
            except (TypeError, ValueError):
                continue
        sig = ";".join(f"{g.get('id')}|{g.get('expires_at')}|"
                       f"{','.join(g.get('ops', []))}" for g in alive)
        if sig == getattr(self, "_grants_sig", None):
            return
        self._grants_sig = sig
        self.grants_list.clear()
        for g in alive:
            ops = ",".join(g.get("ops", []))
            item = QListWidgetItem(
                f"[{ops}] {g.get('scope')}\n"
                f"        agent {g.get('agent')}, expires "
                f"{g.get('expires_at')}  ({g.get('id')})")
            item.setData(Qt.ItemDataRole.UserRole, g.get("id"))
            self.grants_list.addItem(item)

    def _revoke_selected_grant(self) -> None:
        item = self.grants_list.currentItem()
        if not item:
            return
        gid = item.data(Qt.ItemDataRole.UserRole)
        self.settings["grants"] = [
            g for g in (self.settings.get("grants") or [])
            if g.get("id") != gid]
        self._save_state(event_type="grant_revoked", payload={"grant": gid})
        self._log(f"Grant {gid} revoked.", "WARN")
        self._refresh_grants()

    # ------------------------------------------------------------------
    # Processes panel
    # ------------------------------------------------------------------

    def _poll_procs(self) -> None:
        if self.ctx is None:
            self.proc_table.setRowCount(0)
            self.sb_procs_label.setText("")
            self._update_pills(running_n=0)
            return
        try:
            procs = self.ctx.procs.list()
        except Exception:
            return
        self.proc_table.setRowCount(len(procs))
        for row_i, p in enumerate(procs):
            vals = [p["id"], p["name"], p["command"][:120],
                    "running" if p["running"] else "exited",
                    "" if p["running"] else str(p.get("returncode"))]
            for col, val in enumerate(vals):
                item = QTableWidgetItem(val)
                if col in (0, 4):
                    item.setData(Qt.ItemDataRole.UserRole, p["id"])
                self.proc_table.setItem(row_i, col, item)
        running_n = sum(1 for p in procs if p["running"])
        for col in (0, 1, 3, 4):           # ID / Name / Status / Exit
            self.proc_table.resizeColumnToContents(col)
        self.sb_procs_label.setText(
            f"{running_n} proc running  " if running_n else "")
        self._update_pills(running_n=running_n)

    def _stop_selected_proc(self) -> None:
        row = self.proc_table.currentRow()
        if row < 0 or self.ctx is None:
            return
        item = self.proc_table.item(row, 0)
        pid = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not pid:
            return
        res = self.ctx.procs.stop(pid, force=True)
        self._log(f"Stop proc {pid}: {res.get('stopped', False)} "
                  f"(rc={res.get('returncode')})", "WARN")
        self._poll_procs()

    def _selected_proc_id(self) -> str | None:
        """v2.4.8: the pid stored on the selected row (UserRole), or None."""
        row = self.proc_table.currentRow()
        if row < 0 or self.ctx is None:
            return None
        item = self.proc_table.item(row, 0)
        pid = item.data(Qt.ItemDataRole.UserRole) if item else None
        return pid or None

    def _tail_selected_proc(self) -> None:
        """v2.4.8: open (or raise) the live tail window for the selected
        process — one window per pid, modeless so the supervisor stays
        usable while logs stream."""
        pid = self._selected_proc_id()
        if not pid:
            QMessageBox.information(self, "No process selected",
                                    "Select a process row first.")
            return
        for dlg in list(self._proc_tail_windows):
            if getattr(dlg, "pid", None) == pid:
                dlg.raise_()
                dlg.activateWindow()
                return
        dlg = ProcTailDialog(self, self.ctx, pid)
        self._proc_tail_windows.append(dlg)
        dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        dlg.destroyed.connect(
            lambda _obj=None, _d=dlg: self._forget_tail_dialog(_d))
        dlg.show()

    def _forget_tail_dialog(self, dlg) -> None:
        if dlg in self._proc_tail_windows:
            self._proc_tail_windows.remove(dlg)

    def _stop_all_procs(self) -> None:
        if self.ctx is None:
            return
        n = self.ctx.procs.stop_all()
        self._log(f"Stopped all background processes ({n}).", "WARN")
        self._poll_procs()

    # ------------------------------------------------------------------
    # Pills / badges / status
    # ------------------------------------------------------------------

    def _update_pills(self, pending_n: int | None = None,
                      running_n: int | None = None) -> None:
        """Badge the tabs and header pills. None = leave unchanged."""
        if pending_n is not None:
            self._pending_n = pending_n
            self.pend_pill.setText(f"● {pending_n} pending")
            self.pend_pill.setVisible(pending_n > 0)
            self.tabs.setTabText(
                self.TAB_APPROVALS,
                f"Approvals ({pending_n})" if pending_n else "Approvals")
        if running_n is not None:
            self._running_n = running_n
            self.procs_pill.setText(f"● {running_n} running")
            self.procs_pill.setVisible(running_n > 0)
            self.tabs.setTabText(
                self.TAB_PROCS,
                f"Processes ({running_n})" if running_n else "Processes")

    def _refresh_status(self) -> None:
        running = self.server is not None
        if running:
            self.status_pill.setText("● running")
            self.status_pill.setStyleSheet(
                f"background-color: #12281c; color: {C_GREEN}; border: none; "
                "border-radius: 12px; padding: 3px 12px; font-weight: 600;")
            self.sb_status_label.setText("running")
            self.sb_status_label.setStyleSheet(
                f"color: {C_GREEN}; font-weight: 600;")
        else:
            self.status_pill.setText("○ stopped")
            self.status_pill.setStyleSheet(
                f"background-color: #2a1416; color: {C_RED}; border: none; "
                "border-radius: 12px; padding: 3px 12px; font-weight: 600;")
            self.sb_status_label.setText("stopped")
            self.sb_status_label.setStyleSheet(
                f"color: {C_RED}; font-weight: 600;")
        self.local_addr_label.setText(f"{self.host_addr}:{self.port}")
        self.sb_local_label.setText(
            f"local {self.host_addr}:{self.port}" if running else "")
        self._update_public_addr_display()
        self.start_btn.setEnabled(not running)
        self.stop_btn.setEnabled(running)

    def _set_bind_fields_enabled(self, enabled: bool) -> None:
        self.host_combo.setEnabled(enabled)
        self.port_edit.setEnabled(enabled)
        self.tls_check.setEnabled(enabled)

    def _refresh_local_ips(self) -> None:
        """v2.8: re-run zero-packet IPv4 discovery and rebuild the bind
        dropdown, keeping the operator's current selection."""
        ips = netinfo.local_ipv4s()
        self._log("Detected local IPv4: "
                  + (", ".join(ips) if ips else "(none)"))
        self._rebuild_host_items()

    def _rebuild_host_items(self, preserve: str = None) -> None:
        """Bind dropdown items: 127.0.0.1, detected local IPv4s, then
        the wildcards. Zero-packet discovery (core/netinfo.py) — nothing
        is sent anywhere."""
        cur = (preserve if preserve is not None
               else self.host_combo.currentText().strip())
        items = ["127.0.0.1"] + netinfo.local_ipv4s() + ["0.0.0.0", "::"]
        self.host_combo.blockSignals(True)
        self.host_combo.clear()
        self.host_combo.addItems(items)
        if cur:
            self.host_combo.setCurrentText(cur)
        self.host_combo.blockSignals(False)
        self._update_exposure_warning()

    def _update_exposure_warning(self, *args) -> None:
        # v2.8.1: this can fire during _build_overview_tab() — the
        # dropdown is populated (and its currentTextChanged signal is
        # armed) before the exposure label further down the same
        # Connection card exists. Stay a no-op until the widget tree
        # is complete; __init__ re-runs this right after _build_ui().
        if getattr(self, "exposure_label", None) is None:
            return
        host = self.host_combo.currentText().strip()
        scope = netinfo.bind_scope(host)
        if scope == "wildcard":
            self.exposure_label.setText(
                "⚠ reachable from your whole network")
            self.exposure_label.setStyleSheet(
                f"color: {C_RED}; font-weight: 600;")
        elif scope == "loopback":
            self.exposure_label.setText("localhost-only (safe)")
            self.exposure_label.setStyleSheet(
                f"color: {C_GREEN}; font-weight: 600;")
        else:
            # v2.8: the scoped middle ground — one real interface.
            self.exposure_label.setText(
                f"bound to {host} — reachable from your local network "
                f"only. Fine on a trusted LAN; prefer a tunnel for "
                f"remote agents.")
            self.exposure_label.setStyleSheet(
                f"color: {C_AMBER}; font-weight: 600;")

    # ------------------------------------------------------------------
    # Public IP helpers
    # ------------------------------------------------------------------

    def _fetch_public_ip_async(self) -> None:
        self.public_ip = None
        self._update_public_addr_display()
        self._log("Fetching public IP...")
        if self._ip_worker is not None and self._ip_worker.isRunning():
            self._ip_worker.quit()
            self._ip_worker.wait(1000)
        self._ip_worker = IPFetchWorker()
        self._ip_worker.ip_fetched.connect(self._on_ip_fetched)
        self._ip_worker.start()

    def _on_ip_fetched(self, ip: str) -> None:
        self.public_ip = ip if ip else None
        if ip:
            self._log(f"Public IP resolved: {ip}")
        else:
            self._log("Public IP lookup failed (no internet / all "
                      "services unreachable).", "WARN")
        self._update_public_addr_display()

    def _compute_public_addr(self) -> str:
        ip = self.public_ip if self.public_ip else "(unknown)"
        try:
            port_str = str(int(self.port_edit.text()))
        except (ValueError, AttributeError):
            port_str = str(self.port)
        return f"{ip}:{port_str}"

    def _update_public_addr_display(self, *args) -> None:
        addr = self._compute_public_addr()
        self.public_addr_label.setText(addr)

    # ------------------------------------------------------------------
    # Logging (thread-safe via queue + QTimer poller)
    # ------------------------------------------------------------------

    def _log(self, msg: str, level: str = "INFO",
             agent: str | None = None) -> None:
        """Thread-safe log: queues an event + mirrors to stderr + gui.log.
        v2.5.2 (ASK-009): `agent` names the acting agent on OP lines —
        the Log-tab filter and the gui.log audit trail are built on it."""
        ts = time.strftime("%H:%M:%S")
        ev = {"ts": ts, "level": level, "msg": msg, "agent": agent}
        self._log_queue.put(ev)
        who = f"[{agent}] " if agent else ""
        sys.stderr.write(f"[{ts}] {level:<8} {who}{msg}\n")
        sys.stderr.flush()
        try:
            with open(os.path.join(self.data_dir, "gui.log"), "a",
                      encoding="utf-8") as f:
                f.write(f"[{ts}] {level:<8} {who}{msg}\n")
        except OSError:
            pass

    def _on_http_log(self, ev) -> None:
        """Callback for BridgeHTTPRequestHandler logging.
        v2.5.2 (ASK-009): the op-log tuple widened to ("OP", level,
        msg, agent_name); the pre-2.5.2 3-tuple is still tolerated."""
        if isinstance(ev, tuple) and len(ev) == 4 and ev[0] == "OP":
            _, level, msg, agent = ev
            self._log(msg, level, agent)
        elif isinstance(ev, tuple) and len(ev) == 3 and ev[0] == "OP":
            _, level, msg = ev
            self._log(msg, level)
        else:
            self._log(str(ev), "REQUEST")

    def _poll_log_queue(self) -> None:
        """Drain the log queue and append to the QPlainTextEdit widget."""
        drained = 0
        try:
            while True:
                try:
                    ev = self._log_queue.get_nowait()
                except Exception:
                    break
                if not isinstance(ev, dict):
                    ev = {"ts": time.strftime("%H:%M:%S"),
                          "level": "INFO", "msg": str(ev)}
                self._log_buffer.append(ev)
                if len(self._log_buffer) > 500:
                    self._log_buffer = self._log_buffer[-500:]
                drained += 1
                if drained > 200:
                    break
        except Exception:
            pass

        if drained > 0:
            # v2.5.2 (ASK-009): the live tail honors the agent filter;
            # the buffer keeps EVERY entry (a filter change re-renders
            # from it via _render_log_buffer).
            agent = self._log_filter_agent()
            self._sync_log_filter_agents()
            for ev in self._log_buffer[-drained:]:
                if agent and ev.get("agent") != agent:
                    continue
                self.log_widget.appendHtml(self._log_line_html(ev))
            self.log_widget.moveCursor(QTextCursor.MoveOperation.End)
            self.log_widget.ensureCursorVisible()

    def _clear_log(self) -> None:
        self.log_widget.clear()
        self._log_buffer.clear()

    # ------------------------------------------------------------------
    # v2.5.2 (ASK-009) — Log-tab agent filter (a view, never a gate)
    # ------------------------------------------------------------------

    @staticmethod
    def _log_line_html(ev: dict) -> str:
        """One retained log entry as HTML — the v2.5.0 colors, plus the
        muted agent tag for OP lines that carry one."""
        ts = ev.get("ts", "")
        level = ev.get("level", "INFO")
        msg = ev.get("msg", "")
        color = LOG_COLORS.get(level, C_TEXT)
        safe_msg = (msg.replace("&", "&amp;")
                       .replace("<", "&lt;")
                       .replace(">", "&gt;"))
        safe_msg = safe_msg.replace("\n", "<br>")
        agent = ev.get("agent")
        who = (f'<span style="color:#64748b;">'
               f"[{html.escape(agent)}]</span> " if agent else "")
        return (f'<span style="color:#768390;">[{ts}]</span> '
                f'<span style="color:{color}; font-weight:bold;">'
                f'{level:<8}</span> {who}'
                f'<span style="color:{color};">{safe_msg}</span>')

    def _log_filter_agent(self) -> str | None:
        """The active Log-tab filter: None = All agents."""
        txt = self.log_agent_filter.currentText()
        return None if (not txt or txt == "All agents") else txt

    def _on_log_filter_changed(self, _idx) -> None:
        self._render_log_buffer()

    def _render_log_buffer(self) -> None:
        """Full Log-tab re-render from the retained buffer, honoring
        the agent filter. The widget caps itself at 1000 blocks; the
        buffer holds the last 500 — every retained entry fits."""
        agent = self._log_filter_agent()
        self.log_widget.clear()
        shown = 0
        for ev in self._log_buffer:
            if agent and ev.get("agent") != agent:
                continue
            self.log_widget.appendHtml(self._log_line_html(ev))
            shown += 1
        if shown:
            self.log_widget.moveCursor(QTextCursor.MoveOperation.End)
            self.log_widget.ensureCursorVisible()

    def _sync_log_filter_agents(self) -> None:
        """Keep the filter combo current: registry names plus any agent
        seen in the buffer. Signal-blocked so a rebuild never fires a
        re-render; the user's selection survives rebuilds."""
        seen = set()
        for a in (self.agents or []):
            if isinstance(a, dict) and a.get("name"):
                seen.add(a["name"])
        for ev in self._log_buffer:
            if ev.get("agent"):
                seen.add(ev["agent"])
        want = ["All agents"] + sorted(seen)
        cur = self.log_agent_filter.currentText()
        have = [self.log_agent_filter.itemText(i)
                for i in range(self.log_agent_filter.count())]
        if have != want:
            self.log_agent_filter.blockSignals(True)
            self.log_agent_filter.clear()
            self.log_agent_filter.addItems(want)
            if cur in want:
                self.log_agent_filter.setCurrentText(cur)
            self.log_agent_filter.blockSignals(False)

    # ------------------------------------------------------------------
    # Export / Import / Open Data Folder
    # ------------------------------------------------------------------

    def _export_settings(self) -> None:
        default_name = f"llmac-session-{time.strftime('%Y%m%d-%H%M%S')}.json"
        default_dir = os.path.join(self.data_dir, "exports")
        os.makedirs(default_dir, exist_ok=True)
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Session Settings",
            os.path.join(default_dir, default_name),
            "JSON files (*.json);;All files (*.*)")
        if not path:
            return
        state = self.state_store.build_state(
            roots=self.roots, host=self.host_addr, port=self.port,
            agents=self.agents, settings=self.settings)
        try:
            export_session(state, path,
                           notes="Exported from LLMAC v2 GUI")
        except OSError as e:
            QMessageBox.critical(self, "Export failed",
                                f"Could not write {path}:\n{e}")
            return
        self._log(f"Settings exported to {path}")
        self.data_status_label.setText(
            f"exported {time.strftime('%H:%M')}")
        self.history.append({
            "type": "export", "path": path,
            "key_fp": key_fingerprint(self.key),
            "roots_n": len(self.roots),
        })
        QMessageBox.information(self, "Exported",
            f"Session settings exported to:\n{path}\n\n"
            f"The file contains agent keys in plaintext - "
            f"store it securely.")

    def _import_settings(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Session Settings",
            os.path.join(self.data_dir, "exports"),
            "JSON files (*.json);;All files (*.*)")
        if not path:
            return
        try:
            export = import_session(path)
        except (OSError, ValueError) as e:
            QMessageBox.critical(self, "Import failed",
                                f"Could not read {path}:\n{e}")
            return
        new_state = export["state"]
        new_roots = list(new_state.get("roots") or [])

        missing = [r for r in new_roots if not os.path.isdir(r)]
        if missing:
            warn = ("The following directories from the export do not exist "
                    "on this machine:\n\n  - " + "\n  - ".join(missing) +
                    "\n\nThey will still be added to the list. Continue?")
            reply = QMessageBox.question(self, "Missing directories", warn,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if reply != QMessageBox.StandardButton.Yes:
                return

        if self.server is not None:
            self._stop_server()
        new_state = export["state"]
        self.roots = list(new_state.get("roots") or [])
        self.agents = [normalize_agent(a)
                       for a in (new_state.get("agents") or [])] or \
            [make_default_agent(new_state.get("key") or "")]
        self.settings.update(new_state.get("settings") or {})
        self.host_addr = new_state.get("host") or self.host_addr
        self.port = int(new_state.get("port") or self.port)
        self.key_edit.setText(self.key)
        self.key_edit.setToolTip(self.key)
        self.host_combo.setCurrentText(self.host_addr)
        self.port_edit.setText(str(self.port))
        self._sync_policy_venvs()
        self._refresh_dir_list()
        self._refresh_agents_list()
        self._refresh_venv_list()
        self._refresh_status()
        self._update_exposure_warning()
        self._update_policy_description()
        self._save_state(event_type="import",
                         payload={"source": path, "roots_n": len(self.roots),
                                   "host": self.host_addr, "port": self.port,
                                   "key_fp": key_fingerprint(self.key),
                                   "missing_dirs": missing})
        self._log(f"Settings imported from {path}")
        self.data_status_label.setText(f"imported {time.strftime('%H:%M')}")
        QMessageBox.information(self, "Imported",
            f"Session imported from:\n{path}\n\n"
            f"Shared directories: {len(self.roots)}\n"
            f"Agents: {len(self.agents)}\n"
            f"Bind host: {self.host_addr}\n"
            f"Port: {self.port}\n\n"
            f"Click 'Start Server' to apply.")

    def _open_data_folder(self) -> None:
        import subprocess
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", self.data_dir])
            elif os.name == "nt":
                subprocess.Popen(["explorer", self.data_dir])
            else:
                for cmd in (["xdg-open"], ["gio", "open"]):
                    try:
                        subprocess.Popen(cmd + [self.data_dir])
                        return
                    except FileNotFoundError:
                        continue
        except OSError as e:
            self._log(f"Could not open data folder: {e}")

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _save_state(self, *, event_type: str | None = None,
                    payload: dict | None = None) -> None:
        try:
            state = self.state_store.build_state(
                roots=self.roots, host=self.host_addr, port=self.port,
                agents=self.agents, settings=self.settings)
            self.state_store.save(state)
            self.data_status_label.setText(f"saved {time.strftime('%H:%M')}")
        except OSError as e:
            self._log(f"Could not save state: {e}")
        if event_type:
            evt = {"type": event_type}
            if payload:
                evt.update(payload)
            self.history.append(evt)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def closeEvent(self, event) -> None:
        """Called when the user closes the window via the window manager."""
        for t in (self._log_timer, self._approvals_timer, self._procs_timer,
                  self._venvs_timer):
            if t is not None:
                t.stop()
        if self.server is not None:
            self._stop_server()
        self._save_state(event_type="close",
                         payload={"roots_n": len(self.roots),
                                   "key_fp": key_fingerprint(self.key)})
        event.accept()
