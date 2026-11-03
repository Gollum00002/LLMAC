"""v2.5.2 — THE READABLE CHANNEL tests (tests-first: written red
against 2.5.1, made green by the build).

Covers the release items:
  * ASK-008 transcript readability — the Sessions chat pane renders
    HTML in a QTextBrowser: sender labels + colors, timestamps,
    word wrap, long notes paragraph-split; no more setPlainText
    wall-of-text (the transcript the user pasted was the bug report).
  * ASK-009 op_log agent field + Log-tab filter — every op_log call
    site passes its agent; the GUI callback tuple widens to carry
    the agent name; the Log tab gains an agent filter combo over the
    retained buffer (a view filter, never a data gate).
  * ASK-010 agent-scoped log view — the server keeps a bounded op
    ring; NEW POST /session/log returns ONLY the acting agent's
    entries, scoped by authentication and NEVER by a client
    parameter (an explicit "agent" payload key is a clean 400);
    CLI `session log` prints the scoped view.
  * S4 harness rider — batch_median_s (median-of-3) recorded by the
    bench and gated by compare_bench (Task-38's flapping-ratio fix).
  * version truth 2.5.2 in BOTH copies + /info (the era pins in the
    older modules flip with the release as always).
"""
import http.client
import json
import os
import re
import subprocess
import sys
import unittest

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost, make_tree
from core.state import make_default_agent

from core.constants import LLMAC_VERSION

CLI = os.path.join(_PARENT, "llmac.py")
GUI_SRC = os.path.join(_PARENT, "gui.py")
API_SRC = os.path.join(_PARENT, "core", "api.py")
BENCH_SRC = os.path.join(_PARENT, "tools", "bench_llmac.py")
CMP_SRC = os.path.join(_PARENT, "scripts", "compare_bench.py")
CHANGES_SRC = os.path.join(_PARENT, "CHANGES.md")

KEY_DEFAULT = "testkey_llmac_1234567890"
KEY_CLAUDE = "testkey_llmac_claude_450921"


def _second_agent():
    a = make_default_agent(KEY_CLAUDE)
    a["name"] = "claude"
    return a


def run_cli(host, *args, key=None, timeout=90):
    return subprocess.run(
        [sys.executable, CLI, "--plain", "--host", "127.0.0.1",
         "--port", str(host.port), "--key", key or host.key, *args],
        capture_output=True, text=True, timeout=timeout)


def raw_request(host, method, path, payload=None, key=None):
    """http.client request that EXPOSES response headers."""
    conn = http.client.HTTPConnection("127.0.0.1", host.port, timeout=30)
    body = json.dumps(payload or {}) if payload is not None else None
    headers = {}
    if key is not None:
        headers["Authorization"] = f"Bearer {key}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    out = {"status": resp.status,
           "unread": resp.getheader("X-LLMAC-Unread"),
           "json": None}
    try:
        out["json"] = json.loads(data.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError):
        out["raw_bytes"] = len(data)
    conn.close()
    return out


# ---------------------------------------------------------------------------
# ASK-010 — the server half: a bounded op ring + POST /session/log,
# scoped to the acting agent by construction
# ---------------------------------------------------------------------------

class TestSessionLogRoute(unittest.TestCase):

    def setUp(self):
        self.host = TestHost(agents=[make_default_agent(KEY_DEFAULT),
                                     _second_agent()])
        self.addCleanup(self.host.stop)
        make_tree(self.host.root, {"a.txt": "alpha\n", "b.txt": "beta\n"})

    def _write_as(self, key, name, marker):
        return self.host.post(
            "/write", {"path": f"{self.host.root}/{name}.txt",
                       "content": marker}, key=key)

    def test_route_registered(self):
        src = open(API_SRC, encoding="utf-8").read()
        self.assertIn('@route("POST", "/session/log")', src)

    def test_scoped_to_caller(self):
        # The op log records PATHS, not contents — scoping is asserted
        # on the distinct file names each agent wrote.
        self._write_as(KEY_DEFAULT, "a", "marker-default-1111")
        self._write_as(KEY_CLAUDE, "b", "marker-claude-2222")
        out_d, st_d = self.host.post("/session/log", {"limit": 100},
                                    key=KEY_DEFAULT)
        self.assertEqual(st_d, 200)
        self.assertEqual(out_d.get("agent"), "default")
        msgs_d = " ".join(e["msg"] for e in out_d.get("entries", []))
        self.assertIn("a.txt", msgs_d)
        self.assertNotIn("b.txt", msgs_d)
        for e in out_d.get("entries", []):
            self.assertEqual(e["agent"], "default")
        out_c, st_c = self.host.post("/session/log", {"limit": 100},
                                    key=KEY_CLAUDE)
        self.assertEqual(st_c, 200)
        self.assertEqual(out_c.get("agent"), "claude")
        msgs_c = " ".join(e["msg"] for e in out_c.get("entries", []))
        self.assertIn("b.txt", msgs_c)
        self.assertNotIn("a.txt", msgs_c)

    def test_entry_shape(self):
        self._write_as(KEY_DEFAULT, "a", "shape-check")
        out, st = self.host.post("/session/log", {}, key=KEY_DEFAULT)
        self.assertEqual(st, 200)
        entries = out.get("entries", [])
        self.assertTrue(entries)
        e = entries[-1]
        self.assertIsInstance(e["seq"], int)
        self.assertTrue(e["ts"])
        self.assertEqual(e["agent"], "default")
        self.assertEqual(e["level"], "OK")
        self.assertIn("WRITE", e["msg"])
        self.assertIn("next_after", out)
        self.assertEqual(out["next_after"], entries[-1]["seq"])

    def test_client_agent_param_rejected(self):
        self._write_as(KEY_DEFAULT, "a", "x")
        out, st = self.host.post(
            "/session/log", {"agent": "claude"}, key=KEY_DEFAULT)
        self.assertEqual(st, 400)
        self.assertEqual(out.get("error"), "agent_scoping_is_automatic")

    def test_after_cursor(self):
        self._write_as(KEY_DEFAULT, "cursor1", "x")
        first, st = self.host.post("/session/log", {}, key=KEY_DEFAULT)
        self.assertEqual(st, 200)
        cursor = first["next_after"]
        self._write_as(KEY_DEFAULT, "cursor2", "y")
        second, st = self.host.post("/session/log", {"after": cursor},
                                    key=KEY_DEFAULT)
        self.assertEqual(st, 200)
        self.assertEqual(len(second["entries"]), 1)
        self.assertIn("cursor2.txt", second["entries"][0]["msg"])
        self.assertNotIn("cursor1.txt", second["entries"][0]["msg"])
        self.assertGreater(second["entries"][0]["seq"], cursor)

    def test_limit_and_bad_fields(self):
        self._write_as(KEY_DEFAULT, "a", "lim-1")
        self._write_as(KEY_DEFAULT, "b", "lim-2")
        out, st = self.host.post("/session/log", {"limit": 1},
                                 key=KEY_DEFAULT)
        self.assertEqual(st, 200)
        self.assertEqual(len(out["entries"]), 1)
        out, st = self.host.post("/session/log", {"limit": 0},
                                 key=KEY_DEFAULT)
        self.assertEqual(st, 400)
        self.assertEqual(out.get("error"), "bad_field")
        out, st = self.host.post("/session/log", {"after": -3},
                                 key=KEY_DEFAULT)
        self.assertEqual(st, 400)
        self.assertEqual(out.get("error"), "bad_field")

    def test_unauthenticated_is_401(self):
        out = raw_request(self.host, "POST", "/session/log", {})
        self.assertEqual(out["status"], 401)

    def test_unread_header_stamped_on_log_too(self):
        self.host.ctx.sessions.inbox("default", "hello?")
        out = raw_request(self.host, "POST", "/session/log", {},
                          key=KEY_DEFAULT)
        self.assertEqual(out["status"], 200)
        self.assertEqual(out["unread"], "1")


class TestOpRing(unittest.TestCase):
    """Unit level: the ring itself (bounded, agent-tagged, seq'd)."""

    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)

    def test_op_log_agent_param_recorded(self):
        ctx = self.host.ctx
        ctx.op_log("OK", "m1", agent={"name": "x"})
        ctx.op_log("WARN", "m2", agent="y")
        ctx.op_log("OP", "m3")
        ring = ctx.op_ring
        self.assertEqual([e["agent"] for e in ring], ["x", "y", None])
        self.assertEqual([e["level"] for e in ring], ["OK", "WARN", "OP"])
        seqs = [e["seq"] for e in ring]
        self.assertEqual(seqs, sorted(seqs))

    def test_ring_bounded(self):
        ctx = self.host.ctx
        for i in range(1005):
            ctx.op_log("OP", f"m{i}", agent="flooder")
        self.assertEqual(len(ctx.op_ring), 1000)
        self.assertIn("m1004", ctx.op_ring[-1]["msg"])

    def test_callback_tuple_carries_agent(self):
        seen = []
        self.host.ctx.log_callback = seen.append
        self.host.ctx.op_log("OK", "cb", agent={"name": "z"})
        self.assertEqual(seen[-1], ("OP", "OK", "cb", "z"))


# ---------------------------------------------------------------------------
# ASK-010 — the CLI half: `session log`
# ---------------------------------------------------------------------------

class TestCliSessionLog(unittest.TestCase):

    def setUp(self):
        self.host = TestHost(agents=[make_default_agent(KEY_DEFAULT),
                                    _second_agent()])
        self.addCleanup(self.host.stop)
        make_tree(self.host.root, {"a.txt": "alpha\n", "b.txt": "beta\n"})

    def test_prints_only_own_entries(self):
        self.host.post("/write", {"path": f"{self.host.root}/a.txt",
                                  "content": "own-marker-777"},
                       key=KEY_DEFAULT)
        self.host.post("/write", {"path": f"{self.host.root}/b.txt",
                                  "content": "foreign-marker-888"},
                       key=KEY_CLAUDE)
        r = run_cli(self.host, "session", "log")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("a.txt", r.stdout)
        self.assertNotIn("b.txt", r.stdout)
        self.assertIn("next_after", r.stdout)

    def test_after_and_limit_flags(self):
        for i in range(4):
            self.host.post("/write", {
                "path": f"{self.host.root}/a.txt",
                "content": f"payload-{i}"}, key=KEY_DEFAULT)
        r = run_cli(self.host, "session", "log", "--limit", "2")
        self.assertEqual(r.returncode, 0, r.stderr)
        lines = [ln for ln in r.stdout.splitlines()
                 if re.match(r"\[.*\]  ?(OK|OP|WARN|REJECTED) ", ln)]
        self.assertEqual(len(lines), 2)
        first = run_cli(self.host, "session", "log")
        cursor = int(re.search(r"next_after: (\d+)", first.stdout).group(1))
        self.host.post("/write", {"path": f"{self.host.root}/b.txt",
                                  "content": "after-marker"},
                       key=KEY_DEFAULT)
        r = run_cli(self.host, "session", "log", "--after", str(cursor))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("b.txt", r.stdout)
        self.assertNotIn("a.txt", r.stdout)

    def test_bad_after_is_rc1(self):
        r = run_cli(self.host, "session", "log", "--after", "-1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("bad_field", r.stdout + r.stderr)


# ---------------------------------------------------------------------------
# ASK-008 — transcript readability (GUI source pins; the offscreen
# acceptance run exercises the rendered HTML on the host)
# ---------------------------------------------------------------------------

class TestTranscriptSourcePins(unittest.TestCase):

    def setUp(self):
        self.src = open(GUI_SRC, encoding="utf-8").read()

    def test_chat_view_is_qtextbrowser(self):
        self.assertIn("QTextBrowser", self.src)
        self.assertIn("self.chat_view = QTextBrowser(", self.src)

    def test_no_plain_text_thread_render(self):
        self.assertNotIn("self.chat_view.setPlainText(", self.src)

    def test_thread_renders_html_with_escape(self):
        self.assertIn("self.chat_view.setHtml(", self.src)
        self.assertIn("html.escape", self.src)

    def test_paragraph_split_helper(self):
        self.assertIn("def _split_thread_paragraphs(", self.src)

    def test_word_wrap_configured(self):
        self.assertIn("self.chat_view.setLineWrapMode(", self.src)


# ---------------------------------------------------------------------------
# ASK-009 — op_log agent field + Log-tab filter (source pins + server
# behavior; the callback behavior is unit-tested in TestOpRing)
# ---------------------------------------------------------------------------

class TestLogAgentFilterSourcePins(unittest.TestCase):

    def setUp(self):
        self.gui = open(GUI_SRC, encoding="utf-8").read()
        self.api = open(API_SRC, encoding="utf-8").read()

    def test_op_log_signature_has_agent(self):
        self.assertIn(
            "def op_log(self, level: str, msg: str, agent=None) -> None:",
            self.api)

    def test_every_op_log_callsite_passes_agent(self):
        """No 2-arg ctx.op_log(...) call survives in api.py."""
        calls = re.findall(r"ctx\.op_log\(([^()]*(?:\([^()]*\)[^()]*)*)\)",
                          self.api)
        self.assertTrue(calls)
        for c in calls:
            self.assertRegex(
                c, r"agent\s*=",
                msg=f"op_log call without agent param: op_log({c})")

    def test_write_callsite_example(self):
        m = re.search(
            r'ctx\.op_log\("OK", f"WRITE \{path\}[^"]*",\s*\n\s*agent=agent\)',
            self.api)
        self.assertTrue(m, "WRITE call site lost its agent param")

    def test_http_log_unpacks_four_tuple(self):
        self.assertIn('len(ev) == 4', self.gui)

    def test_log_gains_agent_param(self):
        self.assertIn('agent: str | None = None', self.gui)

    def test_filter_combo_exists(self):
        self.assertIn("self.log_agent_filter = QComboBox()", self.gui)
        self.assertIn("self.log_agent_filter.currentIndexChanged",
                      self.gui)

    def test_filter_rerenders_from_buffer(self):
        self.assertIn("def _render_log_buffer(", self.gui)


# ---------------------------------------------------------------------------
# S4 harness rider — batch_median_s recorded + gated
# ---------------------------------------------------------------------------

class TestHarnessPins(unittest.TestCase):

    def test_bench_records_batch_median(self):
        src = open(BENCH_SRC, encoding="utf-8").read()
        self.assertIn("batch_median_s", src)
        self.assertIn("statistics.median", src)

    def test_compare_gates_batch_median(self):
        src = open(CMP_SRC, encoding="utf-8").read()
        self.assertIn("batch_median_s", src)
        self.assertIn("S4_MEDIAN_KEY", src)


# ---------------------------------------------------------------------------
# Version truth — 2.5.2 everywhere it must be
# ---------------------------------------------------------------------------

class TestVersion252(unittest.TestCase):

    def test_constants_version(self):
        self.assertEqual(LLMAC_VERSION, "2.7.3")

    def test_constants_src_literal(self):
        src = open(os.path.join(_PARENT, "core", "constants.py"),
                   encoding="utf-8").read()
        self.assertIn('LLMAC_VERSION = "2.7.3"', src)

    def test_cli_fallback_literal(self):
        src = open(CLI, encoding="utf-8").read()
        self.assertIn('VERSION = "2.7.3"', src)

    def test_info_version_live(self):
        host = TestHost()
        self.addCleanup(host.stop)
        resp, st = host.get("/info")
        self.assertEqual(st, 200)
        self.assertEqual(resp["version"], "2.7.3")

    def test_changes_entry(self):
        src = open(CHANGES_SRC, encoding="utf-8").read()
        self.assertIn("## v2.5.2", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
