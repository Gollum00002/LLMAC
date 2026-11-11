"""v2.5.1 — THE STRAIGHTENED CHANNEL tests (tests-first: written red
against 2.5.0, made green by the build).

Covers the release items:
  * ASK-005 ENFORCED notice — the server stamps X-LLMAC-Unread (the
    acting agent's unread count) on EVERY authenticated response, JSON
    and raw alike; the CLI prints a loud stderr banner after ANY op
    while unread > 0 — except the inbox read itself; rc stays
    transport-only (agent.md tip 17 unchanged).
  * ASK-006 tab miswiring — gui.py tab indices become widget-derived
    (captured from addTab return values), never a hardcoded range.
    The v2.5.0 bug: TAB_ constants said range(6) while the bar had 7
    tabs, so _update_pills relabeled Sessions as "Approvals" and
    Approvals as "Processes" (the user's bug report, symptom for
    symptom). Pinned so a future insertion can never re-miswire.
  * ASK-007 Overview agent picker — the Connection card gains a
    picker; the copied agent prompt uses the SELECTED agent's key +
    name instead of hardcoded agents[0].
  * version truth 2.5.1 in BOTH copies + /info (the era pins in the
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

from core.constants import LLMAC_VERSION

CLI = os.path.join(_PARENT, "llmac.py")
GUI_SRC = os.path.join(_PARENT, "gui.py")
API_SRC = os.path.join(_PARENT, "core", "api.py")


def run_cli(host, *args, timeout=90, cwd=None):
    return subprocess.run(
        [sys.executable, CLI, "--plain", "--host", "127.0.0.1",
         "--port", str(host.port), "--key", host.key, *args],
        capture_output=True, text=True, timeout=timeout, cwd=cwd)


def raw_request(host, method, path, payload=None, key=None):
    """http.client request that EXPOSES response headers (helpers.req
    drops them — the enforced-notice contract lives in a header)."""
    conn = http.client.HTTPConnection("127.0.0.1", host.port, timeout=30)
    body = json.dumps(payload or {}) if payload is not None else None
    headers = {"Authorization": f"Bearer {key or host.key}"}
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
# ASK-005 server half — the unread notice rides every authenticated
# response, JSON and raw, success and error
# ---------------------------------------------------------------------------

class TestEnforcedHeader(unittest.TestCase):

    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)
        make_tree(self.host.root, {"f.txt": "x\n"})

    def test_header_on_plain_op_starts_zero(self):
        out = raw_request(self.host, "GET", "/info")
        self.assertEqual(out["status"], 200)
        self.assertEqual(out["unread"], "0")   # present even when quiet

    def test_header_counts_unread(self):
        self.host.ctx.sessions.inbox("default", "one")
        out = raw_request(self.host, "GET", "/info")
        self.assertEqual(out["unread"], "1")
        self.host.ctx.sessions.inbox("default", "two")
        out = raw_request(self.host, "GET", "/info")
        self.assertEqual(out["unread"], "2")

    def test_header_zero_after_consume(self):
        self.host.ctx.sessions.inbox("default", "read me")
        out = raw_request(self.host, "POST", "/session/inbox", {})
        self.assertEqual(out["json"]["unread"], 0)
        self.assertEqual(out["unread"], "0")
        out2 = raw_request(self.host, "GET", "/info")
        self.assertEqual(out2["unread"], "0")

    def test_header_kept_after_peek(self):
        self.host.ctx.sessions.inbox("default", "still here")
        out = raw_request(self.host, "POST", "/session/inbox", {"peek": True})
        self.assertEqual(out["unread"], "1")
        out2 = raw_request(self.host, "GET", "/info")
        self.assertEqual(out2["unread"], "1")

    def test_no_header_unauthenticated(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.host.port,
                                          timeout=30)
        conn.request("GET", "/health")
        resp = conn.getresponse()
        unread = resp.getheader("X-LLMAC-Unread")
        resp.read()
        conn.close()
        self.assertIsNone(unread)

    def test_no_header_on_bad_key(self):
        out = raw_request(self.host, "GET", "/info", key="llmac_wrong")
        self.assertEqual(out["status"], 401)
        self.assertIsNone(out["unread"])

    def test_header_on_raw_response(self):
        # the archive download streams a tar.gz via _send_raw — the
        # notice must ride raw responses too
        self.host.ctx.sessions.inbox("default", "during download")
        out = raw_request(self.host, "GET",
                         f"/archive?path={self.host.root}")
        self.assertEqual(out["status"], 200)
        self.assertEqual(out["unread"], "1")
        self.assertGreater(out.get("raw_bytes", 0), 0)

    def test_header_on_error_response(self):
        # a 409 stale-edit error still carries the notice — enforcement
        # survives failure paths
        p = os.path.join(self.host.root, "f.txt")
        self.host.post("/write", {"path": p, "content": "alpha\n"})
        r, _ = self.host.post("/read", {"path": p})
        v = r.get("version", "")
        self.host.post("/edit", {"path": p, "expected_version": v,
                                 "ops": [{"op": "append",
                                          "content": "b\n"}]})
        self.host.ctx.sessions.inbox("default", "while broken")
        out = raw_request(self.host, "POST", "/edit",
                         {"path": p, "expected_version": v,
                          "ops": [{"op": "append", "content": "x\n"}]})
        self.assertEqual(out["status"], 409)
        self.assertEqual(out["unread"], "1")

    def test_both_chokepoints_stamp_it(self):
        # source belt+suspenders: _send_json AND _send_raw both stamp
        with open(API_SRC, encoding="utf-8") as f:
            src = f.read()
        self.assertGreaterEqual(src.count("X-LLMAC-Unread"), 2)


# ---------------------------------------------------------------------------
# ASK-005 CLI half — the banner is unmissable, on every op, rc untouched
# ---------------------------------------------------------------------------

class TestCliBanner(unittest.TestCase):
    """v2.7.3: the notice moved from a mid-request stderr banner to a
    trailer on the operation's own stdout result (see
    test_v273_inbox_notice.py for the full contract); these pins keep
    the v2.5.1 behaviours that did not change."""

    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)
        make_tree(self.host.root, {"f.txt": "x\n"})

    def test_notice_fires_on_plain_op(self):
        self.host.ctx.sessions.inbox("default", "steer left")
        r = run_cli(self.host, "info")
        self.assertEqual(r.returncode, 0)
        self.assertIn("1 message waiting to be addressed in Inbox", r.stdout)
        self.assertIn("session inbox", r.stdout)

    def test_notice_repeats_every_op_while_unread(self):
        self.host.ctx.sessions.inbox("default", "once")
        first = run_cli(self.host, "info")
        second = run_cli(self.host, "stat",
                         "--path", os.path.join(self.host.root, "f.txt"))
        self.assertIn("waiting to be addressed in Inbox", first.stdout)
        self.assertIn("waiting to be addressed in Inbox", second.stdout)

    def test_inbox_read_is_exempt(self):
        self.host.ctx.sessions.inbox("default", "hello yourself")
        r = run_cli(self.host, "session", "inbox")
        self.assertEqual(r.returncode, 0)
        self.assertIn("hello yourself", r.stdout)
        self.assertNotIn("waiting to be addressed", r.stdout + r.stderr)

    def test_notice_silent_after_consume(self):
        self.host.ctx.sessions.inbox("default", "then cleared")
        run_cli(self.host, "session", "inbox")
        r = run_cli(self.host, "info")
        self.assertNotIn("waiting to be addressed", r.stdout + r.stderr)

    def test_peek_keeps_notice_alive(self):
        self.host.ctx.sessions.inbox("default", "peeked")
        run_cli(self.host, "session", "inbox", "--peek")
        r = run_cli(self.host, "info")
        self.assertIn("waiting to be addressed in Inbox", r.stdout)

    def test_no_notice_when_quiet(self):
        r = run_cli(self.host, "info")
        self.assertNotIn("waiting to be addressed", r.stdout + r.stderr)

    def test_notice_does_not_change_rc(self):
        # tip 17 holds: the rc reports the TRANSPORT, the notice is
        # printed context, never an exit-code change
        self.host.ctx.sessions.inbox("default", "rc must stay transport")
        r = run_cli(self.host, "info")
        self.assertEqual(r.returncode, 0)


# ---------------------------------------------------------------------------
# ASK-006 — widget-derived tab indices (the range(6) era is over)
# ---------------------------------------------------------------------------

class TestTabSourcePins(unittest.TestCase):
    """The v2.5.0 bug: module constants described a 6-tab bar while
    _build_ui added 7; _update_pills then relabeled the wrong tabs.
    These pins make that class of bug impossible to reintroduce."""

    @classmethod
    def setUpClass(cls):
        with open(GUI_SRC, encoding="utf-8") as f:
            cls.src = f.read()

    def test_hardcoded_range_constants_gone(self):
        self.assertNotIn("TAB_OVERVIEW, TAB_AGENTS", self.src)
        # the CODE pattern is gone — no TAB_ tuple assignment fed by
        # range() (a comment may honestly mention the history)
        self.assertNotRegex(self.src, re.compile(
            r"TAB_[A-Z_,\s]+=\s*\\?\s*\n?\s*range\("))

    def test_every_tab_index_captured_from_addTab(self):
        for name in ("TAB_OVERVIEW", "TAB_AGENTS", "TAB_SESSIONS",
                     "TAB_APPROVALS", "TAB_PROCS", "TAB_SECURITY",
                     "TAB_LOG"):
            self.assertRegex(
                self.src, rf"self\.{name} = self\.tabs\.addTab\(")

    def test_seven_tabs_in_order(self):
        found = re.findall(r"self\.TAB_\w+ = self\.tabs\.addTab\(",
                           self.src)
        self.assertEqual(len(found), 7)
        labels = []
        for m in re.finditer(r"self\.TAB_\w+ = self\.tabs\.addTab\(",
                             self.src):
            tail = self.src[m.end():m.end() + 160]
            lm = re.search(r'"(\w+)"\)', tail)
            labels.append(lm.group(1) if lm else None)
        self.assertEqual(labels, ["Overview", "Agents", "Sessions",
                                  "Approvals", "Processes", "Security",
                                  "Log"])

    def test_no_bare_tab_constant_uses_remain(self):
        # every TAB_ reference must be an instance attr (self.TAB_*);
        # a bare module-style use is the regression signature
        bare = re.findall(
            r"(?<!self\.)\bTAB_(?:APPROVALS|PROCS|SESSIONS|OVERVIEW"
            r"|AGENTS|SECURITY|LOG)\b", self.src)
        self.assertEqual(bare, [])

    def test_jump_and_badge_sites_use_instance_attrs(self):
        self.assertIn("setCurrentIndex(self.TAB_APPROVALS)", self.src)
        self.assertIn("setCurrentIndex(self.TAB_PROCS)", self.src)
        self.assertRegex(self.src, r"setTabText\(\s*self\.TAB_APPROVALS,")
        self.assertRegex(self.src, r"setTabText\(\s*self\.TAB_PROCS,")


# ---------------------------------------------------------------------------
# ASK-007 — the Overview picker: the prompt follows the selected agent
# ---------------------------------------------------------------------------

class TestPickerPins(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(GUI_SRC, encoding="utf-8") as f:
            cls.src = f.read()

    def test_picker_combo_in_connection_card(self):
        self.assertIn("agent_picker", self.src)
        self.assertIn("Prompt agent", self.src)
        self.assertIn("_on_prompt_agent_changed", self.src)

    def test_prompt_uses_selected_agent(self):
        self.assertIn("_prompt_agent_idx", self.src)
        self.assertIn("agent_name=", self.src)      # build_prompt_text call
        self.assertNotIn("key=self.key", self.src)  # hardcoded default gone

    def test_combo_syncs_with_agents_list(self):
        self.assertIn("_sync_prompt_agents", self.src)


# ---------------------------------------------------------------------------
# Version truth 2.5.1
# ---------------------------------------------------------------------------

class TestVersionTruth251(unittest.TestCase):

    def test_constants_version(self):
        self.assertEqual(LLMAC_VERSION, "2.8.2")

    def test_cli_fallback_in_sync(self):
        with open(CLI, encoding="utf-8") as f:
            src = f.read()
        self.assertIn('VERSION = "2.8.2"', src)

    def test_info_reports_version(self):
        host = TestHost()
        self.addCleanup(host.stop)
        resp, status = host.get("/info")
        self.assertEqual(status, 200)
        self.assertEqual(resp["version"], "2.8.2")


if __name__ == "__main__":
    unittest.main()
