"""v2.6.0 — DURABLE EVIDENCE tests (tests-first: written red against
2.5.2, made green by the build).

Covers the release items:
  * ASK-014 transcript search/export — the Sessions tab gains a search
    box over the rendered thread (case-insensitive hit count, Enter
    next / Shift+Enter previous / Esc clear, re-applied across the 1 s
    re-render) + an Export… button writing the FULL thread to
    .md/.txt/.html with a metadata preamble — the durable evidence
    artifact a rule-6 capture cites. Pure logic lives in the NEW
    Qt-free core/transcript.py so the suite imports it directly on
    platforms without PyQt6.
  * ASK-015 ledger linter — rule 6 as code: `llmac.py ledger lint`
    flags any ask whose own text records a satisfied gate while its
    status is not shipped. The ACTUAL pre-flip ASK-002/006/007 texts
    are pinned fixtures so the ASK-012 stale-echo class stays detected
    forever; --state escalates across consecutive runs (the
    session-boundary class); rc contract 0 clean / 1 flags / 2 usage.
  * version truth 2.6.0 in BOTH copies + /info (the era pins in the
    older modules flip with the release as always).
"""
import http.client
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost

from core.constants import LLMAC_VERSION

CLI = os.path.join(_PARENT, "llmac.py")
GUI_SRC = os.path.join(_PARENT, "gui.py")
CHANGES_SRC = os.path.join(_PARENT, "CHANGES.md")
AGENT_SRC = os.path.join(_PARENT, "agent.md")

# The core.transcript module is NEW in 2.6.0 — importing it here is the
# red gate (ImportError until the build lands it).
from core.transcript import (
    count_hits, default_export_name, guess_format,
    transcript_html, transcript_markdown, transcript_plaintext,
)


def run_cli_locally(*args, timeout=90):
    """`ledger lint` is fully local — no server, no key needed."""
    return subprocess.run([sys.executable, CLI, *args],
                          capture_output=True, text=True, timeout=timeout)


# ---------------------------------------------------------------------------
# Fixtures — the real ASK-012 incident texts, verbatim-shaped

LEDGER_WITH_INCIDENTS = """# ASKS.md — user asks ledger (test fixture)

PROTOCOL: see the canonical file.

## OPEN / QUEUED / BUILDING

### ASK-011 — communicate in English only (standing preference)
- first heard: 2026-10-29
- quote (2026-10-29): "communicate in english only please"
- status: open (standing rule, effective immediately, no build
  needed) | task: 39

### ASK-002 — multi-session GUI
- first heard: pre-v2 history
- status: building (was v2.5.0 item 2 | task: 35/40)
- acceptance: two agents live concurrently, clean GUI switching,
  threads isolated.
- live note: v2.5.1 LIVE, deploy 12/12 == zip bytes; offscreen
  acceptance rendered two agents with the exact relabel trigger.
- the eyeball HAPPENED — the user pasted the GUI transcript they
  were reading during Task 39 — the gate was satisfied a full
  session before the flip.

### ASK-006 — GUI tab miswiring (bug fix)
- first heard: 2026-10-29
- status: building | task: 37/38/40
- fix: widget-derived tab indices, pinned by test.
- the user closed it explicitly: "these were already done, clearly
  something is wrong with how ask's states....."

### ASK-008 — live-session transcript readability (GUI)
- first heard: 2026-10-29
- status: building (v2.5.2 item 1) | task: 39/40/41
- live evidence (post-restart): live tree 13/13 == zip bytes; a
  fresh chat-sized thread note posted through the new render path.
- user quote: "looks good" — the post-restart eyeball of the
  rendered thread.

### ASK-014 — transcript search/export in the Sessions tab (GUI)
- first heard: 2026-10-29
- status: building (v2.6.0 item 1) | task: 43
- scope: search box over the open transcript + Export button
  writing the FULL thread.
- flip gate: user exercises search + performs one export in the
  post-restart GUI (rule 6 capture — closes on use, never re-asked).

### ASK-016 — agent screenshot capability (multi-monitor, per-screen)
- first heard: 2026-10-29
- status: queued (v2.7.0 candidate; plan pinned; enters building
  only on an explicit user go) | task: 43
- flip gate: set at build time (user exercises a real multi-monitor
  capture).

## SHIPPED / CLOSED

### ASK-013 — standing carry-over clicks closed by capture
- status: shipped 2026-10-29 (rule 6 capture, same ops run as the
  user's assertion) | task: 43
- quote: "These were confirmed at one point so mark it complete"

### ASK-000 — retro entry for the record
- status: shipped (Task 34)

## WITHDRAWN BY USER

- 2026-10-29: one parked version candidate was withdrawn and removed.
"""

CLEAN_LEDGER = """# ASKS.md — clean fixture

### ASK-011 — communicate in English only (standing preference)
- status: open (standing rule, no build needed)

### ASK-014 — transcript search/export in the Sessions tab (GUI)
- status: building (v2.6.0 item 1) | task: 43
- flip gate: user exercises search + performs one export in the
  post-restart GUI (rule 6 capture — closes on use, never re-asked).

### ASK-015 — ledger linter (rule 6 as code)
- status: building (v2.6.0 item 2) | task: 43
- flip gate: user runs or observes a lint pass live (rule 6
  capture — closes on use, never re-asked).

### ASK-016 — agent screenshot capability
- status: queued (v2.7.0 candidate; plan pinned)
- flip gate: set at build time.

### ASK-013 — carry-over clicks closed by capture
- status: shipped 2026-10-29 (rule 6 capture)

### ASK-004 — anti-context-loss method
- status: shipped 2026-10-29
"""


class TestTranscriptHelpers(unittest.TestCase):
    """core/transcript.py — the pure, Qt-free evidence helpers."""

    ITEMS = [
        {"ts": "2026-10-29T05:31:59+00:00", "kind": "note",
         "text": "Live check done — v2.5.2 is serving and byte-true."},
        {"ts": "2026-10-29T05:49:10+00:00", "kind": "message",
         "text": "looks good"},
        {"ts": "2026-10-29T06:04:19+00:00", "kind": "note",
         "text": "Handoff recovered, all green."},
    ]

    def test_count_hits_case_insensitive_and_multiple(self):
        text = "Live check done. Live tree 13/13. live verify."
        self.assertEqual(count_hits(text, "live"), 3)
        self.assertEqual(count_hits(text, "LIVE"), 3)

    def test_count_hits_escapes_regex_metacharacters(self):
        text = "a.b axb a.b"
        self.assertEqual(count_hits(text, "a.b"), 2)
        self.assertEqual(count_hits(text, "."), 2)

    def test_count_hits_empty_term_and_no_match(self):
        self.assertEqual(count_hits("anything", ""), 0)
        self.assertEqual(count_hits("anything", "zebra"), 0)

    def test_markdown_preamble_and_entries(self):
        out = transcript_markdown("default", self.ITEMS, "2026-10-29T07:00:00")
        self.assertIn("# LLMAC transcript — default", out)
        self.assertIn("- agent: default", out)
        self.assertIn("- exported: 2026-10-29T07:00:00", out)
        self.assertIn("- time range: 2026-10-29T05:31:59+00:00 "
                      ".. 2026-10-29T06:04:19+00:00", out)
        self.assertIn("- entries: 3", out)
        self.assertIn("**[05:31:59] default:**", out)
        self.assertIn("**[05:49:10] YOU:**", out)
        self.assertIn("Live check done — v2.5.2 is serving and byte-true.", out)
        # entries are separated so the artifact is readable
        self.assertRegex(out, r"byte-true\.\n\n\*\*\[05:49:10\]")

    def test_plaintext_lines(self):
        out = transcript_plaintext("default", self.ITEMS, "2026-10-29T07:00:00")
        self.assertIn("LLMAC transcript — default", out)
        self.assertIn("[05:49:10] YOU: looks good", out)
        self.assertIn("[06:04:19] default: Handoff recovered, all green.", out)

    def test_html_escapes_and_labels(self):
        out = transcript_html("default", self.ITEMS, "2026-10-29T07:00:00")
        self.assertIn("<!DOCTYPE html>", out)
        self.assertIn("LLMAC transcript — default</title>", out)
        self.assertIn("YOU", out)
        # html export escapes the raw text, never injects it
        bad = [{"ts": "2026-10-29T05:00:00+00:00", "kind": "message",
                "text": "<script>alert(1)</script>"}]
        bad_out = transcript_html("a", bad, "now")
        self.assertNotIn("<script>alert", bad_out)
        self.assertIn("&lt;script&gt;", bad_out)

    def test_default_export_name(self):
        name = default_export_name("Deus Ex Agent", None)
        self.assertRegex(name, r"^transcript-Deus-Ex-Agent-\d{8}-\d{6}\.md$")
        # traversal-ish agent names sanitize to a safe filename stem
        self.assertTrue(default_export_name("../etc", None)
                        .startswith("transcript-etc-"))

    def test_guess_format(self):
        self.assertEqual(guess_format("/tmp/a.md", ""), "md")
        self.assertEqual(guess_format("/tmp/a.txt", ""), "txt")
        self.assertEqual(guess_format("/tmp/a.html", ""), "html")
        self.assertEqual(guess_format("/tmp/a", "Plain text (*.txt)"), "txt")
        self.assertEqual(guess_format("/tmp/a", "HTML (*.html)"), "html")
        self.assertEqual(guess_format("/tmp/a", ""), "md")


class TestGuiSearchExportWiring(unittest.TestCase):
    """gui.py source pins — the Sessions tab grows the search/export
    row (the suite never imports PyQt6; source pins are the house
    style since v2.5.2)."""

    @classmethod
    def setUpClass(cls):
        cls.src = open(GUI_SRC, encoding="utf-8").read()

    def test_search_box_and_export_button_exist(self):
        self.assertIn("self.chat_search", self.src)
        self.assertIn("self.chat_export_btn", self.src)
        self.assertIn("Export…", self.src)

    def test_search_row_sits_between_transcript_and_input(self):
        i_view = self.src.index("right.addWidget(self.chat_view, 1)")
        i_search = self.src.index("self.chat_search = QLineEdit()")
        i_input = self.src.index("self.chat_input = QLineEdit()")
        self.assertLess(i_view, i_search)
        self.assertLess(i_search, i_input)

    def test_search_contract_wired(self):
        # hit count label, Enter next / Shift prev, Esc clear
        self.assertIn("self.chat_search_hits", self.src)
        self.assertIn("queryKeyboardModifiers", self.src)
        self.assertIn("Key_Escape", self.src)
        # the search re-applies after the 1 s re-render
        self.assertIn("_chat_apply_search", self.src)

    def test_gui_uses_core_transcript(self):
        self.assertRegex(self.src, r"from core\.transcript import")
        self.assertIn("count_hits(", self.src)

    def test_export_uses_dialog_and_writes_full_thread(self):
        self.assertIn("QFileDialog.getSaveFileName", self.src)
        self.assertIn("transcript_markdown(", self.src)
        self.assertIn("transcript_plaintext(", self.src)
        self.assertIn("transcript_html(", self.src)
        self.assertIn("default_export_name(", self.src)
        self.assertIn("guess_format(", self.src)

    def test_thread_items_cached_for_export(self):
        # the export writes the FULL thread, not the visible widget
        self.assertIn("self._chat_items", self.src)

    def test_render_untouched(self):
        # the v2.5.2 ASK-008 render blocks stay in gui.py
        self.assertIn("_split_thread_paragraphs(raw)", self.src)
        self.assertIn('self.chat_view.setHtml(render)', self.src)


class TestLedgerLint(unittest.TestCase):
    """ASK-015 — rule 6 as code. The linter is fully local."""

    def _write(self, text):
        f = tempfile.NamedTemporaryFile(
            "w", suffix=".md", delete=False, encoding="utf-8")
        f.write(text)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_incident_texts_flag(self):
        """The exact ASK-012 class: the three real pre-flip texts
        (satisfied gate on record, status still building) MUST flag."""
        path = self._write(LEDGER_WITH_INCIDENTS)
        r = run_cli_locally("ledger", "lint", "--path", path)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("ASK-002", r.stdout)
        self.assertIn("ASK-006", r.stdout)
        self.assertIn("ASK-008", r.stdout)
        self.assertIn("STALE-FLIP", r.stdout)
        self.assertIn("rule 6", r.stdout)

    def test_incident_evidence_is_quoted_in_the_flag(self):
        path = self._write(LEDGER_WITH_INCIDENTS)
        r = run_cli_locally("ledger", "lint", "--path", path)
        self.assertIn("gate was satisfied", r.stdout)
        self.assertIn("already done", r.stdout)

    def test_shipped_open_queued_and_exempts_do_not_flag(self):
        """The current ledger shape lints clean: standing open,
        building with gate DESCRIPTIONS, queued, shipped with
        satisfied-gate prose, withdrawn."""
        path = self._write(CLEAN_LEDGER)
        r = run_cli_locally("ledger", "lint", "--path", path)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("clean", r.stdout.lower())

    def test_flip_gate_description_lines_never_flag(self):
        """A gate DESCRIPTION naming the acceptance words is a gate,
        not evidence — the linter skips `- flip gate:` lines."""
        ledger = """### ASK-099 — hypothetical
- status: building
- flip gate: closes when the user says "looks good" in the GUI.
- scope: something reasonable.
"""
        path = self._write(ledger)
        r = run_cli_locally("ledger", "lint", "--path", path)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_tier1_explicit_gate_evidence_flags(self):
        ledger = """### ASK-098 — hypothetical
- status: building
- flip gate: the user's acceptance.
- gate-evidence: user read the thread 2026-10-29 (on file).
"""
        path = self._write(ledger)
        r = run_cli_locally("ledger", "lint", "--path", path)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("ASK-098", r.stdout)
        self.assertIn("gate-evidence", r.stdout)

    def test_withdrawn_and_deferred_never_flag(self):
        ledger = """### ASK-097 — withdrawn
- status: withdrawn-by-user
- note: the user said these were already done and pulled the item.

### ASK-096 — deferred
- status: deferred-by-user
- note: user said it already looks good but postponed it.

### ASK-095 — wontfix
- status: wontfix
- note: user said it was already done, wontfix.
"""
        path = self._write(ledger)
        r = run_cli_locally("ledger", "lint", "--path", path)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_state_escalates_across_runs(self):
        """The session-boundary class: the same flag surviving to the
        next lint run escalates — 'N consecutive lint runs'."""
        path = self._write(LEDGER_WITH_INCIDENTS)
        state = path + ".lint-state.json"
        self.addCleanup(lambda: os.path.exists(state) and os.unlink(state))
        r1 = run_cli_locally("ledger", "lint", "--path", path,
                             "--state", state)
        self.assertEqual(r1.returncode, 1)
        self.assertIn("consecutive", r1.stdout)
        r2 = run_cli_locally("ledger", "lint", "--path", path,
                             "--state", state)
        self.assertEqual(r2.returncode, 1)
        self.assertIn("2 consecutive", r2.stdout)
        st = json.load(open(state))
        self.assertIn("ASK-002", st)

    def test_state_drops_entries_that_clean_up(self):
        path = self._write(LEDGER_WITH_INCIDENTS)
        state = path + ".lint-state.json"
        self.addCleanup(lambda: os.path.exists(state) and os.unlink(state))
        run_cli_locally("ledger", "lint", "--path", path, "--state", state)
        # clean the ledger; the state must not carry stale baggage
        path2 = self._write(CLEAN_LEDGER)
        r = run_cli_locally("ledger", "lint", "--path", path2,
                            "--state", state)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        st = json.load(open(state))
        self.assertEqual(st, {})

    def test_json_output_contract(self):
        path = self._write(LEDGER_WITH_INCIDENTS)
        r = run_cli_locally("ledger", "lint", "--path", path, "--json")
        self.assertEqual(r.returncode, 1)
        data = json.loads(r.stdout)
        self.assertIn("flags", data)
        ids = [f["id"] for f in data["flags"]]
        self.assertIn("ASK-002", ids)
        self.assertIn("ASK-006", ids)

    def test_missing_path_refuses_loudly(self):
        r = run_cli_locally("ledger", "lint", "--path",
                            "/nonexistent/asks.md")
        self.assertEqual(r.returncode, 2)
        self.assertIn("/nonexistent/asks.md", r.stderr)
        r = run_cli_locally("ledger", "lint")
        self.assertEqual(r.returncode, 2)
        self.assertIn("--path", r.stderr)

    def test_help_documents_the_linter(self):
        r = run_cli_locally("--help")
        self.assertIn("ledger lint", r.stdout)
        self.assertIn("rule 6", r.stdout)


class TestVersionTruth260(unittest.TestCase):
    """2.6.0 everywhere it must be; era pins flip as always."""

    def test_constants_version(self):
        self.assertEqual(LLMAC_VERSION, "2.8.1")

    def test_both_copies_pin(self):
        c = open(os.path.join(_PARENT, "core", "constants.py"),
                 encoding="utf-8").read()
        self.assertIn('LLMAC_VERSION = "2.8.1"', c)
        cli = open(CLI, encoding="utf-8").read()
        self.assertIn('VERSION = "2.8.1"', cli)

    def test_live_info_reports_260(self):
        host = TestHost()
        self.addCleanup(host.server.shutdown)
        conn = http.client.HTTPConnection("127.0.0.1", host.port,
                                          timeout=30)
        conn.request("GET", "/info",
                     headers={"Authorization": f"Bearer {host.key}"})
        resp = conn.getresponse()
        data = json.loads(resp.read())
        self.assertEqual(resp.status, 200)
        self.assertEqual(data["version"], "2.8.1")

    def test_changes_has_entry(self):
        src = open(CHANGES_SRC, encoding="utf-8").read()
        self.assertIn("## v2.6.0", src)

    def test_agent_md_tip_19_lint_convention(self):
        src = open(AGENT_SRC, encoding="utf-8").read()
        self.assertIn("19.", src)
        # the phrase may wrap across lines in the markdown
        self.assertRegex(src, r"ledger\s+lint")


if __name__ == "__main__":
    unittest.main()
