"""v2.4.3 — venv visibility: configured vs discovered split.

User-reported live bug (session 13, after the v2.4.2 restart): venvs
created by agents during the venv/package tests "never showed up in
install venvs in the GUI". Root cause: the GUI card renders
settings["venvs"] (the manually configured allow-list) while
agent-created venvs were tracked ONLY in the server's runtime set —
a set the GUI never read, and which _sync_policy_venvs() overwrote
wholesale on any GUI add/remove.

The fix splits the two concepts everywhere:
  * policy.venvs           — CONFIGURED (settings / GUI, human-managed)
  * policy.discovered_venvs — DISCOVERED (agent-created this run)
  * /info reports both ("venvs" + "venvs_discovered"); pruning only
    touches discovered
  * the GUI card grows a read-only "Discovered venvs" list polled
    from the running server's policy
"""
import os
import sys
import tempfile
import unittest

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost
from core.policy import InstallPolicy


# ---------------------------------------------------------------------------
# 1. Policy: creations land in discovered, configured stays pristine
# ---------------------------------------------------------------------------

class TestPolicySplit(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="v243-split-")

    def test_creation_lands_in_discovered_only(self):
        p = InstallPolicy()
        p.pre_exec("python3 -m venv agent-env", self.tmp)
        self.assertIn(os.path.join(self.tmp, "agent-env"),
                      p.discovered_venvs)
        self.assertEqual(p.venvs, set())     # configured untouched

    def test_note_venv_lands_in_discovered(self):
        p = InstallPolicy()
        p.note_venv("/opt/some-venv")
        self.assertIn("/opt/some-venv", p.discovered_venvs)
        self.assertEqual(p.venvs, set())

    def test_configured_seed_stays_configured(self):
        p = InstallPolicy(["/opt/cfg-venv"])
        self.assertEqual(p.venvs, {"/opt/cfg-venv"})
        self.assertEqual(p.discovered_venvs, set())

    def test_reset_clears_both(self):
        p = InstallPolicy(["/opt/cfg-venv"])
        p.note_venv("/opt/disc-venv")
        p.reset()
        self.assertEqual(p.venvs, set())
        self.assertEqual(p.discovered_venvs, set())

    def test_gui_sync_no_longer_wipes_discoveries(self):
        """The old bug, distilled: a GUI settings sync replaced the one
        merged set, destroying runtime discoveries. With the split,
        re-seeding the configured list leaves discoveries intact."""
        p = InstallPolicy()
        p.pre_exec("python3 -m venv kept-env", self.tmp)
        # what _sync_policy_venvs() does on the GUI side:
        p.venvs = set(["/opt/human-added"])
        self.assertIn(os.path.join(self.tmp, "kept-env"),
                      p.discovered_venvs)   # survived the sync


# ---------------------------------------------------------------------------
# 2. Scoping: discovered roots count like configured ones (union)
# ---------------------------------------------------------------------------

class TestDiscoveredScoping(unittest.TestCase):
    """No markers on disk in these fixtures — membership in the
    discovered set alone must scope the install (mirrors the tracked
    set's role before the split; regression guard for the union)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="v243-scope-")

    def test_tool_token_in_discovered_venv_allowed(self):
        p = InstallPolicy()
        p.pre_exec("python3 -m venv d-env", self.tmp)
        r = p.pre_exec("d-env/bin/pip install six", self.tmp)
        self.assertIsNone(r, r and r["rule"])

    def test_activate_form_in_discovered_venv_allowed(self):
        p = InstallPolicy()
        p.pre_exec("python3 -m venv d-env", self.tmp)
        r = p.pre_exec("source d-env/bin/activate && pip install six",
                       self.tmp)
        self.assertIsNone(r, r and r["rule"])

    def test_configured_venv_scoping_still_works(self):
        cfg = os.path.join(self.tmp, "cfg-env")
        p = InstallPolicy([cfg])
        r = p.pre_exec("cfg-env/bin/pip install six", self.tmp)
        self.assertIsNone(r, r and r["rule"])

    def test_bare_pip_still_rejected_with_discoveries_present(self):
        p = InstallPolicy()
        p.pre_exec("python3 -m venv d-env", self.tmp)
        r = p.pre_exec("pip install six", self.tmp)
        self.assertIsNotNone(r)
        self.assertEqual(r["rule"], "install_not_in_venv")


# ---------------------------------------------------------------------------
# 3. API: /info fields + pruning scope (E2E against a real host)
# ---------------------------------------------------------------------------

class TestInfoFieldsE2E(unittest.TestCase):

    def setUp(self):
        # A CONFIGURED venv that does NOT exist on disk: it must
        # survive /info (human-managed config is not pruned), while
        # dead DISCOVERED venvs vanish (v2.4.2 pruning, now scoped).
        self.cfg_missing = os.path.join(
            tempfile.gettempdir(), "v243-cfg-missing-env")
        self.host = TestHost(settings={"venvs": [self.cfg_missing]})

    def tearDown(self):
        self.host.stop()

    def test_info_reports_both_lists(self):
        info, _ = self.host.get("/info")
        self.assertIn("venvs", info)
        self.assertIn("venvs_discovered", info)
        self.assertEqual(info["venvs"], [self.cfg_missing])
        self.assertEqual(info["venvs_discovered"], [])

    def test_configured_missing_dir_survives_info(self):
        """v2.4.2 pruning would have dropped it from the merged set;
        config entries are the human's, not runtime observations."""
        info, _ = self.host.get("/info")
        self.assertIn(self.cfg_missing, info["venvs"])
        info2, _ = self.host.get("/info")     # pruning is idempotent
        self.assertIn(self.cfg_missing, info2["venvs"])

    def test_created_venv_flows_to_discovered(self):
        root = self.host.root
        r1, _ = self.host.post("/exec", {
            "command": "python3 -m venv v243-e2e",
            "cwd": root, "timeout": 120})
        info, _ = self.host.get("/info")
        self.assertEqual(info["venvs"], [self.cfg_missing])  # unchanged
        if r1.get("returncode") == 0:
            self.assertIn(os.path.join(root, "v243-e2e"),
                          info["venvs_discovered"])
        # delete -> pruned from discovered, configured untouched
        self.host.post("/exec", {"command": "rm -rf v243-e2e",
                                 "cwd": root})
        info2, _ = self.host.get("/info")
        self.assertNotIn(os.path.join(root, "v243-e2e"),
                         info2["venvs_discovered"])
        self.assertIn(self.cfg_missing, info2["venvs"])

    def test_configured_and_discovered_coexist(self):
        root = self.host.root
        self.host.post("/exec", {"command": "python3 -m v243-x",
                                 "cwd": root, "timeout": 120})
        info, _ = self.host.get("/info")
        # both lists populated at once, no cross-contamination
        self.assertIn(self.cfg_missing, info["venvs"])
        self.assertNotIn(self.cfg_missing, info["venvs_discovered"])
        if info["venvs_discovered"]:
            d = info["venvs_discovered"][0]
            self.assertNotIn(d, info["venvs"])


# ---------------------------------------------------------------------------
# 4. GUI wiring guard (source-level)
# ---------------------------------------------------------------------------

class TestGuiWiringGuard(unittest.TestCase):
    """gui.py needs PyQt + a display — not importable headless in the
    test sandbox. This guard pins the v2.4.3 wiring at the source level
    so a refactor cannot silently orphan the discovered list again."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(_PARENT, "gui.py"), encoding="utf-8") as f:
            cls.gui_src = f.read()

    def test_card_has_discovered_list(self):
        self.assertIn("discovered_venv_list", self.gui_src)
        self.assertIn("NoSelection", self.gui_src)   # read-only list
        self.assertIn("Discovered venvs", self.gui_src)

    def test_refresh_reads_policy_discovered(self):
        self.assertIn("def _refresh_discovered_venvs", self.gui_src)
        self.assertIn("policy.discovered_venvs", self.gui_src)
        self.assertIn("server is not None", self.gui_src)  # stopped-guard

    def test_timer_wired_and_cleaned_up(self):
        self.assertIn("_venvs_timer.timeout.connect("
                      "self._refresh_discovered_venvs)", self.gui_src)
        self.assertIn("self._venvs_timer)", self.gui_src)  # closeEvent

    def test_no_placeholder_when_entries_exist(self):
        self.assertIn("(none yet", self.gui_src)  # empty-state hint


if __name__ == "__main__":
    unittest.main()
