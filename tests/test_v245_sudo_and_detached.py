"""v2.4.5 — sudo package installs (forced approval + 2-min countdown)
and restart-surviving detached procs.

User spec (session 16): agents may install DISTRIBUTION packages via
sudo. Such commands ALWAYS raise a host approval — regardless of the
approval policy (auto_all included; there is no silent path). The
approval carries a 2-minute countdown; on expiry it auto-approves or
auto-rejects per a NEW security-panel setting (default reject).
Everything else under sudo stays blocked. Detached procs: a GUI
restart must not kill a long analysis run.
"""
import json
import os
import sys
import tempfile
import threading
import time
import unittest

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost
from core.approvals import ApprovalRegistry
from core.policy import InstallPolicy
from core.procs import ProcessManager, _pid_alive

# A manager that does not exist in the test container: the approval
# path is what's under test, and `sudo apk add x` failing with a
# non-zero rc PROVES the command actually ran after approval.
_SUDO_CMD = "sudo apk add llmac-should-not-exist"


# ---------------------------------------------------------------------------
# 1. Policy: the sudo verdict matrix (pure)
# ---------------------------------------------------------------------------

class TestPolicySudoMatrix(unittest.TestCase):

    def setUp(self):
        self.p = InstallPolicy()

    def _marker(self, cmd):
        v = self.p.pre_exec(cmd, "/tmp")
        return (v is not None and v.get("needs_sudo_approval") is True
                and v.get("rule") == "sudo_package_install")

    def _rejected(self, cmd, rule):
        v = self.p.pre_exec(cmd, "/tmp")
        return (v is not None and v.get("rule") == rule
                and not v.get("needs_sudo_approval"))

    def test_distro_install_forms_are_markers(self):
        for cmd in (
                "sudo pacman -S ghidra",
                "sudo pacman -Sy redis",
                "sudo pacman -Syu",
                "sudo pacman --sync gcc",
                "sudo apt install build-essential",
                "sudo apt-get install -y cmake",
                "sudo apt -y install gdb",
                "sudo dnf install radare2",
                "sudo yum install nmap",
                "sudo zypper install hexyl",
                "sudo apk add strace"):
            self.assertTrue(self._marker(cmd), cmd)

    def test_non_install_sudo_rejected(self):
        # v2.4.6: removal forms graduated to their own approval marker
        # (see test_v246) — they are no longer in this rejected list.
        for cmd in ("sudo rm -rf /",
                    "sudo pip install requests",    # not a distro manager
                    "sudo tee /etc/passwd",
                    "sudo pacman -Q htop",          # query, not a change
                    "sudo",
                    "sudo bash"):
            self.assertTrue(self._rejected(cmd, "sudo_not_package_install"),
                            cmd)

    def test_chains_and_redirects_never_reach_the_sudo_path(self):
        for cmd in ("sudo pacman -S x && rm -rf /",
                    "sudo pacman -S x; id",
                    "sudo pacman -S x > /etc/passwd",
                    "echo hi && sudo pacman -S x",
                    "sudo pacman -S x | sh"):
            v = self.p.pre_exec(cmd, "/tmp")
            self.assertTrue(v is not None, cmd)
            self.assertFalse(v.get("needs_sudo_approval"), cmd)
            self.assertNotEqual(v["rule"], "sudo_package_install", cmd)

    def test_bare_managers_still_rejected_as_before(self):
        v = self.p.pre_exec("pacman -S ghidra", "/tmp")
        self.assertEqual(v["rule"], "system_package_manager")
        v = self.p.pre_exec("apt install gdb", "/tmp")
        self.assertEqual(v["rule"], "system_package_manager")

    def test_sudo_as_argument_not_invocation(self):
        self.assertIsNone(self.p.pre_exec("echo sudo is a word", "/tmp"))
        self.assertIsNone(self.p.pre_exec("cat sudo-notes.txt", "/tmp"))


# ---------------------------------------------------------------------------
# 2. Approval registry: countdown + auto-resolve (pure)
# ---------------------------------------------------------------------------

class TestApprovalCountdown(unittest.TestCase):

    def test_timeout_auto_reject(self):
        r = ApprovalRegistry()
        aid = r.create("a", "sudo_install", "sudo pacman -S x",
                       expires_in=0.5, timeout_action="reject")
        t0 = time.time()
        status = r.wait(aid, 30)
        self.assertEqual(status, "denied")
        self.assertLess(time.time() - t0, 5)
        d = r.recent_decided(5)[0]
        self.assertEqual(d["decided_by"], "timeout")
        self.assertEqual(d["status"], "denied")

    def test_timeout_auto_approve(self):
        r = ApprovalRegistry()
        aid = r.create("a", "sudo_install", "sudo apt install x",
                       expires_in=0.5, timeout_action="approve")
        self.assertEqual(r.wait(aid, 30), "approved")
        d = r.recent_decided(5)[0]
        self.assertEqual(d["decided_by"], "timeout")
        self.assertEqual(d["status"], "approved")

    def test_human_decision_beats_the_clock(self):
        r = ApprovalRegistry()

        def approver():
            time.sleep(0.3)
            pend = r.pending()
            r.decide(pend[0]["id"], True, "test-human")

        aid = r.create("a", "sudo_install", "cmd",
                       expires_in=5.0, timeout_action="reject")
        th = threading.Thread(target=approver)
        th.start()
        self.assertEqual(r.wait(aid, 30), "approved")
        th.join()
        self.assertEqual(r.recent_decided(5)[0]["decided_by"], "test-human")

    def test_sweep_resolves_when_waiter_vanished(self):
        r = ApprovalRegistry()
        r.create("a", "sudo_install", "cmd",
                 expires_in=0.2, timeout_action="reject")
        time.sleep(0.5)               # nobody waits on it
        n = r.sweep_expired()
        self.assertEqual(n, 1)
        self.assertEqual(r.pending(), [])
        self.assertEqual(r.recent_decided(5)[0]["decided_by"], "timeout")

    def test_to_dict_carries_countdown(self):
        r = ApprovalRegistry()
        r.create("a", "sudo_install", "cmd", expires_in=10,
                 timeout_action="approve")
        a = r.pending()[0]
        self.assertIsNotNone(a["expires_in"])
        self.assertLessEqual(a["expires_in"], 10)
        self.assertEqual(a["timeout_action"], "approve")


# ---------------------------------------------------------------------------
# 3. API end-to-end: forced gate under auto, timeout actions, human paths
# ---------------------------------------------------------------------------

class TestSudoApprovalE2E(unittest.TestCase):

    def _host(self, **settings):
        base = {"sudo_timeout_s": 5}
        base.update(settings)
        return TestHost(settings=base)

    def test_auto_policy_still_prompts_and_timeout_rejects(self):
        """THE user spec: even under 'auto' the sudo install prompts; an
        undecided 2-min countdown fails closed (shortened to 5s here)."""
        host = self._host(approval_policy="auto")
        try:
            t0 = time.time()
            resp, status = host.req("POST", "/exec",
                                    {"command": _SUDO_CMD, "timeout": 20})
            self.assertEqual(status, 403)
            self.assertEqual(resp["error"], "approval_denied")
            self.assertGreaterEqual(time.time() - t0, 4)
            d = host.ctx.approvals.recent_decided(5)[0]
            self.assertEqual(d["op"], "sudo_install")
            self.assertEqual(d["decided_by"], "timeout")
            self.assertEqual(d["status"], "denied")
        finally:
            host.stop()

    def test_auto_all_policy_still_prompts(self):
        """No silent path: 'auto_all' (agents expand sandbox themselves)
        still gates sudo installs."""
        host = self._host(approval_policy="auto_all",
                          sudo_timeout_action="reject")
        try:
            th = threading.Thread(
                target=lambda: self._deny_when_pending(host))
            th.start()
            resp, status = host.req("POST", "/exec",
                                    {"command": _SUDO_CMD, "timeout": 30})
            th.join()
            self.assertEqual(status, 403)
            self.assertEqual(resp["error"], "approval_denied")
        finally:
            host.stop()

    def test_timeout_approve_runs_the_command(self):
        host = self._host(approval_policy="auto",
                          sudo_timeout_action="approve")
        try:
            resp, status = host.req("POST", "/exec",
                                    {"command": _SUDO_CMD, "timeout": 20})
            self.assertEqual(status, 200)
            self.assertNotIn("rejected", resp)
            # The command RAN: sudo/apk are missing or need a password in
            # the test container, so rc != 0 — what matters is that the
            # approval path let it execute at all.
            self.assertIsInstance(resp["returncode"], int)
            self.assertNotEqual(resp["returncode"], -1)
            d = host.ctx.approvals.recent_decided(5)[0]
            self.assertEqual(d["status"], "approved")
            self.assertEqual(d["decided_by"], "timeout")
        finally:
            host.stop()

    def test_human_approve_end_to_end(self):
        host = self._host(approval_policy="auto")
        try:
            result = {}

            def do_exec():
                result["r"] = host.req("POST", "/exec",
                                       {"command": _SUDO_CMD,
                                        "timeout": 30})

            th = threading.Thread(target=do_exec)
            th.start()
            deadline = time.time() + 10
            aid = None
            while time.time() < deadline:
                pend = host.ctx.approvals.pending()
                if pend:
                    aid = pend[0]["id"]
                    self.assertEqual(pend[0]["op"], "sudo_install")
                    break
                time.sleep(0.05)
            self.assertIsNotNone(aid, "approval never became pending")
            host.ctx.approvals.decide(aid, True, "test-human")
            th.join(timeout=15)
            resp, status = result["r"]
            self.assertEqual(status, 200)
            self.assertNotIn("rejected", resp)
            self.assertIsInstance(resp["returncode"], int)
            self.assertEqual(
                host.ctx.approvals.recent_decided(5)[0]["decided_by"],
                "test-human")
        finally:
            host.stop()

    @staticmethod
    def _deny_when_pending(host):
        deadline = time.time() + 10
        while time.time() < deadline:
            pend = host.ctx.approvals.pending()
            if pend:
                host.ctx.approvals.decide(pend[0]["id"], False, "test-human")
                return
            time.sleep(0.05)

    def test_proc_start_cannot_bypass(self):
        """Background procs take no approvals, so sudo there is refused
        outright — no silent bypass around the countdown."""
        host = self._host(approval_policy="auto")
        try:
            resp, status = host.req("POST", "/proc/start",
                                    {"command": _SUDO_CMD})
            self.assertEqual(status, 200)
            self.assertEqual(resp["error"], "command_rejected")
            self.assertEqual(resp["rule"], "sudo_package_install")
        finally:
            host.stop()

    def test_batch_sudo_denied_is_a_per_op_result(self):
        host = self._host(approval_policy="auto")
        try:
            th = threading.Thread(
                target=lambda: self._deny_when_pending(host))
            th.start()
            resp, status = host.req("POST", "/batch", {
                "ops": [{"op": "exec", "command": _SUDO_CMD,
                         "timeout": 30}]})
            th.join()
            self.assertEqual(status, 200)      # batch itself is fine
            r0 = resp["results"][0]
            self.assertEqual(r0.get("error"), "approval_denied")
        finally:
            host.stop()

    def test_sudo_timeout_setting_clamped(self):
        from core.api import _sudo_timeout_s, _sudo_timeout_action
        host = self._host(sudo_timeout_s=0)     # absurd -> clamped to floor
        try:
            self.assertGreaterEqual(_sudo_timeout_s(host.ctx), 5)
            self.assertEqual(_sudo_timeout_action(host.ctx), "reject")
        finally:
            host.stop()


# ---------------------------------------------------------------------------
# 4. Detached procs: persistence, re-attach, no-kill shutdown
# ---------------------------------------------------------------------------

class TestDetachedProcs(unittest.TestCase):

    def setUp(self):
        self.data = tempfile.mkdtemp(prefix="v245-procs-")
        self.shell = "/bin/sh"

    def _mgr(self):
        return ProcessManager(self.shell, data_dir=self.data)

    def test_meta_and_logs_persisted_to_disk(self):
        m = self._mgr()
        r = m.start("echo hello-durable; sleep 30", self.data,
                    name="analysis")
        self.assertNotIn("error", r)
        pid = r["proc"]["id"]
        deadline = time.time() + 5
        while time.time() < deadline:
            logs = m.logs(pid)
            if logs.get("stdout"):
                break
            time.sleep(0.1)
        self.assertIn("hello-durable", logs["stdout"])
        meta_p = os.path.join(self.data, "procs", pid, "meta.json")
        self.assertTrue(os.path.isfile(meta_p))
        with open(meta_p) as fh:
            meta = json.load(fh)
        self.assertEqual(meta["command"], "echo hello-durable; sleep 30")
        self.assertTrue(_pid_alive(meta["os_pid"]))
        m.stop(pid, force=True)

    def test_shutdown_leaves_procs_running_and_reattach(self):
        m1 = self._mgr()
        r = m1.start("echo before-restart; sleep 60", self.data,
                     name="ghidra-run")
        pid = r["proc"]["id"]
        os_pid = r["proc"]["os_pid"]
        # server shutdown: v2.4.5 semantics — NOT killed
        alive_after_stop_all = m1.stop_all()
        self.assertEqual(alive_after_stop_all, 1)
        self.assertTrue(_pid_alive(os_pid))
        # "restart": a brand-new manager over the same data dir
        m2 = self._mgr()
        procs = m2.list()
        self.assertEqual(len(procs), 1)
        p = procs[0]
        self.assertEqual(p["id"], pid)
        self.assertTrue(p["running"])
        self.assertTrue(p["reattached"])
        self.assertEqual(p["os_pid"], os_pid)
        # logs survived the restart
        deadline = time.time() + 5
        while time.time() < deadline:
            logs = m2.logs(pid)
            if logs.get("stdout"):
                break
            time.sleep(0.1)
        self.assertIn("before-restart", logs["stdout"])
        # stop works on the re-attached proc (killpg on the session leader)
        m2.stop(pid, force=True)
        deadline = time.time() + 5
        while time.time() < deadline and _pid_alive(os_pid):
            time.sleep(0.1)
        self.assertFalse(_pid_alive(os_pid))

    def test_finished_proc_reloaded_readable(self):
        m1 = self._mgr()
        r = m1.start("echo quick-exit", self.data)
        pid = r["proc"]["id"]
        deadline = time.time() + 8
        while time.time() < deadline:
            if not m1.get(pid).running:
                break
            time.sleep(0.1)
        self.assertFalse(m1.get(pid).running)
        m2 = self._mgr()
        procs = m2.list()
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0]["returncode"], 0)
        logs = m2.logs(pid)
        self.assertIn("quick-exit", logs["stdout"])

    def test_old_finished_procs_pruned(self):
        m = self._mgr()
        pid = "proc_dead0000"
        d = os.path.join(self.data, "procs", pid)
        os.makedirs(d)
        with open(os.path.join(d, "meta.json"), "w") as fh:
            json.dump({"id": pid, "name": "old", "command": "x",
                       "cwd": self.data, "started_at": time.time() - 90000,
                       "os_pid": 12345, "returncode": 0}, fh)
        m2 = self._mgr()
        self.assertEqual(m2.list(), [])
        self.assertFalse(os.path.isdir(d))

    def test_e2e_proc_survives_host_object_rebuild(self):
        """Full stack: proc started via HTTP on host A, 'restarted' as
        host B sharing the same data dir — the proc is still there."""
        host_a = TestHost()
        try:
            resp, status = host_a.req("POST", "/proc/start",
                                      {"command": "echo e2e; sleep 60",
                                       "name": "keeper"})
            self.assertEqual(status, 200)
            pid = resp["proc"]["id"]
            meta_p = os.path.join(host_a.data_dir, "procs", pid,
                                  "meta.json")
            self.assertTrue(os.path.isfile(meta_p))
            # simulate the restart: brand-new context on the same data
            from core.server import build_context
            from core.state import StateStore
            store_b = StateStore(host_a.data_dir)
            ctx_b = build_context(store_b, host_a.roots, host_a.agents,
                                  host_a.settings, host_a.history)
            procs = ctx_b.procs.list()
            self.assertEqual(len(procs), 1)
            self.assertTrue(procs[0]["running"])
            self.assertTrue(procs[0]["reattached"])
            ctx_b.procs.stop(pid, force=True)
        finally:
            host_a.stop()


# ---------------------------------------------------------------------------
# 5. Version pin
# ---------------------------------------------------------------------------

class TestVersion(unittest.TestCase):

    def test_info_reports_245(self):
        host = TestHost()
        try:
            resp, status = host.req("GET", "/info")
            self.assertEqual(status, 200)
            self.assertEqual(resp["version"], "2.8.2")
        finally:
            host.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
