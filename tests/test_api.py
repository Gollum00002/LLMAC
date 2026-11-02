"""End-to-end API integration tests against a live headless server."""
import json
import os
import subprocess
import sys
import threading
import time
import unittest

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost, make_tree
from core.state import make_default_agent, normalize_agent

CLI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "cli.py")


class TestAuth(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_bad_key_401(self):
        resp, status = self.host.post("/list", {}, key="llmac_wrong")
        self.assertEqual(status, 401)
        self.assertEqual(resp["error"], "unauthorized")

    def test_health_no_auth(self):
        resp, status = self.host.get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(resp["server"], "llmac")

    def test_rate_limited(self):
        for i in range(5):
            self.host.post("/list", {}, key="llmac_wrong")
        resp, status = self.host.post("/list", {}, key="llmac_wrong")
        self.assertEqual(status, 429)

    def test_info_shows_agent(self):
        make_tree(self.host.root, {"a.txt": "x"})
        resp, status = self.host.get("/info")
        self.assertEqual(status, 200)
        self.assertEqual(resp["agent"]["name"], "default")
        self.assertEqual(resp["roots"], [self.host.root])

    def test_agent_scope_restriction(self):
        root2 = self.host._mkroot("root2")
        self.host.roots.append(root2)
        self.host.ctx.sandbox  # unchanged
        from core.sandbox import Sandbox
        self.host.ctx.sandbox = Sandbox = Sandbox([self.host.root, root2])
        scoped = normalize_agent({
            "name": "scoped", "key": "llmac_scoped_key_abcdef",
            "roots": [root2],
            "perms": {"read": True, "write": False, "delete": False,
                       "exec": False, "proc": False},
        })
        self.host.agents.append(scoped)
        self.host.ctx.auth.update(self.host.agents)
        # In-scope path works:
        make_tree(root2, {"ok.txt": "hi"})
        resp, status = self.host.post("/read", {"path": f"{root2}/ok.txt"},
                                      key=scoped["key"])
        self.assertEqual(status, 200)
        # Out-of-scope path is forbidden even though globally shared:
        make_tree(self.host.root, {"secret.txt": "s"})
        resp, status = self.host.post("/read",
                                      {"path": f"{self.host.root}/secret.txt"},
                                      key=scoped["key"])
        self.assertEqual(status, 403)
        # Write permission denied:
        resp, status = self.host.post("/write",
                                      {"path": f"{root2}/new.txt",
                                       "content": "x"},
                                      key=scoped["key"])
        self.assertEqual(status, 403)
        self.assertEqual(resp["error"], "permission_denied")


class TestFileOps(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        make_tree(self.host.root, {
            "hello.py": "print('hello')\n",
            "data.bin": bytes([0, 1, 2, 255]).decode("latin-1"),
            "sub/nested.txt": "nested\n",
        })
        # write binary properly
        with open(os.path.join(self.host.root, "data.bin"), "wb") as f:
            f.write(bytes([0, 1, 2, 255]))

    def tearDown(self):
        self.host.stop()

    def test_write_read_roundtrip(self):
        p = os.path.join(self.host.root, "w1.txt")
        resp, status = self.host.post("/write", {"path": p, "content": "abc"})
        self.assertEqual(status, 200)
        self.assertEqual(resp["bytes"], 3)
        resp, status = self.host.post("/read", {"path": p})
        self.assertEqual(resp["content"], "abc")

    def test_binary_read(self):
        resp, status = self.host.post(
            "/read", {"path": os.path.join(self.host.root, "data.bin")})
        self.assertTrue(resp["binary"])
        import base64
        self.assertEqual(base64.b64decode(resp["content_b64"]),
                         bytes([0, 1, 2, 255]))

    def test_read_line_range(self):
        p = os.path.join(self.host.root, "lines.txt")
        with open(p, "w") as f:
            f.write("l1\nl2\nl3\nl4\nl5\n")
        resp, status = self.host.post("/read", {"path": p, "from_line": 2,
                                                 "to_line": 4})
        self.assertEqual(resp["content"], "l2\nl3\nl4")
        self.assertEqual(resp["total_lines"], 5)

    def test_read_offset_limit(self):
        p = os.path.join(self.host.root, "bytes.txt")
        with open(p, "wb") as f:
            f.write(b"0123456789")
        resp, status = self.host.post("/read", {"path": p, "offset": 4,
                                                 "limit": 3})
        self.assertEqual(resp["content"], "456")
        self.assertTrue(resp["truncated"])
        self.assertEqual(resp["next_offset"], 7)

    def test_version_conflict(self):
        p = os.path.join(self.host.root, "v.txt")
        resp, _ = self.host.post("/write", {"path": p, "content": "v1"})
        v1 = resp["version"]
        # Concurrent human edit changes the file:
        with open(p, "a") as f:
            f.write("v2")
        resp, status = self.host.post(
            "/write", {"path": p, "content": "clobber", "expected_version": v1})
        self.assertEqual(status, 409)
        self.assertEqual(resp["error"], "version_conflict")

    def test_edit_returns_diff(self):
        p = os.path.join(self.host.root, "code.py")
        with open(p, "w") as f:
            f.write("x = 1\ny = 2\n")
        resp, status = self.host.post("/edit", {
            "path": p,
            "ops": [{"op": "replace", "find": "x = 1", "replace": "x = 42"}],
        })
        self.assertEqual(status, 200)
        self.assertEqual(resp["changes"], 1)
        self.assertIn("-x = 1", resp["diff"])
        self.assertIn("+x = 42", resp["diff"])
        with open(p) as f:
            self.assertEqual(f.read(), "x = 42\ny = 2\n")

    def test_edit_preserves_mode(self):
        p = os.path.join(self.host.root, "script.sh")
        with open(p, "w") as f:
            f.write("echo one\n")
        os.chmod(p, 0o755)
        resp, status = self.host.post("/edit", {
            "path": p,
            "ops": [{"op": "replace", "find": "one", "replace": "two"}],
        })
        self.assertEqual(status, 200)
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o755)

    def test_search_endpoint(self):
        make_tree(self.host.root, {"app2.py": "def run():\n    pass\n"})
        resp, status = self.host.post("/search", {"query": "def run"})
        self.assertEqual(status, 200)
        self.assertTrue(any("app2.py" in m["path"] for m in resp["matches"]))

    def test_tree_endpoint(self):
        resp, status = self.host.post("/tree", {"depth": 2})
        self.assertEqual(status, 200)
        names = [e["name"] for t in resp["trees"] for e in t["entries"]]
        self.assertIn("hello.py", names)
        self.assertIn("sub", names)

    def test_list_and_stat(self):
        resp, status = self.host.post("/list", {"path": self.host.root})
        names = [e["name"] for e in resp["entries"]]
        self.assertIn("hello.py", names)
        self.assertIn("sub", names)
        resp, status = self.host.post("/stat", {"path": os.path.join(
            self.host.root, "hello.py")})
        self.assertTrue(resp["is_file"])

    def test_delete_root_rejected(self):
        resp, status = self.host.post("/delete", {"path": self.host.root})
        self.assertEqual(status, 403)
        self.assertEqual(resp["error"], "protected_path")
        self.assertTrue(os.path.isdir(self.host.root))

    def test_delete_git_rejected(self):
        make_tree(self.host.root, {".git/config": "[core]\n"})
        resp, status = self.host.post("/delete", {
            "path": os.path.join(self.host.root, ".git")})
        self.assertEqual(status, 403)
        self.assertEqual(resp["error"], "protected_path")

    def test_large_recursive_delete_needs_confirm(self):
        big = os.path.join(self.host.root, "big")
        os.makedirs(big, exist_ok=True)
        for i in range(30):
            with open(os.path.join(big, f"f{i}"), "w") as f:
                f.write("x")
        resp, status = self.host.post("/delete", {"path": big})
        self.assertEqual(status, 409)     # v2.4.1: real status, was 200
        self.assertEqual(resp["error"], "confirm_required")
        # With confirm it works:
        resp, status = self.host.post("/delete", {"path": big, "confirm": True})
        self.assertTrue(resp.get("deleted"))
        self.assertFalse(os.path.exists(big))

    def test_move_copy(self):
        src = os.path.join(self.host.root, "hello.py")
        dst = os.path.join(self.host.root, "sub", "moved.py")
        resp, status = self.host.post("/move", {"src": src, "dest": dst})
        self.assertTrue(resp.get("moved"))
        self.assertTrue(os.path.isfile(dst))
        resp, status = self.host.post("/copy", {"src": dst, "dest": src})
        self.assertTrue(resp.get("copied"))

    def test_traversal_via_api_rejected(self):
        resp, status = self.host.post("/read", {
            "path": os.path.join(self.host.root, "..", "outside.txt")})
        self.assertEqual(status, 403)


class TestExecAndProcs(unittest.TestCase):
    def setUp(self):
        self.host = TestHost(settings={"allow_exec": True})

    def tearDown(self):
        self.host.stop()

    def test_exec_runs(self):
        resp, status = self.host.post("/exec", {
            "command": "echo hello", "cwd": self.host.root})
        self.assertEqual(resp["returncode"], 0)
        self.assertIn("hello", resp["stdout"])

    def test_exec_disabled(self):
        self.host.settings["allow_exec"] = False
        resp, status = self.host.post("/exec", {
            "command": "echo hi", "cwd": self.host.root})
        self.assertEqual(status, 403)
        self.assertEqual(resp["error"], "exec_disabled")

    def test_exec_sandbox_rejects_outside(self):
        resp, status = self.host.post("/exec", {
            "command": "cat /etc/passwd", "cwd": self.host.root})
        self.assertTrue(resp.get("rejected"))
        self.assertEqual(resp["rule"], "path_outside_sandbox")

    def test_exec_policy_rejects_bare_pip(self):
        resp, status = self.host.post("/exec", {
            "command": "pip install requests", "cwd": self.host.root})
        self.assertTrue(resp.get("rejected"))
        self.assertEqual(resp["rule"], "install_not_in_venv")

    def test_exec_venv_flow_works(self):
        resp, status = self.host.post("/exec", {
            "command": "python3 -m venv .venv", "cwd": self.host.root})
        # venv creation may fail without ensurepip; tolerate rc != 0
        if resp.get("returncode") == 0:
            resp2, _ = self.host.post("/exec", {
                "command": ".venv/bin/pip install --no-input "
                           "--quiet certifi 2>&1 | tail -1",
                "cwd": self.host.root, "timeout": 120})
            self.assertNotIn("rejected", resp2)

    def test_exec_timeout_clamped_and_kills(self):
        resp, status = self.host.post("/exec", {
            "command": "sleep 5", "cwd": self.host.root, "timeout": 1})
        self.assertTrue(resp.get("timed_out"))

    def test_exec_output_capped(self):
        resp, status = self.host.post("/exec", {
            "command": "head -c 3000000 /dev/zero | base64",
            "cwd": self.host.root, "timeout": 60})
        self.assertTrue(resp.get("truncated"))
        self.assertLess(len(resp["stdout"]), 2 * 1024 * 1024)

    def test_proc_lifecycle(self):
        resp, status = self.host.post("/proc/start", {
            "command": "echo started; sleep 2; echo done",
            "cwd": self.host.root, "name": "sleeper"})
        self.assertEqual(status, 200)
        pid = resp["proc"]["id"]
        # Wait for exit event.
        self.assertTrue(self.host.wait_for(
            lambda: not self.host.ctx.procs.get(pid).running, timeout=6))
        resp, status = self.host.post("/proc/logs", {"id": pid})
        out = "\n".join(resp.get("stdout", []))
        self.assertIn("started", out)
        self.assertIn("done", out)
        resp, status = self.host.post("/proc/list", {})
        self.assertTrue(any(p["id"] == pid for p in resp["procs"]))


class TestSessionsApprovalsEvents(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_session_records_and_digests(self):
        p = os.path.join(self.host.root, "s.txt")
        self.host.post("/write", {"path": p, "content": "x"})
        self.host.post("/read", {"path": p})
        self.host.post("/session/note", {"text": "the plan: do stuff"})
        resp, status = self.host.post("/session/status", {})
        self.assertEqual(status, 200)
        self.assertEqual(resp["op_count"], 3)
        self.assertEqual(resp["files_touched"], 1)
        self.assertTrue(any("do stuff" in n["text"] for n in resp["notes"]))
        self.host.post("/session/reset", {})
        resp, _ = self.host.post("/session/status", {})
        self.assertEqual(resp["op_count"], 0)

    def test_approval_flow(self):
        """destructive policy: recursive dir delete needs approval."""
        self.host.settings["approval_policy"] = "destructive"
        d = os.path.join(self.host.root, "deleteme")
        os.makedirs(d, exist_ok=True)
        for i in range(10):
            with open(os.path.join(d, f"f{i}"), "w") as f:
                f.write("x")
        # Auto-approve from a "GUI thread" after a short delay.
        def approver():
            time.sleep(0.5)
            for _ in range(100):
                pending = self.host.ctx.approvals.pending()
                if pending:
                    self.host.ctx.approvals.decide(pending[0]["id"], True)
                    return
                time.sleep(0.1)
        t = threading.Thread(target=approver, daemon=True)
        t.start()
        resp, status = self.host.post("/delete", {"path": d})
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("deleted"))
        self.assertFalse(os.path.exists(d))

    def test_approval_denied(self):
        self.host.settings["approval_policy"] = "strict"
        p = os.path.join(self.host.root, "protected.txt")
        with open(p, "w") as f:
            f.write("safe\n")

        def denier():
            time.sleep(0.5)
            for _ in range(100):
                pending = self.host.ctx.approvals.pending()
                if pending:
                    self.host.ctx.approvals.decide(pending[0]["id"], False)
                    return
                time.sleep(0.1)
        threading.Thread(target=denier, daemon=True).start()
        resp, status = self.host.post("/write", {"path": p, "content": "no"})
        self.assertEqual(status, 403)
        self.assertEqual(resp["error"], "approval_denied")
        with open(p) as f:
            self.assertEqual(f.read(), "safe\n")   # untouched

    def test_events_longpoll(self):
        results = {}

        def poller():
            resp, status = self.host.get("/events?since=0&wait=3")
            results["resp"] = resp

        t = threading.Thread(target=poller, daemon=True)
        t.start()
        time.sleep(0.5)
        self.host.post("/session/note", {"text": "trigger"})
        t.join(timeout=10)
        types = [e["type"] for e in results["resp"]["events"]]
        self.assertIn("note", types)


class TestBootstrapAndBodyCaps(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_bootstrap_serves_cli(self):
        resp, status = self.host.get("/bootstrap")
        self.assertEqual(status, 200)
        self.assertIn("def main", resp["cli_py"])
        self.assertEqual(resp["name"], "llmac.py")

    def test_body_too_large(self):
        resp, status = self.host.post("/write", {
            "path": os.path.join(self.host.root, "big.txt"),
            "content": "x" * (17 * 1024 * 1024)})
        self.assertEqual(status, 413)


class TestCliEndToEnd(unittest.TestCase):
    """Drive cli.py as a subprocess against a live host (plain HTTP)."""

    def setUp(self):
        self.host = TestHost()
        make_tree(self.host.root, {"file.txt": "alpha\nbeta\n",
                                    "sub/x.py": "def run(): pass\n"})
        self.conn = f"unittest-{int(time.time())}"

    def tearDown(self):
        self.host.stop()

    def cli(self, *args, env_extra=None, input_=None):
        env = dict(os.environ)
        env.update({
            "LLMAC_HOST": "127.0.0.1",
            "LLMAC_PORT": str(self.host.port),
            "LLMAC_KEY": self.host.key,
            "LLMAC_CONN": self.conn,
        })
        env.pop("LDB_HOST", None)
        env.pop("LDB_PORT", None)
        env.pop("LDB_KEY", None)
        if env_extra:
            env.update(env_extra)
        p = subprocess.run([sys.executable, CLI, "--plain", *args],
                           capture_output=True, text=True, input=input_,
                           env=env, timeout=60)
        return p

    def test_health(self):
        p = self.cli("health")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("ok", p.stdout)

    def test_read_and_search(self):
        p = self.cli("read", "--path", os.path.join(self.host.root,
                                                    "file.txt"))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("alpha", p.stdout)
        p = self.cli("search", "--query", "def run")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("x.py", p.stdout)

    def test_edit_cli(self):
        p = self.cli("edit", "--path", os.path.join(self.host.root, "file.txt"),
                     "--replace", "alpha", "--with", "ALPHA")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("+ALPHA", p.stdout)

    def test_exec_cli_rejected(self):
        p = self.cli("exec", "--cwd", self.host.root,
                     "--command", "cat /etc/passwd")
        self.assertEqual(p.returncode, 2)
        self.assertIn("REJECTED", p.stderr)

    def test_connect_saves(self):
        # HERMETIC (v2.4.1): run the subprocess with a throwaway HOME so
        # it can never read or clobber the developer's real
        # ~/.llmac/connections.json (an isolation bug here once wiped a
        # production connection mid-session).
        import tempfile
        import cli as cli_mod
        with tempfile.TemporaryDirectory() as fake_home:
            real_file = cli_mod.CONNECTIONS_FILE
            p = subprocess.run(
                [sys.executable, CLI, "connect",
                 "--host", "127.0.0.1", "--port", str(self.host.port),
                 "--key", self.host.key, "--plain", "--save",
                 "--name", self.conn],
                capture_output=True, text=True, timeout=60,
                env={**os.environ, "HOME": fake_home,
                     "LLMAC_CONN": self.conn})
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("Connected", p.stdout)
            # In-process check against the SAME throwaway file.
            try:
                cli_mod.CONNECTIONS_FILE = os.path.join(
                    fake_home, ".llmac", "connections.json")
                from cli import Conns
                saved = Conns.get(self.conn)
                self.assertIsNotNone(saved)
                self.assertEqual(saved["port"], self.host.port)
                Conns.delete(self.conn)
            finally:
                cli_mod.CONNECTIONS_FILE = real_file
        # And the real file must be untouched by this test.
        self.assertEqual(
            os.path.realpath(os.path.expanduser(
                "~/.llmac/connections.json")),
            os.path.realpath(real_file))


if __name__ == "__main__":
    unittest.main()
