"""v2.8.4: detachable exec + client self-deadline.

Regression for: agent tool limit kills the client mid-call, the host keeps
running the command with nobody to take the result (orphan), and retries
re-run it. Now a call can return {detached, job} and the result is fetched
later; the client can also exit by itself before the tool limit."""
import os
import socket
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
from helpers import TestHost

CLIENT = os.path.join(_PARENT, "llmac.py")


class TestDetachableExec(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_fast_command_is_not_detached(self):
        r, s = self.host.post("/exec", {"command": "echo hi", "wait_s": 10})
        self.assertEqual(s, 200)
        self.assertNotIn("detached", r)
        self.assertIn("hi", r["stdout"])

    def test_slow_command_detaches_then_result_arrives(self):
        t0 = time.monotonic()
        r, s = self.host.post("/exec", {"command": "sleep 3; echo done",
                                        "wait_s": 1})
        self.assertLess(time.monotonic() - t0, 2.5)
        self.assertEqual(s, 200)
        self.assertTrue(r["detached"])
        job = r["job"]
        r2, s2 = self.host.post("/exec/result", {"job": job, "wait_s": 10})
        self.assertEqual(s2, 200)
        self.assertNotIn("detached", r2)
        self.assertIn("done", r2["stdout"])
        self.assertEqual(r2["returncode"], 0)

    def test_request_id_dedupes_retry(self):
        f = os.path.join(self.host.root, "count.txt")
        cmd = "sleep 2; echo x >> '%s'" % f
        r1, _ = self.host.post("/exec", {"command": cmd, "wait_s": 0.5,
                                         "request_id": "abc"})
        self.assertTrue(r1["detached"])
        r2, _ = self.host.post("/exec", {"command": cmd, "wait_s": 10,
                                         "request_id": "abc"})
        self.assertTrue(r2.get("deduplicated"))
        self.assertEqual(r2["returncode"], 0)
        with open(f) as fh:
            self.assertEqual(fh.read().count("x"), 1)   # ran ONCE

    def test_unknown_job_404(self):
        r, s = self.host.post("/exec/result", {"job": "nope"})
        self.assertEqual(s, 404)
        self.assertEqual(r["error"], "exec_job_unknown")

    def test_detach_does_not_hold_request_slot(self):
        r, _ = self.host.post("/exec", {"command": "sleep 3", "wait_s": 0.3})
        self.assertTrue(r["detached"])
        free = self.host.ctx._req_sem._value
        from core.constants import MAX_CONCURRENT_REQUESTS
        self.assertEqual(free, MAX_CONCURRENT_REQUESTS)

    def test_legacy_exec_unchanged(self):
        r, s = self.host.post("/exec", {"command": "echo legacy"})
        self.assertEqual(s, 200)
        self.assertIn("legacy", r["stdout"])


class TestClientDeadline(unittest.TestCase):
    def _run(self, host, port, key, extra, env_limit, timeout=30):
        env = dict(os.environ, LLMAC_TOOL_LIMIT=str(env_limit))
        t0 = time.monotonic()
        p = subprocess.run(
            [sys.executable, CLIENT, "--plain", "--host", host,
             "--port", str(port), "--key", key] + extra,
            capture_output=True, text=True, env=env, timeout=timeout)
        return p, time.monotonic() - t0

    def test_exec_detaches_under_tool_limit(self):
        h = TestHost()
        try:
            p, el = self._run("127.0.0.1", h.server.server_address[1], h.key,
                              ["exec", "--command", "sleep 15; echo late"], 8)
            self.assertEqual(p.returncode, 75, p.stdout + p.stderr)
            self.assertLess(el, 8)
            self.assertIn("job=", p.stdout)
            job = p.stdout.split("job=")[1].split()[0]
            p2, _ = self._run("127.0.0.1", h.server.server_address[1], h.key,
                              ["exec-result", "--job", job, "--wait", "3"], 8)
            self.assertEqual(p2.returncode, 75)      # still running
        finally:
            h.stop()

    def test_hung_host_exits_before_limit(self):
        # Accepts TCP, never answers: the exact half-open scenario.
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        held = []
        threading.Thread(target=lambda: [held.append(srv.accept())
                                         for _ in range(3)],
                         daemon=True).start()
        try:
            p, el = self._run("127.0.0.1", srv.getsockname()[1], "k_llmac_x",
                              ["info"], 6)
            self.assertEqual(p.returncode, 124, p.stdout + p.stderr)
            self.assertLess(el, 6)
            self.assertIn("self-deadline", p.stderr)
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()
