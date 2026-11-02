"""Share-request flow: the agent-initiated way to grow the sandbox.

The v2.1 contract:
* an agent with zero roots is not stranded — it can POST /roots/request;
* the request is ALWAYS human-gated, even under the `auto` policy;
* duplicate pending requests collapse into one;
* the side effect (adding the root) happens host-side on approve — the
  API test simulates exactly what the GUI does.
"""
import os
import sys
import time
import unittest

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost
from core.sandbox import Sandbox


class TestShareRequest(unittest.TestCase):

    def setUp(self):
        self.host = TestHost(settings={"approval_policy": "auto"})
        self.extra = os.path.join(self.host.tmp, "extra_project")
        os.makedirs(self.extra, exist_ok=True)
        with open(os.path.join(self.extra, "hello.txt"), "w") as f:
            f.write("hi\n")

    def tearDown(self):
        self.host.stop()

    def test_info_advertises_capability(self):
        resp, status = self.host.get("/info")
        self.assertEqual(status, 200)
        self.assertTrue(resp["can_request_roots"])

    def test_request_creates_pending_approval_even_under_auto(self):
        resp, status = self.host.post("/roots/request",
                                      {"path": self.extra,
                                       "reason": "need project files"})
        self.assertEqual(status, 202)
        self.assertIn("approval_id", resp)
        aid = resp["approval_id"]
        # visible in the approval queue with the structured payload
        lst, _ = self.host.post("/approvals/list", {})
        pending = lst["pending"]
        self.assertEqual(len(pending), 1)
        a = pending[0]
        self.assertEqual(a["id"], aid)
        self.assertEqual(a["op"], "share_root")
        self.assertEqual(a["payload"]["path"], os.path.realpath(self.extra))
        self.assertEqual(a["payload"]["reason"], "need project files")
        self.assertEqual(a["agent"], "default")

    def test_duplicate_requests_collapse(self):
        r1, s1 = self.host.post("/roots/request", {"path": self.extra})
        r2, s2 = self.host.post("/roots/request", {"path": self.extra,
                                                   "reason": "again"})
        self.assertEqual(s1, 202)
        self.assertEqual(s2, 202)
        self.assertEqual(r1["approval_id"], r2["approval_id"])
        lst, _ = self.host.post("/approvals/list", {})
        self.assertEqual(len(lst["pending"]), 1)

    def test_already_shared_returns_success_without_approval(self):
        r, s = self.host.post("/roots/request", {"path": self.host.root})
        self.assertEqual(s, 200)
        self.assertEqual(r["status"], "already_shared")
        lst, _ = self.host.post("/approvals/list", {})
        self.assertEqual(len(lst["pending"]), 0)

    def test_rejects_relative_and_missing_paths(self):
        r, s = self.host.post("/roots/request", {"path": "some/rel/path"})
        self.assertEqual(s, 400)          # v2.4.1: real status, was 200
        self.assertIn("error", r)
        r, s = self.host.post("/roots/request",
                              {"path": "/definitely/not/here"})
        self.assertEqual(s, 400)
        self.assertIn("error", r)
        r, s = self.host.post("/roots/request", {"path": ""})
        self.assertEqual(s, 400)
        self.assertIn("error", r)

    def test_deny_flow(self):
        r, _ = self.host.post("/roots/request", {"path": self.extra})
        aid = r["approval_id"]
        # Human denies in the GUI:
        self.host.ctx.approvals.decide(aid, False, by="host")
        w, _ = self.host.post("/approvals/wait", {"id": aid, "timeout": 1})
        self.assertEqual(w["status"], "denied")
        # sandbox untouched
        self.assertNotIn(os.path.realpath(self.extra),
                         self.host.ctx.sandbox.roots)

    def test_approve_flow_applies_root_host_side(self):
        r, _ = self.host.post("/roots/request",
                              {"path": self.extra, "reason": "edit files"})
        aid = r["approval_id"]
        # --- what the GUI does on Approve ---
        path = os.path.realpath(self.extra)
        self.host.roots.append(path)
        self.host.ctx.sandbox = Sandbox(self.host.roots)
        self.host.ctx.approvals.decide(aid, True, by="host")
        # ------------------------------------
        w, _ = self.host.post("/approvals/wait", {"id": aid, "timeout": 1})
        self.assertEqual(w["status"], "approved")
        # the agent can now see the new root and read a file in it
        info, _ = self.host.get("/info")
        self.assertIn(path, info["roots"])
        resp, status = self.host.post(
            "/read", {"path": os.path.join(self.extra, "hello.txt")})
        self.assertEqual(status, 200)
        self.assertEqual(resp["content"], "hi\n")

    def test_zero_root_agent_can_request_and_receive_access(self):
        # Simulate a host started with no directories (allowed since v2.1).
        self.host.ctx.sandbox = Sandbox([])
        info, _ = self.host.get("/info")
        self.assertEqual(info["roots"], [])
        # agent cannot read anything yet
        resp, status = self.host.post(
            "/read", {"path": os.path.join(self.extra, "hello.txt")})
        self.assertEqual(status, 403)
        # ...but it can ask
        r, s = self.host.post("/roots/request",
                              {"path": self.extra, "reason": "my project"})
        self.assertEqual(s, 202)
        # host approves + applies
        self.host.ctx.sandbox = Sandbox([os.path.realpath(self.extra)])
        self.host.ctx.approvals.decide(r["approval_id"], True, by="host")
        resp, status = self.host.post(
            "/read", {"path": os.path.join(self.extra, "hello.txt")})
        self.assertEqual(status, 200)
        self.assertEqual(resp["content"], "hi\n")

    def test_reason_is_capped(self):
        r, _ = self.host.post("/roots/request",
                              {"path": self.extra, "reason": "x" * 2000})
        lst, _ = self.host.post("/approvals/list", {})
        self.assertEqual(len(lst["pending"][0]["payload"]["reason"]), 500)

    def test_pending_flood_capped(self):
        for i in range(20):
            d = os.path.join(self.host.tmp, f"flood{i}")
            os.makedirs(d, exist_ok=True)
            r, s = self.host.post("/roots/request", {"path": d})
            self.assertEqual(s, 202, f"request {i} should be accepted")
        one_more = os.path.join(self.host.tmp, "flood20")
        os.makedirs(one_more, exist_ok=True)
        r, s = self.host.post("/roots/request", {"path": one_more})
        self.assertEqual(s, 429)
        self.assertEqual(r["error"], "too_many_pending")


if __name__ == "__main__":
    unittest.main()
