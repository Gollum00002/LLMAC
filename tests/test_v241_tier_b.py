"""v2.4.1 Tier B — server-side agent-efficiency features + error statuses.

Covers:
  ERR   handler error dicts now carry real HTTP statuses (404 not_found,
        400 missing_field/bad_request, 409 dest_exists/confirm_required,
        403 no_roots, 503 exec_busy) with UNCHANGED bodies; batch embeds
        per-op errors with the op name; the CLI tolerates 4xx transparently
  B3    /stat {hash:true} -> sha256 (file), skipped note (oversize),
        nothing (directory); batch stat-hash; `llmac verify` MATCH/MISMATCH
        with exec DISABLED on the host; `llmac stat --hash`
  B1    POST /overview: info core + depth-capped tree + doc heads +
        session pointer; byte-budget trim; not_a_directory 400;
        `llmac orient` output
  B2    POST /diff: two paths, inline proposal, identical, 404 missing,
        400 binary, 403 protected/sandbox; `llmac diff` incl. --inline-file
  B4    exec-in-batch: in-order after writes, pre-flight rejection refuses
        the WHOLE batch with zero side effects, rc!=0 is a per-op result,
        strict policy refuses batched exec, exec-disabled 403,
        bad cwd refuses whole batch; `llmac batch` shows rc=
  DEP   deploy rides stat-hash in the same batch -> verifies with exec
        disabled; old-server fallback (no sha256 in stat) -> exec
  VER   2.4.1 everywhere (/health, /info, --version)
"""
import hashlib
import json
import os
import subprocess
import sys
import unittest
from types import SimpleNamespace

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost

CLI = os.path.join(_PARENT, "llmac.py")


def run_cli(host, *args, timeout=90):
    return subprocess.run(
        [sys.executable, CLI, "--plain", "--host", "127.0.0.1",
         "--port", str(host.port), "--key", host.key, *args],
        capture_output=True, text=True, timeout=timeout)


def load_cli_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("llmac_cli_test_241", CLI)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_tree(root, spec: dict):
    for rel, content in spec.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

class TestVersion241(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_health_and_info_report_241(self):
        resp, status = self.host.get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(resp["version"], "2.8.2")
        r = run_cli(self.host, "info")
        self.assertEqual(r.returncode, 0)
        self.assertIn('"2.8.2"', r.stdout)


# ---------------------------------------------------------------------------
# Error statuses (the v2.4.1 fix)
# ---------------------------------------------------------------------------

class TestErrorStatuses(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_read_missing_is_404(self):
        resp, status = self.host.post(
            "/read", {"path": os.path.join(self.host.root, "ghost")})
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"], "not_found")
        self.assertIn("message", resp)

    def test_write_missing_field_is_400(self):
        resp, status = self.host.post("/write", {})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "missing_field")

    def test_write_bad_b64_is_400(self):
        resp, status = self.host.post(
            "/write", {"path": os.path.join(self.host.root, "x"),
                       "content_b64": "!!!not base64!!!"})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "bad_request")

    def test_move_dest_exists_is_409(self):
        make_tree(self.host.root, {"a": "A", "b": "B"})
        resp, status = self.host.post(
            "/move", {"src": os.path.join(self.host.root, "a"),
                      "dest": os.path.join(self.host.root, "b")})
        self.assertEqual(status, 409)
        self.assertEqual(resp["error"], "dest_exists")

    def test_exec_cwd_not_found_is_404(self):
        resp, status = self.host.post(
            "/exec", {"command": "true",
                      "cwd": os.path.join(self.host.root, "nope")})
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"], "cwd_not_found")

    def test_read_range_invalid_is_400(self):
        p = os.path.join(self.host.root, "t.txt")
        with open(p, "w") as f:
            f.write("one\ntwo\n")
        resp, status = self.host.post(
            "/read", {"path": p, "from_line": 9, "to_line": 12})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "range_invalid")

    def test_batch_embeds_op_errors_with_op_name(self):
        resp, status = self.host.post("/batch", {"ops": [
            {"op": "read", "path": os.path.join(self.host.root, "there")}]})
        self.assertEqual(status, 200)          # per-op errors stay 200
        r = resp["results"][0]
        self.assertEqual(r["op"], "read")
        self.assertEqual(r["error"], "not_found")

    def test_cli_tolerates_4xx_bodies(self):
        r = run_cli(self.host, "read", "--path",
                    os.path.join(self.host.root, "ghost"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("not_found", r.stderr)
        r = run_cli(self.host, "write", "--path",
                    os.path.join(self.host.root, "w.txt"), "--content", "hi")
        self.assertEqual(r.returncode, 0)
        r = run_cli(self.host, "mv", "--src",
                    os.path.join(self.host.root, "w.txt"), "--dest",
                    os.path.join(self.host.root, "w.txt"))
        # mv onto itself -> dest_exists 409, clean CLI error
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("dest_exists", r.stderr)


# ---------------------------------------------------------------------------
# B3: stat --hash + verify
# ---------------------------------------------------------------------------

class TestStatHash(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.f = os.path.join(self.host.root, "f.bin")
        with open(self.f, "wb") as f:
            f.write(b"hello hashable world" * 10)

    def tearDown(self):
        self.host.stop()

    def test_stat_hash_matches_local(self):
        resp, status = self.host.post("/stat", {"path": self.f, "hash": True})
        self.assertEqual(status, 200)
        self.assertEqual(resp.get("sha256"),
                         sha(b"hello hashable world" * 10))

    def test_stat_without_hash_has_no_sha(self):
        resp, status = self.host.post("/stat", {"path": self.f})
        self.assertEqual(status, 200)
        self.assertNotIn("sha256", resp)

    def test_stat_directory_has_no_sha(self):
        resp, status = self.host.post(
            "/stat", {"path": self.host.root, "hash": True})
        self.assertEqual(status, 200)
        self.assertTrue(resp["is_dir"])
        self.assertNotIn("sha256", resp)

    def test_stat_oversize_skips(self):
        import core.api as api
        from unittest.mock import patch
        with patch.object(api, "STAT_HASH_MAX_BYTES", 10):
            resp, status = self.host.post(
                "/stat", {"path": self.f, "hash": True})
        self.assertEqual(status, 200)
        self.assertNotIn("sha256", resp)
        self.assertIn("sha256_skipped", resp)

    def test_batch_stat_hash(self):
        resp, status = self.host.post("/batch", {"ops": [
            {"op": "stat", "path": self.f, "hash": True}]})
        self.assertEqual(status, 200)
        ok = resp["results"][0]["ok"]
        self.assertEqual(ok["sha256"], sha(b"hello hashable world" * 10))

    def test_cli_verify_match_and_mismatch_with_exec_off(self):
        host = TestHost(settings={"allow_exec": False})
        try:
            local = os.path.join(host.tmp, "local.bin")
            with open(local, "wb") as f:
                f.write(b"hello hashable world" * 10)
            remote = os.path.join(host.root, "f.bin")
            with open(remote, "wb") as f:
                f.write(b"hello hashable world" * 10)
            r = run_cli(host, "verify", "--local", local, "--remote", remote)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("MATCH", r.stdout)
            with open(local, "wb") as f:
                f.write(b"different" * 5)
            r = run_cli(host, "verify", "--local", local, "--remote", remote)
            self.assertEqual(r.returncode, 1)
            self.assertIn("MISMATCH", r.stdout)
        finally:
            host.stop()

    def test_cli_stat_hash_flag(self):
        r = run_cli(self.host, "stat", "--path", self.f, "--hash")
        self.assertEqual(r.returncode, 0)
        self.assertIn(sha(b"hello hashable world" * 10), r.stdout)


# ---------------------------------------------------------------------------
# B1: /overview + orient
# ---------------------------------------------------------------------------

class TestOverview(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        make_tree(self.host.root, {
            "README.md": "# Project\nline2\nline3\n",
            "agent.md": "# Agent notes\n",
            "src/a.py": "x = 1\n",
            "src/deep/b.py": "y = 2\n",
        })

    def tearDown(self):
        self.host.stop()

    def test_overview_shape(self):
        resp, status = self.host.post("/overview", {})
        self.assertEqual(status, 200)
        self.assertEqual(resp["info"]["version"], "2.8.2")
        self.assertIn("policy", resp["info"])
        self.assertIn("roots", resp["info"])
        self.assertTrue(any(e["name"] == "README.md"
                            for e in resp["tree"]["entries"]))
        docs = {d["path"] for d in resp["docs"]}
        self.assertTrue(any(p.endswith("README.md") for p in docs))
        self.assertTrue(any(p.endswith("agent.md") for p in docs))
        self.assertIn("op_count", resp["session"])
        self.assertLessEqual(resp["bytes"], resp["budget"])

    def test_overview_budget_trim(self):
        resp, status = self.host.post("/overview", {"budget": 600})
        self.assertEqual(status, 200)
        self.assertLessEqual(resp["bytes"], 700)
        # Something must have been flagged as trimmed.
        self.assertTrue(any(v for k, v in resp["trimmed"].items()))

    def test_overview_doc_heads_cap(self):
        resp, status = self.host.post(
            "/overview", {"doc_heads": 1})
        self.assertEqual(status, 200)
        for d in resp["docs"]:
            self.assertLessEqual(d["lines"], 1)

    def test_overview_depth_cap(self):
        resp, status = self.host.post(
            "/overview", {"depth": 99, "doc_heads": 0})
        self.assertEqual(status, 200)
        depths = [e["depth"] for e in resp["tree"]["entries"]]
        self.assertLessEqual(max(depths), 4)

    def test_overview_not_a_directory(self):
        resp, status = self.host.post(
            "/overview", {"path": os.path.join(self.host.root, "README.md")})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "not_a_directory")

    def test_cli_orient(self):
        r = run_cli(self.host, "orient")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("policy=", r.stdout)
        self.assertIn("--- tree", r.stdout)
        self.assertIn("session:", r.stdout)


# ---------------------------------------------------------------------------
# B2: /diff + diff CLI
# ---------------------------------------------------------------------------

class TestDiff(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        make_tree(self.host.root, {
            "a.txt": "one\ntwo\nthree\n",
            "b.txt": "one\nTWO!\nthree\nfour\n",
            "same1.txt": "identical\n",
            "same2.txt": "identical\n",
            "bin.bin": "\x00\x01\x02binary",
        })

    def tearDown(self):
        self.host.stop()

    def test_diff_two_paths(self):
        a = os.path.join(self.host.root, "a.txt")
        b = os.path.join(self.host.root, "b.txt")
        resp, status = self.host.post("/diff", {"a": a, "b": b})
        self.assertEqual(status, 200)
        self.assertFalse(resp["same"])
        self.assertIn("+TWO!", resp["diff"])
        self.assertEqual(resp["added"], 2)     # TWO! + four
        self.assertEqual(resp["removed"], 1)

    def test_diff_identical(self):
        resp, status = self.host.post("/diff", {
            "a": os.path.join(self.host.root, "same1.txt"),
            "b": os.path.join(self.host.root, "same2.txt")})
        self.assertEqual(status, 200)
        self.assertTrue(resp["same"])

    def test_diff_inline_proposal(self):
        resp, status = self.host.post("/diff", {
            "a": os.path.join(self.host.root, "a.txt"),
            "inline": "one\ntwo\nthree\nNEW\n"})
        self.assertEqual(status, 200)
        self.assertEqual(resp["b"], "(inline proposal)")
        self.assertIn("+NEW", resp["diff"])

    def test_diff_missing_is_404(self):
        resp, status = self.host.post("/diff", {
            "a": os.path.join(self.host.root, "ghost.txt"),
            "b": os.path.join(self.host.root, "a.txt")})
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"], "not_found")

    def test_diff_binary_is_400(self):
        resp, status = self.host.post("/diff", {
            "a": os.path.join(self.host.root, "bin.bin"),
            "b": os.path.join(self.host.root, "a.txt")})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "binary_file")

    def test_diff_protected_is_403(self):
        resp, status = self.host.post("/diff", {
            "a": self.host.data_dir,
            "b": os.path.join(self.host.root, "a.txt")})
        self.assertEqual(status, 403)

    def test_diff_outside_sandbox_is_403(self):
        resp, status = self.host.post("/diff", {
            "a": "/etc/hostname",
            "b": os.path.join(self.host.root, "a.txt")})
        self.assertEqual(status, 403)
        self.assertEqual(resp["error"], "forbidden")

    def test_cli_diff_paths_and_inline(self):
        a = os.path.join(self.host.root, "a.txt")
        b = os.path.join(self.host.root, "b.txt")
        r = run_cli(self.host, "diff", "--a", a, "--b", b)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("+TWO!", r.stdout)
        self.assertIn("[diff: +2 -1]", r.stderr)
        # inline dry-run
        proposal = os.path.join(self.host.tmp, "prop.txt")
        with open(proposal, "w") as f:
            f.write("one\ntwo\nthree\nNEW\n")
        r = run_cli(self.host, "diff", "--a", a, "--inline-file", proposal)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("+NEW", r.stdout)


# ---------------------------------------------------------------------------
# B4: exec in batch
# ---------------------------------------------------------------------------

class TestExecInBatch(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_write_then_exec_sees_written_file(self):
        f = os.path.join(self.host.root, "made.txt")
        resp, status = self.host.post("/batch", {"ops": [
            {"op": "write", "path": f, "content": "42"},
            {"op": "exec", "command": "cat " + f},
        ]})
        self.assertEqual(status, 200)
        w, x = resp["results"]
        self.assertIn("ok", w)
        self.assertIn("ok", x)
        self.assertIn("42", x["ok"]["stdout"])
        self.assertEqual(x["op"], "exec")

    def test_preflight_rejection_refuses_whole_batch(self):
        f = os.path.join(self.host.root, "never.txt")
        resp, status = self.host.post("/batch", {"ops": [
            {"op": "write", "path": f, "content": "x"},
            {"op": "exec", "command": "cat /etc/shadow"},   # outside sandbox
        ]})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "exec_preflight")
        self.assertEqual(resp["index"], 1)
        # ATOMICITY: the preceding write must NOT have happened.
        self.assertFalse(os.path.exists(f))

    def test_bad_cwd_refuses_whole_batch(self):
        f = os.path.join(self.host.root, "never2.txt")
        resp, status = self.host.post("/batch", {"ops": [
            {"op": "write", "path": f, "content": "x"},
            {"op": "exec", "command": "true",
             "cwd": os.path.join(self.host.root, "missing-dir")},
        ]})
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"], "exec_preflight")
        self.assertEqual(resp["cause"], "cwd_not_found")
        self.assertFalse(os.path.exists(f))

    def test_missing_command_refuses_whole_batch(self):
        resp, status = self.host.post("/batch", {"ops": [
            {"op": "exec"}]})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "exec_preflight")

    def test_rc_nonzero_is_per_op_result_not_batch_abort(self):
        f = os.path.join(self.host.root, "independent.txt")
        resp, status = self.host.post("/batch", {"ops": [
            {"op": "write", "path": f, "content": "still here"},
            {"op": "exec", "command": "exit 3"},
            {"op": "read", "path": f},
        ]})
        self.assertEqual(status, 200)
        w, x, r = resp["results"]
        self.assertIn("ok", w)
        self.assertEqual(x["ok"]["returncode"], 3)
        self.assertIn("ok", r)               # later ops still ran
        self.assertIn("still here", r["ok"]["content"])

    def test_strict_policy_refuses_batched_exec(self):
        host = TestHost(settings={"approval_policy": "strict"})
        try:
            resp, status = host.post("/batch", {"ops": [
                {"op": "exec", "command": "true"}]})
            self.assertEqual(status, 400)
            self.assertEqual(resp["error"], "batch_policy")
        finally:
            host.stop()

    def test_exec_disabled_refuses_batched_exec_403(self):
        host = TestHost(settings={"allow_exec": False})
        try:
            f = os.path.join(host.root, "never3.txt")
            resp, status = host.post("/batch", {"ops": [
                {"op": "write", "path": f, "content": "x"},
                {"op": "exec", "command": "true"}]})
            self.assertEqual(status, 403)
            self.assertEqual(resp["error"], "exec_disabled")
            self.assertFalse(os.path.exists(f))
        finally:
            host.stop()

    def test_cli_batch_shows_rc(self):
        f = os.path.join(self.host.root, "rc.txt")
        r = run_cli(self.host, "batch", "--ops", json.dumps([
            {"op": "write", "path": f, "content": "hi"},
            {"op": "exec", "command": "cat " + f},
            {"op": "exec", "command": "exit 5"},
        ]))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("exec: ok rc=0 | hi", r.stdout)
        self.assertIn("exec: ok rc=5", r.stdout)


# ---------------------------------------------------------------------------
# Deploy: stat-hash fast path + old-server fallback
# ---------------------------------------------------------------------------

class TestDeployFastPath(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_deploy_verifies_with_exec_off(self):
        """The B3 acceptance: deploy upload+verify works on a host with
        exec DISABLED (hashes ride in the same batch, no exec needed)."""
        host = TestHost(settings={"allow_exec": False})
        try:
            local_dir = os.path.join(host.tmp, "locals")
            os.makedirs(local_dir)
            pairs = []
            for name, body in (("one.txt", "alpha"), ("two.txt", "beta")):
                lp = os.path.join(local_dir, name)
                with open(lp, "w") as f:
                    f.write(body)
                pairs.append(f"{lp}={os.path.join(host.root, name)}")
            r = run_cli(host, "deploy", *sum(([ "--pairs", p]
                                              for p in pairs), []))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("2/2 verified", r.stdout)
            self.assertNotIn("WARNING", r.stderr)
        finally:
            host.stop()

    def test_deploy_dry_run_reports_calls(self):
        local = os.path.join(self.host.tmp, "one.txt")
        with open(local, "w") as f:
            f.write("x")
        r = run_cli(self.host, "deploy", "--pairs",
                    f"{local}={os.path.join(self.host.root, 'one.txt')}",
                    "--dry-run")
        self.assertEqual(r.returncode, 0)
        self.assertIn("1 batch call(s)", r.stdout)

    def test_old_server_falls_back_to_exec(self):
        """Server predates stat --hash: stats come back WITHOUT sha256,
        deploy falls back to the one sha256sum exec (v2.4.0 behavior)."""
        mod = load_cli_module()
        calls = []

        class FakeClient:
            retry_seconds = 0.0

            def post(self, path, payload=None, timeout=130.0):
                calls.append(path)
                if path == "/batch":
                    results = []
                    for o in payload["ops"]:
                        if o["op"] == "write":
                            results.append({"index": len(results),
                                            "op": "write",
                                            "ok": {"path": o["path"],
                                                   "bytes": 1}})
                        else:                      # OLD server: no sha256
                            results.append({"index": len(results),
                                            "op": "stat",
                                            "ok": {"path": o["path"],
                                                   "size": 1}})
                    return {"results": results}, 200
                if path == "/exec":
                    return {"stdout": "deadbeef  /r\n", "returncode": 0,
                            "stderr": ""}, 200
                raise AssertionError("unexpected " + path)

        ck = ("127.0.0.1", 1, "k", "", False, False)  # v2.8: +tap field
        mod._CLIENT_CACHE[ck] = FakeClient()
        try:
            # conn="v241-hermetic": a NONEXISTENT conn name so the real
            # ~/.llmac state can never leak into the client cache key
            # (a real pinned 'default' would change fp -> cache miss).
            args = SimpleNamespace(
                manifest=None, pairs=["L=/r"], dry_run=False,
                no_verify=False, host="127.0.0.1", port=1, key="k",
                fp=None, plain=True, retry=0, conn="v241-hermetic",
                no_verify_flag=None, verbose=False)
            # exact expected hash for content "x": feed via file
            lp = os.path.join(self.host.tmp, "l.txt")
            with open(lp, "w") as f:
                f.write("x")
            args.pairs = [f"{lp}=/r"]
            rc = mod.cmd_deploy(args)
            self.assertIn("/batch", calls)
            self.assertIn("/exec", calls)      # fallback fired
            # sha256("x") != deadbeef -> MISMATCH reported, exit 1
            self.assertEqual(rc, 1)
        finally:
            mod._CLIENT_CACHE.pop(ck, None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
