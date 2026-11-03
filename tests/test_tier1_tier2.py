"""v2.3.0 Tier 1 + Tier 2 tests.

Covers: gzip + keep-alive transport, POST /batch, archive GET/PUT,
approval grants, the info-with-zero-roots regression (W1), error
messages for no_roots (W2), CLI download fix (W5), exec --json (F6),
and the settings round-trip that keeps allow_exec / grants alive
across host restarts (W3).
"""
import base64
import gzip
import http.client
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost, make_tree
import core.api as api
from core.constants import GZIP_MIN_BYTES
from core.sandbox import Sandbox
from core.state import StateStore, make_default_agent, default_settings

CLI = os.path.join(_PARENT, "llmac.py")


def run_cli(host, *args, timeout=90):
    return subprocess.run(
        [sys.executable, CLI, "--plain", "--host", "127.0.0.1",
         "--port", str(host.port), "--key", host.key, *args],
        capture_output=True, text=True, timeout=timeout)


# ---------------------------------------------------------------------------
# W1 / W2: identity endpoints work with zero roots; errors carry messages
# ---------------------------------------------------------------------------

class TestInfoZeroRoots(unittest.TestCase):
    def test_identity_ops_with_no_roots(self):
        host = TestHost()
        try:
            host.ctx.sandbox = Sandbox([])   # simulate all shares removed
            resp, status = host.get("/info")
            self.assertEqual(status, 200)
            self.assertEqual(resp["roots"], [])
            self.assertTrue(resp["can_request_roots"])

            resp, status = host.post("/list", {})
            self.assertEqual(status, 200)
            self.assertEqual(resp["entries"], [])

            resp, status = host.post("/search", {"query": "zzz"})
            self.assertEqual(status, 403)  # v2.4.1: real status, was 200
            self.assertEqual(resp["error"], "no_roots")
            self.assertTrue(resp.get("message"),
                            "no_roots must now carry a message (W2)")
        finally:
            host.stop()

    def test_state_roundtrip_preserves_exec_and_grants(self):
        """W3: allow_exec + agent perms + grants survive save/load."""
        with tempfile.TemporaryDirectory() as d:
            st = StateStore(d)
            agent = make_default_agent()
            agent["perms"]["exec"] = True
            settings = default_settings()
            settings["allow_exec"] = True
            settings["grants"] = [{
                "id": "gra_test", "agent": "default", "ops": ["write"],
                "scope": "/tmp/x", "created_at": "now",
                "created_by": "host",
                "expires_at": "2099-01-01T00:00:00+00:00"}]
            st.save(st.build_state(roots=[d], host="127.0.0.1", port=1234,
                                   agents=[agent], settings=settings))
            loaded = StateStore(d).load()
            self.assertTrue(loaded["settings"]["allow_exec"])
            self.assertTrue(loaded["agents"][0]["perms"]["exec"])
            self.assertEqual(loaded["settings"]["grants"][0]["id"], "gra_test")


# ---------------------------------------------------------------------------
# F1: gzip + keep-alive
# ---------------------------------------------------------------------------

class TestGzipKeepAlive(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def _post(self, conn, path, payload, accept_gzip=True):
        body = json.dumps(payload).encode()
        headers = {"Authorization": f"Bearer {self.host.key}",
                   "Content-Type": "application/json",
                   "Content-Length": str(len(body))}
        if accept_gzip:
            headers["Accept-Encoding"] = "gzip"
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp, resp.read()

    def test_gzip_large_response(self):
        make_tree(self.host.root, {"big.txt": "z" * (GZIP_MIN_BYTES * 8)})
        conn = http.client.HTTPConnection("127.0.0.1", self.host.port,
                                          timeout=15)
        resp, data = self._post(
            conn, "/read", {"path": os.path.join(self.host.root, "big.txt")})
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.getheader("Content-Encoding"), "gzip")
        out = json.loads(gzip.decompress(data))
        self.assertEqual(out["content"], "z" * (GZIP_MIN_BYTES * 8))
        conn.close()

    def test_no_gzip_unasked(self):
        make_tree(self.host.root, {"big.txt": "z" * (GZIP_MIN_BYTES * 8)})
        conn = http.client.HTTPConnection("127.0.0.1", self.host.port,
                                          timeout=15)
        resp, data = self._post(
            conn, "/read", {"path": os.path.join(self.host.root, "big.txt")},
            accept_gzip=False)
        self.assertEqual(resp.status, 200)
        self.assertIsNone(resp.getheader("Content-Encoding"))
        self.assertFalse(json.loads(data.decode())["binary"])
        conn.close()

    def test_keep_alive_reuses_connection(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.host.port,
                                          timeout=15)
        conn.request("GET", "/health")
        r1 = conn.getresponse()
        r1.read()
        self.assertEqual(r1.status, 200)
        self.assertFalse(r1.will_close,
                         "server must not force Connection: close (F1)")
        # Second request on the SAME socket (raises if the server closed).
        conn.request("GET", "/info",
                     headers={"Authorization": f"Bearer {self.host.key}"})
        r2 = conn.getresponse()
        r2.read()
        self.assertEqual(r2.status, 200)
        self.assertFalse(r2.will_close)
        conn.close()


# ---------------------------------------------------------------------------
# F2: batch
# ---------------------------------------------------------------------------

class TestBatch(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        make_tree(self.host.root, {"a.txt": "alpha",
                                   "sub/b.txt": "beta",
                                   "node_modules/junk.js": "x"})

    def tearDown(self):
        self.host.stop()

    def test_mixed_reads_with_errors_isolated(self):
        ops = [
            {"op": "read", "path": os.path.join(self.host.root, "a.txt")},
            {"op": "list", "path": self.host.root},
            {"op": "stat", "path": os.path.join(self.host.root, "sub/b.txt")},
            {"op": "read", "path": os.path.join(self.host.root, "missing")},
            {"op": "frobnicate"},
        ]
        resp, status = self.host.post("/batch", {"ops": ops})
        self.assertEqual(status, 200)
        self.assertFalse(resp["truncated"])
        rs = resp["results"]
        self.assertEqual(len(rs), 5)
        self.assertEqual(rs[0]["ok"]["content"], "alpha")
        self.assertEqual(rs[1]["ok"]["path"], self.host.root)
        self.assertEqual(rs[2]["ok"]["size"], 4)
        # v2.3.1 (F4): a missing file is not_found with a real message,
        # not the old not_a_file with an empty one.
        self.assertEqual(rs[3]["error"], "not_found")
        self.assertIn("No such file", rs[3]["message"])
        self.assertEqual(rs[4]["error"], "unknown_op")

    def test_write_ops_under_auto(self):
        ops = [
            {"op": "mkdir", "path": os.path.join(self.host.root, "d1")},
            {"op": "write", "path": os.path.join(self.host.root, "d1/x.txt"),
             "content": "hi"},
        ]
        resp, status = self.host.post("/batch", {"ops": ops})
        self.assertEqual(status, 200)
        self.assertTrue(resp["results"][0]["ok"]["created"])
        self.assertEqual(resp["results"][1]["ok"]["bytes"], 2)
        with open(os.path.join(self.host.root, "d1/x.txt")) as f:
            self.assertEqual(f.read(), "hi")

    def test_strict_rejects_batch_writes_but_allows_reads(self):
        host = TestHost(settings={"approval_policy": "strict"})
        try:
            make_tree(host.root, {"a.txt": "x"})
            resp, status = host.post("/batch", {"ops": [
                {"op": "write", "path": os.path.join(host.root, "w.txt"),
                 "content": "x"}]})
            self.assertEqual(status, 400)
            self.assertEqual(resp["error"], "batch_policy")
            resp, status = host.post("/batch", {"ops": [
                {"op": "read", "path": os.path.join(host.root, "a.txt")}]})
            self.assertEqual(status, 200)
            self.assertEqual(resp["results"][0]["ok"]["content"], "x")
        finally:
            host.stop()

    def test_too_many_ops(self):
        ops = [{"op": "list", "path": self.host.root}] * 65
        resp, status = self.host.post("/batch", {"ops": ops})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "batch_too_large")

    def test_response_cap(self):
        make_tree(self.host.root, {"huge.txt": "y" * (2 * 1024 * 1024)})
        ops = [{"op": "read",
                "path": os.path.join(self.host.root, "huge.txt")}] * 5
        resp, status = self.host.post("/batch", {"ops": ops})
        self.assertEqual(status, 200)
        self.assertTrue(resp["truncated"])
        self.assertEqual(resp["results"][-1]["error"], "batch_response_cap")


# ---------------------------------------------------------------------------
# F3: archives
# ---------------------------------------------------------------------------

class TestArchive(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def _get_archive(self, host, path, all_flag=False):
        conn = http.client.HTTPConnection("127.0.0.1", host.port, timeout=30)
        q = f"/archive?path={path}"
        if all_flag:
            q += "&all=1"
        conn.request("GET", q,
                     headers={"Authorization": f"Bearer {host.key}"})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    @staticmethod
    def _make_tar(files: dict) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, content in files.items():
                ti = tarfile.TarInfo(name)
                data = content.encode()
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
        return buf.getvalue()

    def test_roundtrip(self):
        make_tree(self.host.root, {
            "src/a.txt": "alpha",
            "src/sub/b.txt": "beta",
            "src/node_modules/ignored.js": "junk",
            "src/.secret": "hidden",
        })
        status, data = self._get_archive(
            self.host, os.path.join(self.host.root, "src"))
        self.assertEqual(status, 200)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            names = set(tf.getnames())
        self.assertIn("a.txt", names)
        self.assertIn("sub/b.txt", names)
        self.assertNotIn("node_modules/ignored.js", names)
        self.assertNotIn(".secret", names)

        dest = os.path.join(self.host.root, "restored")
        resp, status = self.host.post("/archive", {
            "path": dest, "archive_b64": base64.b64encode(data).decode()})
        self.assertEqual(status, 200)
        self.assertEqual(resp["files"], 2)
        with open(os.path.join(dest, "sub/b.txt")) as f:
            self.assertEqual(f.read(), "beta")

        # Extracting again without overwrite must refuse (409)...
        resp, status = self.host.post("/archive", {
            "path": dest, "archive_b64": base64.b64encode(data).decode()})
        self.assertEqual(status, 409)
        # ... and succeed with overwrite=true.
        resp, status = self.host.post("/archive", {
            "path": dest, "archive_b64": base64.b64encode(data).decode(),
            "overwrite": True})
        self.assertEqual(status, 200)

    def test_all_flag_includes_hidden(self):
        make_tree(self.host.root, {"src/.dotfile": "d",
                                   "src/node_modules/x.js": "junk",
                                   "src/.git/config": "gitstuff"})
        status, data = self._get_archive(
            self.host, os.path.join(self.host.root, "src"), all_flag=True)
        self.assertEqual(status, 200)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            names = set(tf.getnames())
        self.assertIn(".dotfile", names)
        self.assertIn("node_modules/x.js", names)
        self.assertNotIn(".git/config", names,
                         ".git must NEVER be archived, even with all=1")

    def test_traversal_member_rejected(self):
        blob = self._make_tar({"ok.txt": "fine", "../evil.txt": "bad"})
        resp, status = self.host.post("/archive", {
            "path": self.host.root,
            "archive_b64": base64.b64encode(blob).decode()})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "archive_bad_member")

    def test_symlink_member_rejected(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            ti = tarfile.TarInfo("link")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "/etc/passwd"
            tf.addfile(ti)
        resp, status = self.host.post("/archive", {
            "path": self.host.root,
            "archive_b64": base64.b64encode(buf.getvalue()).decode()})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "archive_bad_member")

    def test_git_member_rejected_on_put(self):
        blob = self._make_tar({".git/hooks/x": "nope"})
        resp, status = self.host.post("/archive", {
            "path": self.host.root,
            "archive_b64": base64.b64encode(blob).decode()})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "archive_bad_member")


# ---------------------------------------------------------------------------
# F7: approval grants
# ---------------------------------------------------------------------------

class TestGrants(unittest.TestCase):
    def setUp(self):
        self.host = TestHost(settings={"approval_policy": "strict"})
        self.agent = self.host.agents[0]

    def tearDown(self):
        self.host.stop()

    def test_grant_short_circuits_strict_write(self):
        # Grant a SUBTREE of a shared root (grants never widen the
        # sandbox — the path still has to resolve inside shared roots).
        scope = os.path.join(self.host.root, "grantscope")
        os.makedirs(scope, exist_ok=True)
        api.add_grant(self.host.ctx, "default", "write", scope, 30)
        target = os.path.join(scope, "f.txt")
        resp, status = self.host.post("/write",
                                      {"path": target, "content": "ok"})
        self.assertEqual(status, 200)
        # No approval was ever queued for the granted path.
        self.assertEqual(self.host.ctx.approvals.pending(), [])

    def test_grant_scope_and_op_matching(self):
        scope = self.host._mkroot("grantscope2")
        api.add_grant(self.host.ctx, "default", "write", scope, 30)
        self.assertTrue(api._grant_covers(
            self.host.ctx, self.agent, "write", os.path.join(scope, "a.txt")))
        self.assertFalse(api._grant_covers(
            self.host.ctx, self.agent, "delete",
            os.path.join(scope, "a.txt")))
        self.assertFalse(api._grant_covers(
            self.host.ctx, self.agent, "write",
            os.path.join(self.host.root, "elsewhere.txt")))

    def test_expired_grants_ignored(self):
        self.host.ctx.settings["grants"] = [{
            "id": "gra_old", "agent": "default", "ops": ["write"],
            "scope": self.host.root,
            "expires_at": "2000-01-01T00:00:00+00:00"}]
        self.assertFalse(api._grant_covers(
            self.host.ctx, self.agent, "write",
            os.path.join(self.host.root, "f.txt")))
        resp, status = self.host.get("/grants")
        self.assertEqual(status, 200)
        self.assertEqual(resp["grants"], [])

    def test_grants_route_lists_active(self):
        api.add_grant(self.host.ctx, "default", "write", self.host.root, 60)
        resp, status = self.host.get("/grants")
        self.assertEqual(status, 200)
        self.assertEqual(len(resp["grants"]), 1)
        g = resp["grants"][0]
        self.assertEqual(g["ops"], ["write"])
        self.assertEqual(g["scope"], self.host.root)
        self.assertTrue(g["id"].startswith("gra_"))

    def test_add_grant_merges_same_scope(self):
        api.add_grant(self.host.ctx, "default", "write", self.host.root, 30)
        api.add_grant(self.host.ctx, "default", "mkdir", self.host.root, 30)
        grants = self.host.ctx.settings["grants"]
        self.assertEqual(len(grants), 1)
        self.assertCountEqual(grants[0]["ops"], ["write", "mkdir"])


# ---------------------------------------------------------------------------
# CLI: download fix (W5), exec --json (F6), batch/archive/grants, gzip client
# ---------------------------------------------------------------------------

class TestCLIV230(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.tmp = tempfile.mkdtemp(prefix="llmac-cli-")

    def tearDown(self):
        self.host.stop()
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_download_works(self):
        # W5: `download` used to crash with AttributeError (missing
        # --lines/--offset/--limit on its subparser).
        blob = os.urandom(2048)
        with open(os.path.join(self.host.root, "big.bin"), "wb") as f:
            f.write(blob)
        out = os.path.join(self.tmp, "big.bin")
        p = run_cli(self.host, "download",
                    "--path", os.path.join(self.host.root, "big.bin"),
                    "--to", out)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(out, "rb") as f:
            self.assertEqual(f.read(), blob)

    def test_exec_json(self):
        p = run_cli(self.host, "exec", "--command", "echo hi", "--json")
        self.assertEqual(p.returncode, 0, p.stderr)
        out = json.loads(p.stdout)
        self.assertEqual(out["returncode"], 0)
        self.assertEqual(out["stdout"], "hi\n")

    def test_batch_cli(self):
        make_tree(self.host.root, {"a.txt": "one", "b.txt": "two"})
        ops = [{"op": "read", "path": os.path.join(self.host.root, "a.txt")},
               {"op": "read", "path": os.path.join(self.host.root, "zzz")}]
        p = run_cli(self.host, "batch", "--ops", json.dumps(ops))
        self.assertEqual(p.returncode, 0, p.stderr)
        # v2.3.1: plain mode shows a bounded read preview (F27) and a
        # missing file reports not_found with the path (F4).
        self.assertIn("[0] read: ok", p.stdout)
        self.assertIn("a.txt | one", p.stdout)
        self.assertIn("not_found", p.stdout)
        self.assertIn("zzz", p.stdout)

    def test_archive_cli_roundtrip(self):
        make_tree(self.host.root, {"src/x.txt": "ex", "src/d/y.txt": "why"})
        tgz = os.path.join(self.tmp, "src.tgz")
        p = run_cli(self.host, "archive", "--get",
                    "--path", os.path.join(self.host.root, "src"),
                    "--to", tgz)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(os.path.exists(tgz))
        dest = os.path.join(self.host.root, "restored-cli")
        p = run_cli(self.host, "archive", "--put", "--path", dest,
                    "--file", tgz)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(os.path.join(dest, "d/y.txt")) as f:
            self.assertEqual(f.read(), "why")

    def test_grants_cli(self):
        api.add_grant(self.host.ctx, "default", "write", self.host.root, 30)
        p = run_cli(self.host, "grants")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("[write]", p.stdout)
        self.assertIn(self.host.root, p.stdout)

    def test_cli_gzip_transport_transparent(self):
        # The client always sends Accept-Encoding: gzip and must decode
        # compressed responses transparently (F1 client side).
        make_tree(self.host.root, {"big.txt": "q" * (GZIP_MIN_BYTES * 8)})
        p = run_cli(self.host, "read",
                    "--path", os.path.join(self.host.root, "big.txt"))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("q" * 40, p.stdout)


if __name__ == "__main__":
    unittest.main()
