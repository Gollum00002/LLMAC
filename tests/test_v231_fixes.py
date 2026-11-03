"""LLMAC v2.3.1 regression tests — one (or more) per stress-test fix.

Covers:
  F21/F22  server's own data dir is a protected tree (read/write/edit/stat/
           list/search/archive/exec all refuse; walkers never leak contents)
  F14      cp copies symlinks as links, never materializes targets
  F16      output-redirect write targets must be inside the sandbox
           (/dev/null & co exempt); input redirects keep the read whitelist
  F18      privilege-escalator token denylist (sudo/su/doas/pkexec/sudoedit)
  F20      BoundedCapture is linear + head/tail/marker correct; exec pump
           emits exact stdout
  F28      NUL/control-byte files read back as binary base64, not NUL soup
  F4       read of a missing file -> not_found + message
  F5       user-caused OSErrors -> clean 4xx (os_error / access_denied)
  F11      edit insert/append no longer add a stray blank line
  F6       replace no-match error quotes the needle
  F12      atomic-write temp names fit in 255-byte components
  F29/F29a archive GET refuses over-cap trees; not_a_directory -> 404 JSON
  F30      global auth failure counter throttles across IPs
  F19      exec with a refused cwd -> server 403, CLI exit 2
  F1/F2    connect verifies an explicitly pinned fp; probe failures fail closed
  NEW      'auto_all' policy: share requests are granted instantly, the
           sandbox actually grows, the queue is set for the owner app, and
           'auto' still human-gates shares
"""
import base64
import errno
import http.client
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost, make_tree
import core.api as api
from core.constants import (
    EXEC_OUTPUT_CAP, MAX_ARCHIVE_ENTRIES,
)
from core.sandbox import Sandbox, ProtectedPathError

CLI = os.path.join(_PARENT, "llmac.py")


def run_cli(host, *args, timeout=90):
    return subprocess.run(
        [sys.executable, CLI, "--plain", "--host", "127.0.0.1",
         "--port", str(host.port), "--key", host.key, *args],
        capture_output=True, text=True, timeout=timeout)


def get_archive_raw(host, path, all_flag=False):
    conn = http.client.HTTPConnection("127.0.0.1", host.port, timeout=60)
    q = f"/archive?path={path}" + ("&all=1" if all_flag else "")
    conn.request("GET", q, headers={"Authorization": f"Bearer {host.key}"})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


# ---------------------------------------------------------------------------
# F21/F22 — the server's own data dir is off-limits through every surface
# ---------------------------------------------------------------------------

class TestProtectedDataDir(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        # The data dir sits NEXT TO the root, not inside it; move it inside
        # to prove protection works even when the tree is shared.
        real_data = self.host.data_dir
        inside = os.path.join(self.host.root, "bridge_data")
        shutil.rmtree(inside, ignore_errors=True)
        shutil.copytree(real_data, inside)
        # Rebuild the sandbox with the data dir inside the shared root.
        self.host.ctx.sandbox = Sandbox([self.host.root],
                                        protected=[inside])
        self.protected = inside
        # Put a juicy secret in it.
        os.makedirs(os.path.join(inside, "tls"), exist_ok=True)
        with open(os.path.join(inside, "state.json"), "w") as f:
            f.write('{"keys": ["llmac_SUPERSECRET"]}')
        with open(os.path.join(inside, "tls", "server.key"), "w") as f:
            f.write("PRIVATE KEY MATERIAL")

    def tearDown(self):
        self.host.stop()

    def test_read_refused(self):
        resp, status = self.host.post(
            "/read", {"path": os.path.join(self.protected, "state.json")})
        self.assertEqual(status, 403)
        self.assertEqual(resp["error"], "protected_path")
        self.assertIn("off-limits", resp["message"])

    def test_write_refused(self):
        resp, status = self.host.post(
            "/write", {"path": os.path.join(self.protected, "pwn.txt"),
                       "content": "x"})
        self.assertEqual(status, 403)
        self.assertEqual(resp["error"], "protected_path")

    def test_edit_and_stat_refused(self):
        p = os.path.join(self.protected, "state.json")
        r1, s1 = self.host.post("/edit", {"path": p, "ops": [
            {"op": "replace", "find": "keys", "replace": "oops"}]})
        self.assertEqual(s1, 403)
        self.assertEqual(r1["error"], "protected_path")
        r2, s2 = self.host.post("/stat", {"path": p})
        self.assertEqual(s2, 403)
        self.assertEqual(r2["error"], "protected_path")

    def test_list_refused(self):
        resp, status = self.host.post("/list",
                                      {"path": self.protected})
        self.assertEqual(status, 403)
        self.assertEqual(resp["error"], "protected_path")

    def test_search_from_parent_finds_nothing_inside(self):
        make_tree(self.host.root, {"outside.txt": "llmac_SUPERSECRET"})
        resp, status = self.host.post(
            "/search", {"query": "SUPERSECRET", "path": self.host.root,
                        "all": True})
        self.assertEqual(status, 200)
        paths = [m["path"] for m in resp["matches"]]
        self.assertEqual(len(paths), 1)
        self.assertIn("outside.txt", paths[0])
        for p in paths:
            self.assertNotIn("bridge_data", p)

    def test_tree_from_parent_excludes_data_dir(self):
        resp, status = self.host.post(
            "/tree", {"path": self.host.root, "depth": 2, "all": True})
        self.assertEqual(status, 200)
        names = [e["name"] for e in resp["entries"]]
        self.assertNotIn("bridge_data", names)

    def test_archive_get_excludes_data_dir(self):
        status, data = get_archive_raw(self.host, self.host.root,
                                       all_flag=True)
        self.assertEqual(status, 200)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            names = tf.getnames()
        self.assertFalse([n for n in names if "bridge_data" in n])

    def test_exec_cannot_read_data_dir(self):
        resp, status = self.host.post("/exec", {
            "command": f"cat {self.protected}/state.json",
            "cwd": self.host.root})
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("rejected"))
        self.assertIn("off-limits", resp["stderr"])

    def test_exec_cannot_write_data_dir_via_redirect(self):
        resp, status = self.host.post("/exec", {
            "command": f"echo x > {self.protected}/dropped.txt",
            "cwd": self.host.root})
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("rejected"))


# ---------------------------------------------------------------------------
# F14 — cp must copy symlinks AS LINKS
# ---------------------------------------------------------------------------

class TestCopySymlinks(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_cp_does_not_materialize_target(self):
        src = os.path.join(self.host.root, "src")
        os.makedirs(src, exist_ok=True)
        # A symlink pointing outside (as if created by an earlier exec or
        # any host-side process).
        os.symlink("/etc", os.path.join(src, "esc"))
        resp, status = self.host.post("/copy", {
            "src": src, "dest": os.path.join(self.host.root, "copy")})
        self.assertEqual(status, 200)
        link = os.path.join(self.host.root, "copy", "esc")
        self.assertTrue(os.path.islink(link),
                        "the copy must contain a LINK, not a materialized /etc")
        self.assertEqual(os.readlink(link), "/etc")
        # Reading through the copy of the link is blocked by containment.
        r2, s2 = self.host.post("/read", {"path": link + "/passwd"})
        self.assertEqual(s2, 403)


# ---------------------------------------------------------------------------
# F16 — output-redirect write targets must stay inside the sandbox
# ---------------------------------------------------------------------------

class TestRedirectWriteSplit(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_write_to_tmp_refused(self):
        resp, status = self.host.post("/exec", {
            "command": "echo pwn > /tmp/llmac_f16_test.txt",
            "cwd": self.host.root})
        self.assertEqual(status, 200)
        self.assertTrue(resp.get("rejected"))
        self.assertIn("redirect target", resp["stderr"].lower())

    def test_dev_null_and_inside_still_allowed(self):
        for cmd in ("echo hi > /dev/null",
                    f"echo hi > {self.host.root}/ok.txt"):
            resp, status = self.host.post("/exec", {"command": cmd,
                                                    "cwd": self.host.root})
            self.assertEqual(status, 200, cmd)
            self.assertFalse(resp.get("rejected"), cmd)

    def test_input_redirect_keeps_read_whitelist(self):
        resp, status = self.host.post("/exec", {
            "command": "wc -c < /etc/hostname", "cwd": self.host.root})
        self.assertEqual(status, 200)
        self.assertFalse(resp.get("rejected"))


# ---------------------------------------------------------------------------
# F18 — privilege escalators are banned at token granularity
# ---------------------------------------------------------------------------

class TestEscalatorDenylist(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_sudo_rejected(self):
        for cmd in ("sudo reboot", "echo hi && sudo id", "doas id"):
            resp, status = self.host.post("/exec", {"command": cmd,
                                                    "cwd": self.host.root})
            self.assertEqual(status, 200, cmd)
            self.assertTrue(resp.get("rejected"), cmd)
            self.assertIn("privilege-escalation", resp["stderr"])


# ---------------------------------------------------------------------------
# F20 — capture must be linear and correct
# ---------------------------------------------------------------------------

class TestBoundedCapture(unittest.TestCase):
    def test_head_tail_marker_semantics(self):
        cap = api._BoundedCapture(cap=1000)
        cap.feed(b"A" * 1000)
        self.assertEqual(cap.total, 1000)
        self.assertEqual(len(cap.head), 1000)
        cap.feed(b"B" * 1000)
        # head keeps the first chunk (1000 == cap) + marker + tail window
        text = cap.text()
        self.assertIn("bytes truncated, 2000 total", text)
        self.assertIn("AAA", text)
        self.assertIn("BBB", text)

    def test_feed_is_fast_for_many_small_chunks(self):
        cap = api._BoundedCapture()
        chunk = b"x" + b"0123456789" * 63 + b"\n"      # 641B lines
        t0 = time.monotonic()
        for _ in range(20000):                          # ~12.8MB
            cap.feed(chunk)
        cap.text()
        dt = time.monotonic() - t0
        self.assertLess(dt, 8.0,
                        f"12.8MB in 20k chunks took {dt:.1f}s — "
                        "regression to quadratic behavior")
        self.assertGreater(cap.total, EXEC_OUTPUT_CAP)

    def test_exec_binary_pump_exact_output(self):
        host = TestHost()
        try:
            resp, status = host.post("/exec", {
                "command": "seq 1 100", "cwd": host.root})
            self.assertEqual(status, 200)
            self.assertFalse(resp.get("truncated"))
            self.assertEqual(resp["stdout"],
                             "".join(f"{i}\n" for i in range(1, 101)))
        finally:
            host.stop()


# ---------------------------------------------------------------------------
# F28 — binary-looking text files come back as base64
# ---------------------------------------------------------------------------

class TestBinaryDetection(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        with open(os.path.join(self.host.root, "zeros.bin"), "wb") as f:
            f.write(b"\x00" * 4096)
        with open(os.path.join(self.host.root, "ctrl.txt"), "wb") as f:
            f.write(b"hello\x01world\n")

    def tearDown(self):
        self.host.stop()

    def test_nul_file_is_binary_b64(self):
        resp, status = self.host.post(
            "/read", {"path": os.path.join(self.host.root, "zeros.bin")})
        self.assertEqual(status, 200)
        self.assertTrue(resp["binary"])
        self.assertEqual(base64.b64decode(resp["content_b64"]),
                         b"\x00" * 4096)

    def test_control_char_file_is_binary(self):
        resp, status = self.host.post(
            "/read", {"path": os.path.join(self.host.root, "ctrl.txt")})
        self.assertEqual(status, 200)
        self.assertTrue(resp["binary"])

    def test_normal_text_stays_text(self):
        with open(os.path.join(self.host.root, "t.txt"), "w") as f:
            f.write("plain\ntext\n")
        resp, _ = self.host.post(
            "/read", {"path": os.path.join(self.host.root, "t.txt")})
        self.assertFalse(resp["binary"])
        self.assertEqual(resp["content"], "plain\ntext\n")


# ---------------------------------------------------------------------------
# F4 / F5 / F11 / F6 / F12 — quick quality fixes
# ---------------------------------------------------------------------------

class TestQuickFixes(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_read_missing_not_found(self):
        resp, status = self.host.post(
            "/read", {"path": os.path.join(self.host.root, "ghost")})
        # v2.4.1: handler errors now carry real HTTP statuses (was 200
        # + error dict); the body shape is unchanged for old clients.
        self.assertEqual(status, 404)
        self.assertEqual(resp["error"], "not_found")
        self.assertIn("ghost", resp["message"])

    def test_os_error_is_clean_4xx(self):
        long_name = "L" * 300
        resp, status = self.host.post(
            "/write", {"path": os.path.join(self.host.root, long_name),
                       "content": "x"})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "os_error")
        self.assertEqual(resp["errno"], errno.ENAMETOOLONG)
        self.assertNotIn("Traceback", resp.get("message", ""))

    def test_edit_insert_no_double_newline(self):
        p = os.path.join(self.host.root, "f.txt")
        with open(p, "w") as f:
            f.write("a\nb\nc\n")
        resp, status = self.host.post("/edit", {"path": p, "ops": [
            {"op": "insert", "content": "X\n", "before_line": 2}]})
        self.assertEqual(status, 200)
        with open(p) as f:
            self.assertEqual(f.read(), "a\nX\nb\nc\n")

    def test_edit_append_no_double_newline(self):
        p = os.path.join(self.host.root, "f2.txt")
        with open(p, "w") as f:
            f.write("a\nb\n")
        resp, status = self.host.post("/edit", {"path": p, "ops": [
            {"op": "append", "content": "tail\n"}]})
        self.assertEqual(status, 200)
        with open(p) as f:
            self.assertEqual(f.read(), "a\nb\ntail\n")

    def test_edit_no_match_message_quotes_needle(self):
        p = os.path.join(self.host.root, "f3.txt")
        with open(p, "w") as f:
            f.write("a\nb\n")
        resp, status = self.host.post("/edit", {"path": p, "ops": [
            {"op": "replace", "find": "NEEDLE", "replace": "x"}]})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "edit_failed")
        self.assertIn("NEEDLE", resp["message"])

    def test_atomic_write_long_filename(self):
        # 250-char final component is legal on ext4; the old ".llmac.tmp"
        # suffix made the TEMP name exceed 255 and the write failed (F12).
        name = "N" * 250
        p = os.path.join(self.host.root, name)
        resp, status = self.host.post("/write", {"path": p,
                                                 "content": "ok"})
        self.assertEqual(status, 200)
        self.assertTrue(os.path.exists(p))
        # no temp litter left behind
        leftovers = [f for f in os.listdir(self.host.root)
                     if f.startswith(".llmac_tmp")]
        self.assertEqual(leftovers, [])


# ---------------------------------------------------------------------------
# F29/F29a — archive GET refuses over-cap trees; errors are real statuses
# ---------------------------------------------------------------------------

class TestArchiveRefusals(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        make_tree(self.host.root,
                  {f"d/f{i}.txt": str(i) for i in range(30)})

    def tearDown(self):
        self.host.stop()

    def test_not_a_directory_is_404_json(self):
        status, data = get_archive_raw(
            self.host, os.path.join(self.host.root, "d/f0.txt"))
        self.assertEqual(status, 404)
        resp = json.loads(data)
        self.assertEqual(resp["error"], "not_a_directory")

    def test_over_cap_refused_not_truncated(self):
        real = api.MAX_ARCHIVE_ENTRIES
        try:
            api.MAX_ARCHIVE_ENTRIES = 10
            status, data = get_archive_raw(self.host, self.host.root)
            self.assertEqual(status, 400)
            resp = json.loads(data)
            self.assertEqual(resp["error"], "archive_too_large")
            self.assertIn("subdirectories", resp["message"])
        finally:
            api.MAX_ARCHIVE_ENTRIES = real

    def test_under_cap_still_works(self):
        status, data = get_archive_raw(self.host, self.host.root)
        self.assertEqual(status, 200)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            self.assertEqual(len(tf.getnames()), 30)


# ---------------------------------------------------------------------------
# F30 — global auth failure counter
# ---------------------------------------------------------------------------

class TestGlobalAuthThrottle(unittest.TestCase):
    def test_global_failures_pause_auth(self):
        host = TestHost()
        try:
            real_max, real_global = api._AUTH_MAX_FAILURES, \
                api._AUTH_GLOBAL_MAX_FAILURES
            api._AUTH_MAX_FAILURES = 10 ** 9   # disable the per-IP gate
            api._AUTH_GLOBAL_MAX_FAILURES = 5
            try:
                for i in range(5):
                    r, s = host.post("/list", {"path": host.root},
                                     key="llmac_wrong_key")
                    self.assertEqual(s, 401)
                # per-IP gate is off; global counter is full:
                r, s = host.post("/list", {"path": host.root},
                                 key="llmac_wrong_key")
                self.assertEqual(s, 429)
                self.assertEqual(r["error"], "rate_limited_global")
                # ...and even the GOOD key is throttled now:
                r, s = host.post("/list", {"path": host.root})
                self.assertEqual(s, 429)
                self.assertEqual(r["error"], "rate_limited_global")
            finally:
                api._AUTH_MAX_FAILURES = real_max
                api._AUTH_GLOBAL_MAX_FAILURES = real_global
        finally:
            host.stop()


# ---------------------------------------------------------------------------
# F19 — exec with a refused cwd exits non-zero on the CLI
# ---------------------------------------------------------------------------

class TestExecCwdExitCode(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_server_returns_403(self):
        resp, status = self.host.post("/exec", {
            "command": "pwd", "cwd": "/etc"})
        self.assertEqual(status, 403)
        self.assertEqual(resp["error"], "forbidden")

    def test_cli_plain_mode_exits_2(self):
        p = run_cli(self.host, "exec", "--command", "pwd", "--cwd", "/etc")
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)

    def test_cli_json_mode_exits_1_with_error_key(self):
        p = run_cli(self.host, "exec", "--command", "pwd",
                    "--cwd", "/etc", "--json")
        self.assertEqual(p.returncode, 1)
        out = json.loads(p.stdout)
        self.assertEqual(out["error"], "forbidden")

    def test_cli_rejected_command_exits_2(self):
        p = run_cli(self.host, "exec", "--command", "cat /etc/passwd")
        self.assertEqual(p.returncode, 2)


# ---------------------------------------------------------------------------
# F1/F2 — connect verifies an explicitly pinned fingerprint
# ---------------------------------------------------------------------------

class TestConnectFingerprint(unittest.TestCase):
    def setUp(self):
        self.host = TestHost(tls=True)
        self.tmp = tempfile.mkdtemp(prefix="llmac-fp-")

    def tearDown(self):
        self.host.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, CLI, *args, "--host", "127.0.0.1",
             "--port", str(self.host.port), "--key", self.host.key],
            capture_output=True, text=True, timeout=60)

    def test_wrong_fp_refused(self):
        p = self._run("connect", "--fp",
                      "SHA256:" + "00" * 32)
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
        self.assertIn("mismatch", (p.stderr + p.stdout))

    def test_probe_failure_fails_closed(self):
        # Point the client at a dead port: the TLS probe must fail and,
        # with a pinned fp, connect must abort instead of skipping
        # verification.
        p = subprocess.run(
            [sys.executable, CLI, "connect", "--host", "127.0.0.1",
             "--port", "1", "--key", "llmac_x",
             "--fp", "SHA256:" + "00" * 32],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
        self.assertIn("probe", (p.stderr + p.stdout).lower())


# ---------------------------------------------------------------------------
# NEW — 'auto_all' policy: agent-driven sandbox expansion
# ---------------------------------------------------------------------------

class TestAutoAllPolicy(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.extra = os.path.join(self.host.tmp, "extra")
        os.makedirs(self.extra, exist_ok=True)
        with open(os.path.join(self.extra, "hello.txt"), "w") as f:
            f.write("hi\n")

    def tearDown(self):
        self.host.stop()

    def _fullauto(self):
        self.host.settings["approval_policy"] = "auto_all"

    def test_share_request_granted_instantly(self):
        self._fullauto()
        resp, status = self.host.post(
            "/roots/request", {"path": self.extra, "reason": "need it"})
        self.assertEqual(status, 200)
        self.assertEqual(resp["status"], "approved")
        self.assertTrue(resp["auto"])
        # the sandbox actually grew
        self.assertIn(os.path.realpath(self.extra),
                      self.host.ctx.sandbox.roots)
        # the owner app has something to persist
        self.assertIn(os.path.realpath(self.extra),
                      self.host.ctx.share_queue)
        # ...and the agent can read the new root right away
        r, s = self.host.post("/read",
                              {"path": os.path.join(self.extra, "hello.txt")})
        self.assertEqual(s, 200)
        self.assertEqual(r["content"], "hi\n")

    def test_info_advertises_auto_roots(self):
        self._fullauto()
        info, _ = self.host.get("/info")
        self.assertEqual(info["approval_policy"], "auto_all")
        self.assertTrue(info["roots_auto_approved"])

    def test_auto_still_human_gates_shares(self):
        # The whole point of the user's report: under plain 'auto' a share
        # request MUST wait for the human.
        resp, status = self.host.post(
            "/roots/request", {"path": self.extra, "reason": "r"})
        self.assertEqual(status, 202)
        self.assertEqual(resp["error"], "approval_pending")
        self.assertNotIn(os.path.realpath(self.extra),
                         self.host.ctx.sandbox.roots)

    def test_scoped_agent_gains_share_in_own_scope(self):
        self._fullauto()
        agent = self.host.agents[0]
        agent["roots"] = [self.host.root]
        self.host.ctx.auth.update(self.host.agents)
        resp, status = self.host.post(
            "/roots/request", {"path": self.extra, "reason": "scoped"})
        self.assertEqual(status, 200)
        self.assertIn(os.path.realpath(self.extra), agent["roots"])

    def test_bad_path_still_refused_under_fullauto(self):
        self._fullauto()
        r, s = self.host.post("/roots/request",
                              {"path": "/definitely/not/here"})
        self.assertEqual(s, 400)          # v2.4.1: real status, was 200
        self.assertEqual(r["error"], "bad_request")
        r, s = self.host.post("/roots/request",
                              {"path": "/mnt"})
        self.assertIn(s, (200,))
        self.assertIn(r["status"], ("approved", "already_shared"))

    def test_cli_reports_auto_approval(self):
        self._fullauto()
        p = run_cli(self.host, "roots", "request",
                    "--path", self.extra, "--reason", "test")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("auto-approved", p.stdout)


if __name__ == "__main__":
    unittest.main()
