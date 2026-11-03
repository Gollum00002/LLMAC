"""v2.4.0 Tier A — agent-efficiency client features.

Covers:
  A1  deploy: happy path + dry-run + manifest + per-op failure (protected
      path) + --no-verify + chunk packing under the 64-op / 4 MB caps
  A2  run: multi-command over one TLS session, stop-at-first-failure,
      --keep-going, run-inside-run rejected, client cache reuse
  A3  exec: pre-flight lint ($(...), backticks, $VAR; --i-know bypass)
      and the always-on [rc=N] footer (plain mode only)
  A4  read: smart truncation of large text files (head 200 + tail 50 +
      stderr marker), --raw byte-exact opt-out, ranges unaffected,
      small files unaffected, --to unaffected
  A5  VERSION derived from core.constants (repo) + standalone fallback
  W6  download without --to goes to stdout, never a file named '-'
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost
from core.sandbox import Sandbox

CLI = os.path.join(_PARENT, "llmac.py")


def run_cli(host, *args, timeout=90, cwd=None):
    return subprocess.run(
        [sys.executable, CLI, "--plain", "--host", "127.0.0.1",
         "--port", str(host.port), "--key", host.key, *args],
        capture_output=True, text=True, timeout=timeout, cwd=cwd)


def load_cli_module():
    """Import llmac.py as a module for unit-testing pure functions."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("llmac_cli_test", CLI)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# A5: version
# ---------------------------------------------------------------------------

class TestVersion(unittest.TestCase):
    def test_version_flag_reports_core_version(self):
        r = subprocess.run([sys.executable, CLI, "--version"],
                           capture_output=True, text=True, cwd=_PARENT)
        self.assertEqual(r.returncode, 0)
        self.assertIn("llmac 2.7.3", r.stdout)
        self.assertNotIn("2.3.0", r.stdout)

    def test_standalone_fallback_without_core(self):
        """The bootstrap file works alone: no core/ next to it -> the
        ImportError branch supplies the version literal."""
        with tempfile.TemporaryDirectory() as td:
            shutil = __import__("shutil")
            shutil.copyfile(CLI, os.path.join(td, "llmac.py"))
            r = subprocess.run([sys.executable, "llmac.py", "--version"],
                               capture_output=True, text=True, cwd=td)
            self.assertEqual(r.returncode, 0)
            self.assertIn("llmac 2.7.3", r.stdout)


# ---------------------------------------------------------------------------
# A3: exec lint + rc footer
# ---------------------------------------------------------------------------

class TestExecLint(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def _lint_refused(self, command, expect_local_shell=True):
        r = run_cli(self.host, "exec", "--command", command)
        self.assertEqual(r.returncode, 2)
        self.assertIn("PRE-FLIGHT LINT", r.stderr)
        if expect_local_shell:
            self.assertIn("LOCAL shell", r.stderr)

    def test_substitution_refused(self):
        self._lint_refused("echo $(pwd)")

    def test_backtick_refused(self):
        self._lint_refused("echo `id`")

    def test_var_refused(self):
        self._lint_refused("echo $HOME", expect_local_shell=False)

    def test_i_know_bypasses_client_lint(self):
        r = run_cli(self.host, "exec", "--command", "echo $HOME", "--i-know")
        self.assertNotIn("PRE-FLIGHT LINT", r.stderr)
        # (the SERVER may still reject the variable; that is its business)

    def test_clean_command_not_linted(self):
        r = run_cli(self.host, "exec", "--command", "echo lint-free")
        self.assertEqual(r.returncode, 0)
        self.assertIn("lint-free", r.stdout)


class TestExecRcFooter(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()

    def tearDown(self):
        self.host.stop()

    def test_footer_zero(self):
        r = run_cli(self.host, "exec", "--command", "true")
        self.assertEqual(r.returncode, 0)
        self.assertIn("[rc=0]", r.stderr)

    def test_footer_nonzero_propagates(self):
        r = run_cli(self.host, "exec", "--command", "exit 7")
        self.assertEqual(r.returncode, 7)
        self.assertIn("[rc=7]", r.stderr)

    def test_json_mode_has_no_footer(self):
        r = run_cli(self.host, "exec", "--command", "true", "--json")
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("[rc=", r.stdout + r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["returncode"], 0)


# ---------------------------------------------------------------------------
# A4: smart read
# ---------------------------------------------------------------------------

class TestSmartRead(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.small = os.path.join(self.host.root, "small.txt")
        self.host.post("/write", {"path": self.small, "content": "a\nb\nc\n"})
        lines = [f"line-{i:04d}-" + "x" * 70 for i in range(600)]
        self.content = "\n".join(lines) + "\n"
        self.big = os.path.join(self.host.root, "big.txt")
        r, s = self.host.post("/write", {"path": self.big,
                                        "content": self.content})
        assert s == 200, r

    def tearDown(self):
        self.host.stop()

    def test_smart_truncation(self):
        r = run_cli(self.host, "read", "--path", self.big)
        self.assertEqual(r.returncode, 0)
        self.assertIn("smart-truncated", r.stderr)
        self.assertIn("lines omitted", r.stderr)
        self.assertIn("line-0000", r.stdout)          # head kept
        self.assertIn("line-0599", r.stdout)         # tail kept
        self.assertNotIn("line-0300", r.stdout)      # middle omitted
        self.assertLess(len(r.stdout), len(self.content) / 2)

    def test_raw_is_byte_exact(self):
        r = run_cli(self.host, "read", "--path", self.big, "--raw")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout, self.content)
        self.assertNotIn("smart-truncated", r.stderr)

    def test_ranges_unaffected(self):
        r = run_cli(self.host, "read", "--path", self.big, "--lines", "1-3")
        self.assertEqual(r.returncode, 0)
        self.assertNotIn("smart-truncated", r.stderr)
        self.assertIn("line-0000", r.stdout)
        self.assertIn("line-0002", r.stdout)
        self.assertNotIn("line-0003", r.stdout)

    def test_small_file_unaffected(self):
        r = run_cli(self.host, "read", "--path", self.small)
        self.assertEqual(r.stdout, "a\nb\nc\n")
        self.assertNotIn("smart-truncated", r.stderr)

    def test_to_unaffected(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "out.txt")
            r = run_cli(self.host, "read", "--path", self.big, "--to", out)
            self.assertEqual(r.returncode, 0)
            with open(out) as f:
                self.assertEqual(f.read(), self.content)

    def test_w6_download_default_is_stdout_not_dash_file(self):
        with tempfile.TemporaryDirectory() as td:
            r = run_cli(self.host, "download", "--path", self.small, cwd=td)
            self.assertEqual(r.returncode, 0)
            self.assertEqual(r.stdout, "a\nb\nc\n")
            self.assertFalse(os.path.exists(os.path.join(td, "-")))


# ---------------------------------------------------------------------------
# A2: run
# ---------------------------------------------------------------------------

class TestRun(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.small = os.path.join(self.host.root, "small.txt")
        self.host.post("/write", {"path": self.small, "content": "RUNTOK\n"})
        self.td = tempfile.mkdtemp(prefix="llmac-run-")
        self.cmds = os.path.join(self.td, "cmds.json")

    def tearDown(self):
        self.host.stop()
        import shutil
        shutil.rmtree(self.td, ignore_errors=True)

    def _write_cmds(self, vectors):
        with open(self.cmds, "w") as f:
            json.dump(vectors, f)

    def test_happy_path(self):
        self._write_cmds([["read", "--path", self.small],
                          ["stat", "--path", self.small],
                          ["session", "status"]])
        r = run_cli(self.host, "run", "--file", self.cmds)
        self.assertEqual(r.returncode, 0)
        self.assertIn("RUNTOK", r.stdout)
        self.assertIn("3/3 commands", r.stderr)
        self.assertIn("all ok", r.stderr)
        self.assertEqual(r.stderr.count("=== ["), 3)

    def test_stops_at_first_failure(self):
        self._write_cmds([["read", "--path", "/nonexistent-xyz"],
                          ["read", "--path", self.small]])
        r = run_cli(self.host, "run", "--file", self.cmds)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("1/2", r.stderr)
        self.assertNotIn("RUNTOK", r.stdout)   # second command never ran

    def test_keep_going(self):
        self._write_cmds([["read", "--path", "/nonexistent-xyz"],
                          ["read", "--path", self.small]])
        r = run_cli(self.host, "run", "--file", self.cmds, "--keep-going")
        self.assertNotEqual(r.returncode, 0)          # still reports failure
        self.assertIn("2/2", r.stderr)
        self.assertIn("RUNTOK", r.stdout)

    def test_run_inside_run_rejected(self):
        self._write_cmds([["run", "--file", self.cmds]])
        r = run_cli(self.host, "run", "--file", self.cmds)
        self.assertEqual(r.returncode, 2)

    def test_bad_vectors_rejected(self):
        self._write_cmds([["read"], 42])
        r = run_cli(self.host, "run", "--file", self.cmds)
        self.assertEqual(r.returncode, 2)

    def test_client_cache_reuses_one_client(self):
        mod = load_cli_module()
        mod._CLIENT_CACHE.clear()
        ns = SimpleNamespace(host="127.0.0.1", port=12345, key="k",
                              fp="", plain=True, retry=0, conn=None,
                              no_verify=False)
        c1 = mod._client_from_args(ns)
        c2 = mod._client_from_args(ns)
        self.assertIs(c1, c2)
        ns2 = SimpleNamespace(**vars(ns))
        ns2.key = "other"
        c3 = mod._client_from_args(ns2)
        self.assertIsNot(c1, c3)


# ---------------------------------------------------------------------------
# A1: deploy
# ---------------------------------------------------------------------------

class TestDeploy(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.td = tempfile.mkdtemp(prefix="llmac-deploy-")
        self.l1 = os.path.join(self.td, "f1.txt")
        self.l2 = os.path.join(self.td, "f2.bin")
        with open(self.l1, "w") as f:
            f.write("deploy one\n")
        with open(self.l2, "wb") as f:
            f.write(bytes(range(256)))       # non-UTF8 -> content_b64 path
        self.r1 = os.path.join(self.host.root, "deploy", "f1.txt")
        self.r2 = os.path.join(self.host.root, "deploy", "f2.bin")

    def tearDown(self):
        self.host.stop()
        import shutil
        shutil.rmtree(self.td, ignore_errors=True)

    def test_happy_path_verified(self):
        r = run_cli(self.host, "deploy", "--pairs", f"{self.l1}={self.r1}",
                    "--pairs", f"{self.l2}={self.r2}")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("2/2 verified", r.stdout)
        resp, s = self.host.post("/read", {"path": self.r1})
        self.assertEqual(resp.get("content"), "deploy one\n")
        resp, s = self.host.post("/read", {"path": self.r2})
        import base64
        self.assertEqual(base64.b64decode(resp["content_b64"]),
                         bytes(range(256)))

    def test_dry_run_touches_nothing(self):
        r = run_cli(self.host, "deploy", "--pairs", f"{self.l1}={self.r1}",
                    "--dry-run")
        self.assertEqual(r.returncode, 0)
        self.assertIn("would deploy 1 files", r.stdout)
        resp, s = self.host.post("/read", {"path": self.r1})
        self.assertEqual(resp.get("error"), "not_found")

    def test_manifest_form(self):
        m = os.path.join(self.td, "manifest.json")
        with open(m, "w") as f:
            json.dump({"files": [{"local": self.l1, "remote": self.r1},
                                 {"local": self.l2, "remote": self.r2}]}, f)
        r = run_cli(self.host, "deploy", "--manifest", m)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("2/2 verified", r.stdout)

    def test_no_verify(self):
        r = run_cli(self.host, "deploy", "--pairs", f"{self.l1}={self.r1}",
                    "--no-verify")
        self.assertEqual(r.returncode, 0)
        self.assertIn("verification skipped", r.stdout)

    def test_per_op_failure_refuses_everything(self):
        # make a protected tree inside the shared root, then target it
        inside = os.path.join(self.host.root, "vault")
        os.makedirs(inside, exist_ok=True)
        self.host.ctx.sandbox = Sandbox([self.host.root], protected=[inside])
        target = os.path.join(inside, "f1.txt")
        r = run_cli(self.host, "deploy", "--pairs", f"{self.l1}={target}")
        self.assertEqual(r.returncode, 1)
        self.assertIn("deploy failed for 1 file(s)", r.stderr)
        self.assertIn("protected", r.stderr)

    def test_local_file_missing(self):
        r = run_cli(self.host, "deploy", "--pairs",
                    f"{self.td}/nope.txt={self.r1}")
        self.assertEqual(r.returncode, 2)
        self.assertIn("local file not found", r.stderr)

    def test_relative_remote_rejected(self):
        r = run_cli(self.host, "deploy", "--pairs", f"{self.l1}=relative/x")
        self.assertEqual(r.returncode, 2)

    def test_chunk_packing(self):
        mod = load_cli_module()
        tiny = [{"op": "write", "path": "/x", "content": "y"}] * 70
        self.assertEqual(len(mod._deploy_chunks(tiny)), 2)
        self.assertEqual(len(mod._deploy_chunks(tiny[:64])), 1)
        self.assertEqual(len(mod._deploy_chunks(tiny[:65])), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
