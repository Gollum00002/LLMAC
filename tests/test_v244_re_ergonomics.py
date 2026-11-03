"""v2.4.4 — RE (reverse-engineering) ergonomics + client UX.

Scope (re-ranked against the RE-at-scale goal):
  1. Stale-connection UX hint — the client distinguishes "a live
     connection died under me (server restart)" from "could never
     connect at all (down / wrong flags)". The hint lives in ONE
     place (Client._request) so every call site benefits.
  2. exec --save PATH — the RE workflow primitive: stream a command's
     FULL stdout (uncapped, no shell redirect, no quoting games) into
     a host-side file inside the sandbox, then grep / ranged-read /
     diff the artifact. Validated BEFORE the command runs; a bad
     target refuses the op (and in a batch, the WHOLE batch, keeping
     B4 atomicity).
  3. session export — `llmac session export [--out F]` dumps the FULL
     notes log (up to the 100 cap) as a local JSON hand-off artifact.
"""
import json
import os
import sys
import tempfile
import unittest

# The sandbox redirect analyzer (correctly) refuses fd-dup forms like
# `1>&2`, so tests that need stderr use a command that writes to it
# natively instead of shell redirection.
_STDERR_CMD = ("python3 -c \"import sys; "
               "sys.stderr.write('to-err\\n')\"")

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost


# ---------------------------------------------------------------------------
# 1. Client stale-connection hint (pure client, no network)
# ---------------------------------------------------------------------------

class TestStaleConnectionHint(unittest.TestCase):

    def _client(self, reused: bool):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "llmac_cli_v244", os.path.join(_PARENT, "llmac.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        c = mod.Client("127.0.0.1", 8765, "k", tls=False)
        if reused:
            # A previously-working keep-alive connection (any truthy obj;
            # _attempt is mocked so it is never actually used).
            c._conn = object()
        calls = []

        def fake_attempt(method, path, body, headers, raw=False,
                         timeout=30.0):
            calls.append(1)
            return None, 0          # transport failure

        c._attempt = fake_attempt
        return c, calls

    def test_mid_session_death_says_restarted(self):
        c, calls = self._client(reused=True)
        result, status = c.get("/info")
        self.assertEqual(status, 0)
        self.assertTrue(result["mid_session"])
        self.assertIn("RESTARTED", result["message"])
        self.assertIn("--retry", result["message"])
        self.assertEqual(len(calls), 2)   # one free stale retry, then give up

    def test_fresh_refusal_says_down_or_flags(self):
        c, calls = self._client(reused=False)
        result, status = c.get("/info")
        self.assertEqual(status, 0)
        self.assertFalse(result["mid_session"])
        self.assertIn("--plain", result["message"])
        self.assertIn("connection refused", result["message"])
        self.assertEqual(len(calls), 1)   # nothing to retry: fresh dial

    def test_mid_session_survives_retry_window(self):
        c, calls = self._client(reused=True)
        c.retry_seconds = 0.05
        result, status = c.get("/info")
        self.assertEqual(status, 0)
        self.assertTrue(result["mid_session"])
        # stale retry + window retries, all failing -> still flagged
        self.assertGreaterEqual(len(calls), 3)


# ---------------------------------------------------------------------------
# 2. exec --save (real headless server)
# ---------------------------------------------------------------------------

class TestExecSave(unittest.TestCase):

    def setUp(self):
        self.host = TestHost()
        self.root = self.host.root

    def tearDown(self):
        self.host.stop()

    def _exec(self, command, save="", cwd="", timeout=30):
        payload = {"command": command, "timeout": timeout}
        if save:
            payload["save"] = save
        if cwd:
            payload["cwd"] = cwd
        return self.host.req("POST", "/exec", payload)

    def test_save_streams_full_stdout(self):
        target = os.path.join(self.root, "out.txt")
        resp, status = self._exec("printf 'alpha\\nbeta\\ngamma\\n'",
                                  save=target)
        self.assertEqual(status, 200)
        self.assertEqual(resp["returncode"], 0)
        self.assertEqual(resp["stdout"], "")       # the stream is in the file
        self.assertEqual(resp["saved_path"], target)
        with open(target, "rb") as fh:
            data = fh.read()
        self.assertEqual(data, b"alpha\nbeta\ngamma\n")
        self.assertEqual(resp["saved_bytes"], len(data))
        self.assertFalse(resp["truncated"])

    def test_stderr_still_inline_with_save(self):
        target = os.path.join(self.root, "mixed.txt")
        resp, status = self._exec(
            "echo to-out; " + _STDERR_CMD, save=target)
        self.assertEqual(status, 200)
        self.assertIn("to-err", resp["stderr"])
        with open(target, "rb") as fh:
            self.assertEqual(fh.read().strip(), b"to-out")

    def test_save_is_uncapped_beyond_1mb(self):
        """The whole point for RE: a >1MB disassembly dump lands in the
        file COMPLETE — the inline path would cap+truncate it."""
        target = os.path.join(self.root, "big.txt")
        resp, status = self._exec("seq 1 200000", save=target)
        self.assertEqual(status, 200)
        self.assertGreater(resp["saved_bytes"], 1024 * 1024)
        self.assertFalse(resp["truncated"])
        with open(target) as fh:
            lines = fh.read().strip().splitlines()
        self.assertEqual(len(lines), 200000)
        self.assertEqual(lines[-1], "200000")

    def test_missing_parent_dir_refuses_without_running(self):
        marker = os.path.join(self.root, "marker.txt")
        resp, status = self._exec("touch marker.txt",
                                  save=os.path.join(self.root, "no", "x.txt"))
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "save_dir_missing")
        self.assertFalse(os.path.exists(marker))   # command never ran

    def test_save_outside_roots_refused(self):
        resp, status = self._exec("echo x",
                                  save="/tmp/v244-should-not-exist.txt")
        self.assertEqual(status, 403)
        self.assertEqual(resp["error"], "save_outside_sandbox")

    def test_save_into_protected_git_refused(self):
        gitdir = os.path.join(self.root, ".git")
        os.makedirs(gitdir, exist_ok=True)
        resp, status = self._exec("echo x",
                                  save=os.path.join(gitdir, "config"))
        self.assertEqual(status, 403)
        self.assertEqual(resp["error"], "protected_path")

    def test_timeout_with_save_keeps_partial_output(self):
        target = os.path.join(self.root, "partial.txt")
        resp, status = self._exec("echo partial; sleep 30", save=target,
                                  timeout=1)
        self.assertEqual(status, 200)
        self.assertTrue(resp["timed_out"])
        with open(target) as fh:
            self.assertEqual(fh.read().strip(), "partial")
        self.assertGreater(resp["saved_bytes"], 0)

    def test_without_save_unchanged(self):
        resp, status = self._exec("printf 'plain\\n'")
        self.assertEqual(status, 200)
        self.assertEqual(resp["stdout"], "plain\n")
        self.assertNotIn("saved_path", resp)
        self.assertNotIn("saved_bytes", resp)

    def test_batch_exec_with_save(self):
        target = os.path.join(self.root, "batch-out.txt")
        ops = [{"op": "exec", "command": "printf 'from-batch\\n'",
                "save": target}]
        resp, status = self.host.req("POST", "/batch", {"ops": ops})
        self.assertEqual(status, 200)
        r0 = resp["results"][0]
        self.assertIn("ok", r0)
        self.assertEqual(r0["ok"]["saved_path"], target)
        with open(target) as fh:
            self.assertEqual(fh.read(), "from-batch\n")

    def test_batch_bad_save_refuses_whole_batch_atomically(self):
        """B4 atomicity extends to --save: one bad target refuses the
        ENTIRE batch and NOTHING executes (earlier ops included)."""
        marker = os.path.join(self.root, "atomic-marker.txt")
        ops = [
            {"op": "exec", "command": "touch atomic-marker.txt",
             "cwd": self.root},
            {"op": "exec", "command": "echo x",
             "save": os.path.join(self.root, "no", "dir", "f.txt")},
        ]
        resp, status = self.host.req("POST", "/batch", {"ops": ops})
        self.assertEqual(status, 400)
        self.assertEqual(resp["error"], "exec_preflight")
        self.assertEqual(resp["index"], 1)
        self.assertEqual(resp["cause"], "save_dir_missing")
        self.assertFalse(os.path.exists(marker))   # op 0 never ran


# ---------------------------------------------------------------------------
# 3. session export (all_notes) + CLI round trip
# ---------------------------------------------------------------------------

class TestSessionExport(unittest.TestCase):

    def setUp(self):
        self.host = TestHost()
        for i in range(12):
            resp, status = self.host.req(
                "POST", "/session/note", {"text": f"note-{i:02d}"})
            self.assertEqual(status, 200)

    def tearDown(self):
        self.host.stop()

    def test_status_default_last10(self):
        resp, status = self.host.req("POST", "/session/status", {})
        self.assertEqual(status, 200)
        self.assertEqual(len(resp["notes"]), 10)
        texts = [n["text"] for n in resp["notes"]]
        self.assertEqual(texts[0], "note-02")      # last 10 of 12

    def test_all_notes_returns_everything(self):
        resp, status = self.host.req(
            "POST", "/session/status", {"all_notes": True})
        self.assertEqual(status, 200)
        texts = [n["text"] for n in resp["notes"]]
        self.assertEqual(len(texts), 12)
        self.assertEqual(texts[0], "note-00")
        self.assertEqual(texts[-1], "note-11")

    def test_cli_export_round_trip(self):
        """`llmac session export --out F` against a live headless host —
        the exact hand-off an agent runs before a session ends."""
        import importlib.util
        import subprocess
        spec = importlib.util.spec_from_file_location(
            "llmac_cli_v244_exp", os.path.join(_PARENT, "llmac.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        outdir = tempfile.mkdtemp(prefix="v244-export-")
        outfile = os.path.join(outdir, "notes.json")
        r = subprocess.run(
            [sys.executable, os.path.join(_PARENT, "llmac.py"),
             "--plain", "--host", "127.0.0.1",
             "--port", str(self.host.port), "--key", self.host.key,
             "--no-verify", "session", "export", "--out", outfile],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(outfile, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["note_count"], 12)
        self.assertEqual(data["notes"][0]["text"], "note-00")
        self.assertIn("exported 12 note(s)", r.stdout)


# ---------------------------------------------------------------------------
# 4. Version pin
# ---------------------------------------------------------------------------

class TestVersion(unittest.TestCase):

    def test_info_reports_244(self):
        host = TestHost()
        try:
            resp, status = host.req("GET", "/info")
            self.assertEqual(status, 200)
            self.assertEqual(resp["version"], "2.7.3")
        finally:
            host.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
