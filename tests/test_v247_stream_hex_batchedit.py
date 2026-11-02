"""v2.4.7 — proc log streaming, batch edit ops, hex dumps, S5 median.

Covers:
  STREAM  proc_log events fire when a running proc produces output;
          silent procs emit nothing (baseline, no spam)
  FOLLOW  `proc logs --follow` streams to completion and exits 0
          (CLI end-to-end against a live host)
  RESYNC  the slice-protocol fix: a >20000-line window resyncs VISIBLY
          (resynced + skipped + true next) instead of silently dropping
          lines; in-window afters slice exactly
  CURSORS after_stdout / after_stderr advance independently; the old
          single `after` still applies to both streams
  HEX     offset/hex/ascii rendering, absolute offsets, default slice,
          hard cap, offset+limit paging, hex+lines 400, text files,
          past-EOF, hex inside batch, CLI --hex
  BATCH   edit ops: happy path with per-op diffs, per-op isolation,
          stale version per-op 409, strict policy refuses the batch,
          CLI prints diffs (and --no-diffs suppresses)
  GUARD   the bench harness records llmac_deploy_median_s (lesson #4)
"""
import json
import os
import subprocess
import sys
import time
import unittest

_THIS = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_THIS)
for _p in (_PARENT, _THIS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from helpers import TestHost, make_tree

CLI = os.path.join(_PARENT, "cli.py")


def run_cli(host, *args, timeout=90, cwd=None):
    return subprocess.run(
        [sys.executable, CLI, "--plain", "--host", "127.0.0.1",
         "--port", str(host.port), "--key", host.key, *args],
        capture_output=True, text=True, timeout=timeout, cwd=cwd)


# ---------------------------------------------------------------------------
# proc_log events + slice protocol
# ---------------------------------------------------------------------------

class TestProcLogStreaming(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)

    def _events_since(self, since, wait):
        return self.host.get(
            f"/events?since={since}&wait={wait}")[0]

    def test_proc_log_event_fires_on_output(self):
        r, s = self.host.post("/proc/start", {
            # NOTE: no shell variables — the sandbox analyzer rejects
            # $VAR tokens by design (same rule as exec).
            "command": "echo beat one; sleep 0.4; echo beat two; "
                       "sleep 0.4; echo beat three; sleep 0.4; "
                       "echo beat four; sleep 0.4; echo beat five",
            "cwd": self.host.root, "name": "beater"})
        self.assertEqual(s, 200)
        pid = r["proc"]["id"]
        since = self._events_since(0, 0.1)["last_seq"]
        deadline = time.monotonic() + 6.0
        hits = []
        while time.monotonic() < deadline and not hits:
            resp = self._events_since(since, 2.0)
            since = resp.get("last_seq", since)
            hits = [e for e in resp.get("events", [])
                    if e["type"] == "proc_log"
                    and (e.get("data") or {}).get("id") == pid]
        self.assertTrue(hits, "no proc_log event within 6s")
        d = hits[0]["data"]
        self.assertEqual(d["stream"], "stdout")
        self.assertGreater(d["size"], 0)
        self.host.post("/proc/stop", {"id": pid, "force": True})

    def test_silent_proc_emits_no_log_events(self):
        r, s = self.host.post("/proc/start", {
            "command": "sleep 5", "cwd": self.host.root, "name": "quiet"})
        self.assertEqual(s, 200)
        pid = r["proc"]["id"]
        resp = self._events_since(0, 2.6)     # blocks the full wait when
        # nothing at all fires; ANY proc_log for this pid would be a bug
        hits = [e for e in resp.get("events", [])
                if e["type"] == "proc_log"
                and (e.get("data") or {}).get("id") == pid]
        self.assertEqual(hits, [])
        self.host.post("/proc/stop", {"id": pid, "force": True})

    def test_resync_visible_when_window_rolls(self):
        """The v2.4.7 fix: 25000 lines + after=0 used to return the last
        20000 MISLABELED as everything; now it says resynced + skipped
        and next is the TRUE count."""
        r, s = self.host.post("/proc/start", {
            "command": "sleep 8", "cwd": self.host.root, "name": "paper"})
        self.assertEqual(s, 200)
        pid = r["proc"]["id"]
        log = os.path.join(self.host.data_dir, "procs", pid, "stdout.log")
        with open(log, "w", encoding="utf-8") as f:
            for i in range(25000):
                f.write(f"line-{i:05d}\n")
        resp, st = self.host.post("/proc/logs", {"id": pid, "after": 0})
        self.assertEqual(st, 200)
        self.assertTrue(resp["stdout_resynced"])
        self.assertEqual(resp["stdout_skipped"], 5000)
        self.assertEqual(resp["stdout_next"], 25000)
        self.assertEqual(len(resp["stdout"]), 20000)
        self.assertEqual(resp["stdout"][0], "line-05000")
        self.assertEqual(resp["stdout"][-1], "line-24999")
        # an in-window after slices exactly, no resync flag
        resp2, _ = self.host.post("/proc/logs", {"id": pid, "after": 20000})
        self.assertFalse(resp2["stdout_resynced"])
        self.assertEqual(len(resp2["stdout"]), 5000)
        self.assertEqual(resp2["stdout"][0], "line-20000")
        # caught-up cursor is idempotent
        resp3, _ = self.host.post("/proc/logs", {"id": pid, "after": 25000})
        self.assertEqual(resp3["stdout"], [])
        self.assertEqual(resp3["stdout_next"], 25000)
        self.host.post("/proc/stop", {"id": pid, "force": True})

    def test_independent_stream_cursors(self):
        r, s = self.host.post("/proc/start", {
            "command": "echo out1; echo err1 >&2; sleep 0.5; "
                       "echo out2; echo err2 >&2; sleep 4",
            "cwd": self.host.root, "name": "duo"})
        self.assertEqual(s, 200)
        pid = r["proc"]["id"]
        # let all four lines land
        time.sleep(1.2)
        resp, st = self.host.post("/proc/logs", {
            "id": pid, "after_stdout": 1, "after_stderr": 0})
        self.assertEqual(st, 200)
        self.assertEqual(resp["stdout"], ["out2"])
        self.assertEqual(resp["stderr"], ["err1", "err2"])
        self.assertEqual(resp["stdout_next"], 2)
        self.assertEqual(resp["stderr_next"], 2)
        # single `after` still applies to BOTH (backward compatible)
        resp2, _ = self.host.post("/proc/logs", {"id": pid, "after": 1})
        self.assertEqual(resp2["stdout"], ["out2"])
        self.assertEqual(resp2["stderr"], ["err2"])
        self.host.post("/proc/stop", {"id": pid, "force": True})

    def test_cli_follow_streams_to_completion(self):
        r, s = self.host.post("/proc/start", {
            "command": "echo hi; sleep 1.2; echo bye",
            "cwd": self.host.root, "name": "short"})
        self.assertEqual(s, 200)
        pid = r["proc"]["id"]
        out = run_cli(self.host, "proc", "logs", "--id", pid, "--follow",
                      "--max-idle", "30", timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("hi", out.stdout)
        self.assertIn("bye", out.stdout)
        self.assertIn("exited rc=0", out.stdout)


# ---------------------------------------------------------------------------
# read --hex
# ---------------------------------------------------------------------------

class TestHexDump(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)
        self.bin_path = os.path.join(self.host.root, "blob.bin")
        payload = bytes(range(256)) * 32          # 8192 known bytes
        with open(self.bin_path, "wb") as f:
            f.write(payload)
        self.txt_path = os.path.join(self.host.root, "note.txt")
        with open(self.txt_path, "w", encoding="utf-8") as f:
            f.write("AB.CD\n")

    def test_hex_basic(self):
        resp, st = self.host.post("/read", {"path": self.bin_path,
                                            "hex": True})
        self.assertEqual(st, 200)
        self.assertTrue(resp["hex"])
        self.assertTrue(resp["binary"])
        self.assertEqual(resp["dump_bytes"], 512)       # default slice
        self.assertTrue(resp["truncated"])
        self.assertEqual(resp["next_offset"], 512)
        lines = resp["content"].split("\n")
        self.assertEqual(lines[0],
                         "00000000  00 01 02 03 04 05 06 07 08 09 0a 0b "
                         "0c 0d 0e 0f  "
                         "|................|")
        # absolute offsets continue at the requested base
        resp2, _ = self.host.post("/read", {"path": self.bin_path,
                                             "hex": True, "offset": 8176,
                                             "limit": 16})
        self.assertEqual(resp2["dump_bytes"], 16)
        self.assertFalse(resp2["truncated"])          # 8176+16 == 8192
        self.assertIn("00001ff0  f0 f1 f2 f3 f4 f5 f6 f7", resp2["content"])

    def test_hex_cap_and_paging(self):
        resp, _ = self.host.post("/read", {"path": self.bin_path,
                                            "hex": True, "limit": 100000})
        self.assertEqual(resp["dump_bytes"], 4096)       # hard cap
        self.assertEqual(resp["next_offset"], 4096)
        rows = resp["content"].rstrip("\n").split("\n")
        self.assertEqual(len(rows), 4096 // 16)
        self.assertTrue(rows[0].startswith("00000000"))
        self.assertTrue(rows[-1].startswith("00000ff0"))

    def test_hex_lines_conflict(self):
        resp, st = self.host.post("/read", {"path": self.bin_path,
                                            "hex": True, "from_line": 1,
                                            "to_line": 5})
        self.assertEqual(st, 400)
        self.assertEqual(resp["error"], "hex_lines_conflict")

    def test_hex_text_file(self):
        resp, st = self.host.post("/read", {"path": self.txt_path,
                                            "hex": True})
        self.assertEqual(st, 200)
        self.assertTrue(resp["hex"])
        self.assertFalse(resp["binary"])
        self.assertIn("|AB.CD.|", resp["content"])

    def test_hex_past_eof(self):
        resp, st = self.host.post("/read", {"path": self.bin_path,
                                            "hex": True, "offset": 9000})
        self.assertEqual(st, 200)
        self.assertEqual(resp["dump_bytes"], 0)
        self.assertEqual(resp["content"], "")
        self.assertFalse(resp["truncated"])
        self.assertIsNone(resp["next_offset"])

    def test_hex_inside_batch(self):
        resp, st = self.host.post("/batch", {"ops": [
            {"op": "read", "path": self.bin_path, "hex": True,
             "offset": 0, "limit": 32},
            {"op": "stat", "path": self.bin_path, "hash": True}]})
        self.assertEqual(st, 200)
        self.assertNotIn("error", resp["results"][0])
        self.assertTrue(resp["results"][0]["ok"]["hex"])
        self.assertIn("00 01 02", resp["results"][0]["ok"]["content"])
        self.assertIn("sha256", json.dumps(resp["results"][1]))

    def test_cli_hex(self):
        out = run_cli(self.host, "read", "--path", self.bin_path,
                      "--hex", "--offset", "0", "--limit", "16")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("00000000  00 01 02 03", out.stdout)
        self.assertIn("|................|", out.stdout)
        out2 = run_cli(self.host, "read", "--path", self.bin_path,
                       "--hex", "--limit", "999999")
        self.assertIn("[truncated (continue with --hex --offset 4096)]",
                      out2.stderr)


# ---------------------------------------------------------------------------
# batch edit ops
# ---------------------------------------------------------------------------

class TestBatchEdit(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)
        make_tree(self.host.root, {
            "one.txt": "alpha\nbeta\ngamma\n",
            "two.txt": "keep\n",
            "three.txt": "x\ny\nz\n",
        })

    def test_batch_edit_happy_path_with_diffs(self):
        resp, st = self.host.post("/batch", {"ops": [
            {"op": "edit", "path": f"{self.host.root}/one.txt",
             "ops": [{"op": "replace", "find": "beta",
                      "replace": "BETA"}]},
            {"op": "edit", "path": f"{self.host.root}/two.txt",
             "ops": [{"op": "append", "content": "added"}]},
        ]})
        self.assertEqual(st, 200)
        r0, r1 = resp["results"]
        self.assertNotIn("error", r0)
        self.assertEqual(r0["ok"]["changes"], 1)
        self.assertIn("-beta", r0["ok"]["diff"])
        self.assertIn("+BETA", r0["ok"]["diff"])
        self.assertNotIn("error", r1)
        self.assertIn("+added", r1["ok"]["diff"])
        # files really changed
        r, _ = self.host.post("/read", {"path": f"{self.host.root}/one.txt"})
        self.assertIn("BETA", r["content"])

    def test_batch_edit_per_op_isolation(self):
        resp, st = self.host.post("/batch", {"ops": [
            {"op": "edit", "path": f"{self.host.root}/one.txt",
             "ops": [{"op": "append", "content": "first"}]},
            {"op": "edit", "path": f"{self.host.root}/missing.txt",
             "ops": [{"op": "append", "content": "nope"}]},
            {"op": "edit", "path": f"{self.host.root}/three.txt",
             "ops": [{"op": "append", "content": "third"}]},
        ]})
        self.assertEqual(st, 200)
        self.assertNotIn("error", resp["results"][0])
        self.assertEqual(resp["results"][1]["error"], "not_found")
        self.assertNotIn("error", resp["results"][2])
        r, _ = self.host.post("/read", {"path": f"{self.host.root}/one.txt"})
        self.assertIn("first", r["content"])      # landed despite neighbor
        r3, _ = self.host.post("/read",
                               {"path": f"{self.host.root}/three.txt"})
        self.assertIn("third", r3["content"])

    def test_batch_edit_stale_version_per_op(self):
        r, _ = self.host.post("/read", {"path": f"{self.host.root}/one.txt"})
        stale = r["version"]
        self.host.post("/edit", {"path": f"{self.host.root}/one.txt",
                                 "ops": [{"op": "append",
                                          "content": "drift"}]})
        resp, st = self.host.post("/batch", {"ops": [
            {"op": "edit", "path": f"{self.host.root}/one.txt",
             "expected_version": stale,
             "ops": [{"op": "append", "content": "should-not-land"}]},
            {"op": "edit", "path": f"{self.host.root}/two.txt",
             "ops": [{"op": "append", "content": "still-works"}]},
        ]})
        self.assertEqual(st, 200)
        self.assertEqual(resp["results"][0]["error"], "version_conflict")
        self.assertNotIn("error", resp["results"][1])
        r, _ = self.host.post("/read", {"path": f"{self.host.root}/one.txt"})
        self.assertNotIn("should-not-land", r["content"])
        r2, _ = self.host.post("/read", {"path": f"{self.host.root}/two.txt"})
        self.assertIn("still-works", r2["content"])

    def test_batch_edit_strict_policy_refused(self):
        strict = TestHost(settings={"approval_policy": "strict",
                                   "allow_exec": True})
        self.addCleanup(strict.stop)
        resp, st = strict.post("/batch", {"ops": [
            {"op": "edit", "path": f"{strict.root}/whatever.txt",
             "ops": [{"op": "append", "content": "x"}]}]})
        self.assertEqual(st, 400)
        self.assertEqual(resp["error"], "batch_policy")
        self.assertIn("edit", resp["message"])


class TestBatchEditCLI(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)
        make_tree(self.host.root, {"f.txt": "hello world\n"})

    def test_cli_prints_edit_diffs_by_default(self):
        ops = json.dumps([{"op": "edit", "path": f"{self.host.root}/f.txt",
                           "ops": [{"op": "replace", "find": "world",
                                    "replace": "there"}]}])
        out = run_cli(self.host, "batch", "--ops", ops)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("[0] edit: ok", out.stdout)
        self.assertIn("-hello world", out.stdout)
        self.assertIn("+hello there", out.stdout)

    def test_cli_no_diffs_flag(self):
        ops = json.dumps([{"op": "edit", "path": f"{self.host.root}/f.txt",
                           "ops": [{"op": "replace", "find": "world",
                                    "replace": "again"}]}])
        out = run_cli(self.host, "batch", "--ops", ops, "--no-diffs")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("[0] edit: ok", out.stdout)
        self.assertNotIn("-hello world", out.stdout)


# ---------------------------------------------------------------------------
# harness guard (lesson #4)
# ---------------------------------------------------------------------------

class TestBenchHarnessGuard(unittest.TestCase):
    def test_s5_records_median(self):
        src = open(os.path.join(_PARENT, "tools", "bench_llmac.py"),
                   encoding="utf-8").read()
        self.assertIn("llmac_deploy_median_s", src)
        self.assertIn("statistics.median(probes)", src)
        # the sub-second medians must survive too
        self.assertIn("median_wall_s", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
