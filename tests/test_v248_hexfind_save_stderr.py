"""v2.4.8 — hex find (GOTO/search), exec --save-stderr, GUI tail,
bench S7/S8 walk fix.

Covers:
  FIND    hex=true find_hex/find_text: exact offsets, absolute-offset
          context rows, scan paging via --offset + next_offset, hit cap
          + more + continuation, chunk-boundary overlap (a hit spanning
          the 1 MB scan boundary is never missed), text files, past-EOF
          start, all the 400s (needs_hex, conflict, bad hex, too-long
          pattern, limit conflict, lines conflict), find inside batch,
          CLI --find-hex/--find-text + the continuation hint on stderr
  SAVE2   exec --save-stderr: both artifacts, stderr-only, same-path
          refusal WITHOUT running, outside-sandbox/dirty-target
          refusals (command provably never executed), batch exec with
          save_stderr, bad target refuses the WHOLE batch, the timeout
          note lands in the stderr artifact
  TAIL    GUI wiring (source-level — PyQt is unavailable headless):
          Tail logs button -> ProcTailDialog, ring buffer, independent
          after/after_err cursors, one-window-per-pid
  WALK    bench _biggest_file: archives skipped (lesson #8 — a zip
          bigger than every code file must not hijack S7/S8), explicit
          --big-file override, derived file_path recorded
"""
import importlib.util
import json
import os
import subprocess
import sys
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


def _load_bench():
    spec = importlib.util.spec_from_file_location(
        "bench_llmac", os.path.join(_PARENT, "tools", "bench_llmac.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# read --hex --find-*
# ---------------------------------------------------------------------------

class TestHexFind(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)
        # Known layout: MZ header at 0, marker at 100, marker at 200.
        blob = bytearray(b"\x00" * 300)
        blob[0:2] = b"MZ"
        blob[100:100 + 2] = b"MZ"
        blob[200:200 + 2] = b"MZ"
        blob[210:210 + 5] = b"hall\xc3\xb3"        # UTF-8 "halló"
        self.bin_path = os.path.join(self.host.root, "blob.bin")
        with open(self.bin_path, "wb") as f:
            f.write(bytes(blob))

    def test_find_hex_basic_offsets_and_context(self):
        resp, st = self.host.post("/read", {"path": self.bin_path,
                                            "hex": True,
                                            "find_hex": "4d5a"})
        self.assertEqual(st, 200)
        self.assertTrue(resp["hex"])
        self.assertEqual(resp["find"]["kind"], "hex")
        self.assertEqual(resp["find"]["pattern_len"], 2)
        self.assertEqual(resp["find"]["pattern_hex"], "4d5a")
        self.assertEqual(resp["match_count"], 3)
        self.assertEqual([m["offset"] for m in resp["matches"]],
                         [0, 100, 200])
        # context rows carry ABSOLUTE offsets: the hit at 100 renders
        # from (100-32)&~15 == 64.
        ctx_rows = resp["matches"][1]["context"].split("\n")
        self.assertTrue(ctx_rows[0].startswith("00000040"))
        self.assertIn("4d 5a", resp["matches"][1]["context"])
        self.assertFalse(resp["more"])
        self.assertIsNone(resp["next_offset"])

    def test_find_text_literal(self):
        resp, st = self.host.post("/read", {"path": self.bin_path,
                                            "hex": True,
                                            "find_text": "halló"})
        self.assertEqual(st, 200)
        self.assertEqual(resp["find"]["kind"], "text")
        self.assertEqual(resp["find"]["pattern_hex"],
                         "halló".encode("utf-8").hex())
        self.assertEqual(resp["match_count"], 1)
        self.assertEqual(resp["matches"][0]["offset"], 210)
        # the ascii column of the context shows the literal
        self.assertIn("hall", resp["matches"][0]["context"])

    def test_find_paging_with_offset_and_max_hits(self):
        # cap at 1: first hit only, more=True, next points past it
        resp, st = self.host.post("/read", {
            "path": self.bin_path, "hex": True, "find_hex": "4d5a",
            "find_max_hits": 1})
        self.assertEqual(st, 200)
        self.assertEqual([m["offset"] for m in resp["matches"]], [0])
        self.assertTrue(resp["more"])
        self.assertEqual(resp["next_offset"], 1)
        # continue: hits 100 + 200, then scan end
        resp2, _ = self.host.post("/read", {
            "path": self.bin_path, "hex": True, "find_hex": "4d5a",
            "offset": resp["next_offset"]})
        self.assertEqual([m["offset"] for m in resp2["matches"]],
                         [100, 200])
        self.assertFalse(resp2["more"])
        self.assertIsNone(resp2["next_offset"])
        # starting past the last hit: no hits at all
        resp3, st3 = self.host.post("/read", {
            "path": self.bin_path, "hex": True, "find_hex": "4d5a",
            "offset": 250})
        self.assertEqual(st3, 200)
        self.assertEqual(resp3["match_count"], 0)
        self.assertEqual(resp3["matches"], [])
        self.assertFalse(resp3["more"])

    def test_find_overlapping_occurrences_page_by_one(self):
        # "aaa" contains "aa" at 0 AND 1 — next_offset must be last+1
        p = os.path.join(self.host.root, "aaa.bin")
        with open(p, "wb") as f:
            f.write(b"aaa")
        resp, _ = self.host.post("/read", {"path": p, "hex": True,
                                           "find_hex": "6161",
                                           "find_max_hits": 1})
        self.assertEqual([m["offset"] for m in resp["matches"]], [0])
        self.assertEqual(resp["next_offset"], 1)
        resp2, _ = self.host.post("/read", {"path": p, "hex": True,
                                            "find_hex": "6161",
                                            "offset": 1})
        self.assertEqual([m["offset"] for m in resp2["matches"]], [1])

    def test_find_spans_scan_chunk_boundary(self):
        # ~1.05 MB file; the pattern straddles the 1 MB chunk edge.
        p = os.path.join(self.host.root, "big.bin")
        chunk = 1024 * 1024
        blob = bytearray(b"\x11" * (chunk + 7))
        marker = b"EDGE-MARK"
        start = chunk - 4                 # last 4 B of chunk 1 + 5 B of chunk 2
        blob[start:start + len(marker)] = marker
        with open(p, "wb") as f:
            f.write(bytes(blob))
        resp, st = self.host.post("/read", {"path": p, "hex": True,
                                            "find_text": "EDGE-MARK"})
        self.assertEqual(st, 200)
        self.assertEqual(resp["match_count"], 1)
        self.assertEqual(resp["matches"][0]["offset"], start)

    def test_find_text_file(self):
        p = os.path.join(self.host.root, "note.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write("AB.CD\n")
        resp, st = self.host.post("/read", {"path": p, "hex": True,
                                            "find_hex": "2e"})
        self.assertEqual(st, 200)
        self.assertEqual(resp["match_count"], 1)
        self.assertEqual(resp["matches"][0]["offset"], 2)

    def test_find_validations(self):
        base = {"path": self.bin_path, "hex": True}
        r, s = self.host.post("/read", {"path": self.bin_path,
                                         "find_hex": "4d5a"})
        self.assertEqual(s, 400)
        self.assertEqual(r["error"], "find_needs_hex")
        r, s = self.host.post("/read", {**base, "find_hex": "4d5a",
                                        "find_text": "MZ"})
        self.assertEqual(s, 400)
        self.assertEqual(r["error"], "find_conflict")
        for bad in ("4d5", "zz", "4d 5"):
            r, s = self.host.post("/read", {**base, "find_hex": bad})
            self.assertEqual(s, 400, bad)
            self.assertEqual(r["error"], "bad_find_hex", bad)
        r, s = self.host.post("/read", {**base, "find_text": "x" * 1025})
        self.assertEqual(s, 400)
        self.assertEqual(r["error"], "find_pattern_too_long")
        r, s = self.host.post("/read", {**base, "find_hex": "4d5a",
                                        "limit": 16})
        self.assertEqual(s, 400)
        self.assertEqual(r["error"], "find_limit_conflict")
        r, s = self.host.post("/read", {**base, "find_hex": "4d5a",
                                        "from_line": 1, "to_line": 3})
        self.assertEqual(s, 400)
        self.assertEqual(r["error"], "hex_lines_conflict")
        # negative max_hits clamps to 1
        r, s = self.host.post("/read", {**base, "find_hex": "4d5a",
                                        "find_max_hits": -5})
        self.assertEqual(s, 200)
        self.assertEqual(r["match_count"], 1)
        self.assertTrue(r["more"])
        # spaces-only find_hex is "no pattern" — plain hex dump, not a 400
        r, s = self.host.post("/read", {**base, "find_hex": "   "})
        self.assertEqual(s, 200)
        self.assertNotIn("find", r)
        self.assertIn("dump_bytes", r)

    def test_find_inside_batch(self):
        resp, st = self.host.post("/batch", {"ops": [
            {"op": "read", "path": self.bin_path, "hex": True,
             "find_hex": "4d5a"},
            {"op": "stat", "path": self.bin_path}]})
        self.assertEqual(st, 200)
        ok = resp["results"][0]["ok"]
        self.assertEqual(ok["match_count"], 3)
        self.assertEqual([m["offset"] for m in ok["matches"]],
                         [0, 100, 200])

    def test_cli_find_and_continuation_hint(self):
        out = run_cli(self.host, "read", "--path", self.bin_path,
                      "--hex", "--find-hex", "4d5a")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("3 hit(s) for hex '4d5a'", out.stdout)
        self.assertIn("== hit 1 @ 0x00000000 (0) ==", out.stdout)
        self.assertIn("== hit 3 @ 0x000000c8 (200) ==", out.stdout)
        self.assertIn("00000040", out.stdout)        # context row of hit 2
        out2 = run_cli(self.host, "read", "--path", self.bin_path,
                       "--hex", "--find-hex", "4d5a", "--max-hits", "1")
        self.assertEqual(out2.returncode, 0, out2.stderr)
        self.assertIn("1 hit(s)", out2.stdout)
        self.assertIn("[hit cap reached — more may exist; continue with "
                      "--find-hex '4d5a' --offset 1]", out2.stderr)
        out3 = run_cli(self.host, "read", "--path", self.bin_path,
                       "--hex", "--find-text", "halló")
        self.assertEqual(out3.returncode, 0, out3.stderr)
        self.assertIn("text '68616", out3.stdout)
        self.assertIn("(210)", out3.stdout)

    def test_cli_find_without_hex_refused_loudly(self):
        # v2.4.8 post-release: the CLI used to silently DROP
        # --find-hex/--find-text given without --hex and fall back to a
        # plain (binary) read; it must refuse as loudly as the server's
        # find_needs_hex — BEFORE any request goes out.
        out = run_cli(self.host, "read", "--path", self.bin_path,
                      "--find-hex", "4d5a")
        self.assertEqual(out.returncode, 2)
        self.assertIn("find_needs_hex", out.stderr)
        self.assertIn("add --hex", out.stderr)
        self.assertNotIn("hit(s)", out.stdout)
        out2 = run_cli(self.host, "read", "--path", self.bin_path,
                       "--find-text", "MZ")
        self.assertEqual(out2.returncode, 2)
        self.assertIn("find_needs_hex", out2.stderr)
        self.assertIn("add --hex", out2.stderr)


# ---------------------------------------------------------------------------
# exec --save-stderr
# ---------------------------------------------------------------------------

class TestExecSaveStderr(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)
        os.makedirs(os.path.join(self.host.root, "out"), exist_ok=True)

    def test_both_streams_saved(self):
        resp, st = self.host.post("/exec", {
            "command": "echo to-out; echo to-err >&2",
            "cwd": self.host.root, "timeout": 15,
            "save": f"{self.host.root}/out/probe.log",
            "save_stderr": f"{self.host.root}/out/probe.err"})
        self.assertEqual(st, 200)
        self.assertEqual(resp["returncode"], 0)
        self.assertEqual(resp["stdout"], "")
        self.assertEqual(resp["stderr"], "")
        self.assertEqual(resp["saved_path"], f"{self.host.root}/out/probe.log")
        self.assertEqual(resp["saved_stderr_path"],
                         f"{self.host.root}/out/probe.err")
        with open(resp["saved_path"], encoding="utf-8") as f:
            self.assertEqual(f.read().strip(), "to-out")
        with open(resp["saved_stderr_path"], encoding="utf-8") as f:
            self.assertEqual(f.read().strip(), "to-err")
        self.assertGreater(resp["saved_bytes"], 0)
        self.assertGreater(resp["saved_stderr_bytes"], 0)
        self.assertFalse(resp["truncated"])

    def test_stderr_only_stdout_inline(self):
        resp, st = self.host.post("/exec", {
            "command": "echo keep-out; echo keep-err >&2",
            "cwd": self.host.root, "timeout": 15,
            "save_stderr": f"{self.host.root}/out/only.err"})
        self.assertEqual(st, 200)
        self.assertEqual(resp["stdout"].strip(), "keep-out")
        self.assertEqual(resp["stderr"], "")
        self.assertEqual(resp["saved_stderr_bytes"], 9)
        r, _ = self.host.post("/read",
                              {"path": f"{self.host.root}/out/only.err"})
        self.assertEqual(r["content"].strip(), "keep-err")

    def test_same_path_refused_without_running(self):
        marker = os.path.join(self.host.root, "marker.txt")
        resp, st = self.host.post("/exec", {
            "command": f"touch {marker}",
            "cwd": self.host.root, "timeout": 15,
            "save": f"{self.host.root}/out/same.log",
            "save_stderr": f"{self.host.root}/out/same.log"})
        self.assertEqual(st, 400)
        self.assertEqual(resp["error"], "save_same_path")
        self.assertFalse(os.path.exists(marker))

    def test_save_stderr_outside_sandbox_refused(self):
        marker = os.path.join(self.host.root, "marker2.txt")
        resp, st = self.host.post("/exec", {
            "command": f"touch {marker}",
            "cwd": self.host.root, "timeout": 15,
            "save": f"{self.host.root}/out/ok.log",
            "save_stderr": "/etc/llmac-escape.err"})
        self.assertEqual(st, 403)
        self.assertEqual(resp["error"], "save_outside_sandbox")
        self.assertFalse(os.path.exists(marker))

    def test_save_stderr_dir_missing_refused(self):
        marker = os.path.join(self.host.root, "marker3.txt")
        resp, st = self.host.post("/exec", {
            "command": f"touch {marker}",
            "cwd": self.host.root, "timeout": 15,
            "save_stderr": f"{self.host.root}/no-such-dir/x.err"})
        self.assertEqual(st, 400)
        self.assertEqual(resp["error"], "save_dir_missing")
        self.assertIn("--save-stderr", resp["message"])
        self.assertFalse(os.path.exists(marker))

    def test_timeout_note_lands_in_stderr_artifact(self):
        resp, st = self.host.post("/exec", {
            "command": "sleep 5",
            "cwd": self.host.root, "timeout": 1,
            "save_stderr": f"{self.host.root}/out/timeout.err"})
        self.assertEqual(st, 200)
        self.assertTrue(resp["timed_out"])
        self.assertEqual(resp["stderr"], "")
        r, _ = self.host.post("/read",
                              {"path": f"{self.host.root}/out/timeout.err"})
        self.assertIn("[command timed out after 1s]", r["content"])

    def test_batch_exec_save_stderr(self):
        resp, st = self.host.post("/batch", {"ops": [
            {"op": "exec", "command": "echo bo; echo be >&2",
             "cwd": self.host.root, "timeout": 15,
             "save": f"{self.host.root}/out/b.log",
             "save_stderr": f"{self.host.root}/out/b.err"}]})
        self.assertEqual(st, 200)
        ok = resp["results"][0]["ok"]
        self.assertIn("saved_stderr_path", ok)
        r, _ = self.host.post("/read", {"path": f"{self.host.root}/out/b.err"})
        self.assertEqual(r["content"].strip(), "be")

    def test_batch_bad_save_stderr_refuses_whole_batch(self):
        make_tree(self.host.root, {})
        resp, st = self.host.post("/batch", {"ops": [
            {"op": "write", "path": f"{self.host.root}/w.txt",
             "content": "should not land"},
            {"op": "exec", "command": "echo x",
             "cwd": self.host.root, "timeout": 15,
             "save_stderr": "/etc/llmac-escape2.err"}]})
        self.assertEqual(st, 403)
        self.assertEqual(resp["error"], "exec_preflight")
        self.assertEqual(resp["cause"], "save_outside_sandbox")
        r, _ = self.host.post("/stat", {"path": f"{self.host.root}/w.txt"})
        self.assertIn("error", r)          # the write never happened

    def test_cli_save_stderr_flags(self):
        out = run_cli(self.host, "exec",
                      "--command", "echo co; echo ce >&2",
                      "--cwd", self.host.root, "--timeout", "15",
                      "--save", f"{self.host.root}/out/c.log",
                      "--save-stderr", f"{self.host.root}/out/c.err")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(f"[saved 3 B -> {self.host.root}/out/c.log",
                      out.stderr)
        self.assertIn(f"[saved stderr 3 B -> {self.host.root}/out/c.err]",
                      out.stderr)
        out_json = run_cli(self.host, "exec",
                           "--command", "echo jo; echo je >&2",
                           "--cwd", self.host.root, "--timeout", "15",
                           "--save", f"{self.host.root}/out/j.log",
                           "--save-stderr", f"{self.host.root}/out/j.err",
                           "--json")
        obj = json.loads(out_json.stdout)
        self.assertEqual(obj["saved_stderr_path"],
                         f"{self.host.root}/out/j.err")
        self.assertEqual(obj["stdout"], "")
        self.assertEqual(obj["stderr"], "")


# ---------------------------------------------------------------------------
# GUI tail window wiring (source-level — PyQt unavailable headless)
# ---------------------------------------------------------------------------

class TestGuiTailWiring(unittest.TestCase):
    """v2.4.8: the Processes tab grows a 'Tail logs' button opening a
    modeless ProcTailDialog — same conventions as the v2.4.6 GUI
    guards: structural assertions against gui.py source."""

    def test_button_and_dialog_wired(self):
        src = open(os.path.join(_PARENT, "gui.py"), encoding="utf-8").read()
        for needle in (
                "self.proc_tail_btn = QPushButton(\"Tail logs\")",
                "self.proc_tail_btn.clicked.connect(self._tail_selected_proc)",
                "class ProcTailDialog(QDialog)",
                "_tail_selected_proc",
                "_selected_proc_id",
                "setMaximumBlockCount(20000)",
                "after_err=self.cur_err",
                "WA_DeleteOnClose",
                "_proc_tail_windows"):
            self.assertIn(needle, src, needle)
        # the tail window must FOLLOW (timer), not fetch once
        self.assertIn("self._timer.timeout.connect(self._poll)", src)
        # and the procs-tab hint mentions the new affordance
        self.assertIn("'Tail logs' to follow the output here", src)


# ---------------------------------------------------------------------------
# bench S7/S8 biggest-file walk (lesson #8)
# ---------------------------------------------------------------------------

class TestBenchBigFileWalk(unittest.TestCase):
    def setUp(self):
        self.bench = _load_bench()

    def test_archives_are_skipped(self):
        trees = [{"entries": [
            {"type": "file", "path": "/repo/Its/02Archive.zip",
             "size": 225203},
            {"type": "file", "path": "/repo/gui.py", "size": 106649},
            {"type": "file", "path": "/repo/core/api.py", "size": 102800},
        ]}]
        picked = self.bench._biggest_file(trees)
        self.assertEqual(picked["path"], "/repo/gui.py")

    def test_biggest_code_file_wins(self):
        trees = [{"entries": [
            {"type": "file", "path": "/repo/big.tar.gz", "size": 10 ** 9},
            {"type": "file", "path": "/repo/core/api.py", "size": 102800},
            {"type": "dir", "path": "/repo/core", "size": None},
        ]}]
        picked = self.bench._biggest_file(trees)
        self.assertEqual(picked["path"], "/repo/core/api.py")

    def test_explicit_big_file_overrides(self):
        trees = [{"entries": [
            {"type": "file", "path": "/repo/huge.py", "size": 10 ** 8},
        ]}]
        picked = self.bench._biggest_file(trees, "/repo/tiny.txt")
        self.assertEqual(picked["path"], "/repo/tiny.txt")
        self.assertIsNone(picked["size"])     # caller fills via /stat

    def test_no_files_yields_none(self):
        self.assertIsNone(self.bench._biggest_file([{"entries": []}]))
        self.assertIsNone(self.bench._biggest_file([None]))

    def test_source_guards(self):
        src = open(os.path.join(_PARENT, "tools", "bench_llmac.py"),
                   encoding="utf-8").read()
        for needle in ('"--big-file"', "_BIG_FILE_SKIP_SUFFIXES",
                       "file_path", "def _biggest_file("):
            self.assertIn(needle, src, needle)
        # the flag is threaded into both scenarios
        self.assertIn("s7(b, args.repo, args.big_file)", src)
        self.assertIn("s8(b, args.repo, args.big_file)", src)


# ---------------------------------------------------------------------------
# scripts/compare_bench.py (restored gate comparator)
# ---------------------------------------------------------------------------

class TestCompareBench(unittest.TestCase):
    """v2.4.8 restores scripts/compare_bench.py — lost with the host
    reorg while STATE.md still names it as the release gate. Pin the
    verdict policy on synthetic runs: pins, lesson-#8 same-file check,
    wall bands, exit codes."""

    CMP = os.path.join(_PARENT, "scripts", "compare_bench.py")

    @staticmethod
    def _run(walls=(1.0, 0.4, 0.5, 0.3, 2.0, 1.2, 0.9, 1.1, 20.0),
             file_bytes=106649, deploy_rc=0, stale=409, sha=True,
             smart_trunc=True, version="2.4.9"):
        scens = {}
        names = ("S1_fixed_overhead", "S2_context_cost", "S3_search",
                 "S4_stat_batch", "S5_deploy", "S6_edit_cas",
                 "S7_big_read", "S8_transfer", "S9_long_exec")
        for name, wall in zip(names, walls):
            d = {"calls": 1, "wall_s": wall, "call_log": [{"x": 1}]}
            if name in ("S2_context_cost", "S3_search", "S4_stat_batch",
                        "S5_deploy", "S6_edit_cas", "S8_transfer"):
                d["median_wall_s"] = wall
            if name == "S5_deploy":
                d["derived"] = {"llmac_deploy_rc": deploy_rc,
                                "llmac_deploy_median_s": wall}
            elif name == "S6_edit_cas":
                d["derived"] = {"stale_edit_status": stale}
            elif name == "S7_big_read":
                d["derived"] = {"file_bytes": file_bytes,
                               "file_path": "/repo/gui.py",
                               "smart_read_truncated": smart_trunc}
            elif name == "S8_transfer":
                d["derived"] = {"file_bytes": file_bytes,
                                "file_path": "/repo/gui.py",
                                "sha_match": sha}
            scens[name] = d
        return {"meta": {"server_version": version, "ts": "t",
                         "host": "h"}, "scenarios": scens}

    def _cmp(self, base, res):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            bp = os.path.join(td, "b.json")
            rp = os.path.join(td, "r.json")
            for path, obj in ((bp, base), (rp, res)):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(obj, f)
            return subprocess.run(
                [sys.executable, self.CMP, bp, rp],
                capture_output=True, text=True)

    def test_gate_pass(self):
        base = self._run(version="2.4.7")
        res = self._run()                     # identical shape/numbers
        p = self._cmp(base, res)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("GATE PASS", p.stdout)
        self.assertIn("same-file S7_big_read: /repo/gui.py", p.stdout)

    def test_wall_regression_fails(self):
        walls = list((1.0, 0.4, 0.5, 0.3, 2.0, 1.2, 0.9, 1.1, 20.0))
        walls[3] = 0.6                          # S4 +100% (sub-second
        # baseline 0.3 -> band +50% -> FAIL)
        p = self._cmp(self._run(version="2.4.7"),
                      self._run(walls=tuple(walls)))
        self.assertEqual(p.returncode, 1)
        self.assertIn("GATE FAIL", p.stdout)
        self.assertIn("S4_stat_batch", p.stdout)
        self.assertIn("REGRESSION", p.stdout)

    def test_different_file_fails_with_paths(self):
        p = self._cmp(self._run(version="2.4.7"),
                      self._run(file_bytes=225203))
        self.assertEqual(p.returncode, 1)
        # v2.4.9 (lesson #10): the refusal names the branch AND the
        # numbers — same path with a changed size reads FILE-GREW and
        # still fails the gate with the sizes shown.
        self.assertIn("FILE-GREW", p.stdout)
        self.assertIn("225203", p.stdout)
        self.assertIn("/repo/gui.py", p.stdout)

    def test_pin_failure_fails(self):
        p = self._cmp(self._run(version="2.4.7"),
                      self._run(stale=200))
        self.assertEqual(p.returncode, 1)
        self.assertIn("PIN FAIL", p.stdout)
        self.assertIn("stale_edit_status", p.stdout)

    def test_in_band_warning_still_passes(self):
        # S9 (no median, single) +30% on a 20s wall -> over the +25%
        # FAIL band for multi-second scenarios... use +12% instead:
        # WARN territory, gate stays PASS.
        walls = (1.0, 0.4, 0.5, 0.3, 2.0, 1.2, 0.9, 1.1, 22.4)
        p = self._cmp(self._run(version="2.4.7"),
                      self._run(walls=walls))
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertIn("WARN: S9_long_exec", p.stdout)
        self.assertIn("GATE PASS", p.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
