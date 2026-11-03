"""v2.4.9 — loud contracts: client flag-drop sweep (lesson #11),
server read-op field guards, error-context rendering, search on a
single file, comparator wrong-repo/file-grew disambiguation (lesson
#10).

Covers:
  GUARD   one rc-2 pre-request refusal per silently-dropped flag
          class (the 9c4512f pattern, swept): read --max-hits;
          search --context/--regex without --query, --name+--glob;
          proc --max-idle without --follow; write --content+--file;
          edit --occurrence/--regex without --replace and --content
          with no consuming op; batch --ops+--file; diff
          --b+--inline-file; session --text on a non-note verb
  RENDER  _err_from_resp: not_a_directory payloads print their PATH
          (the Task 29 live finding — 'not_a_directory: ' with an
          empty subject)
  SERVER  /read: bare max_hits 400s max_hits_unknown_field;
          find_max_hits without a find 400s find_max_hits_needs_find
          (direct AND as batch read ops); /search --path <FILE>
          greps/matches that one file; a nonexistent path 404s
          not_found naming the path; /tree on a file still 400s but
          the payload carries the path
  CMP     compare_bench lesson-#10 branches: SAME file GREW/SHRANK,
          biggest file MOVED (wrong --repo vs growth, meta.repo aware),
          and the equal-bytes-moved edge that used to pass silently
"""
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

CLI = os.path.join(_PARENT, "llmac.py")
CMP = os.path.join(_PARENT, "scripts", "compare_bench.py")


def run_cli(host, *args, timeout=90, cwd=None):
    return subprocess.run(
        [sys.executable, CLI, "--plain", "--host", "127.0.0.1",
         "--port", str(host.port), "--key", host.key, *args],
        capture_output=True, text=True, timeout=timeout, cwd=cwd)


# ---------------------------------------------------------------------------
# CLI guards — every silently-dropped flag class refuses loudly, rc 2,
# BEFORE any request goes out
# ---------------------------------------------------------------------------

class TestCliGuards(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)
        make_tree(self.host.root, {
            "notes.txt": "the needle is here\nplain line\n",
            "blob.bin": "MZ\x00\x00",
            "ops.json": "[]",
            "local.txt": "x",
        })
        self.root = self.host.root

    def test_read_max_hits_needs_find(self):
        # with --hex but no find pattern: the cap had nowhere to go
        out = run_cli(self.host, "read", "--path",
                      os.path.join(self.root, "blob.bin"),
                      "--hex", "--max-hits", "5")
        self.assertEqual(out.returncode, 2, out.stderr)
        self.assertIn("find_max_hits_needs_find", out.stderr)
        self.assertIn("--find-hex", out.stderr)
        # and with neither --hex nor a find — same refusal, not a scan
        out2 = run_cli(self.host, "read", "--path",
                       os.path.join(self.root, "blob.bin"),
                       "--max-hits", "5")
        self.assertEqual(out2.returncode, 2)
        self.assertIn("find_max_hits_needs_find", out2.stderr)

    def test_search_context_needs_query(self):
        out = run_cli(self.host, "search", "--path", self.root,
                      "--name", "*.txt", "--context", "2")
        self.assertEqual(out.returncode, 2, out.stderr)
        self.assertIn("context_needs_query", out.stderr)
        # control: with --query the context lines work
        ok = run_cli(self.host, "search", "--path", self.root,
                     "--query", "needle", "--context", "1")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn("needle", ok.stdout)

    def test_search_regex_needs_query(self):
        out = run_cli(self.host, "search", "--path", self.root,
                      "--name", "*.txt", "--regex")
        self.assertEqual(out.returncode, 2, out.stderr)
        self.assertIn("regex_needs_query", out.stderr)

    def test_search_name_glob_conflict(self):
        out = run_cli(self.host, "search", "--path", self.root,
                      "--name", "*.txt", "--glob", "*.md")
        self.assertEqual(out.returncode, 2, out.stderr)
        self.assertIn("name_glob_conflict", out.stderr)

    def test_proc_max_idle_needs_follow(self):
        out = run_cli(self.host, "proc", "logs", "--id", "p1",
                      "--max-idle", "5")
        self.assertEqual(out.returncode, 2, out.stderr)
        self.assertIn("max_idle_needs_follow", out.stderr)
        self.assertIn("--follow", out.stderr)

    def test_write_content_file_conflict(self):
        out = run_cli(self.host, "write",
                      "--path", os.path.join(self.root, "dst.txt"),
                      "--content", "hello",
                      "--file", os.path.join(self.root, "local.txt"))
        self.assertEqual(out.returncode, 2, out.stderr)
        self.assertIn("content_file_conflict", out.stderr)

    def test_batch_ops_file_conflict(self):
        out = run_cli(self.host, "batch", "--ops", "[]", "--file",
                      os.path.join(self.root, "ops.json"))
        self.assertEqual(out.returncode, 2, out.stderr)
        self.assertIn("ops_file_conflict", out.stderr)

    def test_diff_b_inline_conflict(self):
        out = run_cli(self.host, "diff",
                      "--a", os.path.join(self.root, "notes.txt"),
                      "--b", os.path.join(self.root, "local.txt"),
                      "--inline-file",
                      os.path.join(self.root, "local.txt"))
        self.assertEqual(out.returncode, 2, out.stderr)
        self.assertIn("diff_targets_conflict", out.stderr)

    def test_edit_modifier_needs_replace(self):
        out = run_cli(self.host, "edit", "--path",
                      os.path.join(self.root, "notes.txt"),
                      "--occurrence", "all")
        self.assertEqual(out.returncode, 2, out.stderr)
        self.assertIn("modifier_needs_replace", out.stderr)
        out2 = run_cli(self.host, "edit", "--path",
                       os.path.join(self.root, "notes.txt"), "--regex")
        self.assertEqual(out2.returncode, 2)
        self.assertIn("modifier_needs_replace", out2.stderr)
        # control: with --replace the modifiers are honored
        ok = run_cli(self.host, "edit", "--path",
                     os.path.join(self.root, "notes.txt"),
                     "--replace", "needle", "--with", "NEEDLE",
                     "--occurrence", "all")
        self.assertEqual(ok.returncode, 0, ok.stderr)

    def test_edit_unused_content(self):
        out = run_cli(self.host, "edit", "--path",
                      os.path.join(self.root, "notes.txt"),
                      "--replace", "needle", "--with", "NEEDLE",
                      "--content", "ignored?")
        self.assertEqual(out.returncode, 2, out.stderr)
        self.assertIn("unused_content", out.stderr)
        # control: --content with a consuming op works
        ok = run_cli(self.host, "edit", "--path",
                     os.path.join(self.root, "notes.txt"),
                     "--append", "--content", "appended")
        self.assertEqual(ok.returncode, 0, ok.stderr)

    def test_session_text_needs_note(self):
        out = run_cli(self.host, "session", "status", "--text", "nope")
        self.assertEqual(out.returncode, 2, out.stderr)
        self.assertIn("text_needs_note", out.stderr)
        ok = run_cli(self.host, "session", "note", "--text", "fine")
        self.assertEqual(ok.returncode, 0, ok.stderr)


# ---------------------------------------------------------------------------
# Error rendering — server context fields are never dropped
# ---------------------------------------------------------------------------

class TestErrRender(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)
        make_tree(self.host.root, {"notes.txt": "hello\n"})
        self.root = self.host.root

    def test_not_a_directory_prints_path(self):
        # Task 29 live finding: this printed 'ERROR: not_a_directory: '
        # with the path dropped on the floor. The renderer must name
        # the subject.
        out = run_cli(self.host, "tree", "--path",
                      os.path.join(self.root, "notes.txt"))
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("not_a_directory", out.stderr)
        self.assertIn("notes.txt", out.stderr)

    def test_render_helper_covers_message_path_field(self):
        # unit-level: the shared formatter must surface message,
        # path AND field for payloads that carry them.
        sys.path.insert(0, _PARENT)
        import importlib
        import llmac as cli_mod
        importlib.reload(cli_mod)
        fmt = getattr(cli_mod, "_fmt_err_fields", None)
        self.assertIsNotNone(fmt, "_fmt_err_fields missing in llmac.py")
        line = fmt({"error": "not_a_directory",
                    "path": "/mnt/x/agent.md"})
        self.assertIn("not_a_directory", line)
        self.assertIn("/mnt/x/agent.md", line)
        line2 = fmt({"error": "missing_field", "field": "query",
                     "message": "query or name/glob is required"})
        self.assertIn("missing_field", line2)
        self.assertIn("query or name/glob is required", line2)
        self.assertIn("field: query", line2)


# ---------------------------------------------------------------------------
# Server: /read field guards (direct + batch) + single-file search
# ---------------------------------------------------------------------------

class TestServerReadFieldGuards(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)
        self.bin_path = os.path.join(self.host.root, "blob.bin")
        blob = bytearray(b"\x00" * 300)
        blob[0:2] = b"MZ"
        blob[100:100 + 2] = b"MZ"
        with open(self.bin_path, "wb") as f:
            f.write(bytes(blob))

    def test_bare_max_hits_direct(self):
        resp, st = self.host.post("/read", {"path": self.bin_path,
                                            "max_hits": 5})
        self.assertEqual(st, 400)
        self.assertEqual(resp["error"], "max_hits_unknown_field")
        self.assertIn("find_max_hits", resp["message"])

    def test_find_max_hits_needs_find_direct(self):
        resp, st = self.host.post("/read", {"path": self.bin_path,
                                            "hex": True,
                                            "find_max_hits": 5})
        self.assertEqual(st, 400)
        self.assertEqual(resp["error"], "find_max_hits_needs_find")

    def test_bare_max_hits_batch_op(self):
        # the Task 28 payload mistake: a bare max_hits in a batch read
        # op was silently ignored — it must be a per-op 400 result.
        resp, st = self.host.post("/batch", {"ops": [
            {"op": "read", "path": self.bin_path, "max_hits": 5}]})
        self.assertEqual(st, 200)
        r = resp["results"][0]
        self.assertEqual(r.get("error"), "max_hits_unknown_field")

    def test_find_max_hits_needs_find_batch_op(self):
        resp, st = self.host.post("/batch", {"ops": [
            {"op": "read", "path": self.bin_path, "hex": True,
             "find_max_hits": 5}]})
        self.assertEqual(st, 200)
        r = resp["results"][0]
        self.assertEqual(r.get("error"), "find_max_hits_needs_find")

    def test_find_with_max_hits_still_works(self):
        resp, st = self.host.post("/read", {
            "path": self.bin_path, "hex": True, "find_hex": "4d5a",
            "find_max_hits": 1})
        self.assertEqual(st, 200)
        self.assertEqual(resp["match_count"], 1)
        self.assertTrue(resp["more"])


class TestSearchOnFile(unittest.TestCase):
    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)
        make_tree(self.host.root, {
            "a/notes.txt": "the needle is here\nplain line\n",
            "b/other.txt": "needle elsewhere too\n",
        })
        self.root = self.host.root
        self.f = os.path.join(self.root, "a", "notes.txt")

    def test_content_search_single_file(self):
        resp, st = self.host.post("/search", {"path": self.f,
                                              "query": "needle"})
        self.assertEqual(st, 200)
        self.assertEqual(resp["files_scanned"], 1)
        self.assertEqual(len(resp["matches"]), 1)
        self.assertEqual(resp["matches"][0]["path"], self.f)
        self.assertEqual(resp["matches"][0]["line"], 1)
        # only THIS file: the hit in b/other.txt is not returned
        paths = {m["path"] for m in resp["matches"]}
        self.assertEqual(paths, {self.f})

    def test_content_search_single_file_context(self):
        resp, st = self.host.post("/search", {"path": self.f,
                                              "query": "needle",
                                              "context": 1})
        self.assertEqual(st, 200)
        self.assertEqual(len(resp["matches"][0]["context"]), 2)

    def test_name_search_single_file(self):
        resp, st = self.host.post("/search", {"path": self.f,
                                               "name": "*.txt"})
        self.assertEqual(st, 200)
        self.assertEqual([m["path"] for m in resp["matches"]], [self.f])
        resp2, st2 = self.host.post("/search", {"path": self.f,
                                                 "name": "*.py"})
        self.assertEqual(st2, 200)
        self.assertEqual(resp2["matches"], [])

    def test_nonexistent_path_not_found(self):
        resp, st = self.host.post("/search", {
            "path": os.path.join(self.root, "nope.txt"),
            "query": "x"})
        self.assertEqual(st, 404)
        self.assertEqual(resp["error"], "not_found")
        self.assertTrue(resp["path"].endswith("nope.txt"))

    def test_cli_search_single_file(self):
        out = run_cli(self.host, "search", "--path", self.f,
                      "--query", "needle")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("notes.txt", out.stdout)
        self.assertIn("needle", out.stdout)

    def test_tree_on_file_still_refuses_with_path(self):
        resp, st = self.host.post("/tree", {"path": self.f})
        self.assertEqual(st, 400)
        self.assertEqual(resp["error"], "not_a_directory")
        self.assertEqual(resp["path"], self.f)


# ---------------------------------------------------------------------------
# compare_bench — lesson #10: wrong repo vs file grew vs moved
# ---------------------------------------------------------------------------

class TestCompareBenchDisambiguation(unittest.TestCase):
    """The v2.4.8 gate refusal could not tell 'wrong --repo' from
    'the file legitimately grew' (lessons #8/#10). v2.4.9 names the
    branch, the numbers, and the remedy."""

    @staticmethod
    def _run(file_bytes=114786, file_path="/repo/core/api.py", repo=None,
             version="2.4.9"):
        scens = {}
        names = ("S1_fixed_overhead", "S2_context_cost", "S3_search",
                 "S4_stat_batch", "S5_deploy", "S6_edit_cas",
                 "S7_big_read", "S8_transfer", "S9_long_exec")
        for name, wall in zip(names, (1.0, 0.4, 0.5, 0.3, 2.0, 1.2,
                                      0.9, 1.1, 20.0)):
            d = {"calls": 1, "wall_s": wall, "call_log": [{"x": 1}]}
            if name in ("S2_context_cost", "S3_search", "S4_stat_batch",
                        "S5_deploy", "S6_edit_cas", "S8_transfer"):
                d["median_wall_s"] = wall
            if name == "S5_deploy":
                d["derived"] = {"llmac_deploy_rc": 0,
                                "llmac_deploy_median_s": wall}
            elif name == "S6_edit_cas":
                d["derived"] = {"stale_edit_status": 409}
            elif name == "S7_big_read":
                d["derived"] = {"file_bytes": file_bytes,
                                "file_path": file_path,
                                "smart_read_truncated": True}
            elif name == "S8_transfer":
                d["derived"] = {"file_bytes": file_bytes,
                                "file_path": file_path,
                                "sha_match": True}
            scens[name] = d
        meta = {"server_version": version, "ts": "t", "host": "h"}
        if repo is not None:
            meta["repo"] = repo
        return {"meta": meta, "scenarios": scens}

    def _cmp(self, base, res):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            bp = os.path.join(td, "b.json")
            rp = os.path.join(td, "r.json")
            for path, obj in ((bp, base), (rp, res)):
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(obj, f)
            return subprocess.run(
                [sys.executable, CMP, bp, rp],
                capture_output=True, text=True)

    def test_same_file_grew_branch(self):
        base = self._run(file_bytes=114786,
                         file_path="/repo/core/api.py")
        res = self._run(file_bytes=120000,
                        file_path="/repo/core/api.py")
        p = self._cmp(base, res)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("FILE-GREW", p.stdout)
        self.assertIn("114786", p.stdout)
        self.assertIn("120000", p.stdout)
        self.assertIn("lesson #10", p.stdout)

    def test_same_file_shrank_branch(self):
        base = self._run(file_bytes=120000,
                         file_path="/repo/core/api.py")
        res = self._run(file_bytes=110000,
                        file_path="/repo/core/api.py")
        p = self._cmp(base, res)
        self.assertEqual(p.returncode, 1)
        self.assertIn("FILE-SHRANK", p.stdout)

    def test_moved_file_branch_names_both_lessons(self):
        # the v2.4.8 shape exactly: gui.py-era baseline vs an api.py
        # measurement — MOVED, with BOTH remedies named
        base = self._run(file_bytes=106649, file_path="/repo/gui.py")
        res = self._run(file_bytes=114786,
                        file_path="/repo/core/api.py")
        p = self._cmp(base, res)
        self.assertEqual(p.returncode, 1)
        self.assertIn("MOVED", p.stdout)
        self.assertIn("lesson #8", p.stdout)
        self.assertIn("lesson #10", p.stdout)
        # equal-but-moved bytes used to PASS the gate silently
        res2 = self._run(file_bytes=106649,
                         file_path="/repo/core/api.py")
        p2 = self._cmp(base, res2)
        self.assertEqual(p2.returncode, 1)
        self.assertIn("MOVED", p2.stdout)

    def test_repo_mismatch_asserts_wrong_repo(self):
        base = self._run(file_path="/repo/gui.py", repo="/repoA")
        res = self._run(file_path="/repo/core/api.py",
                        repo="/repoB")
        p = self._cmp(base, res)
        self.assertEqual(p.returncode, 1)
        self.assertIn("MOVED", p.stdout)
        self.assertIn("--repo DIFFERS", p.stdout)
        self.assertIn("lesson #8", p.stdout)

    def test_repo_match_asserts_growth_move(self):
        base = self._run(file_path="/repo/gui.py", repo="/repoA")
        res = self._run(file_bytes=114786,
                        file_path="/repo/core/api.py", repo="/repoA")
        p = self._cmp(base, res)
        self.assertEqual(p.returncode, 1)
        self.assertIn("MOVED", p.stdout)
        self.assertIn("legitimately", p.stdout)
        self.assertIn("fresh baseline", p.stdout)


if __name__ == "__main__":
    unittest.main()
