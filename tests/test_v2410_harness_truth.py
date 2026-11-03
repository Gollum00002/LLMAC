"""v2.4.10 — harness truth: the comparator's v2.4.7 S5 policy
restored (the scenario wall EXCLUDED from the wall gate — naive
single-shot WAN-leg noise; S5 GATES on derived llmac_deploy_median_s
with a single-shot fallback), and the bench s7/s8 derived metrics
indexed BY OP so --big-file's /stat size-fill can no longer shift
them (Task 31: the probe's "whole_read 173 B" was the /stat
response; every call was 200).

Covers:
  CMP     S5 wall noise never fails the gate (still printed, tagged
          EXCLUDED); the S5 MEDIAN does fail; the sub-second band;
          fallback to llmac_deploy_wall_s when a run lacks the
          median; improvement never fails; S5 absent warns like the
          pins do, it does not fail
  BENCH   s7+s8 walk-mode vs --big-file-pinned on the SAME file, end
          to end against a headless TestHost: the derived read/stat/
          waste numbers must be IDENTICAL (the old position indexing
          read the /stat response as the whole read under --big-file)
  OP      _by_op picks the Nth call of an op, skipping unrelated
          calls (the /stat size-fill), None when the op never ran
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

CLI = os.path.join(_PARENT, "llmac.py")
CMP = os.path.join(_PARENT, "scripts", "compare_bench.py")
BENCH = os.path.join(_PARENT, "tools", "bench_llmac.py")


def _load_bench():
    spec = importlib.util.spec_from_file_location("bench_llmac_v2410",
                                                  BENCH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# compare_bench — the restored v2.4.7 S5 policy
# ---------------------------------------------------------------------------

class TestCompareBenchS5Policy(unittest.TestCase):
    """The v2.4.8 rebuild of the comparator followed "the same verdict
    policy the v2.4.7 gate was read with" but missed the S5 carve-out:
    the scenario wall is naive single-shot WAN-leg noise (v2.4.7:
    1.05->2.44s untouched; Task 31: +61.6% probe -> -13.9% parity) and
    must NOT gate. The Task-31 first probe FALSE-FAILED the gate on it.
    S5 gates on the derived deploy median instead (the v2.4.7 spec
    that survives in the WORKLOG build entry)."""

    @staticmethod
    def _run(s5_wall=2.0, s5_median=1.014, s5_fallback=None,
             version="2.4.9", skip_s5=False):
        scens = {}
        names = ("S1_fixed_overhead", "S2_context_cost", "S3_search",
                 "S4_stat_batch", "S5_deploy", "S6_edit_cas",
                 "S7_big_read", "S8_transfer", "S9_long_exec")
        walls = (1.0, 0.4, 0.5, 0.3, s5_wall, 1.2, 0.9, 1.1, 20.0)
        for name, wall in zip(names, walls):
            if name == "S5_deploy" and skip_s5:
                continue
            d = {"calls": 1, "wall_s": wall, "call_log": [{"x": 1}]}
            if name in ("S2_context_cost", "S3_search", "S4_stat_batch",
                        "S6_edit_cas", "S8_transfer"):
                d["median_wall_s"] = wall
            if name == "S5_deploy":
                der = {"llmac_deploy_rc": 0}
                if s5_median is not None:
                    der["llmac_deploy_median_s"] = s5_median
                if s5_fallback is not None:
                    der["llmac_deploy_wall_s"] = s5_fallback
                d["derived"] = der
            elif name == "S6_edit_cas":
                d["derived"] = {"stale_edit_status": 409}
            elif name == "S7_big_read":
                d["derived"] = {"file_bytes": 116107,
                               "file_path": "/repo/core/api.py",
                               "smart_read_truncated": True}
            elif name == "S8_transfer":
                d["derived"] = {"file_bytes": 116107,
                               "file_path": "/repo/core/api.py",
                               "sha_match": True}
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
                [sys.executable, CMP, bp, rp],
                capture_output=True, text=True)

    def test_s5_wall_noise_does_not_fail_the_gate(self):
        # the Task-31 first probe, exactly: wall +65% single-shot WAN
        # noise while the deploy median IMPROVED (1.014 -> 1.007)
        base = self._run(s5_wall=2.0, s5_median=1.014)
        res = self._run(s5_wall=3.3, s5_median=1.007)
        p = self._cmp(base, res)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("GATE PASS", p.stdout)
        self.assertIn("EXCLUDED", p.stdout)
        self.assertIn("llmac_deploy_median_s", p.stdout)
        self.assertNotIn("REGRESSION", p.stdout)

    def test_s5_median_regression_fails(self):
        # wall flat, the MEDIAN +58% over a ~1s baseline -> +25% band
        base = self._run(s5_wall=2.0, s5_median=1.014)
        res = self._run(s5_wall=2.1, s5_median=1.6)
        p = self._cmp(base, res)
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("GATE FAIL", p.stdout)
        self.assertIn("S5_deploy.llmac_deploy_median_s", p.stdout)
        self.assertIn("REGRESSION", p.stdout)

    def test_s5_median_subsecond_band(self):
        # baseline median 0.6s -> sub-second band (+50%)
        base = self._run(s5_median=0.6)
        hot = self._cmp(base, self._run(s5_median=1.0))   # +67% FAIL
        self.assertEqual(hot.returncode, 1)
        self.assertIn("S5_deploy.llmac_deploy_median_s", hot.stdout)
        # +33% inside the +50% band -> WARN, not FAIL
        warm = self._cmp(base, self._run(s5_median=0.8))
        self.assertEqual(warm.returncode, 0, warm.stdout)
        self.assertIn("WARN", warm.stdout)

    def test_s5_median_fallback_single_shot(self):
        # pre-v2.4.7-era runs carry only the single-shot deploy wall —
        # the gate falls back to it and names the fallback
        base = self._run(s5_median=None, s5_fallback=1.2)
        bad = self._cmp(base, self._run(s5_median=None, s5_fallback=2.0))
        self.assertEqual(bad.returncode, 1, bad.stdout)
        self.assertIn("llmac_deploy_wall_s", bad.stdout)
        self.assertIn("fallback", bad.stdout)
        ok = self._cmp(base, self._run(s5_median=None, s5_fallback=1.3))
        self.assertEqual(ok.returncode, 0, ok.stdout)

    def test_s5_median_improvement_never_fails(self):
        base = self._run(s5_median=1.014)
        res = self._run(s5_median=0.70)                 # -31% FASTER
        p = self._cmp(base, res)
        self.assertEqual(p.returncode, 0, p.stdout)

    def test_s5_absent_from_results_warns(self):
        # S5 skipped (no --deploy-list) -> warn like the pins, not fail
        base = self._run()
        res = self._run(skip_s5=True)
        p = self._cmp(base, res)
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertIn("WARN", p.stdout)
        self.assertIn("absent", p.stdout)


# ---------------------------------------------------------------------------
# bench_llmac — s7/s8 derived metrics index call_log BY OP
# ---------------------------------------------------------------------------

class TestBenchBigFileIndices(unittest.TestCase):
    """Task 31 ran the gate probe with --big-file pinned and s7's
    derived metrics read the /stat size-fill response as the whole
    read ("whole_read 173 B" — every call 200). s7/s8 must pick their
    call records BY OP so the derived numbers are identical between
    walk-mode and pinned-mode on the SAME file."""

    def setUp(self):
        self.host = TestHost()
        self.addCleanup(self.host.stop)
        make_tree(self.host.root, {
            "README.md": "r" * 200,
            "small/a.txt": "y" * 64,
            "core/api.py": "A" * 3000,          # the biggest code file
        })
        self.repo = self.host.root
        self.api = os.path.join(self.host.root, "core", "api.py")
        # the bench's in-scenario llmac.py subprocess reads read the
        # connection from LLMAC_* env vars, exactly like the CLI
        self._env = {k: os.environ.get(k) for k in
                     ("LLMAC_HOST", "LLMAC_PORT", "LLMAC_KEY")}
        os.environ["LLMAC_HOST"] = "127.0.0.1"
        os.environ["LLMAC_PORT"] = str(self.host.port)
        os.environ["LLMAC_KEY"] = self.host.key
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _run_s7(self, big_file):
        bench = _load_bench()
        c = bench.BenchClient("127.0.0.1", self.host.port, self.host.key,
                              tls=False, fp="")
        b = bench.Bench(c)
        bench.s7(b, self.repo, big_file)
        return b.scenarios["S7_big_read"]

    def _run_s8(self, big_file):
        bench = _load_bench()
        c = bench.BenchClient("127.0.0.1", self.host.port, self.host.key,
                              tls=False, fp="")
        b = bench.Bench(c)
        bench.s8(b, self.repo, big_file)
        return b.scenarios["S8_transfer"]

    def test_s7_walk_vs_bigfile_same_derived(self):
        walk = self._run_s7(None)
        pinned = self._run_s7(self.api)
        for k in ("file_path", "file_bytes", "whole_read_resp_bytes",
                  "ranged_read_resp_bytes", "waste_ratio_x"):
            self.assertEqual(walk["derived"][k], pinned["derived"][k],
                             f"{k}: {walk['derived'][k]!r} vs "
                             f"{pinned['derived'][k]!r}")
        # the whole read of a 3000 B file is NOT the ~173 B /stat
        # response the position bug reported under --big-file
        self.assertGreater(pinned["derived"]["whole_read_resp_bytes"],
                           1000)

    def test_s8_walk_vs_bigfile_same_derived(self):
        walk = self._run_s8(None)
        pinned = self._run_s8(self.api)
        for k in ("file_path", "file_bytes", "read_wire_bytes",
                  "read_decoded_bytes", "stat_hash_resp_bytes"):
            self.assertEqual(walk["derived"][k], pinned["derived"][k],
                             f"{k}: {walk['derived'][k]!r} vs "
                             f"{pinned['derived'][k]!r}")
        # NOTE: the CLI download leg cannot run against a plain-HTTP
        # TestHost (llmac.py env-override defaults to TLS; the real bench
        # runs pinned-TLS and the live gate pins sha_match True on S8).
        # Here sha_match must merely be IDENTICAL across the two modes.
        self.assertEqual(walk["derived"]["sha_match"],
                         pinned["derived"]["sha_match"])

    def test_by_op_skips_inserted_stat(self):
        bench = _load_bench()
        d = {"call_log": [
            {"path": "/tree", "decoded_bytes": 500},
            {"path": "/stat", "decoded_bytes": 173},   # size-fill
            {"path": "/read", "decoded_bytes": 4000},
            {"path": "/read", "decoded_bytes": 900},
        ]}
        self.assertEqual(bench._by_op(d, "/read", 0)["decoded_bytes"],
                         4000)
        self.assertEqual(bench._by_op(d, "/read", 1)["decoded_bytes"],
                         900)
        self.assertIsNone(bench._by_op(d, "/read", 2))
        self.assertEqual(bench._by_op(d, "/stat", 0)["decoded_bytes"],
                         173)
        self.assertIsNone(bench._by_op(d, "/delete", 0))


if __name__ == "__main__":
    unittest.main()
