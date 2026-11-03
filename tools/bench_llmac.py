#!/usr/bin/env python3
"""LLMAC agent-workload benchmark — the efficiency regression gate (C2).

Replays real agent workflows against a live host and measures the two
currencies agents pay in: wall time and context bytes. Run before each
release and compare against the committed baseline (delta > 10% on any
scenario blocks the release).

Usage (from anywhere):
  python3 tools/bench_llmac.py --repo /host/path/to/codebase \
      [--deploy-list deploy.json --local-dir LOCAL_FILES_DIR] \
      [--out results.json] [--skip-long]

Scenarios S1-S9 (v2.4.2: S6_edit_cas + S8_transfer ported in so the
committed gate covers every scenario of the 2026-10-25 baseline).

deploy.json: {"files": ["core/api.py", ...]} (paths relative to --repo
on the host, and to --local-dir locally). Connection is read from
~/.llmac/connections.json (--conn NAME) or overridden with
LLMAC_HOST/LLMAC_PORT/LLMAC_KEY env vars, exactly like the CLI.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib  # noqa: F401  (kept for downstream derivations)
import http.client
import json
import os
import statistics
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)
CLI = os.path.join(_REPO_ROOT, "llmac.py")


def _load_cli():
    import importlib.util
    spec = importlib.util.spec_from_file_location("llmac_bench_cli", CLI)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


llmac = _load_cli()


class BenchClient(llmac.Client):
    """Instrumented transport: wire bytes (post-gzip) vs decoded bytes."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.calls = []

    def _attempt(self, method, path, body, headers, raw=False, timeout=30.0):
        t0 = time.perf_counter()
        try:
            if self._conn is None:
                self._conn = self._open_connection(timeout)
            self._conn.request(method, path, body=body, headers=headers)
            resp = self._conn.getresponse()
            wire = resp.read()
            dur = time.perf_counter() - t0
            enc = (resp.getheader("Content-Encoding") or "").lower()
            gz = "gzip" in enc
            decoded = gzip.decompress(wire) if gz else wire
            self.calls.append({
                "method": method, "path": path.split("?")[0][:48],
                "req_bytes": len(body) if body else 0,
                "wire_bytes": len(wire), "decoded_bytes": len(decoded),
                "gzip": gz, "dur_s": round(dur, 4), "status": resp.status})
            if raw:
                return wire, resp.status
            try:
                return json.loads(decoded.decode("utf-8") or "{}"), resp.status
            except json.JSONDecodeError:
                return {"error": "bad_response"}, resp.status
        except (http.client.HTTPException, OSError):
            try:
                if self._conn is not None:
                    self._conn.close()
            except Exception:
                pass
            self._conn = None
            return None, 0


class Bench:
    def __init__(self, client):
        self.c = client
        self.scenarios = {}
        self.cli_calls = []

    def repeat(self, n, fn):
        """v2.4.6 (session-17 lesson #3): sub-second scenarios jitter
        +-15% single-shot on unchanged code. Warm up once, then time
        fn() n times and return the MEDIAN wall — comparators prefer
        scenarios[s]['median_wall_s'] over the single-shot wall_s
        whenever it exists. fn must be read-only or self-cleaning per
        iteration (the S6 CAS loop re-reads its version tokens, so it
        is re-entrant)."""
        fn()                                # warm-up (JIT-ish paths, TLS)
        walls = []
        for _ in range(n):
            t0 = time.perf_counter()
            fn()
            walls.append(time.perf_counter() - t0)
        return round(statistics.median(walls), 3)

    def scenario(self, name, notes=""):
        b = self

        class _S:
            def __enter__(s):
                s._i0 = len(b.c.calls)
                s._c0 = len(b.cli_calls)
                s._t0 = time.perf_counter()
                return b

            def __exit__(s, et, e, tb):
                calls = b.c.calls[s._i0:]
                clis = b.cli_calls[s._c0:]
                b.scenarios[name] = {
                    "notes": notes, "calls": len(calls),
                    "cli_calls": len(clis),
                    "req_bytes": sum(x["req_bytes"] for x in calls),
                    "wire_bytes": sum(x["wire_bytes"] for x in calls),
                    "decoded_bytes": sum(x["decoded_bytes"] for x in calls),
                    "est_tokens": sum(
                        x["decoded_bytes"] for x in calls) // 4
                    + sum(x["stdout_bytes"] + x["stderr_bytes"]
                          for x in clis) // 4,
                    "cli_output_bytes": sum(
                        x["stdout_bytes"] + x["stderr_bytes"] for x in clis),
                    "wall_s": round(time.perf_counter() - s._t0, 3),
                    "call_log": calls, "cli_log": clis}
                return False
        return _S()


def cli_run(*args, cwd=None):
    t0 = time.perf_counter()
    r = subprocess.run([sys.executable, CLI, *args],
                       capture_output=True, cwd=cwd, timeout=120)
    return {"args": " ".join(args)[:60],
            "wall_s": round(time.perf_counter() - t0, 4),
            "stdout_bytes": len(r.stdout), "stderr_bytes": len(r.stderr),
            "rc": r.returncode}


def s1(b: Bench):
    with b.scenario("S1_fixed_overhead", "per-call fixed cost decomposition"):
        for _ in range(15):
            b.c.get("/info")
        for _ in range(3):
            host = b.c.base.split("//")[1].rsplit(":", 1)[0]
            port = int(b.c.base.rsplit(":", 1)[1])
            c2 = BenchClient(host, port, b.c.key,
                             tls=b.c.scheme == "https", fp=b.c.fp)
            c2.get("/info")
            c2._conn.close()
            b.c.calls.extend(c2.calls)
        for _ in range(3):
            b.cli_calls.append(cli_run("--version"))
        for _ in range(8):
            b.cli_calls.append(cli_run("info"))
    d = b.scenarios["S1_fixed_overhead"]
    ka = [x["dur_s"] for x in d["call_log"][:15]]
    cli_t = [x["wall_s"] for x in d["cli_log"][3:]]
    d["derived"] = {
        "keepalive_median_s": round(statistics.median(ka), 4),
        "fresh_tls_median_s": round(statistics.median(
            [x["dur_s"] for x in d["call_log"][15:18]]), 4),
        "cli_startup_median_s": round(statistics.median(
            [x["wall_s"] for x in d["cli_log"][:3]]), 4),
        "cli_full_median_s": round(statistics.median(cli_t), 4),
        "cli_fixed_overhead_s": round(statistics.median(cli_t)
                                      - statistics.median(ka), 4)}


def s2(b: Bench, repo: str):
    with b.scenario("S2_orientation", "fresh-agent boot cost"):
        b.c.get("/info")
        b.c.post("/tree", {"path": repo, "depth": 2, "all": False})
        b.c.post("/read", {"path": repo + "/README.md"})
        b.c.post("/read", {"path": repo + "/agent.md"})
        b.c.post("/session/status", {})
    d = b.scenarios["S2_orientation"]
    d["derived"] = {"context_cost_est_tokens": d["est_tokens"]}
    # v2.4.6: median-of-5 for the 2-RTT-class scenarios (lesson #3).
    d["median_wall_s"] = b.repeat(5, lambda: (
        b.c.get("/info"),
        b.c.post("/tree", {"path": repo, "depth": 2, "all": False}),
        b.c.post("/read", {"path": repo + "/README.md"}),
        b.c.post("/read", {"path": repo + "/agent.md"}),
        b.c.post("/session/status", {})))


def s3(b: Bench, repo: str):
    with b.scenario("S3_search", "search vs read-everything"):
        b.c.post("/search", {"path": repo, "query": "def h_read",
                             "regex": False, "context": 1,
                             "max_results": 50, "all": False})
        resp, _ = b.c.post("/tree", {"path": repo, "depth": 4, "all": False})
    py_total = sum(e.get("size") or 0
                   for t in (resp or {}).get("trees", [resp or {}])
                   for e in t.get("entries", [])
                   if e.get("path", "").endswith(".py"))
    d = b.scenarios["S3_search"]
    d["derived"] = {
        "search_resp_bytes": d["call_log"][0]["decoded_bytes"],
        "naive_read_all_py_bytes": py_total,
        "naive_vs_search": round(py_total / max(
            1, d["call_log"][0]["decoded_bytes"]), 1)}
    # v2.4.6: median-of-5 — S3 is 2 RTTs and the noisiest scenario of
    # the set (live evidence session 17: 0.374-0.422 on IDENTICAL
    # handler code while single-shot flags cried +10-15%).
    d["median_wall_s"] = b.repeat(5, lambda: (
        b.c.post("/search", {"path": repo, "query": "def h_read",
                             "regex": False, "context": 1,
                             "max_results": 50, "all": False}),
        b.c.post("/tree", {"path": repo, "depth": 4, "all": False})))


def s4(b: Bench, repo: str):
    with b.scenario("S4_stat_batch", "21 stats sequential vs batch"):
        tr, _ = b.c.post("/tree", {"path": repo, "depth": 4, "all": False})
        paths = [e["path"] for t in tr.get("trees", [tr])
                 for e in t.get("entries", []) if e.get("type") == "file"][:21]
        for p in paths:
            b.c.post("/stat", {"path": p})
        b.c.post("/batch", {"ops": [{"op": "stat", "path": p}
                                    for p in paths]})
        b.cli_calls.append(cli_run(
            "batch", "--ops",
            json.dumps([{"op": "stat", "path": p} for p in paths])))
    d = b.scenarios["S4_stat_batch"]
    seq = [x["dur_s"] for x in d["call_log"][:len(paths)]]
    bat = d["call_log"][len(paths)]["dur_s"]
    d["derived"] = {"sequential_wall_s": round(sum(seq), 3),
                    "batch_wall_s": round(bat, 4),
                    "speedup": round(sum(seq) / bat, 1),
                    "cli_batch_wall_s": d["cli_log"][0]["wall_s"]}
    # v2.5.2 (Task-38 diagnosis): the single in-scenario batch leg
    # lands in ~40 ms bimodal WAN jitter buckets — the speedup ratio
    # flapped 22.6 -> 18.4 on untouched code (seq legs flat at +1.2%,
    # median-of-3 probe FASTER than the baseline leg). Same cure as S5
    # (v2.4.7 lesson #4): two extra idempotent batch probes give a
    # median-of-3 the gate can trust; the in-scenario call stays
    # single so byte/comparability metrics are untouched.
    probes = [bat]
    for _ in range(2):
        b.c.post("/batch", {"ops": [{"op": "stat", "path": p}
                                    for p in paths]})
        probes.append(b.c.calls[-1]["dur_s"])
    d["derived"]["batch_median_s"] = round(statistics.median(probes), 4)


def s5(b: Bench, repo: str, local_dir: str, deploy_list: list):
    with b.scenario("S5_deploy",
                    "N-file deploy: naive loop vs llmac deploy (A1)"):
        for rel in deploy_list:
            with open(os.path.join(local_dir, rel), "rb") as f:
                data = f.read()
            payload = {"path": f"{repo}/bench-deploy/{rel}"}
            try:
                payload["content"] = data.decode("utf-8")
            except UnicodeDecodeError:
                import base64
                payload["content_b64"] = base64.b64encode(data).decode()
            b.c.post("/write", payload)
        b.c.post("/exec", {"command": "sha256sum " + " ".join(
            f"{repo}/bench-deploy/{r}" for r in deploy_list),
            "cwd": "", "timeout": 60})
        pairs = [f"{local_dir}/{r}={repo}/bench-deploy/{r}"
                 for r in deploy_list]
        argv = ["deploy"]
        for p in pairs:
            argv += ["--pairs", p]
        b.cli_calls.append(cli_run(*argv))
    d = b.scenarios["S5_deploy"]
    naive = [x["dur_s"] for x in d["call_log"]]
    d["derived"] = {
        "naive_wall_s": round(sum(naive), 3), "naive_calls": len(naive),
        "llmac_deploy_wall_s": d["cli_log"][0]["wall_s"],
        "llmac_deploy_rc": d["cli_log"][0]["rc"]}
    # v2.4.7 (session-19 lesson #4): ~2s scenarios spike +-50% single-shot
    # on untouched code (S5 flagged +50.2% once). Two extra deploy probes
    # give a median-of-3 for the gate; the in-scenario call stays single
    # so the byte-economy metrics stay comparable. Deploys are
    # idempotent — same files, new version tokens, no cleanup needed.
    probes = [d["cli_log"][0]["wall_s"]]
    for _ in range(2):
        probes.append(cli_run(*argv)["wall_s"])
    d["derived"]["llmac_deploy_median_s"] = round(
        statistics.median(probes), 3)


def s6(b: Bench, repo: str):
    """v2.4.2: ported from the session-12 pre-release harness so the
    committed gate covers every baseline scenario. The stale-version
    edit doubles as a guard for the v2.4.1 real-status change (409)."""
    with b.scenario("S6_edit_cas",
                    "edit loop incl. one version-conflict recovery"):
        base = f"{repo}/bench-cas"
        p = base + "/cas.txt"
        b.c.post("/mkdir", {"path": base})
        b.c.post("/write", {"path": p, "content": "alpha\nbeta\ngamma\n"})
        r1, _ = b.c.post("/read", {"path": p})
        v1 = (r1 or {}).get("version", "")
        b.c.post("/edit", {"path": p, "expected_version": v1,
                            "ops": [{"op": "append", "content": "delta\n"}]})
        b.c.post("/edit", {"path": p, "expected_version": v1,
                            "ops": [{"op": "append",
                                     "content": "should fail\n"}]})
        r3, _ = b.c.post("/read", {"path": p})
        v3 = (r3 or {}).get("version", "")
        b.c.post("/edit", {"path": p, "expected_version": v3,
                            "ops": [{"op": "append", "content": "epsilon\n"}]})
    d = b.scenarios["S6_edit_cas"]
    d["derived"] = {
        # call order: mkdir, write, read, edit(ok), edit(STALE->409), read, edit
        "stale_edit_status": d["call_log"][4]["status"],
        "statuses": [x["status"] for x in d["call_log"]]}

    def cas_roundtrip():
        base = f"{repo}/bench-cas"
        p = base + "/cas.txt"
        b.c.post("/mkdir", {"path": base})
        b.c.post("/write", {"path": p, "content": "alpha\nbeta\ngamma\n"})
        r1, _ = b.c.post("/read", {"path": p})
        v1 = (r1 or {}).get("version", "")
        b.c.post("/edit", {"path": p, "expected_version": v1,
                            "ops": [{"op": "append", "content": "delta\n"}]})
        b.c.post("/edit", {"path": p, "expected_version": v1,
                            "ops": [{"op": "append",
                                     "content": "should fail\n"}]})
        r3, _ = b.c.post("/read", {"path": p})
        v3 = (r3 or {}).get("version", "")
        b.c.post("/edit", {"path": p, "expected_version": v3,
                            "ops": [{"op": "append", "content": "epsilon\n"}]})

    # v2.4.6: median-of-5 — the loop is re-entrant (versions are
    # re-read each pass) and self-resetting (write recreates cas.txt).
    d["median_wall_s"] = b.repeat(5, cas_roundtrip)


# v2.4.8 (lesson #8): S7/S8 measure the biggest CODE file. Archive
# suffixes are skipped by default — user data parked next to a repo
# (e.g. a 225 KB zip bigger than every source file) must not hijack
# the walk and silently change what the scenario measures. --big-file
# pins the target explicitly when even code-size heuristics are wrong.
_BIG_FILE_SKIP_SUFFIXES = (".zip", ".tar", ".tgz", ".gz", ".7z",
                           ".rar", ".xz", ".bz2", ".zst")


def _biggest_file(trees, big_file=None):
    """The deterministic S7/S8 target: --big-file wins outright;
    otherwise the biggest non-archive FILE entry across the walked
    trees. Kept module-level so tests can exercise the walk policy
    without a live host."""
    if big_file:
        return {"path": big_file, "size": None}   # size filled by /stat
    best = None
    for t in trees:
        for e in (t or {}).get("entries", []):
            if e.get("type") != "file" or not e.get("size"):
                continue
            if str(e.get("path", "")).lower().endswith(
                    _BIG_FILE_SKIP_SUFFIXES):
                continue
            if best is None or e["size"] > best["size"]:
                best = e
    return best


def _by_op(d: dict, path: str, nth: int = 0):
    """v2.4.10: s7/s8 derived metrics index call_log BY OP, not
    position — under --big-file the /stat size-fill lands INSIDE the
    S7 scenario, so the fixed indices read the wrong record (Task 31:
    the probe's "whole_read 173 B" was the /stat response; every
    call was 200). nth picks the Nth call of that op; None when the
    op never ran (the scenario derived is then skipped)."""
    hits = [x for x in d["call_log"] if x.get("path") == path]
    return hits[nth] if len(hits) > nth else None


def s8(b: Bench, repo: str, big_file: str | None = None):
    """v2.4.2: ported (self-contained redesign — no pinned zip path):
    the repo's biggest CODE file is pulled three ways — base64-through-
    /read, hash-only via stat --hash (B3), and CLI download — and all
    three sha256 must agree (transfer integrity without hardcoded
    constants).
    v2.4.8 (lesson #8): archives are skipped by the biggest-file walk
    (user data next to the code — e.g. a 225 KB zip — must not hijack
    the scenario), and --big-file pins the target explicitly."""
    import base64 as _b64
    import hashlib as _hl
    tr, _ = b.c.post("/tree", {"path": repo, "depth": 4, "all": False})
    biggest = _biggest_file((tr or {}).get("trees") or [tr or {}],
                            big_file)
    if big_file and biggest and not biggest.get("size"):
        st, _ = b.c.post("/stat", {"path": big_file})
        biggest["size"] = (st or {}).get("size")
    if not biggest:
        return
    p = biggest["path"]
    with b.scenario("S8_transfer",
                    "big file: /read base64 vs stat --hash vs CLI download"):
        r, _ = b.c.post("/read", {"path": p})
        data = None
        if isinstance(r, dict):
            if r.get("content_b64"):
                data = _b64.b64decode(r["content_b64"])
            elif r.get("content") is not None:
                data = r["content"].encode("utf-8", "surrogateescape")
        sha_read = _hl.sha256(data).hexdigest() if data else None
        st, _ = b.c.post("/stat", {"path": p, "hash": True})
        sha_remote = (st or {}).get("sha256")
        b.cli_calls.append(cli_run(
            "download", "--path", p, "--to", "/tmp/llmac-bench-dl.bin"))
        sha_dl = None
        try:
            with open("/tmp/llmac-bench-dl.bin", "rb") as f:
                sha_dl = _hl.sha256(f.read()).hexdigest()
        except OSError:
            pass
    d = b.scenarios["S8_transfer"]
    read_c = _by_op(d, "/read", 0)
    stat_c = _by_op(d, "/stat", 0)
    if read_c is None or stat_c is None:
        return
    d["derived"] = {
        "file_path": p,
        "file_bytes": biggest.get("size"),
        "read_wire_bytes": read_c["wire_bytes"],
        "read_decoded_bytes": read_c["decoded_bytes"],
        "stat_hash_resp_bytes": stat_c["decoded_bytes"],
        "cli_download_wall_s": d["cli_log"][0]["wall_s"],
        "sha_match": bool(sha_read and sha_read == sha_remote == sha_dl)}
    # v2.4.6: median-of-5 over the two POSTs (the CLI download keeps
    # its own single-shot wall — subprocess startup dominates it).
    d["median_wall_s"] = b.repeat(5, lambda: (
        b.c.post("/read", {"path": p}),
        b.c.post("/stat", {"path": p, "hash": True})))


def s7(b: Bench, repo: str, big_file: str | None = None):
    with b.scenario("S7_big_read",
                    "whole vs ranged vs smart read (A4)"):
        tr, _ = b.c.post("/tree", {"path": repo, "depth": 2, "all": False})
        biggest = _biggest_file(tr.get("trees") or [tr], big_file)
        if big_file and biggest and not biggest.get("size"):
            st, _ = b.c.post("/stat", {"path": big_file})
            biggest["size"] = (st or {}).get("size")
        if not biggest:
            return
        p = biggest["path"]
        b.c.post("/read", {"path": p})
        b.c.post("/read", {"path": p, "from_line": 1, "to_line": 50})
        smart = subprocess.run([sys.executable, CLI, "read", "--path", p],
                               capture_output=True)
        raw = subprocess.run([sys.executable, CLI, "read", "--path", p,
                              "--raw"], capture_output=True)
        b.cli_calls.append({"args": f"read --path {p}", "wall_s": 0.0,
                           "stdout_bytes": len(smart.stdout),
                           "stderr_bytes": len(smart.stderr),
                           "rc": smart.returncode})
        b.cli_calls.append({"args": f"read --path {p} --raw", "wall_s": 0.0,
                           "stdout_bytes": len(raw.stdout),
                           "stderr_bytes": len(raw.stderr),
                           "rc": raw.returncode})
    d = b.scenarios["S7_big_read"]
    if biggest is None:
        return
    whole = _by_op(d, "/read", 0)          # the whole-file /read
    ranged = _by_op(d, "/read", 1)         # the ranged /read
    if whole is None or ranged is None:
        return
    d["derived"] = {
        "file_path": biggest["path"],
        "file_bytes": biggest["size"],
        "whole_read_resp_bytes": whole["decoded_bytes"],
        "ranged_read_resp_bytes": ranged["decoded_bytes"],
        "smart_read_stdout_bytes": len(smart.stdout),
        "smart_read_truncated": b"smart-truncated" in smart.stderr,
        "raw_stdout_bytes": len(raw.stdout),
        "waste_ratio_x": round(
            whole["decoded_bytes"] / max(1, ranged["decoded_bytes"]), 1)}


def s9(b: Bench, skip=False):
    if skip:
        return
    with b.scenario("S9_long_exec", "20s command through exec"):
        b.c.post("/exec", {"command": "sleep 20 && echo bench-done",
                           "cwd": "", "timeout": 40}, timeout=70)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True,
                    help="path to a codebase on the HOST (inside a root)")
    ap.add_argument("--conn", default="default")
    ap.add_argument("--deploy-list", default=None,
                    help='JSON file: {"files": ["rel/path", ...]}')
    ap.add_argument("--local-dir", default=None,
                    help="local dir mirroring the repo (for S5)")
    ap.add_argument("--big-file", default=None, dest="big_file",
                    help="v2.4.8 (lesson #8): explicit S7/S8 target file "
                         "(absolute host path inside a root). Overrides "
                         "the biggest-file walk; archives are skipped "
                         "by the walk either way.")
    ap.add_argument("--out", default="bench-results.json")
    ap.add_argument("--skip-long", action="store_true")
    args = ap.parse_args()

    conns_file = os.path.join(os.path.expanduser("~"),
                              ".llmac", "connections.json")
    saved = {}
    if os.path.exists(conns_file):
        saved = (json.load(open(conns_file))
                 .get(args.conn) or {})
    host = os.environ.get("LLMAC_HOST") or saved.get("host", "127.0.0.1")
    port = int(os.environ.get("LLMAC_PORT") or saved.get("port", 8765))
    key = os.environ.get("LLMAC_KEY") or saved.get("key", "")
    fp = saved.get("fp", "")
    c = BenchClient(host, port, key, tls=saved.get("tls", False), fp=fp)
    b = Bench(c)
    if c.scheme == "https" and fp:
        live = c.server_fingerprint()
        assert live == fp, f"pin mismatch: {live}"

    info, _ = c.get("/info")
    print("server:", info.get("version"), "policy:",
          info.get("approval_policy"))
    c.calls = []            # warmup excluded

    s1(b)
    s2(b, args.repo)
    s3(b, args.repo)
    s4(b, args.repo)
    if args.deploy_list and args.local_dir:
        dl = json.load(open(args.deploy_list))
        s5(b, args.repo, args.local_dir, dl["files"])
    s6(b, args.repo)
    s7(b, args.repo, args.big_file)
    s8(b, args.repo, args.big_file)
    s9(b, args.skip_long)

    if args.deploy_list and args.local_dir:
        c.post("/delete", {"path": args.repo + "/bench-deploy",
                           "confirm": True})
    c.post("/delete", {"path": args.repo + "/bench-cas",
                       "confirm": True})

    out = {"meta": {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "server_version": info.get("version"),
                    "policy": info.get("approval_policy"), "host": host,
                    "repo": args.repo,
                    "client_python": sys.version.split()[0]},
           "scenarios": b.scenarios}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)

    print(f"\n{'scenario':<18}{'calls':>6}{'wire':>10}{'decoded':>10}"
          f"{'est_tok':>9}{'wall_s':>8}")
    for name, d in b.scenarios.items():
        if not isinstance(d, dict) or "calls" not in d:
            continue
        print(f"{name:<18}{d['calls'] + d['cli_calls']:>6}"
              f"{d['wire_bytes']:>10}"
              f"{d['decoded_bytes'] + d['cli_output_bytes']:>10}"
              f"{d['est_tokens']:>9}{d['wall_s']:>8}")
    for name, d in b.scenarios.items():
        for k, v in (d.get("derived") or {}).items():
            print(f"  {name}.{k}: {v}")
        if isinstance(d, dict) and "median_wall_s" in d:
            print(f"  {name}.median_wall_s: {d['median_wall_s']}")
    print("\nwritten:", args.out)


if __name__ == "__main__":
    main()
