#!/usr/bin/env python3
"""v2.4.8 (restored): the gate comparator for the nine-scenario bench run.

scripts/compare_bench.py was lost with the host reorg (STATE.md still
names it as THE release gate: "gate = scripts/compare_bench.py vs
tools/baseline-2026-10-28-full.json") — this is a byte-fresh rebuild
following the same verdict policy the v2.4.7 gate was read with.

v2.4.9 (lesson #10): the same-file refusal now DISEMBIGUATES —
"wrong --repo" (lesson #8) and "the file legitimately GREW" are
different situations with different remedies, and the old message
blamed the repo for both. meta.repo (recorded by bench_llmac.py from
v2.4.9 on) sharpens the call when both runs carry it.

v2.4.10 (harness truth): the v2.4.7 S5 policy the rebuild lost is
RESTORED — the S5 scenario wall is naive single-shot WAN-leg noise
(v2.4.7: 1.05->2.44s on untouched code; Task 31: +61.6% probe ->
-13.9% parity run) and is EXCLUDED from the wall gate; S5 gates on
the derived llmac_deploy_median_s instead, falling back to the
single-shot llmac_deploy_wall_s only when a run lacks the median.

Usage:
  python3 scripts/compare_bench.py tools/baseline-2026-10-28-v249-full.json \
      stress/bench-results/<run>.json

Verdict policy:
  * Correctness pins must hold in the RESULTS run regardless of the
    baseline: S5 llmac_deploy_rc==0, S6 stale_edit_status==409,
    S7 smart_read_truncated, S8 sha_match.
  * S5: the scenario wall is EXCLUDED from the wall gate (naive
    single-shot WAN-leg noise — the v2.4.7 carve-out, restored in
    v2.4.10); S5 gates on derived llmac_deploy_median_s (fallback:
    the single-shot llmac_deploy_wall_s) under the same bands.
  * S7/S8 must measure the SAME file as the baseline (file_path AND
    file_bytes — v2.4.9: a moved target with equal bytes used to
    pass silently); the refusal names WRONG-REPO vs FILE-GREW vs
    MOVED with the numbers and the remedy for each.
  * Walls: medians when both runs carry them (v2.4.6/2.4.7 lesson #4),
    single-shot otherwise. FAIL above +25% — sub-second scenarios get
    a +50% band (their single-shot noise floor) — WARN above +10%.
    Improvements are reported, never failed.
  * Derived-key deltas of >=5% are listed for the eyeball pass
    (waste_ratio, speedup, context cost, ...).

Exit 0 on GATE PASS, 1 on GATE FAIL (scriptable in release notes).
"""
from __future__ import annotations

import argparse
import json
import sys


PINS = [
    ("S5_deploy", "llmac_deploy_rc", 0),
    ("S6_edit_cas", "stale_edit_status", 409),
    ("S7_big_read", "smart_read_truncated", True),
    ("S8_transfer", "sha_match", True),
]

# v2.4.10: the S5 scenario name and its gate keys (see Verdict policy).
S5 = "S5_deploy"
S5_MEDIAN_KEY = "llmac_deploy_median_s"
S5_FALLBACK_KEY = "llmac_deploy_wall_s"

# v2.5.2 (Task-38's flapping-ratio fix): S4's single batch leg lands
# in ~40 ms bimodal WAN jitter buckets, so the speedup ratio flapped
# 22.6 -> 18.4 on untouched code. The batch-leg MEDIAN of 3 is the S4
# gate metric now (the ratio stays eyeball-class); single-shot
# fallback keeps pre-2.5.2 baselines gateable.
S4 = "S4_stat_batch"
S4_MEDIAN_KEY = "batch_median_s"
S4_FALLBACK_KEY = "batch_wall_s"


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _wall(d: dict):
    """Prefer the median when the run recorded one (lesson #4)."""
    return d.get("median_wall_s", d.get("wall_s"))


def _pct(old, new) -> float:
    return (new - old) / old * 100.0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compare a bench run against the release baseline.")
    ap.add_argument("baseline", help="baseline results JSON")
    ap.add_argument("results", help="new results JSON")
    ap.add_argument("--fail-pct", type=float, default=25.0,
                    help="wall regression FAIL threshold (default 25)")
    ap.add_argument("--subsecond-fail-pct", type=float, default=50.0,
                    help="...for scenarios under 1s in the baseline "
                         "(default 50: single-shot noise floor)")
    ap.add_argument("--warn-pct", type=float, default=10.0,
                    help="wall WARN threshold (default 10)")
    args = ap.parse_args()

    base, res = _load(args.baseline), _load(args.results)
    bs, rs = base.get("scenarios", {}), res.get("scenarios", {})
    problems: list = []
    warns: list = []

    bm, rm = base.get("meta", {}), res.get("meta", {})
    print(f"baseline: {bm.get('server_version')}  {bm.get('ts')}"
          f"  host={bm.get('host', '?')}")
    print(f"results:  {rm.get('server_version')}  {rm.get('ts')}"
          f"  host={rm.get('host', '?')}")
    print()

    # ---- correctness pins --------------------------------------------------
    for scen, key, want in PINS:
        d = rs.get(scen)
        if not isinstance(d, dict):
            warns.append(f"{scen}: absent from results (skipped scenario?)")
            continue
        got = (d.get("derived") or {}).get(key)
        ok = got == want
        print(f"  pin {scen}.{key} = {got!r} (want {want!r})"
              f"  {'ok' if ok else 'PIN FAIL'}")
        if not ok:
            problems.append(f"{scen}.{key}: {got!r} != {want!r}")

    # ---- same-file check (lessons #8 + #10) --------------------------------
    # v2.4.9: the old refusal always blamed the repo (lesson #8).
    # Distinguish WRONG-REPO from FILE-GREW / MOVED before telling the
    # user what to re-run — and compare file_path too: a moved target
    # with coincidentally equal byte counts used to pass the gate
    # silently.
    for scen in ("S7_big_read", "S8_transfer"):
        b_, r_ = bs.get(scen), rs.get(scen)
        if not (isinstance(b_, dict) and isinstance(r_, dict)):
            continue
        bd, rd = b_.get("derived") or {}, r_.get("derived") or {}
        b_path, r_path = bd.get("file_path"), rd.get("file_path")
        b_bytes, r_bytes = bd.get("file_bytes"), rd.get("file_bytes")
        if b_path == r_path and b_bytes == r_bytes:
            print(f"  same-file {scen}: {r_path} ({r_bytes} B)")
            continue
        verb = "GREW" if (r_bytes or 0) > (b_bytes or 0) else "SHRANK"
        base_repo, res_repo = bm.get("repo"), rm.get("repo")
        if b_path == r_path:
            problems.append(
                f"{scen}: the SAME file {verb} — {b_bytes} B -> "
                f"{r_bytes} B ({b_path}). Same --repo: a legitimate "
                f"code change (lesson #10) — compare per-byte "
                f"throughput (walls scale with file_bytes), then "
                f"record a FRESH baseline for the next gate.")
            print(f"  same-file {scen}: FILE-{verb} {b_bytes} -> "
                  f"{r_bytes} B (same path)")
        else:
            if base_repo and res_repo and base_repo != res_repo:
                repo_note = (f" --repo DIFFERS ({base_repo} vs "
                             f"{res_repo}): wrong repo (lesson #8) — "
                             f"re-run against the same dev repo")
            elif base_repo and res_repo and base_repo == res_repo:
                repo_note = (f" --repo matches ({base_repo}): the "
                             f"biggest file legitimately MOVED "
                             f"(lesson #10) — record a fresh baseline")
            else:
                repo_note = (" verify --repo (lesson #8: same dev "
                             "repo); else code growth moved the target "
                             "(lesson #10) — then re-baseline")
            problems.append(
                f"{scen}: biggest file MOVED — baseline {b_bytes} B "
                f"({b_path}) vs results {r_bytes} B ({r_path});"
                f"{repo_note}")
            print(f"  same-file {scen}: MOVED {b_path} -> {r_path}")

    # ---- walls -------------------------------------------------------------
    print()
    for scen in sorted(set(bs) | set(rs)):
        b_, r_ = bs.get(scen), rs.get(scen)
        if not (isinstance(b_, dict) and isinstance(r_, dict)
                and "call_log" in b_ and "call_log" in r_):
            continue
        bw, rw = _wall(b_), _wall(r_)
        if not (bw and rw):
            continue
        pct = _pct(bw, rw)
        band = (args.subsecond_fail_pct if bw < 1.0 else args.fail_pct)
        tag = ("median" if "median_wall_s" in b_
               and "median_wall_s" in r_ else "single")
        line = (f"  {scen:<16} {bw:>8.3f}s -> {rw:>8.3f}s"
                f"  {pct:+7.1f}%  [{tag}]")
        if scen == S5:
            # v2.4.10 (the v2.4.7 policy restored): the S5 scenario
            # wall carries the naive single-shot WAN-leg — printed for
            # the eyeball pass but EXCLUDED from gating; S5 gates on
            # the derived deploy median below.
            print(line + "  wall EXCLUDED — gates on " + S5_MEDIAN_KEY)
            continue
        if pct > band:
            problems.append(f"{scen}: wall {pct:+.1f}% breaks the "
                            f"+{band:.0f}% band ({bw:.3f}s -> {rw:.3f}s, "
                            f"{tag})")
            line += "  REGRESSION"
        elif pct > args.warn_pct:
            warns.append(f"{scen}: wall {pct:+.1f}% (in-band, {tag})")
            line += "  (in-band)"
        print(line)

    # ---- S5 gate: the deploy median (the v2.4.7 policy, restored) ----------
    b5 = (bs.get(S5) or {}).get("derived") or {}
    r5 = (rs.get(S5) or {}).get("derived") or {}
    if (b5.get(S5_MEDIAN_KEY) is not None
            and r5.get(S5_MEDIAN_KEY) is not None):
        key, tag = S5_MEDIAN_KEY, "median"
    elif (b5.get(S5_FALLBACK_KEY) is not None
          and r5.get(S5_FALLBACK_KEY) is not None):
        key, tag = S5_FALLBACK_KEY, "single (median absent — fallback)"
    else:
        key = None
        warns.append(f"{S5}: deploy median absent from the runs "
                     f"(skipped scenario?)")
    if key:
        bv, rv = b5.get(key), r5.get(key)
        pct = _pct(bv, rv)
        band = (args.subsecond_fail_pct if bv < 1.0 else args.fail_pct)
        line = (f"  {S5}.{key}  {bv:>8.3f}s -> {rv:>8.3f}s"
                f"  {pct:+7.1f}%  [{tag}]")
        if pct > band:
            problems.append(
                f"{S5}.{key}: {pct:+.1f}% breaks the +{band:.0f}% band "
                f"({bv:.3f}s -> {rv:.3f}s, {tag}) — the deploy MEDIAN "
                f"is the S5 gate metric; probe before diagnosing")
            line += "  REGRESSION"
        elif pct > args.warn_pct:
            warns.append(f"{S5}.{key}: {pct:+.1f}% (in-band, {tag})")
            line += "  (in-band)"
        print(line)

    # ---- S4 gate: the batch-leg median (v2.5.2, Task-38's flap fix) -------
    b4 = (bs.get(S4) or {}).get("derived") or {}
    r4 = (rs.get(S4) or {}).get("derived") or {}
    if (b4.get(S4_MEDIAN_KEY) is not None
            and r4.get(S4_MEDIAN_KEY) is not None):
        key, tag = S4_MEDIAN_KEY, "median"
    elif (b4.get(S4_FALLBACK_KEY) is not None
          and r4.get(S4_FALLBACK_KEY) is not None):
        key, tag = S4_FALLBACK_KEY, "single (median absent — fallback)"
    else:
        key = None
        warns.append(f"{S4}: batch legs absent from the runs "
                     f"(skipped scenario?)")
    if key:
        bv, rv = b4.get(key), r4.get(key)
        pct = _pct(bv, rv)
        band = (args.subsecond_fail_pct if bv < 1.0 else args.fail_pct)
        line = (f"  {S4}.{key}  {bv:>8.3f}s -> {rv:>8.3f}s"
                f"  {pct:+7.1f}%  [{tag}]")
        if pct > band:
            problems.append(
                f"{S4}.{key}: {pct:+.1f}% breaks the +{band:.0f}% band "
                f"({bv:.3f}s -> {rv:.3f}s, {tag}) — the batch-leg MEDIAN "
                f"is the S4 gate metric; the speedup ratio is eyeball-"
                f"class (single-shot WAN buckets flap it)")
            line += "  REGRESSION"
        elif pct > args.warn_pct:
            warns.append(f"{S4}.{key}: {pct:+.1f}% (in-band, {tag})")
            line += "  (in-band)"
        print(line)

    # ---- derived deltas for the eyeball pass --------------------------------
    print()
    for scen in sorted(rs):
        r_ = rs.get(scen)
        if not isinstance(r_, dict):
            continue
        rd = r_.get("derived") or {}
        bd = (bs.get(scen) or {}).get("derived") or {}
        for k in sorted(rd):
            rv, bv = rd[k], bd.get(k)
            if (isinstance(rv, (int, float)) and not isinstance(rv, bool)
                    and isinstance(bv, (int, float))
                    and not isinstance(bv, bool) and bv):
                d = _pct(bv, rv)
                if abs(d) >= 5.0:
                    print(f"  {scen}.{k}: {bv} -> {rv}  ({d:+.1f}%)")

    print()
    for w in warns:
        print(f"WARN: {w}")
    if problems:
        print()
        for p in problems:
            print(f"FAIL: {p}")
        print("\nGATE FAIL")
        return 1
    print("\nGATE PASS — pins ok, same file measured, walls in band")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
