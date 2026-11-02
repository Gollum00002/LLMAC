#!/usr/bin/env python3
"""Print the derived metrics from bench results.json (analysis view)."""
import json, sys

r = json.load(open(sys.argv[1], encoding="utf-8"))
print("meta:", json.dumps(r["meta"]))
print()
for name, d in r["scenarios"].items():
    if not isinstance(d, dict) or "call_log" not in d:
        continue
    print(f"== {name} ==  calls={d['calls']} cli={d['cli_calls']} "
          f"wire={d['wire_bytes']}B decoded={d['decoded_bytes']}B "
          f"est_tok~{d['est_tokens']} wall={d['wall_s']}s")
    for k, v in (d.get("derived") or {}).items():
        print(f"   {k}: {v}")
    gz = [x for x in d["call_log"] if x.get("gzip")]
    if gz:
        w = sum(x["wire_bytes"] for x in d["call_log"])
        dec = sum(x["decoded_bytes"] for x in d["call_log"])
        print(f"   [gzip on wire: {len(gz)}/{len(d['call_log'])} calls, "
              f"wire {w}B vs decoded {dec}B = {dec/max(1,w):.2f}x]")
    print()
