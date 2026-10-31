#!/usr/bin/env python3
"""model-tier.py — P9-T#8 (optional, default OFF): suggest a model routing tier
from the gate's recent token_proxy load. Gated behind HARD_GATE_MODEL_ROUTING=1
so it never changes default behavior. Informs `model-routing` (no auto-switch).
"""
import json
import os
import sys

DEFAULT_ROOT = r"C:\Users\AMMAR\Hermes Agents\Projects\ultimate-skill-catalog"


def main():
    if os.environ.get("HARD_GATE_MODEL_ROUTING", "0") != "1":
        print("model-tier: disabled (set HARD_GATE_MODEL_ROUTING=1 to enable)")
        return 0
    root = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ROOT
    f = os.path.join(root, ".hard-gate-meta", "gate-cost.jsonl")
    if not os.path.isfile(f):
        print("model-tier: no gate-cost.jsonl; tier=t2")
        return 0
    rows = []
    for line in open(f, encoding="utf-8"):
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    recent = rows[-7:] if len(rows) > 7 else rows
    load = sum(r.get("token_proxy", 0) for r in recent) / max(len(recent), 1)
    tier = "t3" if load > 200000 else ("t2" if load > 60000 else "t1")
    print("model-tier: avg_token_proxy=%d -> tier=%s" % (load, tier))
    return 0


if __name__ == "__main__":
    sys.exit(main())
