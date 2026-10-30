#!/usr/bin/env python3
"""aggregate-audit.py — dedupe + summarize all gate audit JSONL under <meta> into
one aggregate file (gate-audit-aggregated.jsonl, already appended to by
report-drift.py) and print a short summary.

Usage: python aggregate-audit.py <root> [--top 25]
"""
import argparse, json, os
from collections import Counter


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args()

    meta = os.path.join(args.root, ".hard-gate-meta")
    agg_path = os.path.join(meta, "gate-audit-aggregated.jsonl")
    seen, entries = set(), []
    for name in sorted(os.listdir(meta)):
        if not name.endswith(".jsonl"):
            continue
        p = os.path.join(meta, name)
        try:
            for line in open(p, encoding="utf-8"):
                line = line.strip()
                if not line:
                    continue
                if line in seen:
                    continue
                seen.add(line)
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
        except Exception:
            pass

    with open(agg_path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    statuses = Counter(e.get("status") for e in entries)
    print(f"aggregated {len(entries)} audit events -> {agg_path}")
    print("status distribution:", dict(statuses))
    if entries and args.top:
        print("latest events:")
        for e in entries[-args.top:]:
            print("  ", e.get("ts", "?"), e.get("status"), e.get("skill", ""))


if __name__ == "__main__":
    main()
