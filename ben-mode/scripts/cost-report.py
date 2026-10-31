#!/usr/bin/env python3
"""cost-report.py — summarize gate-cost.jsonl observability metrics (P4 F3).
Prints cumulative runs, latest tokens, and flags over-budget if --budget given.
Usage: cost-report.py <meta-dir> [--budget TOKENS]
"""
import argparse, json, os, sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("meta")
    ap.add_argument("--budget", type=int, default=0)
    args = ap.parse_args()
    path = os.path.join(args.meta, "gate-cost.jsonl")
    if not os.path.isfile(path):
        print("no gate-cost.jsonl found:", path)
        sys.exit(2)
    runs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                runs.append(json.loads(line))
    total = sum(r.get("token_proxy", 0) for r in runs)
    latest = runs[-1] if runs else {}
    print(f"runs: {len(runs)}  total token_proxy: {total}")
    if latest:
        print("latest:", json.dumps(latest))
    if args.budget and total > args.budget:
        print(f"❌ BUDGET ALERT: {total} > {args.budget}")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
