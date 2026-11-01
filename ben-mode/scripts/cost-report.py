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
    ap.add_argument("--threshold", type=int, default=80)
    ap.add_argument("--attribution", action="store_true", help="P28-E: honest per-skill token attribution from runtime audit")
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
    if args.attribution:
        raudit = os.path.join(args.meta, "runtime-audit.jsonl")
        by_skill = {}
        n = 0
        if os.path.isfile(raudit):
            for line in open(raudit, encoding="utf-8", errors="replace"):
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                sk = ev.get("skill") or ev.get("session_id") or "unattributed"
                tok = ev.get("token_proxy") or 0
                by_skill[sk] = by_skill.get(sk, 0) + tok
                n += 1
        if not by_skill:
            print("  attribution: no per-skill data in runtime-audit.jsonl (honest n/a)")
        else:
            print("  attribution (per-skill token_proxy, top 10):")
            for sk, tok in sorted(by_skill.items(), key=lambda x: -x[1])[:10]:
                print(f"    {sk}: {tok}")
    if latest:
        print("latest:", json.dumps(latest))
    if args.budget and total > args.budget:
        print(f"❌ BUDGET ALERT: {total} > {args.budget}")
        sys.exit(1)
    if args.budget > 0:
        pct = total * 100 // args.budget
        print(f"budget usage: {pct}% of {args.budget}")
        if pct >= args.threshold:
            print(f"⚠️  BUDGET {pct}% >= {args.threshold}% threshold — approaching cap")
    sys.exit(0)


if __name__ == "__main__":
    main()
