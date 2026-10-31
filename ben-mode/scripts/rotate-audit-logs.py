#!/usr/bin/env python3
"""rotate-audit-logs.py — P21-C1: retention/rotation of growing audit JSONL/logs.

Files in <meta>/ larger than --threshold bytes are archived to
<meta>/archive/<ts>/ (copy) then the live file is truncated to empty.
Exit 0 always (best-effort).
"""
import argparse, os, shutil, sys, time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("meta")
    ap.add_argument("--threshold", type=int, default=512 * 1024)
    args = ap.parse_args()

    targets = [
        "gate-time.jsonl", "gate-cost.jsonl", "runtime-audit.jsonl",
        "gate-audit-aggregated.jsonl", "hard-gate-audit.log",
        "hard-gate-audit.log.json", "transparency.merkle.json",
    ]
    ts = time.strftime("%Y%m%d-%H%M%S")
    archived = 0
    for name in targets:
        p = os.path.join(args.meta, name)
        if not os.path.isfile(p):
            continue
        sz = os.path.getsize(p)
        if sz < args.threshold:
            continue
        adir = os.path.join(args.meta, "archive", ts)
        os.makedirs(adir, exist_ok=True)
        shutil.copy2(p, os.path.join(adir, name))
        # truncate live file (history preserved in archive)
        open(p, "w").close()
        archived += 1
    print("rotated %d file(s) > %d bytes -> archive/%s" % (archived, args.threshold, ts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
