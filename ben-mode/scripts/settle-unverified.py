#!/usr/bin/env python3
"""settle-unverified.py — P14-C1: settle the 12 UNVERIFIED corpus records.

Loads the 213-record extraction (merged_records.json) and checks whether each of
the 12 previously-UNVERIFIED arXiv IDs now carries usable extracted content
(title + core_thesis). If yes -> SETTLED; else -> UNRESOLVED (not claimed).
Usage: settle-unverified.py [merged_records.json]
"""
import json, os, sys

UNVERIFIED = ["2602.15376","2602.18681","2604.05589","2607.28431","2608.02695",
              "2608.10662","2608.16937","2608.22858","2610.09374","2610.12168",
              "2610.25788","2610.30216"]
DEFAULT = r"C:\Users\AMMAR\Downloads\pi-bolt-win32-x64\Ebook AI\batches\merged_records.json"


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    if not os.path.isfile(src):
        print("settle: source missing"); return 2
    d = json.load(open(src, encoding="utf-8"))
    records = d.get("records", []) if isinstance(d, dict) else d
    by_id = {}
    for r in records:
        i = str(r.get("arxiv_id", "")).strip()
        if i:
            by_id[i] = r
    settled, unresolved = [], []
    for rid in UNVERIFIED:
        r = by_id.get(rid)
        if r and r.get("title") and r.get("core_thesis"):
            settled.append(rid)
        else:
            unresolved.append(rid)
    print("settle: %d settled, %d unresolved" % (len(settled), len(unresolved)))
    if settled:
        print("  SETTLED:", ", ".join(settled))
    if unresolved:
        print("  UNRESOLVED:", ", ".join(unresolved))
    return 0


if __name__ == "__main__":
    sys.exit(main())
