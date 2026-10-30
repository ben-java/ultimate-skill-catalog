#!/usr/bin/env python3
"""report-drift.py — per-file drift diff of a skill tree vs its manifest baseline.

Baseline artifact: <meta>/<skill>.manifest.json (full per-file sha256 list,
from generate_manifest.py). Compares against the CURRENT tree, prints
added/removed/changed files and an aggregate verdict, then appends one JSONL
line to <meta>/gate-audit-aggregated.jsonl.

Usage:
    python report-drift.py <root> <skill> [--meta-dir <dir>] [--quiet]
Exit 0 = no drift; 1 = drift.
"""
import argparse, datetime, hashlib, json, os, sys


def canonical_sha256(p):
    data = open(p, "rb").read().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def current_files(root):
    out = {}
    for dp, _dn, fn in os.walk(root):
        for f in fn:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            out[rel] = canonical_sha256(p)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("skill")
    ap.add_argument("--meta-dir", default=None)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    meta = args.meta_dir or os.path.join(args.root, ".hard-gate-meta")
    manifest_path = os.path.join(meta, f"{args.skill}.manifest.json")
    if not os.path.isfile(manifest_path):
        print(f"report-drift: baseline manifest not found: {manifest_path}")
        sys.exit(2)

    baseline = json.load(open(manifest_path, encoding="utf-8"))
    base = {e["path"]: e["sha256"] for e in baseline.get("files", [])}
    cur = current_files(os.path.join(args.root, args.skill))

    added = sorted(set(cur) - set(base))
    removed = sorted(set(base) - set(cur))
    changed = sorted(k for k in set(base) & set(cur) if base[k] != cur[k])
    drift = added + removed + changed

    if not args.quiet:
        print(f"skill: {args.skill}")
        print(f"baseline files: {len(base)}  current files: {len(cur)}")
        for k in removed:
            print(f"  REMOVED {k}")
        for k in added:
            print(f"  ADDED   {k}")
        for k in changed:
            print(f"  CHANGED {k}")
        print("verdict:", "DRIFT" if drift else "CLEAN")

    entry = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "skill": args.skill,
        "status": "DRIFT" if drift else "CLEAN",
        "added": len(added), "removed": len(removed), "changed": len(changed),
        "files": {"added": added, "removed": removed, "changed": changed},
    }
    os.makedirs(meta, exist_ok=True)
    with open(os.path.join(meta, "gate-audit-aggregated.jsonl"), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    sys.exit(1 if drift else 0)


if __name__ == "__main__":
    main()
