#!/usr/bin/env python3
"""check-model-signed.py — P7-I#6: optional `P_model_signed` gate.
Verifies that each referenced model/asset (weights, tokenizer, config) in a
manifest exists on disk and its SHA-256 matches the recorded digest.
Manifest: <meta>/model-hashes.json -> {"assets": [{"path": rel, "sha256": hex}]}
Exit: 0 = all match; 1 = any mismatch/missing; 2 = precondition.
"""
import argparse, hashlib, json, os, sys


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 16):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--meta", default=None)
    args = ap.parse_args()
    meta = args.meta or os.path.join(args.root, ".hard-gate-meta")
    manifest = os.path.join(meta, "model-hashes.json")
    if not os.path.isfile(manifest):
        sys.stderr.write("no model-hashes.json\n")
        sys.exit(2)
    d = json.loads(open(manifest, encoding="utf-8").read())
    assets = d.get("assets", [])
    if not assets:
        sys.stderr.write("empty assets\n"); sys.exit(2)
    bad = 0
    for a in assets:
        rel = a["path"]; want = a.get("sha256", "")
        full = os.path.join(args.root, rel) if not os.path.isabs(rel) else rel
        if not os.path.isfile(full):
            print(f"  MISSING {rel}"); bad += 1; continue
        got = sha256_file(full)
        if want and got != want:
            print(f"  HASH MISMATCH {rel}"); bad += 1
    if bad:
        sys.stderr.write(f"P_model_signed FAIL ({bad})\n"); sys.exit(1)
    print("P_model_signed PASS (%d assets)" % len(assets))


if __name__ == "__main__":
    main()
