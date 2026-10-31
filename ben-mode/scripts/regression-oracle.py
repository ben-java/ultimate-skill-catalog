#!/usr/bin/env python3
"""regression-oracle.py — P9-S#6: record and compare a key-metric snapshot of the
HARD GATE #10 verification state across runs. Alerts on silent regression.

Snapshot fields are pulled from `status-matrix.py` JSON plus the last gate run's
exit code (gate-time.jsonl). Usage:
  regression-oracle.py [--accept] [--root <project>]
First run writes baseline. Later runs warn/exit 1 on any changed field unless
--accept is given (which updates the baseline).
"""
import json
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = r"C:\Users\AMMAR\Hermes Agents\Projects\ultimate-skill-catalog"


def load_matrix_json():
    py = sys.executable
    r = subprocess.run([py, os.path.join(SCRIPT_DIR, "status-matrix.py")],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    try:
        dec = json.JSONDecoder()
        obj, _ = dec.raw_decode(r.stdout[r.stdout.find("{"):])
        return obj
    except Exception:
        return None


def last_gate_rc(root):
    f = os.path.join(root, ".hard-gate-meta", "gate-time.jsonl")
    if not os.path.isfile(f):
        return None
    rows = []
    for line in open(f, encoding="utf-8"):
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows[-1].get("rc") if rows else None


def snapshot(root):
    m = load_matrix_json()
    d = {
        "version": (m or {}).get("version"),
        "negative_test_count": (m or {}).get("negative_test_count"),
        "unit_test_count": (m or {}).get("unit_test_count"),
        "bom_missing_count": len((m or {}).get("bom_missing", [])),
        "version_consistent": (m or {}).get("version_consistent"),
        "last_gate_rc": last_gate_rc(root),
    }
    return d


def main():
    accept = "--accept" in sys.argv
    root = None
    if "--root" in sys.argv:
        root = sys.argv[sys.argv.index("--root") + 1]
    root = root or DEFAULT_ROOT
    meta = os.path.join(root, ".hard-gate-meta")
    os.makedirs(meta, exist_ok=True)
    snap_path = os.path.join(meta, "regression-snapshot.json")

    cur = snapshot(root)
    if not os.path.isfile(snap_path):
        json.dump(cur, open(snap_path, "w", encoding="utf-8"), indent=2)
        print("regression-oracle: baseline written", json.dumps(cur))
        sys.exit(0)

    prev = json.loads(open(snap_path, encoding="utf-8").read())
    changed = {k: (prev.get(k), cur.get(k)) for k in cur
               if prev.get(k) != cur.get(k)}
    if changed:
        if accept:
            json.dump(cur, open(snap_path, "w", encoding="utf-8"), indent=2)
            print("regression-oracle: ACCEPTED changes:", json.dumps(changed))
            sys.exit(0)
        print("regression-oracle: ALERT — metric drift detected:")
        for k, (o, n) in changed.items():
            print("  %s: %r -> %r" % (k, o, n))
        sys.exit(1)
    print("regression-oracle: OK (no drift)")
    sys.exit(0)


if __name__ == "__main__":
    main()
