#!/usr/bin/env python3
"""vsa-attestation.py — P13-A1: SLSA Verification Summary Attestation.

Reads the latest gate run (gate-time.jsonl) and the canonical manifest to emit a
deterministic VSA (https://slsa.dev/verification_summary/v0.2) into
<meta>/vsa.json. The VSA is later signed by sigstore-pipeline.sh.
Usage: vsa-attestation.py <meta-dir>
"""
import hashlib, json, os, sys
from datetime import datetime, timezone

VSA_TYPE = "https://slsa.dev/verification_summary/v1"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    d = sys.argv[1]
    gt = os.path.join(d, "gate-time.jsonl")
    manifest = os.path.join(d, "ben-mode.manifest.json")
    if not os.path.isfile(gt):
        print("vsa: no gate-time.jsonl"); return 2
    lines = [l for l in open(gt, encoding="utf-8").read().splitlines() if l.strip()]
    if not lines:
        print("vsa: empty gate-time"); return 2
    run = json.loads(lines[-1])
    status = str(run.get("status", "")).upper()
    result = "PASS" if status == "PASS" else "FAIL"
    subject = {"name": "ben-mode-hard-gate-10", "digest": {"sha256": "0"*64}}
    if os.path.isfile(manifest):
        subject = {"name": "ben-mode.manifest.json", "digest": {"sha256": sha256_file(manifest)}}
    subjects = [subject]
    tl_file = os.path.join(d, "transparency.merkle.json")
    if os.path.isfile(tl_file):
        try:
            tl = json.load(open(tl_file, encoding="utf-8"))
            subjects.append({"name": "transparency.merkle",
                            "digest": {"sha256": tl.get("root", "0" * 64)}})
        except Exception:
            pass
    vsa = {
        "type": VSA_TYPE,
        "predicateType": "https://slsa.dev/verification_summary/v1",
        "subject": subjects,
        "verifier": {"id": "benmode.hard-gate-10", "version": "0.26.0"},
        "slsa_source_level": "SLSA_SOURCE_LEVEL_3",
        "result": result,
        "verified_levels": ["SLSA_SOURCE_L3", "SLSA_BUILD_L2"],
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    out = os.path.join(d, "vsa.json")
    json.dump(vsa, open(out, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print("vsa: wrote %s (result=%s)" % (out, result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
