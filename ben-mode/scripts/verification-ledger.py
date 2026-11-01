#!/usr/bin/env python3
"""verification-ledger.py — P28-F: append a signed verification ledger entry.
Each gate verdict is recorded as a signed entry (Ed25519 via openssl, mirroring
sigstore-pipeline) so it can be consumed externally as a verifiable feedback
signal (e.g. reward/training metadata, per Interleaved Formal-Logic Bonus).
Usage: verification-ledger.py <meta-dir> <verdict> <reason>
Exit: 0 written; 1 fails.
"""
import json, os, subprocess, sys
from datetime import datetime, timezone

def main():
    if len(sys.argv) < 4:
        print("usage: verification-ledger.py <meta-dir> <verdict> <reason>")
        return 2
    d, verdict, reason = sys.argv[1], sys.argv[2].upper(), sys.argv[3]
    sigdir = os.path.join(d, "sigstore")
    pub = os.path.join(sigdir, "manifest.ed25519.pub")
    if not os.path.isfile(pub):
        print("verification-ledger: sigstore pubkey absent (run sigstore-pipeline first)")
        return 2
    entry = {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "verdict": verdict,
        "reason": reason[:200],
    }
    payload = json.dumps(entry, ensure_ascii=False, sort_keys=True)
    core = os.path.splitext(pub)[0]
    # reuse sigstore-managed keypair
    priv = os.path.join(sigdir, "manifest.ed25519.key")
    sig_f = os.path.join(d, "ledger.sig")
    if not os.path.isfile(priv):
        print("verification-ledger: private key absent")
        return 2
    r = subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-inkey", priv, "-rawin",
         "-in", "-", "-out", sig_f],
        input=payload.encode(), capture_output=True)
    if r.returncode != 0:
        print("verification-ledger: signing failed", r.stderr.decode()[:200])
        return 1
    entry["sig"] = open(sig_f, "rb").read().hex()
    led = os.path.join(d, "verification-ledger.jsonl")
    with open(led, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    # verify
    v = subprocess.run(
        ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub, "-rawin",
         "-in", "-", "-sigfile", sig_f],
        input=payload.encode(), capture_output=True)
    if v.returncode != 0:
        print("verification-ledger: self-verify failed")
        return 1
    print(f"verification-ledger: appended {verdict} entry (verified signature)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
