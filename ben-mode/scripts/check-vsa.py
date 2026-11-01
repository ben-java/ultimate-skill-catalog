#!/usr/bin/env python3
"""check-vsa.py — P13-A1: validate VSA schema + Ed25519 signature.

Usage: check-vsa.py <meta-dir>  (exit 0 PASS, 1 FAIL, 2 missing)
"""
import json, os, subprocess, sys

ACCEPTED_VSA_TYPES = {"https://slsa.dev/verification_summary/v0.2", "https://slsa.dev/verification_summary/v1"}


def main():
    d = sys.argv[1]
    vsa = os.path.join(d, "vsa.json")
    sig = os.path.join(d, "vsa.sig")
    pub = os.path.join(d, "sigstore", "manifest.ed25519.pub")
    if not all(os.path.isfile(x) for x in (vsa, sig, pub)):
        print("check-vsa: missing vsa/sig/pubkey"); return 2
    doc = json.load(open(vsa, encoding="utf-8"))
    if doc.get("type") not in ACCEPTED_VSA_TYPES:
        print("check-vsa: bad type"); return 1
    if not doc.get("subject") or "digest" not in doc["subject"][0]:
        print("check-vsa: subject missing"); return 1
    r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub,
                         "-rawin", "-in", vsa, "-sigfile", sig],
                        capture_output=True, text=True)
    if r.returncode != 0:
        print("check-vsa: signature invalid (%s)" % r.stderr.strip().splitlines()[-1:]); return 1
    # P_transparency: VSA subject digest must match recomputed Merkle root.
    try:
        import importlib.util
        mod_p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "transparency-log.py")
        spec_m = importlib.util.spec_from_file_location("transparency_log", mod_p)
        tl_mod = importlib.util.module_from_spec(spec_m)
        spec_m.loader.exec_module(tl_mod)
        _merkle_root = tl_mod._merkle_root
        tl_file = os.path.join(d, "transparency.merkle.json")
        tl = json.load(open(tl_file, encoding="utf-8"))
        recomputed = _merkle_root([l["hash"] for l in tl["leaves"]])
        if recomputed != tl.get("root"):
            print("check-vsa: P_transparency FAIL — stored root mismatch"); return 1
        subj = {x.get("name"): x.get("digest", {}).get("sha256") for x in doc.get("subject", [])}
        if subj.get("transparency.merkle") != recomputed:
            print("check-vsa: P_transparency FAIL — VSA subject != root"); return 1
    except Exception as e:
        print("check-vsa: P_transparency check error (%s)" % e); return 1
    print("check-vsa: OK (type=%s result=%s P_transparency=PASS)" % (doc.get("type"), doc.get("result")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
