#!/usr/bin/env python3
"""sigstore-verify.py — P9-Q#2 / P10-V#1: keyless Sigstore/Cosign verification.

Behaviour:
  - Self-check (default): report whether a `cosign` binary is provisioned;
    exit 0 if yes, 2 if not.
  - Verify mode: when HARD_GATE_COSIGN_VERIFY=1 and an `--artifact` is supplied,
    run `cosign verify-blob` with a cert/signature/identity/issuer (keyless
    OIDC style). Exit 0 on verified, 1 on denial, 2 on error.
Keyless OIDC design (G3): signer identity = CI workflow OIDC token, not a
long-lived key; Fulcio issues a short-lived cert bound to that identity.
"""
import argparse
import os
import shutil
import subprocess
import sys


def find_cosign():
    cand = os.environ.get("COSIGN_BIN") or shutil.which("cosign")
    if not cand:
        for c in (os.path.expanduser("~/bin/cosign.exe"),
                  r"C:\Users\AMMAR\bin\cosign.exe"):
            if os.path.isfile(c):
                return c
    return cand


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact")
    ap.add_argument("--signature")
    ap.add_argument("--cert")
    ap.add_argument("--identity")
    ap.add_argument("--issuer")
    args = ap.parse_args()

    cosign = find_cosign()
    if not cosign:
        print("sigstore-verify: cosign NOT provisioned")
        return 2

    if os.environ.get("HARD_GATE_COSIGN_VERIFY", "0") != "1" or not args.artifact:
        r = subprocess.run([cosign, "version"], capture_output=True, text=True)
        ok = r.returncode == 0 and ("cosign" in (r.stdout + r.stderr).lower())
        print("sigstore-verify: cosign provisioned ->", "OK" if ok else "version?")
        return 0 if ok else 2

    # Real keyless verify-blob enforcement.
    cmd = [cosign, "verify-blob", "--cert", args.cert,
           "--signature", args.signature, args.artifact]
    if args.identity:
        cmd += ["--certificate-identity", args.identity]
    if args.issuer:
        cmd += ["--certificate-oidc-issuer", args.issuer]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode == 0:
        print("sigstore-verify: KEYLESS VERIFICATION PASSED")
        return 0
    print("sigstore-verify: verify-blob failed rc=%s %s"
          % (r.returncode, r.stderr.strip()[-200:]))
    return 1


if __name__ == "__main__":
    sys.exit(main())
