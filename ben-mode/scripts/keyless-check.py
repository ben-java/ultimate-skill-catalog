#!/usr/bin/env python3
"""keyless-check.py — P13-A3: honest keyless OIDC availability probe.

Reports whether ambient keyless attestation (Sigstore / GH attest-build-provenance)
is possible in THIS environment. Never claims keyless verified when unavailable.
Exit 0 always; prints status.
"""
import os, sys


def main():
    is_ci = os.environ.get("GITHUB_ACTIONS") == "true"
    if is_ci:
        print("KEYLESS: available via GITHUB_ACTIONS attest-build-provenance (OIDC/C2)")
    else:
        print("KEYLESS: NOT_AVAILABLE_LOCAL (no OIDC/transparency) — Ed25519 pipeline remains authoritative")
    return 0


if __name__ == "__main__":
    sys.exit(main())
