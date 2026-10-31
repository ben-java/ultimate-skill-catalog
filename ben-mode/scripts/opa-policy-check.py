#!/usr/bin/env python3
"""opa-policy-check.py — OPTIONAL Rego (OPA) enforcement of Rego Rules 6/7
(allowlist + attestation validity).

Behavior:
  - If an `opa` binary is resolvable: evaluate the bundled policy at
    scripts/policies/rule6.rego against a sample governance input; exit 0 on
    allow, 1 on deny, 2 if eval fails.
  - If `opa` is NOT installed: print SKIPPED and exit 0 (honest optional
    enforcement — no engine is shipped by default).

Install OPA: see https://www.openpolicyagent.org/docs/latest/#running-opa
(Windows users: opa_windows_amd64.exe).
"""
import json, os, shutil, subprocess, sys

POLICY = os.path.realpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "policies", "rule6.rego"))

SAMPLE_INPUT = {
    "allowlist": {
        "allowed_drifts": [{
            "skill": "ben-mode",
            "approved_hashes": ["abc"],
            "expires_at": "2099-01-01T00:00:00Z",
        }]
    },
    "attestation": {
        "skill": "ben-mode",
        "tree_hash": "abc",
    },
}


def main():
    opa = os.environ.get("OPA_BIN") or shutil.which("opa")
    if not opa:
        for cand in (os.path.expanduser("~/bin/opa.exe"),
                     r"C:\Users\AMMAR\bin\opa.exe"):
            if os.path.isfile(cand):
                opa = cand
                break
    if not opa:
        print("opa-policy-check: SKIPPED (opa binary not installed; optional enforcement)")
        return 0
    if not os.path.isfile(POLICY):
        print("opa-policy-check: FAIL (policy file missing)")
        return 2
    import tempfile
    fd, in_path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(SAMPLE_INPUT, f)
        r = subprocess.run(
            [opa, "eval", "--format", "json", "--data", POLICY,
             "--input", in_path, "data.hardgate.allow"],
            capture_output=True, text=True)
    finally:
        os.unlink(in_path)
    if r.returncode != 0:
        print("opa-policy-check: eval failed rc=%s stderr=%r stdout=%r" % (
            r.returncode, r.stderr[-300:], r.stdout[-200:]))
        return 2
    try:
        result = json.loads(r.stdout)
    except Exception:
        print("opa-policy-check: unparsable result")
        return 2
    allowed = result.get("result", [{}])[0].get("expressions", [{}])[0].get("value")
    print("opa-policy-check: rule6 allow =", allowed)
    return 0 if allowed is True else 1


if __name__ == "__main__":
    sys.exit(main())
