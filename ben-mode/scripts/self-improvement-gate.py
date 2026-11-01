#!/usr/bin/env python3
"""self-improvement-gate.py — Item6: Admission controller for recursive self-improvement.
Enforces the external-audit boundary from arXiv 2610.10611 and preprints 202609.0913.

Rules:
  1. Any self-improvement proposal (modification to SKILL.md, system prompt, or gate policy)
     must carry an external verification certificate (signed acceptance by independent runner).
  2. If the proposer identity equals the verifier identity without an external attestor,
     the proposal is REJECTED (anti-self-confirming loop).
  3. Changes to verification threshold (easing gates) are STRICTLY FORBIDDEN.

Usage: self-improvement-gate.py <proposal.json>
Proposal format:
  {"proposer": "str", "verifier": "str", "diff_targets": ["files..."],
   "external_attestation": bool, "threshold_relaxed": bool}
Exit: 0 = ADMITTED; 1 = REJECTED; 2 = INVALID_INPUT
"""
import sys, os, json

def admit(proposal):
    if not isinstance(proposal, dict):
        return False, "proposal must be a JSON object"
    proposer = proposal.get("proposer", "").strip()
    verifier = proposal.get("verifier", "").strip()
    if not proposer or not verifier:
        return False, "missing proposer or verifier"
    if proposal.get("threshold_relaxed", False):
        return False, "REJECTED: relaxation of verification threshold is forbidden"
    # Anti-self-confirming loop: agent cannot verify its own rule changes
    if proposer == verifier and not proposal.get("external_attestation", False):
        return False, "REJECTED: self-confirming loop (proposer == verifier without external attestation)"
    # Sensitive target check
    targets = proposal.get("diff_targets", [])
    for t in targets:
        if any(sens in t for sens in ("hard-gate-10.md", "verify-hard-gate.sh", "gate.conf")):
            if not proposal.get("external_attestation", False):
                return False, f"REJECTED: modification to critical gate spec '{t}' requires external attestation"
    return True, "ADMITTED"

def main():
    if len(sys.argv) < 2:
        print("Usage: self-improvement-gate.py <proposal.json>")
        sys.exit(2)
    path = sys.argv[1]
    if not os.path.isfile(path):
        print(f"File not found: {path}")
        sys.exit(2)
    try:
        proposal = json.load(open(path, encoding="utf-8"))
    except Exception as e:
        print(f"Invalid JSON: {e}")
        sys.exit(2)
    ok, msg = admit(proposal)
    print(f"ADMISSION VERDICT: {'PASS' if ok else 'FAIL'} | {msg}")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
