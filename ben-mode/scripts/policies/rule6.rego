# Rego Rule 6/7 — allowlist + attestation validity (HARD GATE #10, BAGIAN 15).
# Optional enforcement engine: opa-policy-check.py (runs only when `opa` exists).
package hardgate

import future.keywords

# Rule 6: attestation_valid — a skill's attested tree hash must be approved
# by a non-expired allowlist entry.
default allow := false

allow if {
    some drift in input.allowlist.allowed_drifts
    drift.skill == input.attestation.skill
    input.attestation.tree_hash in drift.approved_hashes
    not expired(drift.expires_at)
}

expired(ts) if {
    time.parse_rfc3339_ns(ts) < time.now_ns()
}
