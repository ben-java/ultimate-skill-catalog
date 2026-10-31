#!/usr/bin/env python3
"""traceability.py — P13-C3: spec -> predicate/test/file traceability matrix.

Each spec section / external gap maps to the artifacts that implement it. The
script verifies every referenced script/fixture exists and prints a coverage
summary. Exit 0 = all references resolve.
"""
import os, sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(SCRIPT_DIR, "fixtures")

# spec anchor -> (predicates, fixtures, scripts)
MAP = {
    "§1 invariant": (["P_catalogs", "P_files", "P_links", "P_quorum_hash", "P_schema"],
                     [], ["verify-hard-gate.sh", "verify_skill_replicas.py"]),
    "§5 Rego": (["P_attestation", "P_allowlist"], [], ["opa-policy-check.py"]),
    "G1/G4 runtime": (["P_runtime", "P_rt_injection", "P_rt_highrisk_hitl", "P_rt_secrets", "P_rt_output_structure"],
                       ["inject.jsonl", "multi_inject.jsonl", "override_system.jsonl", "highrisk.jsonl", "secrets.jsonl", "output_structure.jsonl"],
                       ["runtime_gate.py", "runtime-gate-watch.py", "zero-trust-pep.py"]),
    "G2/G3 supply-chain": (["P_signed_manifest", "P_attestation"],
                           [], ["generate_manifest.py", "sigstore-pipeline.sh", "vsa-attestation.py", "check-vsa.py", "keyless-check.py"]),
    "G6 SBOM": (["P_bom"], [], ["generate-sbom.py"]),
    "G9 reproducible": (["P_reproducible"], [], ["verify-fresh-machine.sh"]),
    "G11 VC": (["P_allowlist"], [], ["vc-allowlist.py", "allowlist.py"]),
    "§14.1 BMC": (["P_quorum_hash"], [], ["bmc_replica_state.py"]),
    "§16.1 sandbox": (["P_reproducible"], [], ["verify-hard-gate-sandbox.sh", "wasi-sandbox-check.py"]),
    "P13-A2 transparency": ([], [], ["transparency-log.py"]),
    "P13-B3 auto-repair": ([], [], ["auto-repair.sh"]),
    "P14-A1 Merkle->VSA": (["P_transparency"], [], ["vsa-attestation.py", "check-vsa.py"]),
    "P14-A2 daily signed anchor": ([], [], ["daily-root-anchor.sh"]),
    "P14-B1 model signed": (["P_model_signed"], [], ["check-model-signed.py"]),
    "P14-C1 settle unverified": ([], [], ["settle-unverified.py"]),
    "BAGIAN 22 AI RMF": (["P_ai_rmf"], [], ["gate_predicates.py"]),
    "P15-B incremental quick": (["P_tree_sig"], [], ["verify-incremental.sh"]),
    "P16-A OPA direct enforce": (["P_attestation"], [], ["opa-policy-check.py", "verify-hard-gate.sh"]),
    "P17-A live runtime audit": (["P_runtime"], [], ["runtime-monitor.sh", "agentlog2trace.py"]),
    "P17-B budget threshold": ([], [], ["cost-report.py"]),
    "P18-A spec parity": (["P_spec_parity"], [], ["gate_predicates.py"]),
    "P18-B single-flight": ([], [], ["benctl.sh"]),
    "P18-C atomic manifest": (["P_model_signed"], [], ["generate-dashboard.py", "check-model-signed.py"]),
    "P18-D live telemetry": ([], [], ["status-matrix.py"]),
    "P19-A integrated suite/unit": ([], [], ["benctl.sh"]),
    "P19-C spec version": (["P_spec_parity"], [], ["status-matrix.py"]),
    "P19-D routing coverage": ([], [], ["routing-health.py"]),
    "P21-C audit rotation": ([], [], ["rotate-audit-logs.py"]),
    "P23-A fresh default": ([], [], ["benctl.sh", "verify-fresh-machine.sh"]),
    "P23-B actionable coverage": ([], [], ["routing-health.py"]),
    "P23-C gate verdict": ([], [], ["status-matrix.py"]),
    "P24-A spec parity fresh": ([], [], ["gate_predicates.py"]),
    "P24-C git baseline": ([], [], ["benctl.sh"]),
    "P24-D fresh-guard test": ([], [], ["test-hard-gate-negative.sh"]),
    "P25-A hook hardening": ([], [], ["install-precommit-hook.sh"]),
    "P25-B weekly gate verdict": ([], [], ["weekly-summary.py"]),
    "P26-1 tool policy (OPA7)": ([], [], ["opa-policy-check.py", "policies/rule7.rego"]),
    "P26-2 plan drift": (["P_rt_plan_drift"], [], ["runtime_gate.py"]),
    "P26-3 IFC": (["P_rt_ifc"], [], ["runtime_gate.py"]),
    "P26-6 tool schema": (["P_rt_tool_schema"], [], ["runtime_gate.py"]),
}


def main():
    missing = []
    for sec, (_preds, fixes, scripts) in sorted(MAP.items()):
        for scr in scripts:
            if not os.path.isfile(os.path.join(SCRIPT_DIR, scr)):
                missing.append("%s -> script %s" % (sec, scr))
        for fx in fixes:
            if not os.path.isfile(os.path.join(FIX, fx)):
                missing.append("%s -> fixture %s" % (sec, fx))
    print("traceability: %d spec anchors mapped" % len(MAP))
    if missing:
        print("traceability: UNRESOLVED")
        for m in missing:
            print("  -", m)
        return 1
    print("traceability: OK — all referenced scripts/fixtures resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
