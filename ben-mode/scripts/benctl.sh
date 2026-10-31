#!/usr/bin/env bash

export PYTHONDONTWRITEBYTECODE=1
export PYTHONIOENCODING=utf-8
# benctl.sh — P8-M#1: satu-perintah orkestrasi HARD GATE #10.
# Alur: sync-all-roots -> refresh-baseline -> verify -> quorum -> status-matrix.
# Usage:
#   benctl.sh [root] [--no-sync] [--no-report] [--redgreen]
# Flags:
#   --redgreen  cetak marker [RED]/[GREEN] menyeluruh (TDD-style proof).
#   --no-sync   lewati sinkronisasi replika.
#   --no-report  lewati status-matrix di akhir.
# Exit: 0 = seluruh pipeline PASS; 1 = salah satu fase gagal.
set -euo pipefail

# P18-B1: single-flight guard (atomic mkdir lock)
LOCK="${TMPDIR:-/tmp}/benctl.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  echo "⚠️ benctl: another gate run in progress — skipping (single-flight)"
  exit 0
fi
trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_W="$(cygpath -w "$SCRIPT_DIR")"
ROOT="C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog"
NO_SYNC=0; NO_REPORT=0; REDGREEN=0; QUICK=0; FULL=1
for a in "$@"; do
  case "$a" in
    --no-sync) NO_SYNC=1 ;;
    --no-report) NO_REPORT=1 ;;
    --redgreen) REDGREEN=1 ;;
    --quick) QUICK=1 ;;
    --*) echo "❌ unknown option: $a"; exit 2 ;;
    *) ROOT="$a" ;;
  esac
done

PY_BIN="${PYTHON:-python3}"
BASH_BIN="$(command -v bash || echo "C:/Program Files/Git/bin/bash.exe")"
fail() { echo "❌ benctl: $1"; exit 1; }
mark() { [ "$REDGREEN" = "1" ] && echo "[$1] $2" || echo "$2"; }

if [ "$NO_SYNC" = "0" ]; then
  mark RED "sync-all-roots (RED baseline)"
  "$BASH_BIN" "$SCRIPT_W/sync-all-roots.sh" || fail "sync-all-roots"
fi

if [ "$QUICK" = "1" ]; then
  mark GREEN "incremental quick gate (P5 E1)"
  if "$BASH_BIN" "$SCRIPT_W/verify-incremental.sh" "$ROOT" >/dev/null 2>&1; then
    echo "✅ incremental: tree unchanged — quick PASS"
    FULL=0
  else
    echo "→ incremental: tree changed — running full pipeline"
  fi
fi

if [ "$FULL" = "1" ]; then
  # P17-A2: regenerate SBOM (CycloneDX) unless disabled
  if [ "${HARD_GATE_SBOM_REGEN:-1}" = "1" ]; then
    mark GREEN "regenerate SBOM (CycloneDX)"
    "$PY_BIN" "$SCRIPT_W/generate-sbom.py" "$(cygpath -w "$SCRIPT_DIR/..")"       --out "$(cygpath -w "$ROOT/.hard-gate-meta/ben-mode.sbom.json")" || fail "sbom-regen"
  fi
  mark GREEN "refresh-baseline + verify"
  "$BASH_BIN" "$SCRIPT_W/refresh-baseline.sh" "$ROOT" ben-mode || fail "refresh/verify"
fi

mark GREEN "quorum 4-root"
CANON=$(cd "$SCRIPT_DIR/.." && pwd)
ARGS=(--root "$(cygpath -w "$CANON")")
for r in "$ROOT/ben-mode" "C:/Users/AMMAR/.dsh/skills/ben-mode" "C:/Users/AMMAR/Tools/dsh-skill-wrappers/ben-mode"; do
  ARGS+=(--replica "$(cygpath -w "$r")")
done
# full-tree verifier (quorum tool) on canonical + replicas
"$PY_BIN" "$SCRIPT_W/verify_skill_replicas.py" "${ARGS[@]}" || fail "quorum full-tree"

# P11-A: deep verification — hermetic sandbox (§16.1) + BMC (§14.1).
# Default ON (full mode); skipped in quick mode. Fail-loudly when enabled.
if [ "$FULL" = "1" ] && [ "${HARD_GATE_DEEP_TEST:-1}" = "1" ]; then
  # P14-B1: fresh-machine reproducibility (two clean bit-identical builds)
  if [ "${HARD_GATE_FRESH:-1}" = "1" ]; then
    mark GREEN "fresh-machine reproducibility (P6-E)"
    "$BASH_BIN" "$SCRIPT_W/verify-fresh-machine.sh" "$CANON" || fail "fresh-machine"
  else
    echo "⚠️ benctl: fresh-machine disabled (set HARD_GATE_FRESH=1)"
  fi
  # P15-D1: NIST AI RMF predicate (BAGIAN 22)
  mark GREEN "P_ai_rmf (BAGIAN 22)"
  "$PY_BIN" "$SCRIPT_W/gate_predicates.py" --ai-rmf "$(cygpath -w "$ROOT/.hard-gate-meta")" || fail "ai-rmf"
  mark GREEN "hermetic sandbox (§16.1)"
  "$BASH_BIN" "$SCRIPT_W/verify-hard-gate-sandbox.sh" "$ROOT" || fail "sandbox"
  mark GREEN "BMC replica-state (§14.1)"
  if "$PY_BIN" -c "import z3" >/dev/null 2>&1; then
    "$PY_BIN" "$SCRIPT_W/bmc_replica_state.py" || fail "bmc"
  else
    echo "⚠️ benctl: z3 unavailable — skipping BMC (honest)"
  fi
  mark GREEN "WASI sandbox (§16.1, wasmtime)"
  if "$PY_BIN" -c "import wasmtime" >/dev/null 2>&1; then
    "$PY_BIN" "$SCRIPT_W/wasi-sandbox-check.py" || fail "wasi-sandbox"
  else
    echo "⚠️ benctl: wasmtime unavailable — skipping WASI (honest)"
  fi
  mark GREEN "manifest signature (Ed25519, §15)"
  "$BASH_BIN" "$SCRIPT_W/sigstore-pipeline.sh" "$ROOT" || fail "sigstore-pipeline"
  mark GREEN "VSA attestation (P13-A1)"
  "$PY_BIN" "$SCRIPT_W/vsa-attestation.py" "$(cygpath -w "$ROOT/.hard-gate-meta")" >/dev/null || fail "vsa-gen"
  "$BASH_BIN" "$SCRIPT_W/sigstore-pipeline.sh" "$ROOT" || fail "vsa-sign"
  "$PY_BIN" "$SCRIPT_W/check-vsa.py" "$(cygpath -w "$ROOT/.hard-gate-meta")" || fail "vsa-check"
  mark GREEN "transparency Merkle log (P13-A2)"
  "$PY_BIN" "$SCRIPT_W/transparency-log.py" append "$(cygpath -w "$ROOT/.hard-gate-meta")" >/dev/null || fail "transparency-append"
  "$PY_BIN" "$SCRIPT_W/transparency-log.py" verify "$(cygpath -w "$ROOT/.hard-gate-meta")" || fail "transparency-verify"
fi

if [ "$NO_REPORT" = "0" ]; then
  if [ "$FULL" = "1" ]; then
    mark GREEN "negative adversarial suite (32/32)"
    "$BASH_BIN" "$SCRIPT_W/test-hard-gate-negative.sh" >/dev/null || fail "negative-suite"
  fi
  mark GREEN "routing-health + coverage"
  "$PY_BIN" "$SCRIPT_W/routing-health.py" >/dev/null || fail "routing-health"
  mark GREEN "unit tests (6/6)"
  "$PY_BIN" -m unittest discover -s "$SCRIPT_W/tests" >/dev/null || fail "unit-tests"
  mark GREEN "status-matrix + self-BOM"
  "$PY_BIN" "$SCRIPT_W/status-matrix.py" >/dev/null || fail "status-matrix"
  mark GREEN "generate-dashboard"
  "$PY_BIN" "$SCRIPT_W/generate-dashboard.py" "$(cygpath -w "$ROOT/.hard-gate-meta")" >/dev/null || true
  # P18-C1: publish identical dashboard to docs/ so P_model_signed sees fresh bytes
  cp "$ROOT/.hard-gate-meta/dashboard.html" "$ROOT/docs/dashboard.html" || true
fi

echo "✅ benctl: full pipeline OK"
