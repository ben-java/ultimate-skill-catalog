#!/usr/bin/env bash
# verify-hard-gate-sandbox.sh — Hermetic wrapper (BAGIAN 16.1)
# Runs verify-hard-gate.sh in an isolated environment: purges inherited
# non-deterministic environment variables and pins a minimal PATH, so results
# are reproducible across hosts (zero host-drift).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY="$SCRIPT_DIR/verify-hard-gate.sh"

# Minimal, pinned tool PATH (bash, coreutils, sed/awk/grep/wc, jq, date, tee).
MIN_PATH="/usr/bin:/bin:/usr/local/bin"
[ -n "${SYSTEMROOT:-}" ] && MIN_PATH="$MIN_PATH:$SYSTEMROOT/System32"
# P11-A: resolve a python for validator predicates (SBOM/VC) inside hermetic env,
# and expose it as PY_BIN so verify-hard-gate.sh's internal validators run.
PY_BIN=""
for _c in "${PYTHON:-}" python3 python py; do
  [ -n "$_c" ] || continue
  if command -v "$_c" >/dev/null 2>&1 && "$_c" -c "import json" >/dev/null 2>&1; then
    PY_BIN="$_c"; break
  fi
done
[ -n "$PY_BIN" ] && { _PYDIR="$(dirname "$(command -v "$PY_BIN")")"; MIN_PATH="$MIN_PATH:$_PYDIR"; }
TMP_SB="${SANDBOX_TMPDIR:-${TMPDIR:-/tmp}/hg10-sandbox}"
mkdir -p "$TMP_SB"
LOG="$TMP_SB/hard-gate-audit.log"

echo "=== Hermetic sandbox run (env -i) — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "Environment passed into gate: PATH, TMPDIR, HARD_GATE_LOG, HOME, PY_BIN only."

env -i \
  PATH="$MIN_PATH" \
  TMPDIR="$TMP_SB" \
  HARD_GATE_LOG="$LOG" \
  HOME="${HOME:-/tmp}" \
  PY_BIN="$PY_BIN" \
  bash "$VERIFY" "$@"

rc=$?
echo "Sandbox exit code: $rc"
exit $rc
