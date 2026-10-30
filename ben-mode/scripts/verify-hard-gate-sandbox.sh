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
TMP_SB="${SANDBOX_TMPDIR:-${TMPDIR:-/tmp}/hg10-sandbox}"
mkdir -p "$TMP_SB"
LOG="$TMP_SB/hard-gate-audit.log"

echo "=== Hermetic sandbox run (env -i) — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "Environment passed into gate: PATH, TMPDIR, HARD_GATE_LOG, HOME only."

env -i \
  PATH="$MIN_PATH" \
  TMPDIR="$TMP_SB" \
  HARD_GATE_LOG="$LOG" \
  HOME="${HOME:-/tmp}" \
  bash "$VERIFY" "$@"

rc=$?
echo "Sandbox exit code: $rc"
exit $rc
