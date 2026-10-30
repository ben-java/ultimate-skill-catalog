#!/usr/bin/env bash
# cron-hard-gate-monitor.sh — Daily drift detection for HARD GATE #10
# Add to crontab: 0 2 * * * /path/to/cron-hard-gate-monitor.sh
# Patterns from: ML Systems Ch8 (drift detection), TSNA Ch10 (monitoring)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_W="$(cygpath -w "$SCRIPT_DIR")"
VERIFY_SCRIPT="$SCRIPT_DIR/verify-hard-gate.sh"
ROOT="${1:-C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog}"
ALERT_LOG="${ROOT}/hard-gate-alerts.log"
# P3 #2: canonical + all physical replicas (blind-spot coverage).
CANONICAL="C:/Users/AMMAR/AppData/Local/hermes/skills/dsh-imported/ben-mode"
REPLICAS=(
    "$ROOT/ben-mode"
    "C:/Users/AMMAR/.dsh/skills/ben-mode"
    "C:/Users/AMMAR/Tools/dsh-skill-wrappers/ben-mode"
)

[ -f "$VERIFY_SCRIPT" ] || { echo "❌ verify-hard-gate.sh not found"; exit 2; }

find_python() {
    local cand
    for cand in "${PYTHON:-}" python3 python py; do
        [ -n "$cand" ] || continue
        if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "import hashlib" >/dev/null 2>&1; then
            printf '%s' "$cand"; return 0
        fi
    done
    return 1
}
PY_BIN=$(find_python) || { echo "❌ cron monitor: no python found"; exit 2; }

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "=== HARD GATE #10 Daily Drift Check ($TIMESTAMP) ===" | tee -a "$ALERT_LOG"

# Run verification + canonical-vs-replicas quorum (suppress output, capture status)
QARGS=("$(cygpath -w "$CANONICAL")")
for rep in "${REPLICAS[@]}"; do QARGS+=("$(cygpath -w "$rep")"); done
if "$VERIFY_SCRIPT" "$ROOT" >/dev/null 2>&1    && "$PY_BIN" "$SCRIPT_W/quorum-check.py" "${QARGS[@]}" >/dev/null 2>&1; then
    echo "✅ Drift check PASSED — no drift detected (gate + quorum 4-root)" | tee -a "$ALERT_LOG"
    exit 0
else
    echo "⚠️  Drift check FAILED — drift or corruption detected! (gate or canonical quorum)" | tee -a "$ALERT_LOG"
    # Re-run with output for details
    "$VERIFY_SCRIPT" "$ROOT" 2>&1 | tee -a "$ALERT_LOG"
    echo "--- quorum detail ---" | tee -a "$ALERT_LOG"
    "$PY_BIN" "$SCRIPT_W/quorum-check.py" "${QARGS[@]}" 2>&1 | tee -a "$ALERT_LOG"
    # Optional out-of-band notification (P1.4): set ALERT_WEBHOOK to enable.
    if [ -n "${ALERT_WEBHOOK:-}" ]; then
        PAYLOAD=$(printf '{"ts":"%s","status":"FAIL","root":"%s","hook":"hardgate10"}' "$TIMESTAMP" "$ROOT")
        if curl -fsS -m 15 -H "Content-Type: application/json" -d "$PAYLOAD" "$ALERT_WEBHOOK" >/dev/null 2>&1; then
            echo "✅ Alert sent to ALERT_WEBHOOK" | tee -a "$ALERT_LOG"
        else
            echo "⚠️  Alert delivery failed (ALERT_WEBHOOK set but unreachable)" | tee -a "$ALERT_LOG"
        fi
    fi
    exit 1
fi