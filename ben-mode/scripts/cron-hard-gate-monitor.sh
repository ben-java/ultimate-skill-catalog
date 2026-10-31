#!/usr/bin/env bash

export PYTHONDONTWRITEBYTECODE=1
export PYTHONIOENCODING=utf-8
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
BASH_BIN="$(command -v bash || echo "C:/Program Files/Git/bin/bash.exe")"

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
if "$BASH_BIN" "$SCRIPT_DIR/benctl.sh" --quick --no-report >/dev/null 2>&1; then
    echo "✅ Drift check PASSED — no drift detected (gate + quorum 4-root)" | tee -a "$ALERT_LOG"
    # P8-O#6/P9-T#7: keep observability dashboard fresh on every cron pass.
    "$PY_BIN" "$SCRIPT_W/generate-dashboard.py" "$(cygpath -w "$ROOT/.hard-gate-meta")" >/dev/null 2>&1 || true
    "$PY_BIN" "$SCRIPT_W/status-matrix.py" >/dev/null 2>&1 || true
    # P10-X#6: regression-oracle drift detection wired into cron.
    if "$PY_BIN" "$SCRIPT_W/regression-oracle.py" --root "$ROOT" >/dev/null 2>&1; then
        echo "✅ Regression-oracle OK (no metric drift)" | tee -a "$ALERT_LOG"
    else
        echo "⚠️ Regression-oracle ALERT — metric drift detected" | tee -a "$ALERT_LOG"
        "$PY_BIN" "$SCRIPT_W/regression-oracle.py" --root "$ROOT" 2>&1 | tee -a "$ALERT_LOG" || true
    fi
    # P11-D: runtime gate daily self-check (clean PASS / injection FAIL)
    if "$PY_BIN" "$SCRIPT_W/runtime_gate.py" "$SCRIPT_W/fixtures/clean.jsonl" >/dev/null 2>&1        && ! "$PY_BIN" "$SCRIPT_W/runtime_gate.py" "$SCRIPT_W/fixtures/inject.jsonl" >/dev/null 2>&1; then
        echo "✅ P_runtime gate healthy (clean PASS / inject FAIL)" | tee -a "$ALERT_LOG"
        # P17-A1: live agent.log runtime scan (slice -> trace -> runtime_gate)
        "$BASH_BIN" "$SCRIPT_DIR/runtime-monitor.sh" >/dev/null 2>&1; RC_LIVE=$?
        if [ "$RC_LIVE" -eq 0 ]; then
            echo "✅ Live agent.log runtime scan PASS" | tee -a "$ALERT_LOG"
        elif [ "$RC_LIVE" -eq 2 ]; then
            echo "⚠️ Live agent.log scan skipped (no agent.log)" | tee -a "$ALERT_LOG"
        else
            echo "⚠️ Live agent.log scan FAIL — injection/secret detected" | tee -a "$ALERT_LOG"
        fi
        # P19-B1: daily budget threshold alert (80%)
        "$PY_BIN" "$SCRIPT_DIR/cost-report.py" "$(cygpath -w "$ROOT/.hard-gate-meta")" --budget "${HARD_GATE_BUDGET:-1000000}" --threshold 80 >>"$ALERT_LOG" 2>&1 || true
        # P21-C1: rotate audit logs (threshold 512KB)
        "$PY_BIN" "$SCRIPT_DIR/rotate-audit-logs.py" "$(cygpath -w "$ROOT/.hard-gate-meta")" --threshold 524288 >>"$ALERT_LOG" 2>&1 || true
        # P14-A2: daily signed-root anchor
        "$SCRIPT_DIR/daily-root-anchor.sh" "$ROOT" >>"$ALERT_LOG" 2>&1 || true
        # P14-D2: alert if consecutive daily anchors differ (root drift)
        ANCH="$ROOT/.hard-gate-meta/anchors"
        A2=$(ls -1 "$ANCH"/root-*.txt 2>/dev/null | tail -1)
        A1=$(ls -1 "$ANCH"/root-*.txt 2>/dev/null | tail -2 | head -1)
        if [ -n "$A2" ] && [ -n "$A1" ] && [ "$(cat "$A1")" != "$(cat "$A2")" ]; then
            echo "⚠️  Merkle root drift across daily anchors ($(basename "$A1") != $(basename "$A2"))" | tee -a "$ALERT_LOG"
        fi
    else
        echo "⚠️ P_runtime gate anomaly" | tee -a "$ALERT_LOG"
    fi
    exit 0
else
    echo "⚠️  Drift check FAILED — drift or corruption detected! (gate or canonical quorum)" | tee -a "$ALERT_LOG"
    # Re-run with output for details (guard: verify exits 1 under set -e)
    "$VERIFY_SCRIPT" "$ROOT" 2>&1 | tee -a "$ALERT_LOG" || true
    echo "--- quorum detail ---" | tee -a "$ALERT_LOG"
    QOUT=$("$PY_BIN" "$SCRIPT_W/quorum-check.py" "${QARGS[@]}" 2>&1 | tee -a "$ALERT_LOG" || true)
    # P4 A4: optional self-repair (sync canonical -> replicas -> re-verify)
    if [ "${REPAIR_FLAG:-0}" = "1" ]; then
        echo "↻ REPAIR: isolate drifted replicas + re-sync (P13-B3)" | tee -a "$ALERT_LOG"
        if "$SCRIPT_DIR/auto-repair.sh" "$ROOT" >/dev/null 2>&1; then
            echo "✅ REPAIR succeeded — gate GREEN after auto-repair" | tee -a "$ALERT_LOG"
        else
            echo "❌ REPAIR failed — manual intervention required" | tee -a "$ALERT_LOG"
        fi
    fi
    # Optional out-of-band notification (P1.4/P4 A4): set ALERT_WEBHOOK to enable.
    if [ -n "${ALERT_WEBHOOK:-}" ]; then
        QJSON=$(printf '%s' "$QOUT" | python -c "import json,sys; print(json.dumps(sys.stdin.read()[-400:]))" 2>/dev/null || printf '""')
        PAYLOAD=$(printf '{"ts":"%s","status":"FAIL","root":"%s","hook":"hardgate10","quorum":%s}' "$TIMESTAMP" "$ROOT" "$QJSON")
        if curl -fsS -m 15 -H "Content-Type: application/json" -d "$PAYLOAD" "$ALERT_WEBHOOK" >/dev/null 2>&1; then
            echo "✅ Alert sent to ALERT_WEBHOOK" | tee -a "$ALERT_LOG"
        else
            echo "⚠️  Alert delivery failed (ALERT_WEBHOOK set but unreachable)" | tee -a "$ALERT_LOG"
        fi
    fi
    exit 1
fi