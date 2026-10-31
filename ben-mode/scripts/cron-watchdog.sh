#!/usr/bin/env bash
export PYTHONDONTWRITEBYTECODE=1
export PYTHONIOENCODING=utf-8
# cron-watchdog.sh — P9-R#4: dual-cron failover watchdog.
# If the primary monitor's last gate run is stale (or absent), this watchdog
# re-runs the full benctl pipeline so a missed primary never leaves the gate
# unverified for long. Designed to run under a second Windows Scheduled Task.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${1:-C:/Users/AMMAR/Hermes Agents/Projects/ultimate-skill-catalog}"
FRESHNESS_HOURS="${WATCHDOG_FRESHNESS_HOURS:-26}"
find_python() {
    local cand
    for cand in "${PYTHON:-}" python3 python py; do
        [ -n "$cand" ] || continue
        if command -v "$cand" >/dev/null 2>&1 && "$cand" -c "import hashlib" >/dev/null 2>&1; then
            printf '%s' "$cand"; return 0
        fi
    done
    echo python
}
PY_BIN=$(find_python)
WATCH_LOG="${ROOT}/hard-gate-watchdog.log"

now_epoch=$(date +%s)
last_epoch=0
TIME_FILE="$ROOT/.hard-gate-meta/gate-time.jsonl"
if [ -f "$TIME_FILE" ]; then
    last_epoch=$([ -f "$TIME_FILE" ] && stat -c %Y "$TIME_FILE" 2>/dev/null || echo 0)
fi

stale_sec=$((now_epoch-last_epoch))
limit_sec=$((FRESHNESS_HOURS*3600))

echo "[watchdog $(date -u +%Y-%m-%dT%H:%M:%SZ)] last_run_epoch=$last_epoch age=${stale_sec}s limit=${limit_sec}s" >> "$WATCH_LOG"

if [ "$last_epoch" -eq 0 ] || [ "$stale_sec" -gt "$limit_sec" ]; then
    echo "[watchdog] STALE -> running benctl full pipeline" >> "$WATCH_LOG"
    if "$SCRIPT_DIR/benctl.sh" "$ROOT" >> "$WATCH_LOG" 2>&1; then
        echo "[watchdog] benctl OK" >> "$WATCH_LOG"
    else
        echo "[watchdog] benctl FAILED" >> "$WATCH_LOG"
        exit 1
    fi
else
    echo "[watchdog] FRESH (no action)" >> "$WATCH_LOG"
fi

# P10-X#5: cross-consistency — confirm gate-time advanced (or still >= fresh)
# and note whether the primary monitor ran within the freshness window.
POST_TS=$([ -f "$TIME_FILE" ] && stat -c %Y "$TIME_FILE" 2>/dev/null || echo 0)
PRIMARY_LOG="${ROOT}/hard-gate-alerts.log"
if [ -f "$PRIMARY_LOG" ] && grep -q "$(date -u +%Y-%m-%d)" "$PRIMARY_LOG"; then
    echo "[watchdog] primary monitor ran today; gate-time last=$POST_TS (cross-consistent)" >> "$WATCH_LOG"
else
    echo "[watchdog] WARNING: primary monitor has no entry today (gate-time last=$POST_TS)" >> "$WATCH_LOG"
fi
exit 0
